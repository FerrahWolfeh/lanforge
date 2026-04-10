//! Netlink wrapper for IPv6 neighbor queries and event filtering.
//!
//! Centralizes all interaction with the Linux kernel's netlink subsystem.
//!
//! ## Integration Flow with Manager
//!
//! ```mermaid
//! sequenceDiagram
//!     participant K as Kernel (RTM_NEWNEIGH)
//!     participant N as netlink::extract_neigh_info()
//!     participant E as NeighborEvent
//!     participant C as LanforgeContext (apply)
//!
//!     K->>N: Inbound Message
//!     N->>E: Option<NeighborEvent>
//!     Note over E: to_device_update(prefix)
//!     E->>C: SlaacObserved (GUA) / NdpSeen (Other)
//! ```

#[cfg(test)]
pub mod tests;
pub mod utils;

use crate::ndp::utils::{
    extract_neigh_info, get_ipv4_subnet_iterable, probe_neighbor, run_periodic_probes_task,
};
use crate::slaac::bootstrap_table;
use futures::StreamExt;
use futures::channel::mpsc::UnboundedReceiver;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, LanforgeService, ServiceMeta};
use netlink_packet_core::NetlinkMessage;
use netlink_sys::SocketAddr;
use rtnetlink::Handle;
use rtnetlink::packet_route::RouteNetlinkMessage;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::{interval, sleep};
use tracing::{error, info};

// ---------------------------------------------------------------------------
// NdpMonitor — The "Serviceable Struct" for Netlink
// ---------------------------------------------------------------------------

type NetlinkMessageStream = UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>;

/// Monitor that reacts to Netlink neighbor events and keeps the `ManagedTable` updated.
pub struct NeighborMonitor {
    handle: Handle,
    messages: Arc<Mutex<NetlinkMessageStream>>,
    target_ifindex: u32,
    ctx: LanforgeContext,
    scan_interval: Duration,
    scan_in_progress: Arc<AtomicBool>,
}

impl NeighborMonitor {
    pub fn new(
        handle: Handle,
        messages: Arc<Mutex<NetlinkMessageStream>>,
        target_ifindex: u32,
        ctx: LanforgeContext,
        scan_interval: Duration,
    ) -> Self {
        Self {
            handle,
            messages,
            target_ifindex,
            ctx,
            scan_interval,
            scan_in_progress: Arc::new(AtomicBool::new(false)),
        }
    }

    fn spawn_subnet_scan(&self, source: &str) {
        if self.scan_in_progress.load(Ordering::SeqCst) {
            tracing::warn!(
                "NeighborMonitor: Subnet scan already in progress (source: {source}), ignoring request."
            );
            return;
        }

        info!("NeighborMonitor: Spawning subnet scan task (source: {source})");
        let handle = self.handle.clone();
        let ctx = self.ctx.clone();
        let ifindex = self.target_ifindex;
        let in_progress = self.scan_in_progress.clone();

        tokio::spawn(async move {
            in_progress.store(true, Ordering::SeqCst);
            run_subnet_scan_task(handle, ctx, ifindex).await;
            in_progress.store(false, Ordering::SeqCst);
        });
    }

    fn spawn_periodic_probes(
        &self,
        source: &str,
        gua: Option<Ipv6Addr>,
        ula: Option<Ipv6Addr>,
        force_all: bool,
    ) {
        tracing::debug!(
            "NeighborMonitor: Spawning periodic probes task (source: {source}, force_all: {force_all})"
        );
        let handle = self.handle.clone();
        let ctx = self.ctx.clone();
        let ifindex = self.target_ifindex;

        tokio::spawn(async move {
            run_periodic_probes_task(handle, ctx, ifindex, gua, ula, force_all).await;
        });
    }
}

async fn run_subnet_scan_task(handle: Handle, ctx: LanforgeContext, ifindex: u32) {
    let interface_state = ctx.get_interface_state(ifindex);
    if let Some((ip, prefix_len)) = interface_state.v4 {
        let range = get_ipv4_subnet_iterable(ip, prefix_len);
        if !range.is_empty() {
            info!(
                "NeighborMonitor: Unleashing massive ARP scan for {}/{} ({} addresses)",
                ip,
                prefix_len,
                range.len()
            );
            // Notification via event bus
            let _ = ctx.bus().publish(LanforgeEvent::SubnetScanStarted {
                subnet: format!("{ip}/{prefix_len}"),
            });

            for target_ip in range {
                if let Err(e) = probe_neighbor(&handle, ifindex, IpAddr::V4(target_ip), None).await
                {
                    tracing::debug!("NeighborMonitor: ARP probe failed for {target_ip}: {e}");
                }
                // Pacing for manual scan: 10ms between addresses to avoid CPU spikes
                sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

impl LanforgeService for NeighborMonitor {
    fn meta(&self) -> ServiceMeta {
        ServiceMeta {
            id: "monitor",
            display_name: "Neighbor Monitor",
            critical: true,
            max_retries: 0,
            base_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(30),
            stack_kb: 512,
        }
    }

    fn describe(&self) -> String {
        format!("Neighbor Monitor (ifindex: {})", self.target_ifindex)
    }

    fn on_shutdown(&mut self) -> Result<(), CoreError> {
        Ok(())
    }
}

impl AsyncService for NeighborMonitor {
    async fn run(&mut self) -> Result<(), CoreError> {
        let mut bus_rx = self.ctx.bus().subscribe();
        let mut current_gua: Option<Ipv6Addr> = None;
        let mut current_ula: Option<Ipv6Addr> = None;
        let mut probe_interval = interval(Duration::from_secs(60));
        let mut subnet_scan_interval = if self.scan_interval.as_secs() > 0 {
            let mut interval = interval(self.scan_interval);
            // Ensure the first periodic scan happens after the first interval, not immediately.
            interval.reset();
            Some(interval)
        } else {
            None
        };

        // 1. Initial Neighbor Scan (Bootstrap)
        {
            if let Err(e) = bootstrap_table(
                &self.ctx,
                "",
                &self.handle,
                None,
                None,
                Some(self.target_ifindex),
            )
            .await
            {
                error!("NeighborMonitor: Initial bootstrap scan failed: {e}");
            }
        }

        // 2. Initial network-wide probe (Boot Discovery on all known devices)
        {
            let devices = self.ctx.all_devices();
            info!(
                "NeighborMonitor: Triggering initial discovery probe for {} devices",
                devices.len()
            );
            // Non-blocking discovery probe (force_all = true)
            self.spawn_periodic_probes("Boot Discovery", current_gua, current_ula, true);
        }

        loop {
            if !self.ctx.is_running() {
                break;
            }
            let mut rx = self.messages.lock().await;
            tokio::select! {
                res = rx.next() => {
                    drop(rx);
                    let Some((msg, _addr)) = res else { break };
                    // A. Handle Neighbor Events
                    if let Some(event) = extract_neigh_info(&msg)
                        && event.ifindex() == self.target_ifindex {
                            let update = event.to_device_update(current_gua.as_ref(), current_ula.as_ref());
                            if !self.ctx.apply(&update) {
                                // No change or error
                            }
                        }
                }

                Ok(event) = bus_rx.recv() => {
                    drop(rx);
                    match event.event {
                        LanforgeEvent::PrefixChanged { gua, ula, .. } => {
                            current_gua = gua;
                            current_ula = ula;
                        }
                        LanforgeEvent::NeighborScanRequested => {
                            self.spawn_subnet_scan("Manual CLI Request");
                        }
                        _ => {}
                    }
                }

                _ = probe_interval.tick() => {
                    drop(rx);
                    // B. Periodic Surgical Probes for silent online devices
                    self.spawn_periodic_probes("Periodic Timer", current_gua, current_ula, false);
                }

                () = async {
                    if let Some(i) = subnet_scan_interval.as_mut() {
                        i.tick().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    drop(rx);
                    // C. Periodic full subnet discovery
                    self.spawn_subnet_scan("Periodic Subnet Timer");
                }

                else => break,
            }
        }

        info!("NeighborMonitor: Service stopped");
        Ok(())
    }
}
