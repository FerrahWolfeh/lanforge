//! NDP (`Neighbor Discovery Protocol`) monitor for IPv6 and ARP.
//!
//! Reacts to Linux kernel neighbor events (`RTM_NEWNEIGH`/`RTM_DELNEIGH`) and
//! keeps the `LanforgeContext` synchronized with the kernel's NDP/ARP cache.
//!
//! ## Integration Flow
//!
//! ```mermaid
//! sequenceDiagram
//!     participant K as Kernel netlink
//!     participant N as NeighborMonitor
//!     participant E as NeighborEvent
//!     participant C as LanforgeContext
//!
//!     K->>N: RTM_NEWNEIGH / RTM_DELNEIGH
//!     N->>E: extract_neigh_info
//!     E->>C: to_device_update
//!     C->>C: apply update (SlaacObserved/NdpSeen/ArpSeen)
//! ```
//!
//! ## Features
//!
//! - **Event-driven**: Listens to netlink broadcast for neighbor state changes
//! - **Bootstrap**: Full neighbor table dump on startup via `slaac::bootstrap_table()`
//! - **ARP subnet scan**: On `NeighborScanRequested`, probes every IPv4 in the subnet
//!   (paced at 10ms/address to avoid CPU spikes)
//! - **Prefix tracking**: Updates GUA/ULA context from RA for SLAAC classification
//!
//! ## Critical Service
//!
//! Marked as `critical: true` — failure halts the daemon.

#[cfg(test)]
pub mod tests;
pub mod utils;

use crate::ndp::utils::{
    extract_neigh_info, get_ipv4_neighbors, get_ipv4_subnet_iterable, get_ipv6_neighbors,
    probe_neighbor,
};
use lanforge_core::bus::{LanforgeEvent, NetworkEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::ndp::NeighborEvent;
use lanforge_core::service::{AsyncService, ServiceControl};
use netlink_packet_core::NetlinkMessage;
use netlink_sys::SocketAddr;
use rtnetlink::Handle;
use rtnetlink::packet_route::RouteNetlinkMessage;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// NeighborMonitor — Reacts to netlink neighbor events
// ---------------------------------------------------------------------------

type NetlinkMessageStream = broadcast::Receiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>;

/// Monitors kernel neighbor table changes via netlink events.
///
/// Maintains synchronization with the `LanforgeContext` by applying
/// `DeviceUpdate` events for every neighbor state change.
#[lanforge_macros::lanforge_service(
    id = "monitor",
    name = "Neighbor Monitor",
    critical = true,
    retries = 0,
    base_backoff = 2,
    max_backoff = 30
)]
pub struct NeighborMonitor {
    handle: Handle,
    messages: NetlinkMessageStream,
    target_ifindex: u32,
    ctx: LanforgeContext,
    scan_in_progress: Arc<AtomicBool>,
}

impl NeighborMonitor {
    /// Creates a new `NeighborMonitor` for the given interface.
    #[must_use]
    pub fn new(
        handle: Handle,
        messages: NetlinkMessageStream,
        target_ifindex: u32,
        ctx: LanforgeContext,
    ) -> Self {
        Self {
            handle,
            messages,
            target_ifindex,
            ctx,
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
}

async fn run_subnet_scan_task(handle: Handle, ctx: LanforgeContext, ifindex: u32) {
    let interface_state = ctx.get_interface_state(ifindex);
    if let Some((ip, prefix_len)) = interface_state.v4 {
        let range = get_ipv4_subnet_iterable(ip, prefix_len);
        let count = range.size_hint().1.unwrap_or(0);
        if count > 0 {
            info!(
                "NeighborMonitor: Unleashing massive ARP scan for {}/{} ({} addresses)",
                ip, prefix_len, count
            );
            // Notification via event bus
            let _ = ctx
                .bus()
                .publish(LanforgeEvent::Network(NetworkEvent::SubnetScanStarted {
                    subnet: format!("{ip}/{prefix_len}"),
                }));

            for target_ip in range {
                if let Err(e) = probe_neighbor(&handle, ifindex, IpAddr::V4(target_ip), None).await
                {
                    debug!("NeighborMonitor: ARP probe failed for {target_ip}: {e}");
                }
                // Pacing for manual scan: 10ms between addresses to avoid CPU spikes
                sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

impl AsyncService for NeighborMonitor {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        // 0. Wait for Interface Ready (Sanity check)
        // This ensures the initial_scan has completed and ctx is seeded with prefixes.
        self.ctx.wait_for_interfaces().await?;

        let mut bus_rx = self.ctx.bus().subscribe();

        // Initialize prefixes from current context state
        let if_state = self.ctx.get_interface_state(self.target_ifindex);
        let mut current_gua: Option<Ipv6Addr> = if_state.gua;
        let mut current_ula: Option<Ipv6Addr> = if_state.ula;

        // 1. Initial Neighbor Scan (Bootstrap)
        // We perform a simple dump of the kernel's neighbor table for the interface.
        // This is "gentle" because it just sends individual Added events for existing entries.
        {
            info!("NeighborMonitor: Performing initial neighbor bootstrap...");
            let mut bootstrap_events = Vec::new();

            match get_ipv4_neighbors(&self.handle, Some(self.target_ifindex)).await {
                Ok(evs) => bootstrap_events.extend(evs),
                Err(e) => error!("NeighborMonitor: Failed to dump IPv4 neighbors: {e}"),
            }

            match get_ipv6_neighbors(&self.handle, "", Some(self.target_ifindex)).await {
                Ok(evs) => bootstrap_events.extend(evs),
                Err(e) => error!("NeighborMonitor: Failed to dump IPv6 neighbors: {e}"),
            }

            for event in bootstrap_events {
                if let Some(update) =
                    event.to_device_update(current_gua.as_ref(), current_ula.as_ref())
                {
                    let _ = self.ctx.apply(update);
                }
            }
        }

        ctrl.signal_ready();

        let mut pending_batch = Vec::new();
        let mut flush_timer = tokio::time::interval(std::time::Duration::from_millis(100));

        loop {
            if !self.ctx.is_running() {
                break;
            }
            tokio::select! {
                res = self.messages.recv() => {
                    let Ok((msg, _addr)) = res else {
                        if matches!(res, Err(broadcast::error::RecvError::Lagged(_))) {
                            warn!("NeighborMonitor: Netlink broadcast lagged");
                            continue;
                        }
                        break;
                    };
                    // A. Handle Neighbor Events
                    if let Some(event) = extract_neigh_info(&msg)
                        && event.ifindex() == self.target_ifindex {
                            if let NeighborEvent::Added { mac, ip, is_active, .. } = event {
                                // Optimization: Batch Added events during scans/bursts
                                pending_batch.push((mac, ip, is_active));
                                if pending_batch.len() >= 50 {
                                    let batch = std::mem::take(&mut pending_batch);
                                    let _ = self.ctx.apply_neighbor_batch(batch);
                                }
                            } else {
                                // Flush pending batch before processing delete/fail to maintain order
                                if !pending_batch.is_empty() {
                                    let batch = std::mem::take(&mut pending_batch);
                                    let _ = self.ctx.apply_neighbor_batch(batch);
                                }
                                if let Some(update) = event.to_device_update(current_gua.as_ref(), current_ula.as_ref()) {
                                    let _ = self.ctx.apply(update);
                                }
                            }
                        }
                }

                _ = flush_timer.tick() => {
                    if !pending_batch.is_empty() {
                        let batch = std::mem::take(&mut pending_batch);
                        let _ = self.ctx.apply_neighbor_batch(batch);
                    }
                }

                Ok(timed_event) = bus_rx.recv() => {
                    lanforge_core::match_event!(timed_event, {
                        LanforgeEvent::Network(NetworkEvent::PrefixChanged { gua, ula, .. }) => {
                            current_gua = gua;
                            current_ula = ula;
                        }
                        LanforgeEvent::Network(NetworkEvent::NeighborScanRequested) => {
                            self.spawn_subnet_scan("Manual CLI Request");
                        }
                    });
                }

                else => break,
            }
        }

        info!("NeighborMonitor: Service stopped");
        Ok(())
    }
}
