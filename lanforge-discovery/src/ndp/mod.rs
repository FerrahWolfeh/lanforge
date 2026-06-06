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

pub mod config;
#[cfg(test)]
pub mod tests;
pub mod utils;

use crate::ndp::config::MonitorConfig;
use crate::ndp::utils::{
    extract_neigh_info, get_ipv4_neighbors, get_ipv4_subnet_iterable, get_ipv6_neighbors,
    probe_neighbor,
};
use crate::ping::IcmpPinger;
use lanforge_core::bus::{DeviceEvent, LanforgeEvent, NetworkChange, NetworkEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceControl};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::NeighborEvent;
use lanforge_types::update::DeviceUpdate;
use netlink_packet_core::NetlinkMessage;
use netlink_sys::SocketAddr;
use rtnetlink::Handle;
use rtnetlink::packet_route::RouteNetlinkMessage;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// NeighborMonitor — Reacts to netlink neighbor events
// ---------------------------------------------------------------------------

type NetlinkMessageStream = broadcast::Receiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>;

/// Unified neighbor discovery (NDP/ARP) and active ICMP ping engine.
///
/// Maintains synchronization with the `LanforgeContext` by applying
/// `DeviceUpdate` events for every neighbor state change.
#[lanforge_macros::lanforge_service(
    id = "monitor",
    name = "Discovery Service",
    critical = true,
    retries = 0,
    base_backoff = 2,
    max_backoff = 30
)]
pub struct DiscoveryService {
    cfg: MonitorConfig,
    handle: Handle,
    messages: NetlinkMessageStream,
    target_ifindex: u32,
    ctx: LanforgeContext,
    scan_in_progress: Arc<AtomicBool>,
}

impl DiscoveryService {
    /// Creates a new `DiscoveryService` for the given interface.
    #[must_use]
    pub fn new(
        cfg: MonitorConfig,
        handle: Handle,
        messages: NetlinkMessageStream,
        target_ifindex: u32,
        ctx: LanforgeContext,
    ) -> Self {
        Self {
            cfg,
            handle,
            messages,
            target_ifindex,
            ctx,
            scan_in_progress: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn flush_neighbor_batch(&self, batch: Vec<(MacAddr, IpAddr, bool)>) {
        let start = Instant::now();
        let total = batch.len();

        // Apply to state and collect returned events
        let events = self
            .ctx
            .apply_with_events(DeviceUpdate::NeighborBatch { entries: batch });

        // Diagnostic: Publish summary of the batch
        let duration = start.elapsed();
        let new_count = events
            .iter()
            .filter(|e| matches!(e, LanforgeEvent::Device(DeviceEvent::Discovered { .. })))
            .count();

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Device(DeviceEvent::NeighborBatchSummary {
                total,
                new: new_count,
                duration_ms: u64::try_from(duration.as_millis()).unwrap_or_default(),
            }));
    }

    fn spawn_subnet_scan(&self, source: &str) {
        if self.scan_in_progress.load(Ordering::SeqCst) {
            tracing::warn!(
                "DiscoveryService: Subnet scan already in progress (source: {source}), ignoring request."
            );
            return;
        }

        info!("DiscoveryService: Spawning subnet scan task (source: {source})");
        let handle = self.handle.clone();
        let ctx = self.ctx.clone();
        let ifindex = self.target_ifindex;
        let in_progress = self.scan_in_progress.clone();
        let pacing = Duration::from_millis(self.cfg.scan_pacing_ms);

        tokio::spawn(async move {
            in_progress.store(true, Ordering::SeqCst);
            run_subnet_scan_task(handle, ctx, ifindex, pacing).await;
            in_progress.store(false, Ordering::SeqCst);
        });
    }
}

async fn run_subnet_scan_task(
    handle: Handle,
    ctx: LanforgeContext,
    ifindex: u32,
    pacing: Duration,
) {
    let interface_state = ctx.get_interface_state(ifindex);
    if let Some((ip, prefix_len)) = interface_state.v4 {
        let range = get_ipv4_subnet_iterable(ip, prefix_len);
        let count = range.size_hint().1.unwrap_or(0);
        if count > 0 {
            info!(
                "DiscoveryService: Unleashing massive ARP scan for {}/{} ({} addresses)",
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
                    // EEXIST (os error 17) is benign — neighbor already exists in kernel table.
                    let msg = e.to_string();
                    if !msg.contains("os error 17") {
                        debug!("DiscoveryService: ARP probe failed for {target_ip}: {e}");
                    }
                }
                // Pacing for manual scan: from config to avoid CPU spikes
                sleep(pacing).await;
            }
        }
    }
}

impl AsyncService for DiscoveryService {
    #[allow(clippy::too_many_lines)]
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        // 0. Wait for Interface Ready (Sanity check)
        // This ensures the initial_scan has completed and ctx is seeded with prefixes.
        self.ctx.wait_for_interfaces().await?;

        // 0.5. Spin up the integrated ICMP active pinger helper if enabled
        let pinger = if self.cfg.ping_enabled {
            match IcmpPinger::new(self.ctx.clone()) {
                Ok(p) => {
                    info!("DiscoveryService: Integrated active ICMP pinger initialized.");
                    Some(Arc::new(p))
                }
                Err(e) => {
                    warn!("DiscoveryService: Failed to initialize integrated ICMP pinger: {e}");
                    None
                }
            }
        } else {
            None
        };

        if let Some(pinger_ref) = &pinger {
            // A. Spawn periodic ICMP active ping sweep task
            let pinger_sweep = pinger_ref.clone();
            let ctx_sweep = self.ctx.clone();
            let ping_interval = self.cfg.ping_interval_secs;
            tokio::spawn(async move {
                let mut sweep_timer = interval(Duration::from_secs(ping_interval));
                let mut seq_counter = 0u16;
                loop {
                    if !ctx_sweep.is_running() {
                        break;
                    }
                    sweep_timer.tick().await;

                    let ips = {
                        let state = ctx_sweep.read();
                        let mut all_ips = Vec::new();
                        for dev in state.devices.values() {
                            if dev.origin != lanforge_types::device::Origin::System {
                                if let Some(v4) = dev.v4.ip() {
                                    all_ips.push(IpAddr::V4(v4));
                                }
                                for (v4_seen, _) in &dev.seen_v4 {
                                    all_ips.push(IpAddr::V4(*v4_seen));
                                }
                                for v6_state in &dev.v6 {
                                    if let Some(v6_ip) = v6_state.ip() {
                                        all_ips.push(IpAddr::V6(v6_ip));
                                    }
                                }
                            }
                        }
                        drop(state);
                        all_ips
                    };

                    for ip in ips {
                        seq_counter = seq_counter.wrapping_add(1);
                        let pinger_c = pinger_sweep.clone();
                        let ctx_c = ctx_sweep.clone();
                        tokio::spawn(async move {
                            if matches!(pinger_c.ping(ip, seq_counter).await, Ok(true))
                                && let Some(mac) = ctx_c.get_mac_by_ip(ip)
                            {
                                let update = match ip {
                                    IpAddr::V4(v4) => DeviceUpdate::ArpSeen {
                                        mac,
                                        ip: v4,
                                        is_active: true,
                                    },
                                    IpAddr::V6(v6) => DeviceUpdate::NdpSeen {
                                        mac,
                                        ip: v6,
                                        is_active: true,
                                    },
                                };
                                let _ = ctx_c.apply(update);
                            }
                        });
                        sleep(Duration::from_millis(10)).await;
                    }
                }
            });

            // B. Spawn EventBus subscriber for JIT offline verification pings
            let pinger_jit = pinger_ref.clone();
            let ctx_jit = self.ctx.clone();
            tokio::spawn(async move {
                let mut bus_rx = ctx_jit.bus().subscribe();
                let mut seq_counter = 0u16;
                loop {
                    if !ctx_jit.is_running() {
                        break;
                    }
                    match bus_rx.recv().await {
                        Ok(timed_event) => {
                            if let LanforgeEvent::Device(DeviceEvent::NetworkActivity {
                                change,
                                ..
                            }) = &timed_event.event
                                && let NetworkChange::IpOffline { ip } = &**change
                            {
                                seq_counter = seq_counter.wrapping_add(1);
                                let pinger_c = pinger_jit.clone();
                                let ctx_c = ctx_jit.clone();
                                let target_ip = *ip;
                                tokio::spawn(async move {
                                    debug!(
                                        "DiscoveryService: JIT verification ping triggered for offline transition of {}",
                                        target_ip
                                    );
                                    if matches!(
                                        pinger_c.ping(target_ip, seq_counter).await,
                                        Ok(true)
                                    ) && let Some(mac) = ctx_c.get_mac_by_ip(target_ip)
                                    {
                                        let update = match target_ip {
                                            IpAddr::V4(v4) => DeviceUpdate::ArpSeen {
                                                mac,
                                                ip: v4,
                                                is_active: true,
                                            },
                                            IpAddr::V6(v6) => DeviceUpdate::NdpSeen {
                                                mac,
                                                ip: v6,
                                                is_active: true,
                                            },
                                        };
                                        let _ = ctx_c.apply(update);
                                    }
                                });
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!(
                                service = "DiscoveryServicePinger",
                                lost = n,
                                "Event bus lagged"
                            );
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        let mut bus_rx = self.ctx.bus().subscribe();

        // Initialize prefixes from current context state
        let if_state = self.ctx.get_interface_state(self.target_ifindex);
        let mut current_gua: Option<Ipv6Addr> = if_state.gua;
        let mut current_ula: Option<Ipv6Addr> = if_state.ula;

        // 1. Initial Neighbor Scan (Bootstrap)
        // We perform a simple dump of the kernel's neighbor table for the interface.
        // This is "gentle" because it just sends individual Added events for existing entries.
        {
            debug!("DiscoveryService: Performing initial neighbor bootstrap...");
            let mut bootstrap_events = Vec::new();

            match get_ipv4_neighbors(&self.handle, Some(self.target_ifindex)).await {
                Ok(evs) => bootstrap_events.extend(evs),
                Err(e) => error!("DiscoveryService: Failed to dump IPv4 neighbors: {e}"),
            }

            match get_ipv6_neighbors(&self.handle, "", Some(self.target_ifindex)).await {
                Ok(evs) => bootstrap_events.extend(evs),
                Err(e) => error!("DiscoveryService: Failed to dump IPv6 neighbors: {e}"),
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

        let mut pending_batch = Vec::with_capacity(50);
        let mut flush_timer = interval(Duration::from_millis(self.cfg.batch_interval_ms));

        loop {
            if !self.ctx.is_running() {
                break;
            }
            tokio::select! {
                res = self.messages.recv() => {
                    let Ok((msg, _addr)) = res else {
                        if let Err(broadcast::error::RecvError::Lagged(n)) = res {
                            warn!(service = "DiscoveryService", lost = n, "Netlink broadcast lagged");
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
                                    let batch = std::mem::replace(&mut pending_batch, Vec::with_capacity(50));
                                    self.flush_neighbor_batch(batch);
                                }
                            } else {
                                // Flush pending batch before processing delete/fail to maintain order
                                if !pending_batch.is_empty() {
                                    let batch = std::mem::take(&mut pending_batch);
                                    self.flush_neighbor_batch(batch);
                                }
                                if let Some(update) = event.to_device_update(current_gua.as_ref(), current_ula.as_ref()) {
                                    let _ = self.ctx.apply(update);
                                }
                            }
                        }
                }

                _ = flush_timer.tick() => {
                    if !pending_batch.is_empty() {
                        let batch = std::mem::replace(&mut pending_batch, Vec::with_capacity(50));
                        self.flush_neighbor_batch(batch);
                    }
                }

                res = bus_rx.recv() => {
                    let Ok(timed_event) = res else {
                        if let Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) = res {
                            warn!(service = "DiscoveryService", lost = n, "Event bus lagged");
                            continue;
                        }
                        break; // Channel closed
                    };
                    lanforge_core::match_event!(timed_event, {
                        LanforgeEvent::Network(NetworkEvent::PrefixChanged { gua, ula, .. }) => {
                            current_gua = *gua;
                            current_ula = *ula;
                        }
                        LanforgeEvent::Network(NetworkEvent::NeighborScanRequested) => {
                            self.spawn_subnet_scan("Manual CLI Request");
                        }
                    });
                }
            }
        }

        info!("DiscoveryService: Service stopped");
        Ok(())
    }
}
