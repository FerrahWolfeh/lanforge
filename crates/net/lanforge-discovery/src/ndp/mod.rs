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
use crate::ndp::utils::{extract_neigh_info, get_ipv4_neighbors, get_ipv6_neighbors};
use crate::ping::IcmpPinger;
use lanforge_core::bus::{DeviceEvent, LanforgeEvent, NetworkChange, NetworkEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    AsyncService, Condition, Edge, LanforgeService, RestartPolicy, RuntimeClass, ServiceCommand,
    ServiceHandle, ServiceSpec,
};
use lanforge_transport::{ArpProber, TransportStats};
use lanforge_types::device::{IPv4State, IPv6State, Origin};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::NeighborEvent;
use lanforge_types::system::DormantReason;
use lanforge_types::update::DeviceUpdate;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_sys::SocketAddr;
use parking_lot::Mutex;
use rtnetlink::Handle;
use rtnetlink::packet_route::RouteNetlinkMessage;
use smallvec::SmallVec;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::broadcast;
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// NeighborMonitor — Reacts to netlink neighbor events
// ---------------------------------------------------------------------------

type NetlinkMessageStream = broadcast::Receiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>;

fn ifindex_to_name(ifindex: u32) -> Option<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let res = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr().cast()) };
    if res.is_null() {
        None
    } else {
        std::ffi::CStr::from_bytes_until_nul(&buf)
            .ok()
            .and_then(|cs| cs.to_str().ok())
            .map(String::from)
    }
}

#[derive(Default)]
pub(crate) struct IfNameCache {
    pub(crate) cache: std::collections::HashMap<u32, String>,
}

impl IfNameCache {
    pub(crate) fn new() -> Self {
        Self {
            cache: std::collections::HashMap::new(),
        }
    }

    pub(crate) fn get(&mut self, ifindex: u32) -> Option<&str> {
        match self.cache.entry(ifindex) {
            std::collections::hash_map::Entry::Occupied(e) => Some(e.into_mut().as_str()),
            std::collections::hash_map::Entry::Vacant(e) => {
                let name = ifindex_to_name(ifindex)?;
                Some(e.insert(name).as_str())
            }
        }
    }
}

use lanforge_types::system::ServiceId;

const MONITOR_DEPS: &[Edge] = &[
    Edge::requires(
        ServiceId::Interfaces,
        lanforge_core::service::LossPolicy::Degrade,
    ),
    Edge::after(ServiceId::Db),
];

/// Unified neighbor discovery (NDP/ARP) and active ICMP ping engine.
///
/// Maintains synchronization with the `LanforgeContext` by applying
/// `DeviceUpdate` events for every neighbor state change.
pub struct DiscoveryService {
    cfg: MonitorConfig,
    handle: Handle,
    messages: NetlinkMessageStream,
    target_ifindexes: Vec<u32>,
    ctx: LanforgeContext,
    pinger: Option<Arc<IcmpPinger>>,
    prober_cache: Arc<Mutex<HashMap<String, ArpProber>>>,
}

impl TransportStats for DiscoveryService {
    fn snapshot(&self) -> lanforge_types::network::snapshot::TransportSnapshot {
        let mut snap = self
            .pinger
            .as_ref()
            .map(|p| p.snapshot())
            .unwrap_or_default();
        let probers = self.prober_cache.lock();
        for p in probers.values() {
            let s = p.snapshot();
            snap.rx_packets += s.rx_packets;
            snap.rx_bytes += s.rx_bytes;
            snap.tx_packets += s.tx_packets;
            snap.tx_bytes += s.tx_bytes;
            snap.dropped += s.dropped;
            snap.rate_limited += s.rate_limited;
            snap.errors += s.errors;
            if s.last_error_age_secs.is_some()
                && (snap.last_error_age_secs.is_none()
                    || s.last_error_age_secs < snap.last_error_age_secs)
            {
                snap.last_error_age_secs = s.last_error_age_secs;
            }
        }
        drop(probers);
        snap
    }
}

impl DiscoveryService {
    /// Static identifier for the service.
    pub const SERVICE_ID: ServiceId = ServiceId::Discovery;

    /// Creates a new `DiscoveryService` for the given interfaces.
    #[must_use]
    pub fn new(
        cfg: MonitorConfig,
        handle: Handle,
        messages: NetlinkMessageStream,
        target_ifindexes: Vec<u32>,
        ctx: LanforgeContext,
    ) -> Self {
        let pinger = if cfg.ping_enabled {
            IcmpPinger::new().ok().map(Arc::new)
        } else {
            None
        };
        Self {
            cfg,
            handle,
            messages,
            target_ifindexes,
            ctx,
            pinger,
            prober_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub(crate) fn flush_neighbor_batch(&self, batch: Vec<(MacAddr, IpAddr, bool)>) {
        let start = Instant::now();
        let total = batch.len();

        // Apply to state and collect returned events
        let events = self
            .ctx
            .apply_with_events(DeviceUpdate::NeighborBatch { entries: batch });

        // Diagnostic: Publish summary of the batch only if new devices were discovered
        let duration = start.elapsed();
        let new_count = events
            .iter()
            .filter(|e| matches!(e, LanforgeEvent::Device(DeviceEvent::Discovered { .. })))
            .count();

        if new_count > 0 {
            let _ =
                self.ctx
                    .bus()
                    .publish(LanforgeEvent::Device(DeviceEvent::NeighborBatchSummary {
                        total,
                        new: new_count,
                        duration_ms: u64::try_from(duration.as_millis()).unwrap_or_default(),
                    }));
        } else {
            debug!(
                service = "DiscoveryService",
                total,
                duration_ms = duration.as_millis(),
                "Neighbor batch processed with 0 new devices"
            );
        }
    }

    pub(crate) fn process_neighbor_event(
        &self,
        event: &NeighborEvent,
        ifname_cache: &mut IfNameCache,
        ctx: &LanforgeContext,
        pending_batch: &mut Vec<(MacAddr, IpAddr, bool)>,
        current_gua: Option<&lanforge_types::network::Ipv6Prefix>,
        current_ula: Option<&lanforge_types::network::Ipv6Prefix>,
    ) {
        if let NeighborEvent::Added {
            mac,
            ip,
            is_active,
            ifindex,
        } = *event
        {
            if let Some(ifname) = ifname_cache.get(ifindex) {
                let needs_update = ctx.with_state(|state| {
                    state
                        .devices
                        .get(&mac)
                        .is_none_or(|dev| dev.iface.as_deref() != Some(ifname))
                });
                if needs_update {
                    let _ = ctx.apply(DeviceUpdate::DeviceInterfaceSeen {
                        mac,
                        iface: ifname.to_string(),
                    });
                }
            }
            pending_batch.push((mac, ip, is_active));
            if pending_batch.len() >= 50 {
                let batch = std::mem::replace(pending_batch, Vec::with_capacity(50));
                self.flush_neighbor_batch(batch);
            }
        } else {
            if !pending_batch.is_empty() {
                let batch = std::mem::take(pending_batch);
                self.flush_neighbor_batch(batch);
            }
            if let Some(update) = event.to_device_update(current_gua, current_ula) {
                let _ = ctx.apply(update);
            }
        }
    }
}

impl LanforgeService for DiscoveryService {
    fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: Self::SERVICE_ID,
            display_name: "Discovery Service",
            runtime: RuntimeClass::Shared,
            restart: RestartPolicy::default(),
            shutdown_timeout: std::time::Duration::from_secs(5),
            deps: MONITOR_DEPS,
            condition: Condition::ALWAYS,
        }
    }
}

impl AsyncService for DiscoveryService {
    fn transport_snapshot(
        &self,
        _ctx: &LanforgeContext,
    ) -> Option<lanforge_types::network::snapshot::TransportSnapshot> {
        Some(self.snapshot())
    }

    fn stats(&self, ctx: &LanforgeContext) -> Vec<(std::borrow::Cow<'static, str>, String)> {
        let (total_devices, active_devices) = ctx.with_state(|state| {
            let total = state.devices.len();
            let active = state
                .devices
                .values()
                .filter(|d| d.status == lanforge_types::device::DeviceStatus::Online)
                .count();
            (total, active)
        });
        let snap = self.snapshot();
        vec![
            (
                std::borrow::Cow::Borrowed("target_ifindexes"),
                format!("{:?}", self.target_ifindexes),
            ),
            (
                std::borrow::Cow::Borrowed("ping_enabled"),
                self.cfg.ping_enabled.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("ping_interval_secs"),
                self.cfg.ping_interval_secs.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("total_devices"),
                total_devices.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("active_devices"),
                active_devices.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("rx_packets"),
                snap.rx_packets.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("tx_packets"),
                snap.tx_packets.to_string(),
            ),
        ]
    }

    async fn init(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        if !self.cfg.enabled {
            return Ok(());
        }
        let primary_ifindex = self.target_ifindexes.first().copied().unwrap_or(0);
        let if_state = ctx.get_interface_state(primary_ifindex);
        let current_gua = if_state
            .gua
            .map(lanforge_types::network::Ipv6Prefix::from_addr);
        let current_ula = if_state
            .ula
            .map(lanforge_types::network::Ipv6Prefix::from_addr);

        debug!("Performing initial neighbor bootstrap...");
        let mut bootstrap_events = Vec::new();

        for &ifindex in &self.target_ifindexes {
            match get_ipv4_neighbors(&self.handle, Some(ifindex)).await {
                Ok(evs) => bootstrap_events.extend(evs),
                Err(e) => error!("Failed to dump IPv4 neighbors on ifindex {ifindex}: {e}"),
            }

            match get_ipv6_neighbors(&self.handle, "", Some(ifindex)).await {
                Ok(evs) => bootstrap_events.extend(evs),
                Err(e) => error!("Failed to dump IPv6 neighbors on ifindex {ifindex}: {e}"),
            }
        }

        let mut ifname_cache = IfNameCache::new();
        for event in bootstrap_events {
            let ifindex = event.ifindex();
            if let Some(mac) = event.mac()
                && let Some(ifname) = ifname_cache.get(ifindex)
            {
                let _ = ctx.apply(DeviceUpdate::DeviceInterfaceSeen {
                    mac,
                    iface: ifname.to_string(),
                });
            }
            if let Some(update) = event.to_device_update(current_gua.as_ref(), current_ula.as_ref())
            {
                let _ = ctx.apply(update);
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    async fn serve(&mut self, ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        if !self.cfg.enabled {
            info!("Discovery service is disabled in configuration.");
            h.dormant(DormantReason::disabled("discovery.enabled"));
            return Ok(());
        }

        if self.cfg.ping_enabled {
            if let Some(ref pinger) = self.pinger {
                info!("Active ICMP ping probe initialized");
                spawn_sweep_task(pinger.clone(), ctx.clone(), self.cfg.ping_interval_secs);
                spawn_jit_offline_task(pinger.clone(), self.prober_cache.clone(), ctx.clone());
            } else {
                warn!("Failed to initialize ICMP ping probe");
            }
        }

        let mut handle = ctx.service_handle_network();
        let mut ifname_cache = IfNameCache::new();

        let primary_ifindex = self.target_ifindexes.first().copied().unwrap_or(0);
        let if_state = ctx.get_interface_state(primary_ifindex);
        let mut current_gua: Option<lanforge_types::network::Ipv6Prefix> = if_state
            .gua
            .map(lanforge_types::network::Ipv6Prefix::from_addr);
        let mut current_ula: Option<lanforge_types::network::Ipv6Prefix> = if_state
            .ula
            .map(lanforge_types::network::Ipv6Prefix::from_addr);

        let mut pending_batch = Vec::with_capacity(50);
        let mut flush_timer = interval(Duration::from_millis(self.cfg.batch_interval_ms));
        h.ready();

        loop {
            if !ctx.is_running() {
                break;
            }
            tokio::select! {
                cmd = h.next_command() => {
                    match cmd {
                        ServiceCommand::Stop | ServiceCommand::Shutdown => break,
                        ServiceCommand::Restart => {
                            h.request_restart();
                            break;
                        }
                        _ => {}
                    }
                }
                res = self.messages.recv() => {
                    let Ok((msg, _addr)) = res else {
                        if let Err(broadcast::error::RecvError::Lagged(n)) = res {
                            warn!(service = "DiscoveryService", lost = n, "Netlink broadcast lagged");
                            continue;
                        }
                        break;
                    };
                    if let NetlinkPayload::InnerMessage(
                        RouteNetlinkMessage::NewAddress(addr) | RouteNetlinkMessage::DelAddress(addr),
                    ) = &msg.payload
                        && self.target_ifindexes.contains(&addr.header.index)
                    {
                        let event_ifindex = addr.header.index;
                        debug!(
                            "Address event on ifindex {event_ifindex}, refreshing interface..."
                        );
                        if let Err(e) = crate::interface::refresh_interface(
                            &self.handle,
                            event_ifindex,
                            ctx,
                        )
                        .await
                        {
                            warn!(
                                "Failed to refresh interface {event_ifindex}: {e}"
                            );
                        }
                    }

                    if let Some(event) = extract_neigh_info(&msg)
                        && self.target_ifindexes.contains(&event.ifindex())
                    {
                        self.process_neighbor_event(
                            &event,
                            &mut ifname_cache,
                            ctx,
                            &mut pending_batch,
                            current_gua.as_ref(),
                            current_ula.as_ref(),
                        );
                    }
                }

                _ = flush_timer.tick() => {
                    if !pending_batch.is_empty() {
                        let batch = std::mem::replace(&mut pending_batch, Vec::with_capacity(50));
                        self.flush_neighbor_batch(batch);
                    }
                }

                res = handle.next_event() => {
                    let Some(timed_event) = res else {
                        break;
                    };
                    lanforge_core::match_event!(timed_event, {
                        LanforgeEvent::Network(NetworkEvent::PrefixChanged(details)) => {
                            current_gua = details.gua;
                            current_ula = details.ula;
                        }
                    });
                }
            }
        }

        info!("Service stopped");
        Ok(())
    }
}

fn spawn_sweep_task(pinger: Arc<IcmpPinger>, ctx: LanforgeContext, ping_interval: u64) {
    tokio::spawn(async move {
        let mut sweep_timer = interval(Duration::from_secs(ping_interval));
        let mut seq_counter = 0u16;
        let sweep_threshold = Duration::from_secs(ping_interval);
        loop {
            if !ctx.is_running() {
                break;
            }
            sweep_timer.tick().await;

            let now = SystemTime::now();
            let ips = ctx.with_state(|state| {
                let mut all_ips = SmallVec::<[IpAddr; 32]>::new();
                for dev in state.devices.values() {
                    if dev.origin == Origin::System {
                        continue;
                    }
                    match &dev.v4 {
                        IPv4State::Static(ip) => {
                            let elapsed =
                                now.duration_since(dev.last_seen).unwrap_or(Duration::MAX);
                            if elapsed >= sweep_threshold {
                                all_ips.push(IpAddr::V4(*ip));
                            }
                        }
                        IPv4State::Dynamic(lease) => {
                            let elapsed = now
                                .duration_since(lease.last_seen_system_time())
                                .unwrap_or(Duration::MAX);
                            if elapsed >= sweep_threshold {
                                all_ips.push(IpAddr::V4(lease.ip));
                            }
                        }
                        IPv4State::Discovery(ip, ts) => {
                            let elapsed = now.duration_since(*ts).unwrap_or(Duration::MAX);
                            if elapsed >= sweep_threshold {
                                all_ips.push(IpAddr::V4(*ip));
                            }
                        }
                        IPv4State::None => {}
                    }
                    for v6_state in &dev.v6 {
                        if let Some(v6_ip) = v6_state.ip() {
                            let ts = match v6_state {
                                IPv6State::Static(_, ts)
                                | IPv6State::Slaac(_, ts)
                                | IPv6State::Discovery(_, ts)
                                | IPv6State::LinkLocal(_, ts) => *ts,
                                IPv6State::Dynamic(lease) => lease.last_seen_system_time(),
                            };
                            let elapsed = now.duration_since(ts).unwrap_or(Duration::MAX);
                            if elapsed >= sweep_threshold {
                                all_ips.push(IpAddr::V6(v6_ip));
                            }
                        }
                    }
                }
                all_ips
            });

            for ip in ips {
                seq_counter = seq_counter.wrapping_add(1);
                let pinger_c = pinger.clone();
                let ctx_c = ctx.clone();
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
}

fn get_or_create_arp_prober(
    cache: &Mutex<HashMap<String, ArpProber>>,
    iface_name: &str,
) -> Option<ArpProber> {
    {
        let guard = cache.lock();
        if let Some(p) = guard.get(iface_name) {
            return Some(p.clone());
        }
    }

    let ifaces = pnet::datalink::interfaces();
    for iface in ifaces {
        if iface.name == iface_name
            && let Some(mac) = iface.mac
            && let Ok(prober) = ArpProber::bind(iface.index, mac.octets())
        {
            cache.lock().insert(iface_name.to_string(), prober.clone());
            return Some(prober);
        }
    }
    None
}

fn spawn_jit_offline_task(
    pinger: Arc<IcmpPinger>,
    prober_cache: Arc<Mutex<HashMap<String, ArpProber>>>,
    ctx: LanforgeContext,
) {
    tokio::spawn(async move {
        let mut bus_rx = ctx.bus().subscribe_device();
        let mut seq_counter = 0u16;
        loop {
            if !ctx.is_running() {
                break;
            }
            match bus_rx.recv().await {
                Ok(timed_event) => {
                    if let LanforgeEvent::Device(DeviceEvent::NetworkActivity { change, .. }) =
                        &timed_event.event
                        && let NetworkChange::IpOffline { ip } = &**change
                    {
                        seq_counter = seq_counter.wrapping_add(1);
                        let pinger_c = pinger.clone();
                        let ctx_c = ctx.clone();
                        let probers_c = prober_cache.clone();
                        let target_ip = *ip;
                        tokio::spawn(async move {
                            debug!(
                                "JIT verification ping triggered for offline transition of {target_ip}"
                            );
                            let ping_ok =
                                matches!(pinger_c.ping(target_ip, seq_counter).await, Ok(true));
                            if ping_ok && let Some(mac) = ctx_c.get_mac_by_ip(target_ip) {
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
                            } else if !ping_ok && let IpAddr::V4(v4) = target_ip {
                                let dev_opt = ctx_c.with_state(|state| {
                                    state.get_mac_by_ip(target_ip).and_then(|mac| {
                                        state.devices.get(&mac).map(|d| (mac, d.iface.clone()))
                                    })
                                });
                                if let Some((mac, Some(ref iface_name))) = dev_opt
                                    && let Some(prober) =
                                        get_or_create_arp_prober(&probers_c, iface_name)
                                {
                                    debug!(
                                        target_ip = %v4,
                                        iface = %iface_name,
                                        "ICMP ping failed, running fallback ARP probe to verify if device is firewalled..."
                                    );
                                    if let Ok(Some(reply)) =
                                        prober.probe(v4, None, Duration::from_millis(500)).await
                                    {
                                        debug!(
                                            target_ip = %v4,
                                            rtt_us = reply.rtt.as_micros(),
                                            "Device responded to ARP probe; keeping device online (ICMP was dropped by host firewall)"
                                        );
                                        let update = DeviceUpdate::ArpSeen {
                                            mac,
                                            ip: v4,
                                            is_active: true,
                                        };
                                        let _ = ctx_c.apply(update);
                                    }
                                }
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
