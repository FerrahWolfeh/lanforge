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

use crate::error::NetworkError;
use crate::slaac::bootstrap_table;
use futures::StreamExt;
use futures::channel::mpsc::UnboundedReceiver;
use futures::stream::TryStreamExt;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, LanforgeService, ServiceMeta};
use lanforge_core::{identifiers::MacAddr, ndp::NeighborEvent};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_sys::SocketAddr;
use rtnetlink::packet_route::{
    RouteNetlinkMessage,
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState},
};
use rtnetlink::{Handle, IpVersion};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Neighbor event filter (Netlink stream events)
// ---------------------------------------------------------------------------

/// Returns true if `msg` is a relevant NEW or DEL event for the target prefix.
#[cfg(test)]
#[must_use]
pub fn is_relevant_neigh_event(
    msg: &NetlinkMessage<RouteNetlinkMessage>,
    target_prefix: &str,
) -> bool {
    match &msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(neigh)) => {
            if neigh.header.state == NeighbourState::Incomplete {
                return false;
            }
            neigh_matches_prefix(neigh, target_prefix)
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelNeighbour(neigh)) => {
            neigh_matches_prefix(neigh, target_prefix)
        }
        _ => false,
    }
}

#[cfg(test)]
fn neigh_matches_prefix(neigh: &NeighbourMessage, target_prefix: &str) -> bool {
    neigh.attributes.iter().any(|attr| {
        matches!(
            attr,
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(ip))
            if ip.to_string().starts_with(target_prefix)
        )
    })
}

// ---------------------------------------------------------------------------
// Extraction of events from the Netlink stream
// ---------------------------------------------------------------------------

/// Extracts a `NeighborEvent` from an `RTM_NEWNEIGH` (or DELNEIGH) message.
///
/// Returns `None` if:
/// - The protocol is not IPv6/IPv4.
/// - The state is incomplete or failed (MAC address unknown).
/// - IP or MAC attributes are missing.
#[must_use]
pub fn extract_neigh_info(msg: &NetlinkMessage<RouteNetlinkMessage>) -> Option<NeighborEvent> {
    let (neigh, is_delete) = match &msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(n)) => (n, false),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelNeighbour(n)) => (n, true),
        _ => return None,
    };

    let mut ip_v4: Option<std::net::Ipv4Addr> = None;
    let mut ip_v6: Option<Ipv6Addr> = None;
    let mut mac: Option<MacAddr> = None;

    for attr in &neigh.attributes {
        match attr {
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(i)) => ip_v6 = Some(*i),
            NeighbourAttribute::Destination(NeighbourAddress::Inet(i)) => ip_v4 = Some(*i),
            NeighbourAttribute::LinkLocalAddress(m) => {
                mac = MacAddr::from_slice(m);
            }
            _ => {}
        }
    }

    let ip = match neigh.header.family {
        rtnetlink::packet_route::AddressFamily::Inet6 => std::net::IpAddr::V6(ip_v6?),
        rtnetlink::packet_route::AddressFamily::Inet => std::net::IpAddr::V4(ip_v4?),
        _ => return None,
    };

    // We only block Incomplete states when discovering a new host.
    // Failed is now handled to detect offline status.
    if !is_delete && matches!(neigh.header.state, NeighbourState::Incomplete) {
        return None;
    }

    if is_delete {
        Some(NeighborEvent::Deleted {
            ip,
            ifindex: neigh.header.ifindex,
        })
    } else if neigh.header.state == NeighbourState::Failed {
        Some(NeighborEvent::Failed {
            ip,
            ifindex: neigh.header.ifindex,
        })
    } else {
        let mac = mac?;
        if mac.is_zero() || (mac.0[0] & 1) == 1 {
            return None;
        }

        // For additions, the MAC address is strictly required. Returns None if missing.
        Some(NeighborEvent::Added {
            ip,
            mac,
            ifindex: neigh.header.ifindex,
        })
    }
}

fn parse_neighbor_msg(msg: NeighbourMessage) -> Option<NeighborEvent> {
    if matches!(
        msg.header.state,
        NeighbourState::Incomplete | NeighbourState::Failed
    ) {
        return None;
    }

    let mut ip: Option<IpAddr> = None;
    let mut mac: Option<MacAddr> = None;
    let ifindex = msg.header.ifindex;

    for attr in msg.attributes {
        match attr {
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(addr)) => {
                ip = Some(IpAddr::V6(addr));
            }
            NeighbourAttribute::Destination(NeighbourAddress::Inet(addr)) => {
                ip = Some(IpAddr::V4(addr));
            }
            NeighbourAttribute::LinkLocalAddress(bytes) => {
                mac = MacAddr::from_slice(&bytes);
            }
            _ => {}
        }
    }

    let ip = ip?;
    let mac = mac?;

    if mac.is_zero() || (mac.0[0] & 1) == 1 {
        return None;
    }

    Some(NeighborEvent::Added { ip, mac, ifindex })
}

// ---------------------------------------------------------------------------
// Kernel Queries (Uses the shared Handle)
// ---------------------------------------------------------------------------

/// Retrieves all IPv6 neighbors within the target prefix as `NeighborEvent`s.
pub async fn get_ipv6_neighbors(
    handle: &Handle,
    target_prefix: &str,
    target_ifindex: Option<u32>,
) -> Result<Vec<NeighborEvent>, NetworkError> {
    let mut neighbors = Vec::new();
    let neighbours_get = handle.neighbours().get();
    let neighbours_get = neighbours_get.set_family(IpVersion::V6);

    let mut stream = neighbours_get.execute();

    while let Some(msg) = stream.try_next().await? {
        if let Some(event) = parse_neighbor_msg(msg) {
            if let Some(target) = target_ifindex
                && event.ifindex() != target
            {
                continue;
            }

            let matches = match event.ip() {
                IpAddr::V6(ip) => ip.to_string().starts_with(target_prefix),
                IpAddr::V4(_) => false,
            };
            if matches {
                neighbors.push(event);
            }
        }
    }

    Ok(neighbors)
}

/// Retrieves all IPv4 neighbors (ARP table) as `NeighborEvent`s.
pub async fn get_ipv4_neighbors(
    handle: &Handle,
    target_ifindex: Option<u32>,
) -> Result<Vec<NeighborEvent>, NetworkError> {
    let mut neighbors = Vec::new();
    let neighbours_get = handle.neighbours().get();
    let neighbours_get = neighbours_get.set_family(IpVersion::V4);

    let mut stream = neighbours_get.execute();

    while let Some(msg) = stream.try_next().await? {
        if let Some(event) = parse_neighbor_msg(msg) {
            if let Some(target) = target_ifindex
                && event.ifindex() != target
            {
                continue;
            }
            neighbors.push(event);
        }
    }

    Ok(neighbors)
}

/// Triggers a NUD probe for a specific neighbor via Netlink.
///
/// This forces the kernel to send a Neighbor Solicitation (IPv6) or ARP Request (IPv4)
/// to verify the reachability of the given IP address.
pub async fn probe_neighbor(
    handle: &Handle,
    ifindex: u32,
    ip: IpAddr,
) -> Result<(), rtnetlink::Error> {
    handle
        .neighbours()
        .add(ifindex, ip)
        .state(NeighbourState::Probe)
        .execute()
        .await
}

/// Returns an iterator over all usable IPv4 addresses in a given subnet.
///
/// Skips the network address (.0) and the broadcast address (.255 for /24).
#[must_use]
pub fn get_ipv4_subnet_iterable(ip: Ipv4Addr, prefix_len: u8) -> Vec<Ipv4Addr> {
    if prefix_len >= 31 {
        return Vec::new();
    }

    let mask = !u32::MAX.checked_shr(u32::from(prefix_len)).unwrap_or(0);
    let ip_u32 = u32::from_be_bytes(ip.octets());
    let network = ip_u32 & mask;
    let broadcast = network | !mask;

    ((network + 1)..broadcast)
        .map(|addr| Ipv4Addr::from(addr.to_be_bytes()))
        .collect()
}

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

        tracing::info!("NeighborMonitor: Spawning subnet scan task (source: {source})");
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
            tracing::info!(
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
                if let Err(e) = probe_neighbor(&handle, ifindex, IpAddr::V4(target_ip)).await {
                    tracing::debug!("NeighborMonitor: ARP probe failed for {target_ip}: {e}");
                }
                // Pacing for manual scan: 10ms between addresses to avoid CPU spikes
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

async fn run_periodic_probes_task(
    handle: Handle,
    ctx: LanforgeContext,
    ifindex: u32,
    current_gua: Option<Ipv6Addr>,
    current_ula: Option<Ipv6Addr>,
    force_all: bool,
) {
    let devices = ctx.all_devices();
    let now = std::time::SystemTime::now();

    for dev in devices {
        // Surgical Probing Rule: Only probe devices that are ALREADY online but quiet.
        // If they are offline/failed, we stop poking them.
        // Exception: During 'force_all' (Boot Discovery), we probe everyone exactly once.
        if !force_all && !dev.is_online() {
            continue;
        }

        let elapsed = now.duration_since(dev.last_seen).unwrap_or_default();
        if force_all || elapsed.as_secs() > 60 {
            for ip in dev.all_addresses_sorted(current_gua, current_ula) {
                if let Err(e) = probe_neighbor(&handle, ifindex, ip).await {
                    tracing::debug!("NeighborMonitor: Scheduled probe failed for {ip}: {e}");
                }
                // Pacing: 50ms between individual IP probes to keep network load negligible.
                tokio::time::sleep(Duration::from_millis(50)).await;
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
        let mut probe_interval = tokio::time::interval(Duration::from_secs(60));
        let mut subnet_scan_interval = if self.scan_interval.as_secs() > 0 {
            let mut interval = tokio::time::interval(self.scan_interval);
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
                tracing::error!("NeighborMonitor: Initial bootstrap scan failed: {e}");
            }
        }

        // 2. Initial network-wide probe (Boot Discovery on all known devices)
        {
            let devices = self.ctx.all_devices();
            tracing::info!(
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

        tracing::info!("NeighborMonitor: Service stopped");
        Ok(())
    }
}

/// Looks up the MAC address for a specific IPv6 neighbor in the kernel's NDP table.
///
/// Used as a fallback in `DHCPv6` when the DUID does not contain a MAC (DUID-EN,
/// DUID-UUID) and the peer's link-local address is not EUI-64.
pub async fn lookup_mac_for_ipv6(handle: &Handle, ip: &Ipv6Addr) -> Option<MacAddr> {
    let target = ip.to_string();
    let mut stream = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V6)
        .execute();

    while let Ok(Some(msg)) = stream.try_next().await {
        if matches!(
            msg.header.state,
            NeighbourState::Incomplete | NeighbourState::Failed
        ) {
            continue;
        }

        let mut found_ip = false;
        let mut found_mac: Option<MacAddr> = None;

        for attr in &msg.attributes {
            match attr {
                NeighbourAttribute::Destination(NeighbourAddress::Inet6(addr))
                    if addr.to_string() == target =>
                {
                    found_ip = true;
                }
                NeighbourAttribute::LinkLocalAddress(b) => {
                    found_mac = MacAddr::from_slice(b);
                }
                _ => {}
            }
        }

        if found_ip {
            return found_mac;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_core::{
        state::DeviceUpdate,
        utils::{ip_matches_prefix, mac_from_eui64_link_local},
    };
    use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload};
    use rtnetlink::packet_route::{AddressFamily, neighbour::NeighbourHeader};

    fn mock_neigh_msg(
        state: NeighbourState,
        ip: std::net::IpAddr,
        mac: Option<[u8; 6]>,
        is_delete: bool,
    ) -> NetlinkMessage<RouteNetlinkMessage> {
        let addr = match ip {
            std::net::IpAddr::V6(a) => NeighbourAddress::Inet6(a),
            std::net::IpAddr::V4(a) => NeighbourAddress::Inet(a),
        };
        let mut attributes = vec![NeighbourAttribute::Destination(addr)];
        if let Some(m) = mac {
            attributes.push(NeighbourAttribute::LinkLocalAddress(m.to_vec()));
        }

        let header = NeighbourHeader {
            family: AddressFamily::Inet6,
            ifindex: 2,
            state,
            ..Default::default()
        };

        let mut neigh = NeighbourMessage::default();
        neigh.header = header;
        neigh.attributes = attributes;

        let payload = if is_delete {
            RouteNetlinkMessage::DelNeighbour(neigh)
        } else {
            RouteNetlinkMessage::NewNeighbour(neigh)
        };

        NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::InnerMessage(payload),
        )
    }

    // --- extract_neigh_info ---

    #[test]
    fn extract_neigh_info_returns_typed_event() {
        let ip: std::net::IpAddr = "fe80::1".parse().unwrap();
        let mac_bytes = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let msg = mock_neigh_msg(NeighbourState::Reachable, ip, Some(mac_bytes), false);
        let event = extract_neigh_info(&msg).expect("deve extrair evento");

        assert_eq!(*event.ip(), ip);
        assert_eq!(event.mac(), Some(MacAddr(mac_bytes)));
        if let NeighborEvent::Added { ifindex, .. } = event {
            assert_eq!(ifindex, 2);
        } else {
            panic!("esperava NeighborEvent::Added");
        }
    }

    #[test]
    fn extract_neigh_info_ignores_incomplete() {
        let ip: std::net::IpAddr = "fe80::1".parse().unwrap();
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let msg_incomplete = mock_neigh_msg(NeighbourState::Incomplete, ip, Some(mac), false);

        assert!(extract_neigh_info(&msg_incomplete).is_none());
    }

    #[test]
    fn extract_neigh_info_handles_failed() {
        let ip: std::net::IpAddr = "fe80::1".parse().unwrap();
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let msg_failed = mock_neigh_msg(NeighbourState::Failed, ip, Some(mac), false);
        let event = extract_neigh_info(&msg_failed).expect("should extract Failed");
        assert!(matches!(event, NeighborEvent::Failed { .. }));
    }

    #[test]
    fn extract_neigh_info_requires_both_ip_and_mac() {
        let ip: std::net::IpAddr = "fe80::1".parse().unwrap();
        // MAC ausente
        let msg = mock_neigh_msg(NeighbourState::Reachable, ip, None, false);
        assert!(extract_neigh_info(&msg).is_none());
    }

    // --- NeighborEvent::to_device_update ---

    #[test]
    fn to_device_update_gua_becomes_slaac_observed() {
        let gua_prefix: Ipv6Addr = "fd97:f00d:cafe:3731::".parse().unwrap();
        let slaac_ip: Ipv6Addr = "fd97:f00d:cafe:3731::abcd".parse().unwrap();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

        let event = NeighborEvent::Added {
            ip: slaac_ip.into(),
            mac,
            ifindex: 2,
        };
        let update = event.to_device_update(Some(&gua_prefix), None);

        assert!(
            matches!(update, DeviceUpdate::SlaacObserved { addr, .. } if addr == slaac_ip),
            "IP no prefixo GUA deve virar SlaacObserved"
        );
    }

    #[test]
    fn to_device_update_link_local_becomes_ndp_seen() {
        let gua_prefix: Ipv6Addr = "fd97:f00d:cafe:3731::".parse().unwrap();
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

        let event = NeighborEvent::Added {
            ip: link_local.into(),
            mac,
            ifindex: 2,
        };
        let update = event.to_device_update(Some(&gua_prefix), None);

        assert!(
            matches!(update, DeviceUpdate::NdpSeen { .. }),
            "Link-local deve virar NdpSeen"
        );
    }

    #[test]
    fn to_device_update_no_prefix_always_ndp_seen() {
        let ip: Ipv6Addr = "fd97:f00d:cafe:3731::1".parse().unwrap();
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

        let event = NeighborEvent::Added {
            ip: ip.into(),
            mac,
            ifindex: 2,
        };
        // Sem prefixo configurado — nunca assume SLAAC
        let update = event.to_device_update(None, None);

        assert!(matches!(update, DeviceUpdate::NdpSeen { .. }));
    }

    // --- is_relevant_neigh_event ---

    #[test]
    fn is_relevant_event_matches_prefix_and_state() {
        let target_prefix = "fd97:f00d:cafe:3731::";
        let valid_ip: Ipv6Addr = "fd97:f00d:cafe:3731::1234".parse().unwrap();
        let invalid_ip: Ipv6Addr = "2001:db8::1234".parse().unwrap();

        let msg_valid = mock_neigh_msg(NeighbourState::Reachable, valid_ip.into(), None, false);
        let msg_invalid = mock_neigh_msg(NeighbourState::Reachable, invalid_ip.into(), None, false);
        let msg_incomplete =
            mock_neigh_msg(NeighbourState::Incomplete, valid_ip.into(), None, false);

        assert!(is_relevant_neigh_event(&msg_valid, target_prefix));
        assert!(!is_relevant_neigh_event(&msg_invalid, target_prefix));
        assert!(!is_relevant_neigh_event(&msg_incomplete, target_prefix));
    }

    // --- EUI-64 ---

    #[test]
    fn mac_from_eui64_valid() {
        // MAC: 3c:0a:7a:d8:11:78  →  bit U/L invertido: 0x3C ^ 0x02 = 0x3E
        let ip: Ipv6Addr = "fe80::3e0a:7aff:fed8:1178".parse().unwrap();
        let mac = mac_from_eui64_link_local(&ip);
        assert_eq!(mac, Some(MacAddr([0x3c, 0x0a, 0x7a, 0xd8, 0x11, 0x78])));
    }

    #[test]
    fn mac_from_eui64_ignores_non_link_local() {
        let ip: Ipv6Addr = "2001:db8::3e0a:7aff:fed8:1178".parse().unwrap();
        assert_eq!(mac_from_eui64_link_local(&ip), None);
    }

    #[test]
    fn mac_from_eui64_ignores_privacy_extensions() {
        let ip: Ipv6Addr = "fe80::1234:5678:9abc:def0".parse().unwrap();
        assert_eq!(mac_from_eui64_link_local(&ip), None);
    }

    // --- ip_matches_prefix ---

    #[test]
    fn ip_matches_prefix_same_64() {
        let prefix: Ipv6Addr = "fd97:f00d:cafe:3731::".parse().unwrap();
        let inside: Ipv6Addr = "fd97:f00d:cafe:3731::dead:beef".parse().unwrap();
        let outside: Ipv6Addr = "fd97:f00d:cafe:3732::1".parse().unwrap();

        assert!(ip_matches_prefix(&inside, &prefix));
        assert!(!ip_matches_prefix(&outside, &prefix));
    }

    #[test]
    fn parse_neighbor_msg_only_active() {
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        // 1. Mensagem válida (Reachable)
        let mut msg = NeighbourMessage::default();
        msg.header.state = NeighbourState::Reachable;
        msg.header.family = AddressFamily::Inet6;
        msg.attributes = vec![
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(ip)),
            NeighbourAttribute::LinkLocalAddress(mac.to_vec()),
        ];
        let event = parse_neighbor_msg(msg).expect("deve parsear");
        assert!(matches!(event, NeighborEvent::Added { .. }));

        // 2. Mensagem inválida (Failed)
        let mut msg_fail = NeighbourMessage::default();
        msg_fail.header.state = NeighbourState::Failed;
        assert!(parse_neighbor_msg(msg_fail).is_none());
    }

    #[test]
    fn extract_neigh_info_handles_delete() {
        let ip: std::net::IpAddr = "fe80::1".parse().unwrap();
        // No RTM_DELNEIGH o MAC pode estar ausente
        let msg = mock_neigh_msg(NeighbourState::Failed, ip, None, true);
        let event = extract_neigh_info(&msg).expect("deve extrair delete");

        assert_eq!(event, NeighborEvent::Deleted { ip, ifindex: 2 });
    }

    #[test]
    fn test_ipv4_subnet_iterable_24() {
        let ip: Ipv4Addr = "192.168.1.100".parse().unwrap();
        let range = get_ipv4_subnet_iterable(ip, 24);

        assert_eq!(range.len(), 254);
        assert_eq!(range[0], "192.168.1.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(range[253], "192.168.1.254".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_ipv4_subnet_iterable_30() {
        let ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let range = get_ipv4_subnet_iterable(ip, 30);

        // /30 has 4 addresses: .0 (net), .1, .2, .3 (broadcast)
        // Usable: .1, .2
        assert_eq!(range.len(), 2);
        assert_eq!(range[0], "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(range[1], "10.0.0.2".parse::<Ipv4Addr>().unwrap());
    }
}
