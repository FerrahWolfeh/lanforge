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
//!     participant T as ManagedTable (apply_update)
//!
//!     K->>N: Inbound Message
//!     N->>E: Option<NeighborEvent>
//!     Note over E: to_device_update(prefix)
//!     E->>T: SlaacObserved (GUA) / NdpSeen (Other)
//! ```

use crate::{error::Result, slaac::bootstrap_table};
use futures::StreamExt;
use futures::channel::mpsc::UnboundedReceiver;
use futures::stream::TryStreamExt;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, LanforgeService};
use lanforge_core::state::update::DeviceUpdate;
use lanforge_core::{identifiers::MacAddr, ndp::NeighborEvent};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_sys::SocketAddr;
use rtnetlink::packet_route::{
    RouteNetlinkMessage,
    address::AddressAttribute,
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState},
};
use rtnetlink::{Handle, IpVersion, packet_route::AddressFamily};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Neighbor event filter (Netlink stream events)
// ---------------------------------------------------------------------------

/// Returns true if `msg` is a relevant NEW or DEL event for the target prefix.
#[cfg(test)]
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
        AddressFamily::Inet6 => std::net::IpAddr::V6(ip_v6?),
        AddressFamily::Inet => std::net::IpAddr::V4(ip_v4?),
        _ => return None,
    };

    // We only block Incomplete/Failed states when discovering a new host.
    if !is_delete
        && matches!(
            neigh.header.state,
            NeighbourState::Incomplete | NeighbourState::Failed
        )
    {
        return None;
    }

    if is_delete {
        Some(NeighborEvent::Deleted {
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
) -> Result<Vec<NeighborEvent>> {
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
                _ => false,
            };
            if matches {
                neighbors.push(event);
            }
        }
    }

    Ok(neighbors)
}

// ---------------------------------------------------------------------------
// NdpMonitor — The "Serviceable Struct" for Netlink
// ---------------------------------------------------------------------------

pub type NetlinkStream =
    Arc<tokio::sync::Mutex<UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>>>;

type Ifaces = HashMap<
    u32,
    (
        Option<Ipv6Addr>,
        Option<Ipv6Addr>,
        Option<Ipv6Addr>,
        u32,
        u32,
    ),
>;

/// Monitor que reage a eventos Netlink e mantém a ManagedTable atualizada.
pub struct NdpMonitor {
    handle: Handle,
    messages: NetlinkStream,
    target_ifindex: u32,
}

impl NdpMonitor {
    #[must_use]
    pub fn new(handle: Handle, messages: NetlinkStream, target_ifindex: u32) -> Self {
        Self {
            handle,
            messages,
            target_ifindex,
        }
    }

    /// Full refresh of all interfaces known to the kernel.
    ///
    /// # Errors
    /// Returns an error if the Netlink query fails.
    pub async fn refresh_interfaces(&self) -> crate::error::Result<()> {
        let mut stream = self
            .handle
            .address()
            .get()
            .set_link_index_filter(self.target_ifindex)
            .execute();
        let table = LanforgeContext::table();

        // Group extracted IPs by ifindex to aggregate link-local, GUA and ULA
        // Added (Preferred, Valid) lifetimes to the prefix storage
        let mut ifaces: Ifaces = HashMap::new();

        while let Some(msg) = stream.try_next().await? {
            let ifindex = msg.header.index;
            let (ll, g, u, pref, val) = ifaces.entry(ifindex).or_insert((None, None, None, 0, 0));

            for attr in &msg.attributes {
                match attr {
                    AddressAttribute::Address(IpAddr::V6(v6)) => {
                        let o = v6.octets();
                        if o[0] == 0xFE && (o[1] & 0xC0) == 0x80 {
                            *ll = Some(*v6);
                        } else if (0x20..=0x3F).contains(&o[0]) {
                            let mut masked = o;
                            masked[8..].fill(0);
                            *g = Some(Ipv6Addr::from(masked));
                        } else if o[0] == 0xFD {
                            let mut masked = o;
                            masked[8..].fill(0);
                            *u = Some(Ipv6Addr::from(masked));
                        }
                    }
                    AddressAttribute::CacheInfo(info) => {
                        *pref = info.ifa_preferred;
                        *val = info.ifa_valid;
                    }
                    _ => {}
                }
            }
        }

        let interfaces = pnet::datalink::interfaces();
        let if_names: HashMap<u32, String> =
            interfaces.into_iter().map(|i| (i.index, i.name)).collect();

        for (ifindex, (link_local, gua, ula, preferred, valid)) in ifaces {
            let name = if_names
                .get(&ifindex)
                .map(|s| s.as_str())
                .unwrap_or("unnamed");

            match (link_local, gua, ula) {
                (Some(ll), Some(g), Some(u)) => {
                    tracing::info!(
                        "NdpMonitor: Interface {} up (LL: {}, GUA: {}/64, ULA: {}/64)",
                        name,
                        ll,
                        g,
                        u
                    );
                }
                (Some(ll), Some(g), None) => {
                    tracing::info!(
                        "NdpMonitor: Interface {} up (LL: {}, GUA: {}/64)",
                        name,
                        ll,
                        g
                    );
                }
                (Some(ll), None, Some(u)) => {
                    tracing::info!(
                        "NdpMonitor: Interface {} up (LL: {}, ULA: {}/64)",
                        name,
                        ll,
                        u
                    );
                }
                (Some(ll), None, None) => {
                    tracing::info!("NdpMonitor: Interface {} up (LL: {})", name, ll);
                }
                _ => {
                    tracing::debug!("NdpMonitor: Interface {} up (No IPv6 yet)", name);
                }
            }

            let _ = table.update(&DeviceUpdate::InterfaceIpsChanged {
                ifindex,
                link_local,
                gua,
                ula,
                preferred,
                valid,
            });
        }

        Ok(())
    }

    /// Refresh a single interface's IP state.
    async fn refresh_interface(&self, ifindex: u32) -> crate::error::Result<()> {
        let mut stream = self
            .handle
            .address()
            .get()
            .set_link_index_filter(ifindex)
            .execute();

        let table = LanforgeContext::table();
        let mut link_local = None;
        let mut gua = None;
        let mut ula = None;
        let mut preferred = 0;
        let mut valid = 0;

        // Iterate over ALL address messages for this specific interface and aggregate them
        while let Some(msg) = stream.try_next().await? {
            for attr in &msg.attributes {
                match attr {
                    AddressAttribute::Address(IpAddr::V6(v6)) => {
                        let o = v6.octets();
                        if o[0] == 0xFE && (o[1] & 0xC0) == 0x80 {
                            link_local = Some(*v6);
                        } else if (0x20..=0x3F).contains(&o[0]) {
                            let mut masked = o;
                            masked[8..].fill(0);
                            gua = Some(Ipv6Addr::from(masked));
                        } else if o[0] == 0xFD {
                            let mut masked = o;
                            masked[8..].fill(0);
                            ula = Some(Ipv6Addr::from(masked));
                        }
                    }
                    AddressAttribute::CacheInfo(info) => {
                        preferred = info.ifa_preferred;
                        valid = info.ifa_valid;
                    }
                    _ => {}
                }
            }
        }

        let _ = table.update(&DeviceUpdate::InterfaceIpsChanged {
            ifindex,
            link_local,
            gua,
            ula,
            preferred,
            valid,
        });

        Ok(())
    }
}

impl LanforgeService for NdpMonitor {
    fn name(&self) -> &str {
        "NdpMonitor"
    }

    fn on_shutdown(&mut self) -> std::result::Result<(), CoreError> {
        tracing::info!("NdpMonitor: Deinitializing Service");
        Ok(())
    }
}

impl AsyncService for NdpMonitor {
    async fn run(&mut self) -> std::result::Result<(), CoreError> {
        let table = LanforgeContext::table();
        let mut bus_rx = LanforgeContext::bus().subscribe();
        let mut current_gua: Option<Ipv6Addr> = None;
        let current_ula: Option<Ipv6Addr> = None;

        // 1. Initial Interface Scan
        if let Err(e) = self.refresh_interfaces().await {
            tracing::error!("NdpMonitor: Initial interface scan failed: {e}");
        }

        // 2. Initial Neighbor Scan (Bootstrap)
        if let Err(e) =
            bootstrap_table("", &self.handle, None, None, Some(self.target_ifindex)).await
        {
            tracing::error!("NdpMonitor: Initial bootstrap scan failed: {e}");
        }

        tracing::info!("NdpMonitor: Initial scan complete, signaling ready");
        LanforgeContext::set_if_ready(true);
        let _ = LanforgeContext::bus().publish(LanforgeEvent::InterfaceReady);
        let _ = LanforgeContext::bus().publish(LanforgeEvent::ServiceReady {
            name: "monitor".to_string(),
        });

        tracing::info!("NdpMonitor: Service started (reactive mode)");

        let mut rx = self.messages.lock().await;

        loop {
            if !LanforgeContext::is_running() {
                break;
            }
            tokio::select! {
                res = rx.next() => {
                    let Some((msg, _addr)) = res else { break };
                    // A. Handle Neighbor Events
                    if let Some(event) = extract_neigh_info(&msg)
                        && event.ifindex() == self.target_ifindex {
                            let update =
                                event.to_device_update(current_gua.as_ref(), current_ula.as_ref());
                            let _ = table.update(&update);
                        }

                    // B. Handle Address Events
                    if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr))
                    | NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelAddress(addr)) = &msg.payload
                        && addr.header.index == self.target_ifindex
                            && let Err(e) = self.refresh_interface(addr.header.index).await {
                                tracing::warn!(
                                    "NdpMonitor: Failed to refresh interface {}: {e}",
                                    addr.header.index
                                );
                            }
                }

                Ok(event) = bus_rx.recv() => {
                    match event {
                        LanforgeEvent::PrefixChanged { gua, .. } => {
                            current_gua = gua;
                        }
                        LanforgeEvent::Shutdown => break,
                        _ => {}
                    }
                }

                else => break,
            }
        }

        tracing::info!("NdpMonitor: Service stopped");
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
        state::update::DeviceUpdate,
        utils::{ip_matches_prefix, mac_from_eui64_link_local},
    };
    use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload};
    use rtnetlink::packet_route::neighbour::NeighbourHeader;

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
    fn extract_neigh_info_ignores_incomplete_and_failed() {
        let ip: std::net::IpAddr = "fe80::1".parse().unwrap();
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

        let msg_incomplete = mock_neigh_msg(NeighbourState::Incomplete, ip, Some(mac), false);
        let msg_failed = mock_neigh_msg(NeighbourState::Failed, ip, Some(mac), false);

        assert!(extract_neigh_info(&msg_incomplete).is_none());
        assert!(extract_neigh_info(&msg_failed).is_none());
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
}
