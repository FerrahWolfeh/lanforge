use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, SystemTime},
};

use futures::TryStreamExt;
use lanforge_core::{context::LanforgeContext, identifiers::MacAddr, ndp::NeighborEvent};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::{
    Handle, IpVersion,
    packet_route::{
        RouteNetlinkMessage,
        neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState},
    },
};
use tokio::time::sleep;

use crate::error::NetworkError;

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

pub async fn run_periodic_probes_task(
    handle: Handle,
    ctx: LanforgeContext,
    ifindex: u32,
    current_gua: Option<Ipv6Addr>,
    current_ula: Option<Ipv6Addr>,
    force_all: bool,
) {
    let devices = ctx.all_devices();
    let now = SystemTime::now();

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
                if let Err(e) = probe_neighbor(&handle, ifindex, ip, Some(dev.mac)).await {
                    tracing::debug!("NeighborMonitor: Scheduled probe failed for {ip}: {e}");
                }
                // Pacing: 50ms between individual IP probes to keep network load negligible.
                sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

#[must_use]
pub fn parse_neighbor_msg(msg: NeighbourMessage) -> Option<NeighborEvent> {
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
        rtnetlink::packet_route::AddressFamily::Inet6 => IpAddr::V6(ip_v6?),
        rtnetlink::packet_route::AddressFamily::Inet => IpAddr::V4(ip_v4?),
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
///
/// Se `mac` for fornecido, o kernel envia um Unicast Probe (bypassa deep sleep).
/// Se `mac` for None, o kernel envia um Broadcast Probe (usado para discovery).
pub async fn probe_neighbor(
    handle: &Handle,
    ifindex: u32,
    ip: IpAddr,
    mac: Option<MacAddr>, // Aceitando o MAC opcionalmente
) -> Result<(), rtnetlink::Error> {
    let mut req = handle
        .neighbours()
        .add(ifindex, ip)
        .state(NeighbourState::Probe);

    // Se temos a identidade do hardware, preservamos no cache do kernel!
    if let Some(m) = mac {
        req = req.link_local_address(m.as_bytes());
    }

    req.execute().await
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
