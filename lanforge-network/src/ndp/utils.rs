//! NDP (Neighbor Discovery Protocol) utility functions.
//!
//! Provides low-level helpers for interacting with the Linux kernel's
//! neighbor table (NDP for IPv6, ARP for IPv4) via netlink.
//!
//! ## Public API
//!
//! | Function | Purpose |
//! | :--- | :--- |
//! | `lookup_mac_for_ipv6()` | Query kernel NDP table for a MAC address |
//! | `get_ipv6_neighbors()` | Dump all IPv6 neighbors, optionally filtered by prefix/ifindex |
//! | `get_ipv4_neighbors()` | Dump all IPv4 neighbors (ARP table), optionally filtered by ifindex |
//! | `probe_neighbor()` | Trigger an NDP/ARP probe for a specific IP |
//! | `parse_neighbor_msg()` | Parse a raw netlink neighbor message into a `NeighborEvent` |
//! | `extract_neigh_info()` | Extract `NeighborEvent` from a full netlink broadcast message |
//! | `get_ipv4_subnet_iterable()` | Generate all usable IPv4 addresses in a CIDR subnet |

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use futures::TryStreamExt;
use lanforge_types::{identifiers::MacAddr, network::NeighborEvent};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::{
    Handle, IpVersion,
    packet_route::{
        RouteNetlinkMessage,
        neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState},
    },
};

use crate::error::NetworkError;

/// Looks up the MAC address for a specific IPv6 neighbor in the kernel's NDP table.
///
/// Returns `None` if the neighbor is in `Incomplete` or `Failed` state.
pub async fn lookup_mac_for_ipv6(handle: &Handle, ip: &Ipv6Addr) -> Option<MacAddr> {
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
                // OPTIMIZATION: Comparação direta de structs, zero alocação de string!
                NeighbourAttribute::Destination(NeighbourAddress::Inet6(addr)) if addr == ip => {
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

/// Parses a raw `NeighbourMessage` into a `NeighborEvent`.
///
/// Filters out incomplete, failed, zero-MAC, and multicast-MAC entries.
#[must_use]
pub fn parse_neighbor_msg(msg: NeighbourMessage) -> Option<NeighborEvent> {
    let state = msg.header.state;
    if matches!(state, NeighbourState::Incomplete | NeighbourState::Failed) {
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

    // CLEANUP: let-else para early returns mais legíveis
    let (Some(ip), Some(mac)) = (ip, mac) else {
        return None;
    };

    if mac.is_zero() || (mac.0[0] & 1) == 1 {
        return None;
    }

    let is_active = matches!(
        state,
        NeighbourState::Reachable | NeighbourState::Permanent | NeighbourState::Noarp
    );

    Some(NeighborEvent::Added {
        ip,
        mac,
        ifindex,
        is_active,
    })
}

/// Extracts a `NeighborEvent` from a raw netlink broadcast message.
///
/// Handles both `NewNeighbour` and `DelNeighbour` message types.
/// Filters incomplete states and invalid MACs.
#[must_use]
pub fn extract_neigh_info(msg: &NetlinkMessage<RouteNetlinkMessage>) -> Option<NeighborEvent> {
    let (neigh, is_delete) = match &msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(n)) => (n, false),
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelNeighbour(n)) => (n, true),
        _ => return None,
    };

    let mut ip_addr: Option<IpAddr> = None;
    let mut mac: Option<MacAddr> = None;

    for attr in &neigh.attributes {
        match attr {
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(i)) => {
                ip_addr = Some(IpAddr::V6(*i));
            }
            NeighbourAttribute::Destination(NeighbourAddress::Inet(i)) => {
                ip_addr = Some(IpAddr::V4(*i));
            }
            NeighbourAttribute::LinkLocalAddress(m) => mac = MacAddr::from_slice(m),
            _ => {}
        }
    }

    let ip = ip_addr?;
    let state = neigh.header.state;

    if !is_delete && matches!(state, NeighbourState::Incomplete) {
        return None;
    }

    if is_delete {
        Some(NeighborEvent::Deleted {
            ip,
            ifindex: neigh.header.ifindex,
        })
    } else if state == NeighbourState::Failed {
        Some(NeighborEvent::Failed {
            ip,
            ifindex: neigh.header.ifindex,
        })
    } else {
        let mac = mac?;
        if mac.is_zero() || (mac.0[0] & 1) == 1 {
            return None;
        }

        let is_active = matches!(
            state,
            NeighbourState::Reachable | NeighbourState::Permanent | NeighbourState::Noarp
        );

        Some(NeighborEvent::Added {
            ip,
            mac,
            ifindex: neigh.header.ifindex,
            is_active,
        })
    }
}

/// Parses a CIDR string (e.g., "`2001:db8::/64`") into an `Ipv6Addr` and a prefix length.
/// Supports zero-allocation math by avoiding string formatting in the loop.
fn split_prefix_and_length(target_prefix: &str) -> Option<(Ipv6Addr, u8)> {
    if target_prefix.is_empty() {
        return None;
    }
    let mut parts = target_prefix.split('/');
    let ip = parts.next()?.parse::<Ipv6Addr>().ok()?;
    let len = parts
        .next()
        .and_then(|s| s.parse::<u8>().ok())
        .unwrap_or(64);
    Some((ip, len))
}

pub async fn get_ipv6_neighbors(
    handle: &Handle,
    target_prefix: &str,
    target_ifindex: Option<u32>,
) -> Result<Vec<NeighborEvent>, NetworkError> {
    let mut neighbors = Vec::new();
    let mut stream = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V6)
        .execute();

    let prefix_data = split_prefix_and_length(target_prefix);
    let (mask, expected_network) = if let Some((prefix_ip, prefix_len)) = prefix_data {
        let prefix_u128 = u128::from_be_bytes(prefix_ip.octets());
        let mask = if prefix_len == 0 {
            0
        } else if prefix_len >= 128 {
            u128::MAX
        } else {
            u128::MAX << (128 - prefix_len)
        };
        (mask, prefix_u128 & mask)
    } else {
        (0, 0)
    };

    while let Some(msg) = stream.try_next().await? {
        if let Some(event) = parse_neighbor_msg(msg) {
            if let Some(target) = target_ifindex
                && event.ifindex() != target
            {
                continue;
            }

            let matches = if prefix_data.is_some() {
                match event.ip() {
                    IpAddr::V6(ip) => {
                        let ip_u128 = u128::from_be_bytes(ip.octets());
                        (ip_u128 & mask) == expected_network
                    }
                    IpAddr::V4(_) => false,
                }
            } else {
                true // Empty prefix matches everything
            };

            if matches {
                neighbors.push(event);
            }
        }
    }

    Ok(neighbors)
}

pub async fn get_ipv4_neighbors(
    handle: &Handle,
    target_ifindex: Option<u32>,
) -> Result<Vec<NeighborEvent>, NetworkError> {
    let mut neighbors = Vec::new();
    let mut stream = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V4)
        .execute();

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

/// Sends a neighbor probe (NDP for IPv6, ARP for IPv4) to trigger a kernel resolution.
///
/// Sets the neighbor state to `Probe`, which causes the kernel to send a
/// Neighbor Solicitation (IPv6) or ARP Request (IPv4).
pub async fn probe_neighbor(
    handle: &Handle,
    ifindex: u32,
    ip: IpAddr,
    mac: Option<MacAddr>,
) -> Result<(), rtnetlink::Error> {
    let mut req = handle
        .neighbours()
        .add(ifindex, ip)
        .state(NeighbourState::Probe);

    if let Some(m) = mac {
        req = req.link_local_address(m.as_bytes());
    }

    req.execute().await
}

/// Returns an iterator over all usable IPv4 addresses in a given subnet.
/// Skips the network address (.0) and the broadcast address (.255 for /24).
pub fn get_ipv4_subnet_iterable(ip: Ipv4Addr, prefix_len: u8) -> impl Iterator<Item = Ipv4Addr> {
    let (start, end) = if prefix_len >= 31 {
        // Intervalo vazio se o prefixo for 31 ou 32 (sem IPs hosts usáveis para scan padrão)
        (1, 1)
    } else {
        let mask = !u32::MAX.checked_shr(u32::from(prefix_len)).unwrap_or(0);
        let ip_u32 = u32::from_be_bytes(ip.octets());
        let network = ip_u32 & mask;
        let broadcast = network | !mask;
        (network + 1, broadcast)
    };

    // OPTIMIZATION: Retorna um iterador ao invés de alocar um Vec gigante na memória.
    (start..end).map(|addr| Ipv4Addr::from(addr.to_be_bytes()))
}
