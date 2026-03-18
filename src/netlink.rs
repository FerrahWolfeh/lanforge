//! Wrapper do netlink para queries de vizinhos IPv6 e filtragem de eventos.
//!
//! Centraliza toda interação com o subsistema netlink do kernel numa única
//! interface. O Handle é criado em main.rs e passado aqui por referência.

use anyhow::Result;
use futures::stream::TryStreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::{
    RouteNetlinkMessage,
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState},
};
use rtnetlink::{Handle, IpVersion};

// ---------------------------------------------------------------------------
// Neighbour event filter
// ---------------------------------------------------------------------------

/// Returns true if `msg` is a NEW or DEL neighbour event for our target prefix.
pub fn is_relevant_neigh_event(
    msg: &NetlinkMessage<RouteNetlinkMessage>,
    target_prefix: &str,
) -> bool {
    match &msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(neigh)) => {
            // Only purely transient states should be completely ignored.
            // When an entry transitions to Failed, we WANT a scan so we can immediately drop it.
            if neigh.header.state == NeighbourState::Incomplete {
                return false;
            }
            neigh_matches_prefix(neigh, target_prefix)
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelNeighbour(neigh)) => {
            // A deletion always warrants a rescan to remove the entry
            neigh_matches_prefix(neigh, target_prefix)
        }
        _ => false,
    }
}

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
// Netlink neighbour query (uses the shared Handle)
// ---------------------------------------------------------------------------

pub async fn get_ipv6_neighbors(
    handle: &Handle,
    target_prefix: &str,
) -> Result<Vec<(String, String)>> {
    let mut neighbors = Vec::new();
    let mut stream = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V6)
        .execute();

    while let Some(msg) = stream.try_next().await? {
        if let Some((ip, mac)) = parse_neighbor(msg)
            && ip.starts_with(target_prefix)
        {
            neighbors.push((ip, mac));
        }
    }

    Ok(neighbors)
}

fn parse_neighbor(msg: NeighbourMessage) -> Option<(String, String)> {
    if msg.header.state == NeighbourState::Incomplete || msg.header.state == NeighbourState::Failed
    {
        return None;
    }

    let mut ip_str = String::new();
    let mut mac_str = String::new();

    for attr in msg.attributes {
        match attr {
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(ipv6)) => {
                ip_str = ipv6.to_string();
            }
            NeighbourAttribute::LinkLocalAddress(mac_bytes) => {
                mac_str = mac_bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(":");
            }
            _ => {}
        }
    }

    if !ip_str.is_empty() && !mac_str.is_empty() {
        Some((ip_str, mac_str))
    } else {
        None
    }
}
