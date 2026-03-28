// ---------------------------------------------------------------------------
// NeighborEvent — Typed structure for kernel neighbor events
// ---------------------------------------------------------------------------

use std::net::Ipv6Addr;

use crate::{identifiers::MacAddr, state::update::DeviceUpdate, utils::ip_matches_prefix};

/// A neighbor event (IPv4 or IPv6) observed via the kernel `RTM_NEWNEIGH` netlink signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeighborEvent {
    /// A neighbor entry was added or updated.
    Added {
        ip: std::net::IpAddr,
        mac: MacAddr,
        ifindex: u32,
    },
    /// A neighbor entry was deleted from the kernel table.
    Deleted { ip: std::net::IpAddr, ifindex: u32 },
}

impl NeighborEvent {
    pub fn ip(&self) -> &std::net::IpAddr {
        match self {
            NeighborEvent::Added { ip, .. } => ip,
            NeighborEvent::Deleted { ip, .. } => ip,
        }
    }

    pub fn mac(&self) -> Option<MacAddr> {
        match self {
            NeighborEvent::Added { mac, .. } => Some(*mac),
            NeighborEvent::Deleted { .. } => None,
        }
    }

    /// Maps the raw neighbor event into a higher-level [`DeviceUpdate`].
    pub fn to_device_update(&self, gua_prefix: Option<&Ipv6Addr>) -> DeviceUpdate {
        match self {
            NeighborEvent::Added { ip, mac, .. } => match ip {
                std::net::IpAddr::V6(ip6) => {
                    let is_slaac = gua_prefix.is_some_and(|prefix| ip_matches_prefix(ip6, prefix));
                    if is_slaac {
                        DeviceUpdate::SlaacObserved {
                            mac: *mac,
                            addr: *ip6,
                        }
                    } else {
                        DeviceUpdate::NdpSeen {
                            mac: *mac,
                            ip: *ip6,
                        }
                    }
                }
                std::net::IpAddr::V4(ip4) => DeviceUpdate::ArpSeen {
                    mac: *mac,
                    ip: *ip4,
                },
            },
            NeighborEvent::Deleted { ip, .. } => DeviceUpdate::IpDeleted { ip: *ip },
        }
    }
}
