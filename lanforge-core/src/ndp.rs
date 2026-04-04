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
    #[must_use]
    pub const fn ip(&self) -> &std::net::IpAddr {
        match self {
            Self::Added { ip, .. } | Self::Deleted { ip, .. } => ip,
        }
    }

    #[must_use]
    pub const fn mac(&self) -> Option<MacAddr> {
        match self {
            Self::Added { mac, .. } => Some(*mac),
            Self::Deleted { .. } => None,
        }
    }

    #[must_use]
    pub const fn ifindex(&self) -> u32 {
        match self {
            Self::Added { ifindex, .. } | Self::Deleted { ifindex, .. } => *ifindex,
        }
    }

    /// Maps the raw neighbor event into a higher-level [`DeviceUpdate`].
    #[must_use]
    pub fn to_device_update(
        &self,
        gua_prefix: Option<&Ipv6Addr>,
        ula_prefix: Option<&Ipv6Addr>,
    ) -> DeviceUpdate {
        match self {
            Self::Added { ip, mac, .. } => match ip {
                std::net::IpAddr::V6(ip6) => {
                    let matches_gua =
                        gua_prefix.is_some_and(|prefix| ip_matches_prefix(ip6, prefix));
                    let matches_ula =
                        ula_prefix.is_some_and(|prefix| ip_matches_prefix(ip6, prefix));

                    if matches_gua || matches_ula {
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
            Self::Deleted { ip, .. } => DeviceUpdate::IpDeleted { ip: *ip },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn test_to_device_update_strict_slaac() {
        let mac = MacAddr::parse("00:11:22:33:44:55").unwrap();
        let prefix: Ipv6Addr = "fd00::".parse().unwrap();

        // Correct EUI-64: (00^02):11:22:ff:fe:33:44:55 -> 0211:22ff:fe33:4455
        let slaac_ip: Ipv6Addr = "fd00::0211:22ff:fe33:4455".parse().unwrap();
        let dhcp_ip: Ipv6Addr = "fd00::101".parse().unwrap();

        let event_slaac = NeighborEvent::Added {
            ip: slaac_ip.into(),
            mac,
            ifindex: 1,
        };
        let event_dhcp = NeighborEvent::Added {
            ip: dhcp_ip.into(),
            mac,
            ifindex: 1,
        };

        let update_slaac = event_slaac.to_device_update(None, Some(&prefix));
        let update_dhcp = event_dhcp.to_device_update(None, Some(&prefix));

        assert!(
            matches!(update_slaac, DeviceUpdate::SlaacObserved { .. }),
            "EUI-64 should be SlaacObserved"
        );
        assert!(
            matches!(update_dhcp, DeviceUpdate::SlaacObserved { .. }),
            "Custom suffix (potential Privacy Extension) should also be SlaacObserved at the NDP layer"
        );
    }
}
