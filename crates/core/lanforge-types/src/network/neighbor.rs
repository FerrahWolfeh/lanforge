//! Neighbor Discovery Protocol (NDP) and ARP event mapping.

use crate::identifiers::MacAddr;
use crate::network::Ipv6Prefix;
use crate::update::DeviceUpdate;
use std::net::IpAddr;

/// A neighbor event (IPv4 or IPv6) observed via the kernel `RTM_NEWNEIGH` netlink signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeighborEvent {
    /// A neighbor entry was added or updated.
    Added {
        ip: IpAddr,
        mac: MacAddr,
        ifindex: u32,
        /// True if the neighbor is in a "trustworthy" active state (Reachable, Permanent).
        is_active: bool,
    },
    /// A neighbor entry was deleted from the kernel table.
    Deleted { ip: IpAddr, ifindex: u32 },
    /// A neighbor entry reached a FAILED state (`NUD_FAILED`).
    Failed { ip: IpAddr, ifindex: u32 },
}

impl NeighborEvent {
    #[must_use]
    pub const fn ip(&self) -> &IpAddr {
        match self {
            Self::Added { ip, .. } | Self::Deleted { ip, .. } | Self::Failed { ip, .. } => ip,
        }
    }

    #[must_use]
    pub const fn mac(&self) -> Option<MacAddr> {
        match self {
            Self::Added { mac, .. } => Some(*mac),
            Self::Deleted { .. } | Self::Failed { .. } => None,
        }
    }

    #[must_use]
    pub const fn ifindex(&self) -> u32 {
        match self {
            Self::Added { ifindex, .. }
            | Self::Deleted { ifindex, .. }
            | Self::Failed { ifindex, .. } => *ifindex,
        }
    }

    /// Maps the raw neighbor event into a higher-level [`DeviceUpdate`].
    #[must_use]
    pub fn to_device_update(
        &self,
        gua_prefix: Option<&Ipv6Prefix>,
        ula_prefix: Option<&Ipv6Prefix>,
    ) -> Option<DeviceUpdate> {
        match self {
            Self::Added {
                ip, mac, is_active, ..
            } => match ip {
                IpAddr::V6(ip6) => {
                    let matches_gua = gua_prefix.is_some_and(|prefix| prefix.matches(ip6));
                    let matches_ula = ula_prefix.is_some_and(|prefix| prefix.matches(ip6));

                    if matches_gua || matches_ula {
                        Some(DeviceUpdate::SlaacObserved {
                            mac: *mac,
                            addr: *ip6,
                            is_active: *is_active,
                        })
                    } else {
                        Some(DeviceUpdate::NdpSeen {
                            mac: *mac,
                            ip: *ip6,
                            is_active: *is_active,
                        })
                    }
                }
                IpAddr::V4(ip4) => Some(DeviceUpdate::ArpSeen {
                    mac: *mac,
                    ip: *ip4,
                    is_active: *is_active,
                }),
            },
            Self::Deleted { ip, .. } | Self::Failed { ip, .. } => {
                Some(DeviceUpdate::IpOffline { ip: *ip })
            }
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
        let prefix = Ipv6Prefix::from_addr("fd00::".parse().unwrap());

        // Correct EUI-64: (00^02):11:22:ff:fe:33:44:55 -> 0211:22ff:fe33:4455
        let slaac_ip: Ipv6Addr = "fd00::0211:22ff:fe33:4455".parse().unwrap();
        let dhcp_ip: Ipv6Addr = "fd00::101".parse().unwrap();

        let event_slaac = NeighborEvent::Added {
            ip: slaac_ip.into(),
            mac,
            ifindex: 1,
            is_active: true,
        };
        let event_dhcp = NeighborEvent::Added {
            ip: dhcp_ip.into(),
            mac,
            ifindex: 1,
            is_active: true,
        };

        let update_slaac = event_slaac.to_device_update(None, Some(&prefix));
        let update_dhcp = event_dhcp.to_device_update(None, Some(&prefix));

        assert!(
            matches!(update_slaac, Some(DeviceUpdate::SlaacObserved { .. })),
            "EUI-64 should be SlaacObserved"
        );
        assert!(
            matches!(update_dhcp, Some(DeviceUpdate::SlaacObserved { .. })),
            "Custom suffix (potential Privacy Extension) should also be SlaacObserved at the NDP layer"
        );
    }
}
