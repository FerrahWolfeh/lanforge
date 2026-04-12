//! Neighbor Discovery Protocol (NDP) event mapping.
//!
//! This module handles kernel-level neighbor discovery events received via
//! netlink (`RTM_NEWNEIGH` / `RTM_DELNEIGH`) signals.
//!
//! # NDP Overview
//!
//! The Neighbor Discovery Protocol (NDP) is the IPv6 equivalent of ARP.
//! It discovers and tracks which MAC addresses are using which IPv6 addresses
//! on the local network segment.
//!
//! # Event Flow
//!
//! 1. **Kernel**: Emits netlink events when neighbor state changes
//! 2. **Lanforge**: Receives events and wraps as [`NeighborEvent`]
//! 3. **Mapping**: Converts to [`DeviceUpdate`](crate::state::DeviceUpdate) via
//!    [`to_device_update`](NeighborEvent::to_device_update)
//! 4. **State**: Updates are applied to the device table
//!
//! # Neighbor States
//!
//! | State     | Description                                    |
//! |-----------|------------------------------------------------|
//! | Added     | New neighbor entry or existing entry updated   |
//! | Deleted   | Neighbor entry removed from kernel table       |
//! | Failed    | Neighbor reached `NUD_FAILED` (unreachable)      |
//!
//! # SLAAC Detection
//!
//! When processing `Added` events for IPv6, the system attempts to detect
//! SLAAC addresses by checking if the IPv6 address matches the current
//! GUA or ULA prefix. Both EUI-64 and privacy-extension addresses are
//! treated as SLAAC at the NDP layer.

use std::net::{IpAddr, Ipv6Addr};

use crate::{context::state::DeviceUpdate, identifiers::MacAddr, utils::ip_matches_prefix};

/// A neighbor event (IPv4 or IPv6) observed via the kernel `RTM_NEWNEIGH` netlink signal.
///
/// This enum represents the raw events from the kernel's neighbor cache.
/// Use [`to_device_update`](NeighborEvent::to_device_update) to convert
/// these into higher-level device state updates.
///
/// # Example
///
/// ```rust
/// use lanforge_core::ndp::NeighborEvent;
/// use lanforge_core::identifiers::MacAddr;
/// use std::net::Ipv6Addr;
///
/// let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
/// let ip: Ipv6Addr = "fe80::1".parse().unwrap();
///
/// let event = NeighborEvent::Added {
///     ip: ip.into(),
///     mac,
///     ifindex: 2,
/// };
///
/// assert_eq!(event.ifindex(), 2);
/// assert_eq!(event.mac(), Some(mac));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeighborEvent {
    /// A neighbor entry was added or updated.
    Added {
        ip: IpAddr,
        mac: MacAddr,
        ifindex: u32,
    },
    /// A neighbor entry was deleted from the kernel table.
    Deleted { ip: IpAddr, ifindex: u32 },
    /// A neighbor entry reached a FAILED state (`NUD_FAILED`).
    ///
    /// This indicates the neighbor is unreachable.
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
    ///
    /// # Mapping Logic
    ///
    /// | `NeighborEvent`      | `DeviceUpdate` (IPv6, matches prefix) | `DeviceUpdate` (IPv6, no match) | `DeviceUpdate` (IPv4) |
    /// |--------------------|--------------------------------------|-------------------------------|---------------------|
    /// | Added (IPv6)       | `SlaacObserved`                      | `NdpSeen`                     | —                   |
    /// | Added (IPv4)       | —                                    | —                             | `ArpSeen`           |
    /// | Deleted            | `IpDeleted`                          | —                             | `IpDeleted`         |
    /// | Failed             | `IpOffline`                          | —                             | `IpOffline`         |
    ///
    /// # SLAAC Detection
    ///
    /// For IPv6 `Added` events, the address is checked against the provided
    /// `gua_prefix` and `ula_prefix`. If it matches EITHER prefix, it's
    /// considered a SLAAC observation. Otherwise, it's treated as generic
    /// NDP activity (e.g., link-local probes, `DHCPv6` addresses).
    ///
    /// # Parameters
    ///
    /// - `gua_prefix`: The current Global Unicast prefix for the interface
    /// - `ula_prefix`: The current Unique Local prefix for the interface
    ///
    /// # Example
    ///
    /// ```rust
    /// use lanforge_core::ndp::NeighborEvent;
    /// use lanforge_core::state::DeviceUpdate;
    /// use lanforge_core::identifiers::MacAddr;
    /// use std::net::Ipv6Addr;
    ///
    /// let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    /// let prefix: Ipv6Addr = "fd00::".parse().unwrap();
    /// let slaac_ip: Ipv6Addr = "fd00::aabb:ccff:fedd:eeff".parse().unwrap();
    ///
    /// let event = NeighborEvent::Added {
    ///     ip: slaac_ip.into(),
    ///     mac,
    ///     ifindex: 2,
    /// };
    ///
    /// let update = event.to_device_update(None, Some(&prefix));
    /// assert!(matches!(update, DeviceUpdate::SlaacObserved { .. }));
    /// ```
    #[must_use]
    pub fn to_device_update(
        &self,
        gua_prefix: Option<&Ipv6Addr>,
        ula_prefix: Option<&Ipv6Addr>,
    ) -> DeviceUpdate {
        match self {
            Self::Added { ip, mac, .. } => match ip {
                IpAddr::V6(ip6) => {
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
                IpAddr::V4(ip4) => DeviceUpdate::ArpSeen {
                    mac: *mac,
                    ip: *ip4,
                },
            },
            Self::Deleted { ip, .. } => DeviceUpdate::IpDeleted { ip: *ip },
            Self::Failed { ip, .. } => DeviceUpdate::IpOffline { ip: *ip },
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
