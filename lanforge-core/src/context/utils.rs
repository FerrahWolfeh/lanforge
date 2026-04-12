//! Internal helpers for state-to-event conversion.
//!
//! This module provides utilities used by [`LanforgeContext`](super::LanforgeContext)
//! to translate low-level [`DeviceUpdate`](crate::state::DeviceUpdate) instructions
//! into high-level [`DeviceChange`](crate::bus::DeviceChange) events for the bus.
//!
//! # Functions
//!
//! | Function              | Purpose                                    |
//! |-----------------------|--------------------------------------------|
//! | `mac_of`              | Extract MAC address from any `DeviceUpdate`|
//! | `device_change_of`    | Convert `DeviceUpdate` to `DeviceChange`   |

use crate::bus::DeviceChange;
use crate::context::state::DeviceUpdate;
use crate::identifiers::MacAddr;
use crate::state::FieldUpdate;

/// Extracts the MAC address from any variant of [`DeviceUpdate`], if present.
///
/// Returns `None` for updates that don't target a specific device
/// (e.g., `IpDeleted`, `InterfaceIpsChanged`, `PruneZombies`).
pub(crate) const fn mac_of(update: &DeviceUpdate) -> Option<MacAddr> {
    match update {
        DeviceUpdate::V6LeaseGranted { mac, .. }
        | DeviceUpdate::V6PrefixAssigned { mac, .. }
        | DeviceUpdate::DuidAssociated { mac, .. } => *mac,
        DeviceUpdate::SlaacSynced { mac, .. }
        | DeviceUpdate::SlaacObserved { mac, .. }
        | DeviceUpdate::V4LeaseGranted { mac, .. }
        | DeviceUpdate::NdpSeen { mac, .. }
        | DeviceUpdate::ArpSeen { mac, .. }
        | DeviceUpdate::DhcpHostnameHint { mac, .. }
        | DeviceUpdate::MdnsHostnameHint { mac, .. }
        | DeviceUpdate::CliHostUpdated { mac, .. }
        | DeviceUpdate::SlaacCleared { mac }
        | DeviceUpdate::HostRemoved { mac }
        | DeviceUpdate::LeaseReleased { mac, .. } => Some(*mac),

        DeviceUpdate::IpDeleted { .. }
        | DeviceUpdate::IpOffline { .. }
        | DeviceUpdate::InterfaceIpsChanged { .. }
        | DeviceUpdate::PruneZombies
        | DeviceUpdate::RebuildDnsIndices => None,
    }
}

/// Converts a [`DeviceUpdate`] into its corresponding [`DeviceChange`] for the bus.
///
/// This function maps internal state mutations to user-facing event descriptions.
/// Not all updates result in events — some are internal-only (e.g., `PruneZombies`).
///
/// # Mapping
///
/// | DeviceUpdate              | DeviceChange                    |
/// |---------------------------|---------------------------------|
/// | `V4LeaseGranted`          | `V4Assigned`                    |
/// | `V6LeaseGranted`          | `V6Assigned`                    |
/// | `V6PrefixAssigned`        | `V6PrefixAssigned`              |
/// | `SlaacObserved`           | `SlaacObserved`                 |
/// | `SlaacSynced`             | `SlaacSynced`                   |
/// | `DhcpHostnameHint`        | `HostnameChanged`               |
/// | `MdnsHostnameHint`        | `HostnameChanged`               |
/// | `DuidAssociated`          | `DuidAssociated`                |
/// | `NdpSeen`                 | `NdpActivity`                   |
/// | `ArpSeen`                 | `ArpActivity`                   |
/// | `IpOffline`               | `StatusChanged { online: false }`|
/// | `LeaseReleased`           | `LeaseExpired`                  |
/// | `CliHostUpdated` (hostname)| `HostnameChanged`              |
/// | `CliHostUpdated` (v4)     | `V4StaticChanged`               |
/// | `CliHostUpdated` (v6)     | `V6SuffixChanged`               |
/// | `HostRemoved`, `IpDeleted`, etc. | `None`                    |
pub(crate) fn device_change_of(update: &DeviceUpdate) -> Option<DeviceChange> {
    match update {
        DeviceUpdate::V4LeaseGranted { ip, .. } => Some(DeviceChange::V4Assigned { ip: *ip }),
        DeviceUpdate::V6LeaseGranted { ip, iaid, .. } => Some(DeviceChange::V6Assigned {
            ip: *ip,
            iaid: *iaid,
        }),
        DeviceUpdate::V6PrefixAssigned {
            prefix, len, iaid, ..
        } => Some(DeviceChange::V6PrefixAssigned {
            prefix: *prefix,
            len: *len,
            iaid: *iaid,
        }),
        DeviceUpdate::SlaacObserved { addr, .. } => {
            Some(DeviceChange::SlaacObserved { addr: *addr })
        }
        DeviceUpdate::SlaacSynced { addresses, .. } => Some(DeviceChange::SlaacSynced {
            addresses: addresses.clone(),
        }),
        DeviceUpdate::DhcpHostnameHint { hostname, .. }
        | DeviceUpdate::MdnsHostnameHint { hostname, .. } => Some(DeviceChange::HostnameChanged {
            hostname: hostname.clone(),
        }),
        DeviceUpdate::DuidAssociated { duid, .. } => {
            Some(DeviceChange::DuidAssociated { duid: duid.clone() })
        }
        DeviceUpdate::NdpSeen { ip, .. } => Some(DeviceChange::NdpActivity { ip: *ip }),
        DeviceUpdate::ArpSeen { ip, .. } => Some(DeviceChange::ArpActivity { ip: *ip }),
        DeviceUpdate::IpOffline { .. } => Some(DeviceChange::StatusChanged {
            online: false,
            hostname: None,
        }),
        DeviceUpdate::LeaseReleased { target, .. } => Some(DeviceChange::LeaseExpired {
            target: target.clone(),
        }),
        DeviceUpdate::HostRemoved { .. }
        | DeviceUpdate::IpDeleted { .. }
        | DeviceUpdate::SlaacCleared { .. }
        | DeviceUpdate::InterfaceIpsChanged { .. }
        | DeviceUpdate::PruneZombies
        | DeviceUpdate::RebuildDnsIndices => None,
        DeviceUpdate::CliHostUpdated {
            hostname,
            v4_static,
            v6_suffix,
            ..
        } => {
            if let FieldUpdate::Set(hn) = hostname {
                return Some(DeviceChange::HostnameChanged {
                    hostname: hn.clone(),
                });
            }
            if let FieldUpdate::Set(ip) = v4_static {
                return Some(DeviceChange::V4StaticChanged { ip: Some(*ip) });
            }
            if let FieldUpdate::Set(v6) = v6_suffix {
                return Some(DeviceChange::V6SuffixChanged {
                    suffix: Some(v6.clone()),
                });
            }
            None
        }
    }
}
