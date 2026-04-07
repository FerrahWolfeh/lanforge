// ---------------------------------------------------------------------------
// Helpers internos
// ---------------------------------------------------------------------------

use crate::bus::DeviceChange;
use crate::context::state::DeviceUpdate;
use crate::identifiers::MacAddr;
use crate::state::FieldUpdate;

/// Extracts the MAC address from any variant of [`DeviceUpdate`], if present.
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
        | DeviceUpdate::RebuildDnsIndices => None,
    }
}

/// Converts a [`DeviceUpdate`] into its corresponding [`DeviceChange`] for the bus.
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
        DeviceUpdate::DuidAssociated { .. } => Some(DeviceChange::DuidAssociated),
        DeviceUpdate::NdpSeen { ip, .. } => Some(DeviceChange::NdpActivity { ip: *ip }),
        DeviceUpdate::ArpSeen { ip, .. } => Some(DeviceChange::ArpActivity { ip: *ip }),
        DeviceUpdate::IpOffline { .. } => Some(DeviceChange::StatusChanged { online: false }),
        DeviceUpdate::LeaseReleased { target, .. } => Some(DeviceChange::LeaseExpired {
            target: target.clone(),
        }),
        DeviceUpdate::HostRemoved { .. }
        | DeviceUpdate::IpDeleted { .. }
        | DeviceUpdate::SlaacCleared { .. }
        | DeviceUpdate::InterfaceIpsChanged { .. }
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
