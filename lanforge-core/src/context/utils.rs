use crate::bus::DeviceChange;
use crate::context::state::DeviceUpdate;
use crate::identifiers::MacAddr;
use crate::state::FieldUpdate;

pub(crate) const fn mac_of(update: &DeviceUpdate) -> Option<MacAddr> {
    match update {
        DeviceUpdate::V6LeaseGranted { mac, .. }
        | DeviceUpdate::V6PrefixAssigned { mac, .. }
        | DeviceUpdate::DuidAssociated { mac, .. } => *mac,
        DeviceUpdate::SlaacObserved { mac, .. }
        | DeviceUpdate::V4LeaseGranted { mac, .. }
        | DeviceUpdate::NdpSeen { mac, .. }
        | DeviceUpdate::ArpSeen { mac, .. }
        | DeviceUpdate::DhcpHostnameHint { mac, .. }
        | DeviceUpdate::MdnsHostnameHint { mac, .. }
        | DeviceUpdate::CliHostUpdated { mac, .. }
        | DeviceUpdate::ClassHint { mac, .. }
        | DeviceUpdate::TopologyUpdated { mac, .. }
        | DeviceUpdate::HostRemoved { mac }
        | DeviceUpdate::LeaseReleased { mac, .. } => Some(*mac),

        DeviceUpdate::IpDeleted { .. }
        | DeviceUpdate::IpOffline { .. }
        | DeviceUpdate::InterfaceIpsChanged { .. }
        | DeviceUpdate::PruneZombies
        | DeviceUpdate::RebuildDnsIndices
        | DeviceUpdate::Reset => None,
    }
}

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
        DeviceUpdate::CliHostUpdated {
            hostname,
            v4_static,
            v6_suffix,
            duid,
            ..
        } => {
            if let FieldUpdate::Set(hn) = hostname {
                Some(DeviceChange::HostnameChanged {
                    hostname: hn.clone(),
                })
            } else if let FieldUpdate::Set(ip) = v4_static {
                Some(DeviceChange::V4StaticChanged { ip: Some(*ip) })
            } else if let FieldUpdate::Set(suf) = v6_suffix {
                Some(DeviceChange::V6SuffixChanged {
                    suffix: Some(suf.clone()),
                })
            } else if let FieldUpdate::Set(d) = duid {
                Some(DeviceChange::DuidAssociated { duid: d.clone() })
            } else if matches!(hostname, FieldUpdate::Clear) {
                Some(DeviceChange::HostnameChanged {
                    hostname: String::new(),
                })
            } else if matches!(v4_static, FieldUpdate::Clear) {
                Some(DeviceChange::V4StaticChanged { ip: None })
            } else if matches!(v6_suffix, FieldUpdate::Clear) {
                Some(DeviceChange::V6SuffixChanged { suffix: None })
            } else {
                None
            }
        }
        DeviceUpdate::ClassHint { class, .. } => Some(DeviceChange::Classified { class: *class }),
        DeviceUpdate::TopologyUpdated {
            parent_mac, port, ..
        } => Some(DeviceChange::TopologyChanged {
            parent_mac: *parent_mac,
            port: port.clone(),
        }),
        _ => None,
    }
}
