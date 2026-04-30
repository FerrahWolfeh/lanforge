use crate::device::DeviceClass;
use crate::identifiers::{Duid, MacAddr};
use crate::{context::state::LeaseTarget, device::Ipv6AddrOrSuffix};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Detailed changes applied to a specific `Device`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DeviceChange {
    /// An IPv4 address was assigned or renewed via `DHCPv4`.
    V4Assigned { ip: Ipv4Addr },

    /// A dynamic lease expired and was removed from the device.
    LeaseExpired { target: LeaseTarget },

    /// An IPv6 address was assigned or renewed via `DHCPv6`.
    V6Assigned { ip: Ipv6Addr, iaid: u32 },

    /// The device was entirely removed from the active table due to inactivity.
    HostRemoved,

    /// An IPv6 prefix was delegated to the device via `DHCPv6 Prefix Delegation` (`IA_PD`).
    V6PrefixAssigned {
        prefix: Ipv6Addr,
        len: u8,
        iaid: u32,
    },

    /// A SLAAC address was observed via Neighbor Discovery (NDP).
    SlaacObserved { addr: Ipv6Addr },

    /// The device's reachability status has changed.
    StatusChanged {
        online: bool,
        hostname: Option<String>,
    },

    /// The device's hostname was updated (e.g., via DHCP hint or CLI).
    HostnameChanged { hostname: String },

    /// A static IPv4 reservation was modified or removed via CLI.
    V4StaticChanged { ip: Option<Ipv4Addr> },

    /// A static IPv6 Interface ID (suffix) was modified or removed via CLI.
    V6SuffixChanged { suffix: Option<Ipv6AddrOrSuffix> },

    /// A DUID was successfully associated with this device's MAC.
    DuidAssociated { duid: Duid },

    /// A neighbor was observed via NDP (IPv6) but no SLAAC address was extracted.
    NdpActivity { ip: Ipv6Addr },

    /// An IPv4 neighbor event (ARP) was observed.
    ArpActivity { ip: Ipv4Addr },

    /// The device has been classified into a high-level category (e.g., Printer).
    Classified { class: DeviceClass },
    /// The device's physical or logical topology has changed.
    TopologyChanged {
        parent_mac: Option<MacAddr>,
        port: Option<String>,
    },
    /// A specific IP address associated with the device was deleted.
    IpDeleted { ip: IpAddr },
    /// A specific IP address associated with the device went offline.
    IpOffline { ip: IpAddr },
    /// The device was updated via CLI or administrative action.
    CliHostUpdated,
}

impl DeviceChange {
    /// Returns true if this change represents a significant state modification
    /// that should be persisted to the main database immediately.
    ///
    /// Minor changes like activity timestamps or transient status updates
    /// return false to avoid excessive main DB writes.
    #[must_use]
    pub const fn is_persistent(&self) -> bool {
        match self {
            Self::V4Assigned { .. }
            | Self::V6Assigned { .. }
            | Self::V6PrefixAssigned { .. }
            | Self::LeaseExpired { .. }
            | Self::HostnameChanged { .. }
            | Self::V4StaticChanged { .. }
            | Self::V6SuffixChanged { .. }
            | Self::DuidAssociated { .. }
            | Self::Classified { .. }
            | Self::CliHostUpdated
            | Self::IpDeleted { .. }
            | Self::SlaacObserved { .. }
            | Self::TopologyChanged { .. } => true,

            Self::ArpActivity { .. }
            | Self::NdpActivity { .. }
            | Self::StatusChanged { .. }
            | Self::IpOffline { .. }
            | Self::HostRemoved => false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DeviceEvent {
    Discovered {
        mac: MacAddr,
        hostname: Option<String>,
    },
    Updated {
        mac: MacAddr,
        hostname: Option<String>,
        change: Box<DeviceChange>,
    },
    Expired {
        mac: MacAddr,
    },
    Purged {
        mac: MacAddr,
    },
    LeaseRelease {
        mac: MacAddr,
        target: LeaseTarget,
    },
    LeaseRenew {
        mac: MacAddr,
        target: LeaseTarget,
    },
}
