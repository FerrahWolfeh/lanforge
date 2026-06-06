use crate::device::{DeviceClass, DeviceStatus};
use crate::identifiers::{Duid, MacAddr};
use crate::network::Ipv6AddrOrSuffix;
use crate::update::LeaseTarget;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Detailed network-observed changes applied to a specific `Device`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkChange {
    /// An IPv4 address was assigned or renewed via `DHCPv4`.
    V4Assigned { ip: Ipv4Addr },

    /// A dynamic lease expired and was removed from the device.
    LeaseExpired { target: LeaseTarget },

    /// An IPv6 address was assigned or renewed via `DHCPv6`.
    V6Assigned { ip: Ipv6Addr, iaid: u32 },

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
        status: DeviceStatus,
        hostname: Option<String>,
    },

    /// A DUID was successfully associated with this device's MAC.
    DuidAssociated { duid: Duid },

    /// A neighbor was observed via NDP (IPv6) but no SLAAC address was extracted.
    NdpActivity { ip: Ipv6Addr },

    /// An IPv4 neighbor event (ARP) was observed.
    ArpActivity { ip: Ipv4Addr },

    /// A specific IP address associated with the device was deleted.
    IpDeleted { ip: IpAddr },

    /// A specific IP address associated with the device went offline.
    IpOffline { ip: IpAddr },

    /// A hostname hint was learned via DHCP.
    HostnameHint { hostname: String },
}

impl NetworkChange {
    /// Returns true if this change represents a significant state modification
    /// that should be persisted to the main database immediately.
    #[must_use]
    pub const fn is_persistent(&self) -> bool {
        match self {
            Self::V4Assigned { .. }
            | Self::V6Assigned { .. }
            | Self::V6PrefixAssigned { .. }
            | Self::LeaseExpired { .. }
            | Self::DuidAssociated { .. }
            | Self::IpDeleted { .. }
            | Self::SlaacObserved { .. } => true,

            Self::ArpActivity { .. }
            | Self::NdpActivity { .. }
            | Self::StatusChanged { .. }
            | Self::IpOffline { .. }
            | Self::HostnameHint { .. } => false,
        }
    }

    /// Returns true if this change represents a modification to lease state.
    #[must_use]
    pub const fn is_lease_change(&self) -> bool {
        matches!(
            self,
            Self::V4Assigned { .. }
                | Self::V6Assigned { .. }
                | Self::V6PrefixAssigned { .. }
                | Self::LeaseExpired { .. }
                | Self::SlaacObserved { .. }
        )
    }
}

/// Detailed administrative/user configuration changes applied to a specific `Device`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdminChange {
    /// The device was updated via CLI or administrative action.
    CliHostUpdated,

    /// The device's hostname was updated by the user.
    HostnameChanged { hostname: String },

    /// A static IPv4 reservation was modified or removed via CLI.
    V4StaticChanged { ip: Option<Ipv4Addr> },

    /// A static IPv6 Interface ID (suffix) was modified or removed via CLI.
    V6SuffixChanged { suffix: Option<Ipv6AddrOrSuffix> },

    /// The device has been classified into a high-level category (e.g., Printer).
    Classified { class: DeviceClass },

    /// The device was entirely removed from the active table due to user/admin action.
    HostRemoved,
}

/// Lightweight representation of `DHCPv4` message types for diagnostics.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DhcpV4MessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    ForceRenew,
    LeaseQuery,
    LeaseUnassigned,
    LeaseUnknown,
    LeaseActive,
    BulkLeaseQuery,
    LeaseQueryDone,
    LeaseQueryStatus,
    Tls,
    Unknown(u8),
}

impl From<u8> for DhcpV4MessageType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            9 => Self::ForceRenew,
            10 => Self::LeaseQuery,
            11 => Self::LeaseUnassigned,
            12 => Self::LeaseUnknown,
            13 => Self::LeaseActive,
            14 => Self::BulkLeaseQuery,
            15 => Self::LeaseQueryDone,
            16 => Self::LeaseQueryStatus,
            17 => Self::Tls,
            other => Self::Unknown(other),
        }
    }
}

/// Lightweight representation of `DHCPv6` message types for diagnostics.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DhcpV6MessageType {
    Solicit,
    Advertise,
    Request,
    Confirm,
    Renew,
    Rebind,
    Reply,
    Release,
    Decline,
    Reconfigure,
    InformationRequest,
    RelayForw,
    RelayRepl,
    LeaseQuery,
    LeaseQueryReply,
    LeaseQueryData,
    LeaseQueryDone,
    Unknown(u8),
}

impl From<u8> for DhcpV6MessageType {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::Solicit,
            2 => Self::Advertise,
            3 => Self::Request,
            4 => Self::Confirm,
            5 => Self::Renew,
            6 => Self::Rebind,
            7 => Self::Reply,
            8 => Self::Release,
            9 => Self::Decline,
            10 => Self::Reconfigure,
            11 => Self::InformationRequest,
            12 => Self::RelayForw,
            13 => Self::RelayRepl,
            14 => Self::LeaseQuery,
            15 => Self::LeaseQueryReply,
            16 => Self::LeaseQueryData,
            17 => Self::LeaseQueryDone,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DeviceEvent {
    Discovered {
        mac: MacAddr,
        hostname: Option<String>,
    },
    NetworkUpdate {
        mac: MacAddr,
        hostname: Option<String>,
        change: Box<NetworkChange>,
    },
    NetworkActivity {
        mac: MacAddr,
        hostname: Option<String>,
        change: Box<NetworkChange>,
    },
    AdminUpdate {
        mac: MacAddr,
        hostname: Option<String>,
        change: Box<AdminChange>,
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
    /// A `DHCPv4` message was received or sent (Discover, Offer, etc.)
    DhcpV4Transaction {
        mac: MacAddr,
        msg_type: DhcpV4MessageType,
        details: Option<String>,
    },
    /// A `DHCPv6` message was received or sent (Solicit, Advertise, etc.)
    DhcpV6Transaction {
        mac: MacAddr,
        msg_type: DhcpV6MessageType,
        details: Option<String>,
    },
    /// Summary of a background neighbor scan batch.
    NeighborBatchSummary {
        total: usize,
        new: usize,
        duration_ms: u64,
    },
}
