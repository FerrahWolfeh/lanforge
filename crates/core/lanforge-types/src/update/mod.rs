use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use crate::device::{DeviceClass, Origin, TransientOrigin};
use crate::identifiers::{Duid, MacAddr};
use crate::network::{DnsReverseResolver, Hostname, IpSubnet, Ipv6AddrOrSuffix};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FieldUpdate<T> {
    #[serde(rename = "no_change")]
    #[default]
    NoChange,
    #[serde(rename = "clear")]
    Clear,
    #[serde(rename = "set")]
    Set(T),
}

impl<T> From<Option<T>> for FieldUpdate<T> {
    fn from(opt: Option<T>) -> Self {
        opt.map_or_else(|| Self::Clear, |val| Self::Set(val))
    }
}

impl<T> From<T> for FieldUpdate<T> {
    fn from(val: T) -> Self {
        Self::Set(val)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CliHostUpdate {
    pub hostname: FieldUpdate<String>,
    pub duid: FieldUpdate<Duid>,
    pub v4_static: FieldUpdate<Ipv4Addr>,
    pub v6_suffix: FieldUpdate<Ipv6AddrOrSuffix>,
    pub boot_file: FieldUpdate<String>,
    pub dns_fallback: FieldUpdate<String>,
    pub class: FieldUpdate<DeviceClass>,
    pub origin: Origin,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct InterfaceState {
    pub v4: Option<(Ipv4Addr, u8)>,
    pub link_local: Option<Ipv6Addr>,
    pub gua: Option<Ipv6Addr>,
    pub ula: Option<Ipv6Addr>,
    pub gua_preferred: u32,
    pub gua_valid: u32,
    pub mac: Option<MacAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum LeaseTarget {
    V4,
    V6 { iaid: u32 },
    V6Prefix { iaid: u32 },
}

impl std::fmt::Display for LeaseTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4 => write!(f, "V4"),
            Self::V6 { iaid } => write!(f, "V6 (IAID: {iaid})"),
            Self::V6Prefix { iaid } => write!(f, "V6-PD (IAID: {iaid})"),
        }
    }
}

/// Details of an assigned or renewed `DHCPv6` lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V6LeaseUpdate {
    pub mac: Option<MacAddr>,
    pub duid: Duid,
    pub iaid: u32,
    pub ip: Ipv6Addr,
    pub expires: SystemTime,
}

/// Details of a delegated `DHCPv6` prefix (`IA_PD`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V6PrefixUpdate {
    pub mac: Option<MacAddr>,
    pub duid: Duid,
    pub iaid: u32,
    pub prefix: Ipv6Addr,
    pub len: u8,
    pub expires: SystemTime,
}

/// Dynamic, non-persisted transient host resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransientHostUpdate {
    pub ip: IpAddr,
    pub hostname: Hostname,
    pub origin: TransientOrigin,
}

/// `DHCPv4` address pool utilization update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DhcpV4PoolUpdate {
    pub range_start: Ipv4Addr,
    pub range_end: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub total: u32,
    pub used: u32,
    pub available: u32,
    pub utilization_percent: f32,
}

/// `DHCPv6` address pool utilization update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DhcpV6PoolUpdate {
    pub pool_id: u32,
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub total: u32,
    pub used: u32,
    pub available: u32,
    pub utilization_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceUpdate {
    V4LeaseGranted {
        mac: MacAddr,
        ip: Ipv4Addr,
        expires: SystemTime,
    },
    V6LeaseGranted(Box<V6LeaseUpdate>),
    V6PrefixAssigned(Box<V6PrefixUpdate>),
    SlaacObserved {
        mac: MacAddr,
        addr: Ipv6Addr,
        is_active: bool,
    },
    NdpSeen {
        mac: MacAddr,
        ip: Ipv6Addr,
        is_active: bool,
    },
    ArpSeen {
        mac: MacAddr,
        ip: Ipv4Addr,
        is_active: bool,
    },
    DhcpHostnameHint {
        mac: MacAddr,
        hostname: String,
    },
    MdnsHostnameHint {
        mac: MacAddr,
        hostname: String,
    },
    DuidAssociated {
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
    },
    CliHostUpdated {
        mac: MacAddr,
        update: Box<CliHostUpdate>,
    },
    IgnoreDnsLogSet {
        mac: MacAddr,
        ignore: bool,
    },
    IgnoredLogDomainsSet {
        mac: MacAddr,
        domains: Vec<String>,
    },
    HostRemoved {
        mac: MacAddr,
    },
    LeaseReleased {
        mac: MacAddr,
        target: LeaseTarget,
    },
    IpDeleted {
        ip: IpAddr,
    },
    IpOffline {
        ip: IpAddr,
    },
    InterfaceIpsChanged {
        ifindex: u32,
        state: Box<InterfaceState>,
    },
    PruneZombies,
    RebuildDnsIndices,
    ClassHint {
        mac: MacAddr,
        class: DeviceClass,
    },
    DeviceInterfaceSeen {
        mac: MacAddr,
        iface: String,
    },
    Reset,
    NeighborBatch {
        entries: Vec<(MacAddr, IpAddr, bool)>,
    },
    TransientHostResolved(Box<TransientHostUpdate>),
    AddReverseResolver {
        resolver: Box<DnsReverseResolver>,
    },
    RemoveReverseResolver {
        subnet: IpSubnet,
    },
    SetReverseResolvers {
        resolvers: Vec<DnsReverseResolver>,
    },
    DhcpV4PoolUpdated(Box<DhcpV4PoolUpdate>),
    DhcpV6PoolUpdated(Box<DhcpV6PoolUpdate>),
    PppoeStatusUpdated {
        status: Option<Box<crate::system::PppoeStatusResponse>>,
    },
    RaStatusUpdated {
        status: Option<Box<crate::system::RaStatusResponse>>,
    },
    TrafficStatusUpdated {
        status: Option<Box<crate::system::TrafficStatusResponse>>,
    },
}

