use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;
use crate::network::Ipv6AddrOrSuffix;
use crate::utils::serde::{deserialize_time, serialize_time};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V4Lease {
    pub ip: Ipv4Addr,
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub expires: SystemTime,
    #[serde(
        default = "SystemTime::now",
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub last_seen: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V6Lease {
    pub ip: Ipv6Addr,
    pub iaid: u32,
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub expires: SystemTime,
    pub last_seen: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V6PrefixLease {
    pub prefix: Ipv6Addr,
    pub len: u8,
    pub iaid: u32,
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub expires: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IPv4State {
    Static(Ipv4Addr),
    Dynamic(V4Lease),
    None,
}

impl IPv4State {
    #[must_use]
    pub const fn ip(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Static(ip) => Some(*ip),
            Self::Dynamic(lease) => Some(lease.ip),
            Self::None => None,
        }
    }

    #[must_use]
    pub const fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic(_))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IPv6State {
    Static(Ipv6AddrOrSuffix, SystemTime),
    Dynamic(V6Lease),
    Slaac(Ipv6Addr, SystemTime),
    LinkLocal(Ipv6Addr, SystemTime),
    Discovery(Ipv6Addr, SystemTime),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V6ObservationOrigin {
    SlaacTracker,
    NdpMonitor,
}

impl IPv6State {
    #[must_use]
    pub fn ip_with_prefix(&self, prefix: Option<Ipv6Addr>) -> Option<Ipv6Addr> {
        match self {
            Self::Dynamic(lease) => Some(lease.ip),
            Self::Static(Ipv6AddrOrSuffix::Full(ip), _)
            | Self::Slaac(ip, _)
            | Self::LinkLocal(ip, _)
            | Self::Discovery(ip, _) => Some(*ip),
            Self::Static(suf, _) => prefix.map(|p| Ipv6Addr::from(suf.as_u128(Some(p)))),
        }
    }

    #[must_use]
    pub const fn ip(&self) -> Option<Ipv6Addr> {
        match self {
            Self::Dynamic(lease) => Some(lease.ip),
            Self::Static(Ipv6AddrOrSuffix::Full(ip), _)
            | Self::Slaac(ip, _)
            | Self::LinkLocal(ip, _)
            | Self::Discovery(ip, _) => Some(*ip),
            Self::Static(_suf, _) => None,
        }
    }

    #[must_use]
    pub const fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic(_))
    }

    #[must_use]
    pub fn is_link_local(&self) -> bool {
        self.ip()
            .is_some_and(|ip| ip.segments()[0] & 0xffc0 == 0xfe80)
    }
}
