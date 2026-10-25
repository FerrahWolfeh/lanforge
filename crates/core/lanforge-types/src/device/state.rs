use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::network::Ipv6AddrOrSuffix;
use crate::utils::serde::{deserialize_time, serialize_time};

/// Converts a [`SystemTime`] to seconds since Unix Epoch, clamped to `u32::MAX`.
#[inline]
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn system_time_to_epoch_u32(t: SystemTime) -> u32 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().min(u64::from(u32::MAX)) as u32)
}

/// Converts seconds since Unix Epoch to a [`SystemTime`].
#[inline]
#[must_use]
pub fn epoch_u32_to_system_time(secs: u32) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(secs))
}

/// Nature of an IPv4 lease or reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum LeaseKind {
    /// Dynamically assigned via `DHCPv4`.
    Dynamic = 0,
    /// Static reservation pinned to MAC address.
    Static = 1,
    /// Discovered via ARP or network traffic snooping.
    Discovery = 2,
}

/// Canonical, cache-line friendly IPv4 lease structure.
///
/// **Layout:** Exactly 16 bytes (`#[repr(C)]`), aligned to 4 bytes.
/// Four `V4Lease` instances fit into a single 64-byte L1d cache line.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct V4Lease {
    pub ip: Ipv4Addr,
    pub kind: LeaseKind,
    pub flags: u8,
    pub reserved: u16,
    pub expires: u32,
    pub last_seen: u32,
}

const _: () = assert!(std::mem::size_of::<V4Lease>() == 16);
const _: () = assert!(std::mem::align_of::<V4Lease>() == 4);

impl V4Lease {
    #[must_use]
    pub fn dynamic(ip: Ipv4Addr, expires: SystemTime, last_seen: SystemTime) -> Self {
        Self {
            ip,
            kind: LeaseKind::Dynamic,
            flags: 0,
            reserved: 0,
            expires: system_time_to_epoch_u32(expires),
            last_seen: system_time_to_epoch_u32(last_seen),
        }
    }

    #[must_use]
    pub fn static_reservation(ip: Ipv4Addr, last_seen: SystemTime) -> Self {
        Self {
            ip,
            kind: LeaseKind::Static,
            flags: 0,
            reserved: 0,
            expires: u32::MAX,
            last_seen: system_time_to_epoch_u32(last_seen),
        }
    }

    #[must_use]
    pub fn discovery(ip: Ipv4Addr, last_seen: SystemTime) -> Self {
        Self {
            ip,
            kind: LeaseKind::Discovery,
            flags: 0,
            reserved: 0,
            expires: 0,
            last_seen: system_time_to_epoch_u32(last_seen),
        }
    }

    #[must_use]
    pub const fn is_dynamic(&self) -> bool {
        matches!(self.kind, LeaseKind::Dynamic)
    }

    #[must_use]
    pub const fn is_static(&self) -> bool {
        matches!(self.kind, LeaseKind::Static)
    }

    #[must_use]
    pub const fn is_discovery(&self) -> bool {
        matches!(self.kind, LeaseKind::Discovery)
    }

    #[must_use]
    pub const fn is_expired(&self, now_epoch: u32) -> bool {
        self.is_dynamic() && now_epoch >= self.expires
    }

    #[must_use]
    pub fn expires_system_time(&self) -> SystemTime {
        epoch_u32_to_system_time(self.expires)
    }

    #[must_use]
    pub fn last_seen_system_time(&self) -> SystemTime {
        epoch_u32_to_system_time(self.last_seen)
    }
}

/// Nature of an IPv6 lease, address, or observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum V6Kind {
    /// Dynamically assigned via `DHCPv6` (`IA_NA`).
    Dynamic = 0,
    /// Auto-configured address observed via SLAAC.
    Slaac = 1,
    /// Static IPv6 reservation or suffix match.
    Static = 2,
    /// Link-local IPv6 address (`fe80::/10`).
    LinkLocal = 3,
    /// Discovered via NDP or passive packet observation.
    Discovery = 4,
}

/// Canonical, cache-line friendly IPv6 lease structure.
///
/// **Layout:** Exactly 32 bytes (`#[repr(C)]`), aligned to 4 bytes.
/// Two `V6Lease` instances fit into a single 64-byte L1d cache line.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct V6Lease {
    pub ip: Ipv6Addr,
    pub iaid: u32,
    pub expires: u32,
    pub last_seen: u32,
    pub kind: V6Kind,
    pub flags: u8,
    pub reserved: u16,
}

const _: () = assert!(std::mem::size_of::<V6Lease>() == 32);
const _: () = assert!(std::mem::align_of::<V6Lease>() == 4);

impl V6Lease {
    #[must_use]
    pub fn dynamic(ip: Ipv6Addr, iaid: u32, expires: SystemTime, last_seen: SystemTime) -> Self {
        Self {
            ip,
            iaid,
            expires: system_time_to_epoch_u32(expires),
            last_seen: system_time_to_epoch_u32(last_seen),
            kind: V6Kind::Dynamic,
            flags: 0,
            reserved: 0,
        }
    }

    #[must_use]
    pub fn static_reservation(ip: Ipv6Addr, last_seen: SystemTime) -> Self {
        Self {
            ip,
            iaid: 0,
            expires: u32::MAX,
            last_seen: system_time_to_epoch_u32(last_seen),
            kind: V6Kind::Static,
            flags: 0,
            reserved: 0,
        }
    }

    #[must_use]
    pub fn link_local(ip: Ipv6Addr, last_seen: SystemTime) -> Self {
        Self {
            ip,
            iaid: 0,
            expires: u32::MAX,
            last_seen: system_time_to_epoch_u32(last_seen),
            kind: V6Kind::LinkLocal,
            flags: 0,
            reserved: 0,
        }
    }

    #[must_use]
    pub fn discovery(ip: Ipv6Addr, last_seen: SystemTime) -> Self {
        Self {
            ip,
            iaid: 0,
            expires: 0,
            last_seen: system_time_to_epoch_u32(last_seen),
            kind: V6Kind::Discovery,
            flags: 0,
            reserved: 0,
        }
    }

    #[must_use]
    pub const fn is_dynamic(&self) -> bool {
        matches!(self.kind, V6Kind::Dynamic)
    }

    #[must_use]
    pub const fn is_slaac(&self) -> bool {
        matches!(self.kind, V6Kind::Slaac)
    }

    #[must_use]
    pub const fn is_static(&self) -> bool {
        matches!(self.kind, V6Kind::Static)
    }

    #[must_use]
    pub const fn is_discovery(&self) -> bool {
        matches!(self.kind, V6Kind::Discovery)
    }

    #[must_use]
    pub const fn is_link_local(&self) -> bool {
        matches!(self.kind, V6Kind::LinkLocal) || (self.ip.segments()[0] & 0xffc0 == 0xfe80)
    }

    #[must_use]
    pub const fn is_expired(&self, now_epoch: u32) -> bool {
        self.is_dynamic() && now_epoch >= self.expires
    }

    #[must_use]
    pub fn expires_system_time(&self) -> SystemTime {
        epoch_u32_to_system_time(self.expires)
    }

    #[must_use]
    pub fn last_seen_system_time(&self) -> SystemTime {
        epoch_u32_to_system_time(self.last_seen)
    }
}

/// Canonical, cache-line friendly IPv6 prefix delegation lease structure.
///
/// **Layout:** Exactly 32 bytes (`#[repr(C)]`), aligned to 4 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct V6PrefixLease {
    pub prefix: Ipv6Addr,
    pub iaid: u32,
    pub expires: u32,
    pub len: u8,
    pub reserved: [u8; 7],
}

const _: () = assert!(std::mem::size_of::<V6PrefixLease>() == 32);
const _: () = assert!(std::mem::align_of::<V6PrefixLease>() == 4);

impl V6PrefixLease {
    #[must_use]
    pub fn new(prefix: Ipv6Addr, len: u8, iaid: u32, expires: SystemTime) -> Self {
        Self {
            prefix,
            iaid,
            expires: system_time_to_epoch_u32(expires),
            len,
            reserved: [0; 7],
        }
    }

    #[must_use]
    pub fn expires_system_time(&self) -> SystemTime {
        epoch_u32_to_system_time(self.expires)
    }

    #[must_use]
    pub const fn is_expired(&self, now_epoch: u32) -> bool {
        now_epoch >= self.expires
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V6ObservationOrigin {
    SlaacTracker,
    NdpMonitor,
}

// ---------------------------------------------------------------------------
// Transition adapters / compatibility models
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum IPv4State {
    Static(Ipv4Addr),
    Dynamic(Box<V4Lease>),
    Discovery(
        Ipv4Addr,
        #[serde(
            serialize_with = "serialize_time",
            deserialize_with = "deserialize_time"
        )]
        SystemTime,
    ),
    #[default]
    None,
}

impl IPv4State {
    #[must_use]
    pub fn ip(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Static(ip) | Self::Discovery(ip, _) => Some(*ip),
            Self::Dynamic(lease) => Some(lease.ip),
            Self::None => None,
        }
    }

    #[must_use]
    pub const fn is_dynamic(&self) -> bool {
        matches!(self, Self::Dynamic(_))
    }
}

impl From<V4Lease> for IPv4State {
    fn from(lease: V4Lease) -> Self {
        match lease.kind {
            LeaseKind::Static => Self::Static(lease.ip),
            LeaseKind::Dynamic => Self::Dynamic(Box::new(lease)),
            LeaseKind::Discovery => Self::Discovery(lease.ip, lease.last_seen_system_time()),
        }
    }
}

impl From<Option<V4Lease>> for IPv4State {
    fn from(opt: Option<V4Lease>) -> Self {
        opt.map_or(Self::None, Into::into)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IPv6State {
    Static(Ipv6AddrOrSuffix, SystemTime),
    Dynamic(Box<V6Lease>),
    Slaac(Ipv6Addr, SystemTime),
    LinkLocal(Ipv6Addr, SystemTime),
    Discovery(Ipv6Addr, SystemTime),
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
            Self::Static(Ipv6AddrOrSuffix::Suffix(suffix), _) => prefix.map(|p| suffix.resolve(p)),
        }
    }

    #[must_use]
    pub fn ip(&self) -> Option<Ipv6Addr> {
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

impl From<V6Lease> for IPv6State {
    fn from(lease: V6Lease) -> Self {
        match lease.kind {
            V6Kind::Dynamic => Self::Dynamic(Box::new(lease)),
            V6Kind::Slaac => Self::Slaac(lease.ip, lease.last_seen_system_time()),
            V6Kind::Static => Self::Static(
                Ipv6AddrOrSuffix::Full(lease.ip),
                lease.last_seen_system_time(),
            ),
            V6Kind::LinkLocal => Self::LinkLocal(lease.ip, lease.last_seen_system_time()),
            V6Kind::Discovery => Self::Discovery(lease.ip, lease.last_seen_system_time()),
        }
    }
}
