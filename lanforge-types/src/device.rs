//! Network device data structures.

use lanforge_macros::EnumRepr;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::events::DeviceChange;
use crate::identifiers::{Duid, MacAddr};
use crate::updates::LeaseTarget;
use smallvec::SmallVec;

// ---------------------------------------------------------------------------
// Helpers for Serde
// ---------------------------------------------------------------------------

pub fn serialize_time_opt<S>(time: &Option<SystemTime>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match time {
        Some(t) => {
            let elapsed = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
            serializer.serialize_u64(elapsed.as_secs())
        }
        None => serializer.serialize_none(),
    }
}

pub fn serialize_time<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let elapsed = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    serializer.serialize_u64(elapsed.as_secs())
}

pub fn serialize_seen_v4<S>(
    seen: &[(Ipv4Addr, SystemTime)],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(seen.len()))?;
    for (ip, time) in seen {
        let elapsed = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        seq.serialize_element(&(*ip, elapsed.as_secs()))?;
    }
    seq.end()
}

pub fn deserialize_time<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
where
    D: Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    Ok(UNIX_EPOCH + Duration::from_secs(secs))
}

pub fn deserialize_time_opt<'de, D>(deserializer: D) -> Result<Option<SystemTime>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt_secs = Option::<u64>::deserialize(deserializer)?;
    Ok(opt_secs.map(|secs| UNIX_EPOCH + Duration::from_secs(secs)))
}

pub fn deserialize_seen_v4<'de, D>(
    deserializer: D,
) -> Result<SmallVec<[(Ipv4Addr, SystemTime); 4]>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::Deserialize;
    let raw = Vec::<(Ipv4Addr, u64)>::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .map(|(ip, secs)| (ip, SystemTime::UNIX_EPOCH + Duration::from_secs(secs)))
        .collect())
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, EnumRepr,
)]
pub enum Origin {
    #[enum_repr(alias = "static")]
    Toml,
    #[enum_repr(alias = "managed_cli")]
    Cli,
    #[enum_repr(alias = "api")]
    External,
    #[default]
    Dynamic,
}

impl Origin {
    #[must_use]
    pub const fn is_static(&self) -> bool {
        !matches!(self, Self::Dynamic)
    }

    #[must_use]
    pub const fn symbol(&self) -> &'static str {
        match self {
            Self::Toml => "★",
            Self::Cli => "·",
            Self::External => "ⓔ",
            Self::Dynamic => "–",
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Default,
    Hash,
    EnumRepr,
)]
#[repr(u8)]
pub enum DeviceClass {
    #[default]
    None = 0,
    #[enum_repr(alias = "pc")]
    #[enum_repr(alias = "server")]
    Computer = 1,
    #[enum_repr(alias = "phone")]
    #[enum_repr(alias = "tablet")]
    Mobile = 2,
    #[enum_repr(alias = "scanner")]
    Printer = 3,
    #[enum_repr(alias = "tv")]
    #[enum_repr(alias = "audio")]
    #[enum_repr(alias = "speaker")]
    Media = 4,
    #[enum_repr(alias = "smarthome")]
    #[enum_repr(alias = "sensor")]
    IoT = 5,
    #[enum_repr(alias = "switch")]
    #[enum_repr(alias = "router")]
    #[enum_repr(alias = "ap")]
    Network = 6,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default, EnumRepr,
)]
pub enum HostnameOrigin {
    #[default]
    None = 0,
    Mdns = 1,
    Dhcp = 2,
    Static = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Hostname {
    pub name: String,
    pub origin: HostnameOrigin,
}

impl Hostname {
    #[must_use]
    pub fn display(&self) -> &str {
        if self.name.is_empty() {
            "?"
        } else {
            &self.name
        }
    }
}

impl From<String> for Hostname {
    fn from(name: String) -> Self {
        Self {
            name,
            origin: HostnameOrigin::Static,
        }
    }
}

impl From<&str> for Hostname {
    fn from(name: &str) -> Self {
        Self {
            name: name.to_string(),
            origin: HostnameOrigin::Static,
        }
    }
}

impl From<Hostname> for String {
    fn from(val: Hostname) -> Self {
        val.name
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(try_from = "String", into = "String")]
pub enum Ipv6AddrOrSuffix {
    Full(Ipv6Addr),
    Suffix([u8; 8]),
}

impl Ipv6AddrOrSuffix {
    #[must_use]
    pub fn matches(&self, addr: Ipv6Addr) -> bool {
        match self {
            Self::Full(ip) => *ip == addr,
            Self::Suffix(suffix) => {
                let segs = addr.segments();
                let mut addr_suffix = [0u8; 8];
                addr_suffix[0..2].copy_from_slice(&segs[4].to_be_bytes());
                addr_suffix[2..4].copy_from_slice(&segs[5].to_be_bytes());
                addr_suffix[4..6].copy_from_slice(&segs[6].to_be_bytes());
                addr_suffix[6..8].copy_from_slice(&segs[7].to_be_bytes());
                &addr_suffix == suffix
            }
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        if s.is_empty() {
            return None;
        }
        if let Ok(ip) = s.parse::<Ipv6Addr>() {
            let segs = ip.segments();
            if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 {
                let mut bytes = [0u8; 8];
                bytes[0..2].copy_from_slice(&segs[4].to_be_bytes());
                bytes[2..4].copy_from_slice(&segs[5].to_be_bytes());
                bytes[4..6].copy_from_slice(&segs[6].to_be_bytes());
                bytes[6..8].copy_from_slice(&segs[7].to_be_bytes());
                return Some(Self::Suffix(bytes));
            }
            return Some(Self::Full(ip));
        }

        if s.split(':').count() > 4 {
            return None;
        }

        let full_s = format!("::{s}");
        full_s.parse::<Ipv6Addr>().map_or(None, |ip| {
            let segs = ip.segments();
            let mut bytes = [0u8; 8];
            bytes[0..2].copy_from_slice(&segs[4].to_be_bytes());
            bytes[2..4].copy_from_slice(&segs[5].to_be_bytes());
            bytes[4..6].copy_from_slice(&segs[6].to_be_bytes());
            bytes[6..8].copy_from_slice(&segs[7].to_be_bytes());
            Some(Self::Suffix(bytes))
        })
    }

    #[must_use]
    pub fn as_u128(&self, prefix: Option<Ipv6Addr>) -> u128 {
        match self {
            Self::Full(ip) => u128::from_be_bytes(ip.octets()),
            Self::Suffix(s) => {
                let mut bytes = [0u8; 16];
                if let Some(p) = prefix {
                    bytes.copy_from_slice(&p.octets());
                }
                bytes[8..16].copy_from_slice(s);
                u128::from_be_bytes(bytes)
            }
        }
    }
}

impl fmt::Display for Ipv6AddrOrSuffix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full(ip) => ip.fmt(f),
            Self::Suffix(s) => {
                let ip = Ipv6Addr::new(
                    0,
                    0,
                    0,
                    0,
                    u16::from_be_bytes([s[0], s[1]]),
                    u16::from_be_bytes([s[2], s[3]]),
                    u16::from_be_bytes([s[4], s[5]]),
                    u16::from_be_bytes([s[6], s[7]]),
                );
                ip.fmt(f)
            }
        }
    }
}

impl TryFrom<String> for Ipv6AddrOrSuffix {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s).ok_or_else(|| format!("Invalid IPv6 address or suffix: {s}"))
    }
}

impl From<Ipv6AddrOrSuffix> for String {
    fn from(val: Ipv6AddrOrSuffix) -> Self {
        val.to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IpClassification {
    Ula = 0,
    Ipv4 = 1,
    Gua = 2,
    LinkLocal = 3,
    Loopback = 4,
    Other = 10,
}

impl IpClassification {
    #[must_use]
    pub const fn score(&self) -> u8 {
        *self as u8
    }
}

#[must_use]
pub const fn classify_ip(addr: &IpAddr) -> IpClassification {
    match addr {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                IpClassification::Loopback
            } else {
                IpClassification::Ipv4
            }
        }
        IpAddr::V6(v6) => classify_ipv6(v6),
    }
}

#[must_use]
pub const fn classify_ipv6(v6: &Ipv6Addr) -> IpClassification {
    if v6.is_loopback() {
        IpClassification::Loopback
    } else if is_ula(v6) {
        IpClassification::Ula
    } else if (v6.segments()[0] & 0xe000) == 0x2000 {
        IpClassification::Gua
    } else if (v6.segments()[0] & 0xffc0) == 0xfe80 {
        IpClassification::LinkLocal
    } else {
        IpClassification::Other
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv6Prefix {
    pub segments: [u16; 4],
    pub group: IpClassification,
}

impl Ipv6Prefix {
    #[must_use]
    pub const fn from_addr(addr: Ipv6Addr) -> Self {
        let segs = addr.segments();
        Self {
            segments: [segs[0], segs[1], segs[2], segs[3]],
            group: classify_ipv6(&addr),
        }
    }

    #[must_use]
    pub const fn new(addr: Ipv6Addr, group: IpClassification) -> Self {
        let segs = addr.segments();
        Self {
            segments: [segs[0], segs[1], segs[2], segs[3]],
            group,
        }
    }

    #[must_use]
    pub const fn to_addr(&self) -> Ipv6Addr {
        Ipv6Addr::new(
            self.segments[0],
            self.segments[1],
            self.segments[2],
            self.segments[3],
            0,
            0,
            0,
            0,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub mac: MacAddr,
    pub hostname: Hostname,
    pub origin: Origin,
    #[serde(
        serialize_with = "serialize_time_opt",
        deserialize_with = "deserialize_time_opt"
    )]
    pub managed_at: Option<SystemTime>,
    pub v4: IPv4State,
    pub v6: SmallVec<[IPv6State; 4]>,
    pub v6_prefixes: SmallVec<[V6PrefixLease; 2]>,
    #[serde(
        serialize_with = "serialize_seen_v4",
        deserialize_with = "deserialize_seen_v4"
    )]
    pub seen_v4: SmallVec<[(Ipv4Addr, SystemTime); 4]>,
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub last_seen: SystemTime,
    pub duid: Option<Duid>,
    pub dns_fallback: String,
    pub class: DeviceClass,
    pub topology: Option<TopologyInfo>,
    pub boot_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopologyInfo {
    pub parent_mac: Option<MacAddr>,
    pub port: Option<String>,
    pub local_ifindex: u32,
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub last_updated: SystemTime,
}

impl Device {
    pub const ONLINE_THRESHOLD: Duration = Duration::from_secs(300);
    pub const ACTIVITY_DEBOUNCE: Duration = Duration::from_secs(60);

    #[must_use]
    pub fn new(mac: MacAddr) -> Self {
        Self {
            mac,
            hostname: Hostname::default(),
            origin: Origin::Dynamic,
            managed_at: None,
            v4: IPv4State::None,
            v6: SmallVec::new(),
            v6_prefixes: SmallVec::new(),
            seen_v4: SmallVec::new(),
            last_seen: SystemTime::UNIX_EPOCH,
            duid: None,
            dns_fallback: format!("host-{}", mac.to_string().replace(':', "")).to_ascii_lowercase(),
            class: DeviceClass::None,
            topology: None,
            boot_file: None,
        }
    }

    pub fn associate_duid(&mut self, duid: Duid, _iaid: u32) -> Option<DeviceChange> {
        if self.duid.as_ref() != Some(&duid) {
            let change = DeviceChange::DuidAssociated { duid: duid.clone() };
            self.duid = Some(duid);
            self.last_seen = SystemTime::now();
            return Some(change);
        }
        None
    }

    pub fn apply_v4_lease(&mut self, ip: Ipv4Addr, expires: SystemTime) -> Option<DeviceChange> {
        let now = SystemTime::now();
        let mut changed = false;

        match &mut self.v4 {
            IPv4State::Dynamic(lease) if lease.ip == ip && lease.expires == expires => {
                if now.duration_since(lease.last_seen).unwrap_or(Duration::MAX)
                    > Self::ACTIVITY_DEBOUNCE
                {
                    lease.last_seen = now;
                    self.last_seen = self.calculate_last_seen();
                }
            }
            _ => {
                self.v4 = IPv4State::Dynamic(V4Lease {
                    ip,
                    expires,
                    last_seen: now,
                });
                self.last_seen = self.calculate_last_seen();
                changed = true;
            }
        }

        if changed {
            Some(DeviceChange::V4Assigned { ip })
        } else {
            None
        }
    }

    pub fn apply_v6_lease(
        &mut self,
        duid: &Duid,
        iaid: u32,
        ip: Ipv6Addr,
        expires: SystemTime,
    ) -> Option<DeviceChange> {
        let mut changed = if self.duid.as_ref() == Some(duid) {
            false
        } else {
            self.duid = Some(duid.clone());
            true
        };

        let now = SystemTime::now();
        let new_lease = V6Lease {
            ip,
            iaid,
            expires,
            last_seen: now,
        };
        let existing = self
            .v6
            .iter_mut()
            .find(|s| matches!(s, IPv6State::Dynamic(l) if l.iaid == iaid));

        if let Some(IPv6State::Dynamic(lease)) = existing {
            if lease != &new_lease {
                *lease = new_lease;
                changed = true;
            }
        } else {
            if !self
                .v6
                .iter()
                .any(|s| matches!(s, IPv6State::Dynamic(l) if l.ip == ip && l.iaid == iaid))
            {
                self.v6.push(IPv6State::Dynamic(new_lease));
                changed = true;
            }
        }

        if changed {
            self.last_seen = SystemTime::now();
            return Some(DeviceChange::V6Assigned { ip, iaid });
        }
        None
    }

    pub fn apply_v6_prefix(
        &mut self,
        duid: &Duid,
        iaid: u32,
        prefix: Ipv6Addr,
        len: u8,
        expires: SystemTime,
    ) -> Option<DeviceChange> {
        let mut changed = if self.duid.as_ref() == Some(duid) {
            false
        } else {
            self.duid = Some(duid.clone());
            true
        };

        let new_lease = V6PrefixLease {
            prefix,
            len,
            iaid,
            expires,
        };
        let existing = self.v6_prefixes.iter_mut().find(|l| l.iaid == iaid);

        if let Some(lease) = existing {
            if lease != &new_lease {
                *lease = new_lease;
                changed = true;
            }
        } else {
            if !self
                .v6_prefixes
                .iter()
                .any(|l| l.prefix == prefix && l.iaid == iaid)
            {
                self.v6_prefixes.push(new_lease);
                changed = true;
            }
        }

        if changed {
            self.last_seen = SystemTime::now();
            return Some(DeviceChange::V6PrefixAssigned { prefix, len, iaid });
        }
        None
    }

    pub fn apply_v6_observation(
        &mut self,
        addr: Ipv6Addr,
        is_active: bool,
        origin: V6ObservationOrigin,
    ) -> Option<DeviceChange> {
        let mut changed = false;
        let now = SystemTime::now();
        let timestamp = if is_active {
            now
        } else {
            SystemTime::UNIX_EPOCH
        };

        let classification = classify_ipv6(&addr);
        let target_state = match classification {
            IpClassification::LinkLocal => IPv6State::LinkLocal(addr, timestamp),
            _ => match origin {
                V6ObservationOrigin::SlaacTracker => IPv6State::Slaac(addr, timestamp),
                V6ObservationOrigin::NdpMonitor => IPv6State::Discovery(addr, timestamp),
            },
        };

        let existing_index = self.v6.iter().position(|s| match s {
            IPv6State::Static(s, _) => s.matches(addr),
            _ => s.ip() == Some(addr),
        });

        if let Some(idx) = existing_index {
            let state = &mut self.v6[idx];

            if matches!(state, IPv6State::Discovery(..))
                && matches!(target_state, IPv6State::Slaac(..))
            {
                *state = target_state;
                changed = true;
            } else {
                match state {
                    IPv6State::Static(_, ts)
                    | IPv6State::Slaac(_, ts)
                    | IPv6State::Discovery(_, ts)
                    | IPv6State::LinkLocal(_, ts) => {
                        let elapsed = now.duration_since(*ts).unwrap_or(Duration::MAX);
                        let was_active = elapsed < Self::ONLINE_THRESHOLD;

                        if is_active != was_active || elapsed > Self::ACTIVITY_DEBOUNCE {
                            *ts = timestamp;
                            changed = true;
                        }
                    }
                    IPv6State::Dynamic(lease) => {
                        let elapsed = now.duration_since(lease.last_seen).unwrap_or(Duration::MAX);
                        let was_active = elapsed < Self::ONLINE_THRESHOLD;

                        if is_active != was_active || elapsed > Self::ACTIVITY_DEBOUNCE {
                            lease.last_seen = timestamp;
                            changed = true;
                        }
                    }
                }
            }
        } else {
            self.v6.push(target_state.clone());
            self.last_seen = self.calculate_last_seen();

            return match target_state {
                IPv6State::Slaac(..) => Some(DeviceChange::SlaacObserved { addr }),
                _ => Some(DeviceChange::NdpActivity { ip: addr }),
            };
        }

        if changed {
            self.last_seen = self.calculate_last_seen();
            Some(DeviceChange::NdpActivity { ip: addr })
        } else {
            None
        }
    }

    pub fn apply_arp_observation(&mut self, ip: Ipv4Addr, is_active: bool) -> Option<DeviceChange> {
        let now = SystemTime::now();
        let mut changed = false;

        if let Some(entry) = self.seen_v4.iter_mut().find(|(a, _)| *a == ip) {
            let elapsed = now.duration_since(entry.1).unwrap_or(Duration::MAX);
            let was_active = elapsed < Self::ONLINE_THRESHOLD;

            if is_active != was_active || elapsed > Self::ACTIVITY_DEBOUNCE {
                entry.1 = if is_active {
                    now
                } else {
                    SystemTime::UNIX_EPOCH
                };
                changed = true;
            }
        } else {
            self.seen_v4.push((
                ip,
                if is_active {
                    now
                } else {
                    SystemTime::UNIX_EPOCH
                },
            ));
            changed = true;
        }

        if changed {
            self.last_seen = self.calculate_last_seen();
            return Some(DeviceChange::ArpActivity { ip });
        }
        None
    }

    pub fn apply_hostname_hint(
        &mut self,
        hostname: String,
        origin: HostnameOrigin,
    ) -> Option<DeviceChange> {
        if origin >= self.hostname.origin && self.hostname.name != hostname {
            self.hostname = Hostname {
                name: hostname,
                origin,
            };
            return Some(DeviceChange::HostnameChanged {
                hostname: self.hostname.name.clone(),
            });
        }
        None
    }

    #[must_use]
    pub fn calculate_last_seen(&self) -> SystemTime {
        let mut latest = SystemTime::UNIX_EPOCH;
        if let IPv4State::Dynamic(l) = &self.v4 {
            latest = latest.max(l.last_seen);
        }
        for (_, ts) in &self.seen_v4 {
            latest = latest.max(*ts);
        }
        for s in &self.v6 {
            match s {
                IPv6State::Dynamic(l) => {
                    latest = latest.max(l.last_seen);
                }
                IPv6State::Slaac(_, ts)
                | IPv6State::Static(_, ts)
                | IPv6State::LinkLocal(_, ts)
                | IPv6State::Discovery(_, ts) => {
                    latest = latest.max(*ts);
                }
            }
        }
        latest
    }

    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.origin.is_static()
    }

    #[must_use]
    pub fn is_worthy(&self) -> bool {
        if self.topology.is_some() {
            return true;
        }
        if !self.hostname.name.is_empty() {
            return true;
        }
        if !matches!(self.v4, IPv4State::None) || !self.seen_v4.is_empty() {
            return true;
        }
        if self.v6.iter().any(|s| !s.is_link_local()) {
            return true;
        }
        if !matches!(self.origin, Origin::Dynamic) || self.managed_at.is_some() {
            return true;
        }
        if self.duid.is_some() {
            return true;
        }
        false
    }

    #[must_use]
    pub fn is_online(&self) -> bool {
        if matches!(self.v4, IPv4State::Dynamic(_)) || self.v6.iter().any(IPv6State::is_dynamic) {
            return true;
        }
        SystemTime::now()
            .duration_since(self.last_seen)
            .unwrap_or(Duration::MAX)
            < Self::ONLINE_THRESHOLD
    }

    pub fn expire_stale_inner(
        &mut self,
        now: SystemTime,
        ip_expiry_threshold: Duration,
    ) -> Vec<DeviceChange> {
        let mut events = Vec::new();

        // V4
        if let IPv4State::Dynamic(lease) = &self.v4
            && lease.expires < now
        {
            events.push(DeviceChange::LeaseExpired {
                target: LeaseTarget::V4,
            });
            self.v4 = IPv4State::None;
        }

        // V6
        let mut v6_expired_iaids = Vec::new();
        self.v6.retain(|state| match state {
            IPv6State::Dynamic(lease) if lease.expires < now => {
                v6_expired_iaids.push(lease.iaid);
                false
            }
            IPv6State::Slaac(_, ts) | IPv6State::LinkLocal(_, ts) | IPv6State::Discovery(_, ts) => {
                now.duration_since(*ts).unwrap_or(Duration::MAX) <= ip_expiry_threshold
            }
            _ => true,
        });
        for iaid in v6_expired_iaids {
            events.push(DeviceChange::LeaseExpired {
                target: LeaseTarget::V6 { iaid },
            });
        }

        // Prefixes
        let mut prefix_expired_iaids = Vec::new();
        self.v6_prefixes.retain(|p| {
            if p.expires < now {
                prefix_expired_iaids.push(p.iaid);
                false
            } else {
                true
            }
        });
        for iaid in prefix_expired_iaids {
            events.push(DeviceChange::LeaseExpired {
                target: LeaseTarget::V6Prefix { iaid },
            });
        }

        // ARP cleanup
        self.seen_v4.retain(|(_, ts)| {
            now.duration_since(*ts).unwrap_or(Duration::ZERO) <= ip_expiry_threshold
        });

        self.last_seen = self.calculate_last_seen();
        events
    }

    #[must_use]
    pub fn is_zombie(&self, max_age: Duration) -> bool {
        if !matches!(self.v4, IPv4State::None)
            || !self.v6.is_empty()
            || !self.v6_prefixes.is_empty()
        {
            return false;
        }

        self.last_seen.elapsed().unwrap_or(Duration::ZERO) > max_age
    }
}

impl Device {
    #[must_use]
    pub fn display_hostname(&self) -> &str {
        self.hostname.display()
    }

    #[must_use]
    pub fn display_v4(&self) -> String {
        match &self.v4 {
            IPv4State::Static(ip) => ip.to_string(),
            IPv4State::Dynamic(lease) => lease.ip.to_string(),
            IPv4State::None => self
                .seen_v4
                .first()
                .map_or_else(|| "—".to_string(), |(seen, _)| format!("{seen} ?")),
        }
    }

    #[must_use]
    pub fn primary_v6(
        &self,
        gua_prefix: Option<Ipv6Addr>,
        ula_prefix: Option<Ipv6Addr>,
    ) -> Option<Ipv6Addr> {
        let mut best: Option<(u8, Ipv6Addr)> = None;
        let mut update_best = |prio: u8, addr: Ipv6Addr| {
            if best.as_ref().is_none_or(|(b_prio, _)| prio < *b_prio) {
                best = Some((prio, addr));
            }
        };

        for state in &self.v6 {
            if let IPv6State::Slaac(ip, _) = state {
                if is_ula(ip) {
                    update_best(3, *ip);
                } else if matches!(classify_ipv6(ip), IpClassification::Gua) {
                    update_best(4, *ip);
                }
            } else {
                if let Some(ip) = state.ip_with_prefix(ula_prefix)
                    && is_ula(&ip)
                {
                    update_best(1, ip);
                }
                if let Some(ip) = state.ip_with_prefix(gua_prefix)
                    && matches!(classify_ipv6(&ip), IpClassification::Gua)
                {
                    update_best(2, ip);
                }
            }
        }
        best.map(|(_, addr)| addr)
    }

    #[must_use]
    pub fn all_addresses_sorted(
        &self,
        gua_prefix: Option<Ipv6Addr>,
        ula_prefix: Option<Ipv6Addr>,
    ) -> SmallVec<[IpAddr; 32]> {
        let mut addrs: SmallVec<[IpAddr; 32]> = SmallVec::new();
        let mut push_unique = |ip: IpAddr| {
            if !addrs.contains(&ip) {
                addrs.push(ip);
            }
        };

        if let Some(ip) = self.v4.ip() {
            push_unique(IpAddr::V4(ip));
        }
        for (ip, _) in &self.seen_v4 {
            push_unique(IpAddr::V4(*ip));
        }

        for state in &self.v6 {
            if let IPv6State::Static(Ipv6AddrOrSuffix::Suffix(_), _) = state {
                for prefix in [ula_prefix, gua_prefix].into_iter().flatten() {
                    if let Some(ip) = state.ip_with_prefix(Some(prefix)) {
                        push_unique(IpAddr::V6(ip));
                    }
                }
            } else if let Some(ip) = state.ip() {
                push_unique(IpAddr::V6(ip));
            }
        }
        addrs.sort_by_key(|ip| classify_ip(ip).score());
        addrs
    }

    pub fn delete_ip(&mut self, ip: IpAddr) -> bool {
        let mut changed = false;
        match ip {
            IpAddr::V4(ip4) => {
                if let IPv4State::Static(s) = &self.v4
                    && *s == ip4
                {
                    self.v4 = IPv4State::None;
                    changed = true;
                } else if let IPv4State::Dynamic(lease) = &self.v4
                    && lease.ip == ip4
                {
                    self.v4 = IPv4State::None;
                    changed = true;
                }
                let initial_len = self.seen_v4.len();
                self.seen_v4.retain(|(a, _)| *a != ip4);
                if self.seen_v4.len() != initial_len {
                    changed = true;
                }
            }
            IpAddr::V6(ip6) => {
                let initial_v6_len = self.v6.len();
                self.v6.retain(|s| s.ip() != Some(ip6));

                let initial_prefix_len = self.v6_prefixes.len();
                self.v6_prefixes.retain(|p| p.prefix != ip6);

                if initial_v6_len != self.v6.len() || initial_prefix_len != self.v6_prefixes.len() {
                    changed = true;
                }
            }
        }
        if changed {
            self.last_seen = self.calculate_last_seen();
        }
        changed
    }

    pub fn mark_ip_offline(&mut self, ip: IpAddr) -> bool {
        let mut changed = false;
        match ip {
            IpAddr::V4(ip4) => {
                if let IPv4State::Dynamic(lease) = &mut self.v4
                    && lease.ip == ip4
                {
                    lease.last_seen = SystemTime::UNIX_EPOCH;
                    changed = true;
                }
                if let Some(entry) = self.seen_v4.iter_mut().find(|(a, _)| *a == ip4) {
                    entry.1 = SystemTime::UNIX_EPOCH;
                    changed = true;
                }
            }
            IpAddr::V6(ip6) => {
                let initial_len = self.v6.len();
                self.v6.retain(|s| match s {
                    IPv6State::Slaac(addr, _)
                    | IPv6State::LinkLocal(addr, _)
                    | IPv6State::Discovery(addr, _) => *addr != ip6,
                    _ => true,
                });

                if self.v6.len() != initial_len {
                    changed = true;
                } else {
                    for state in &mut self.v6 {
                        match state {
                            IPv6State::Static(Ipv6AddrOrSuffix::Full(addr), ts) if *addr == ip6 => {
                                *ts = SystemTime::UNIX_EPOCH;
                                changed = true;
                                break;
                            }
                            IPv6State::Dynamic(lease) if lease.ip == ip6 => {
                                lease.last_seen = SystemTime::UNIX_EPOCH;
                                changed = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        if changed {
            self.last_seen = self.calculate_last_seen();
        }
        changed
    }

    #[must_use]
    pub fn display_v6(&self, gua_prefix: Option<Ipv6Addr>, ula_prefix: Option<Ipv6Addr>) -> String {
        self.primary_v6(gua_prefix, ula_prefix)
            .map_or_else(|| "—".to_string(), |ip| ip.to_string())
    }

    #[must_use]
    pub fn learning_method(&self) -> LearningMethod {
        match self.origin {
            Origin::Toml => LearningMethod::Static,
            Origin::Cli | Origin::External => LearningMethod::Managed,
            Origin::Dynamic => {
                if matches!(self.v4, IPv4State::Dynamic(_)) {
                    LearningMethod::DhcpV4
                } else if self.v6.iter().any(|s| matches!(s, IPv6State::Dynamic(_))) {
                    LearningMethod::DhcpV6
                } else if self.v6.iter().any(|s| matches!(s, IPv6State::Slaac(..))) {
                    LearningMethod::Slaac
                } else if !self.seen_v4.is_empty()
                    || self
                        .v6
                        .iter()
                        .any(|s| matches!(s, IPv6State::Discovery(..)))
                {
                    LearningMethod::NdpArp
                } else {
                    LearningMethod::Unknown
                }
            }
        }
    }
}

/// The protocol or method by which a device was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LearningMethod {
    Static,
    Managed,
    DhcpV4,
    DhcpV6,
    Slaac,
    NdpArp,
    Unknown,
}

impl fmt::Display for LearningMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static => write!(f, "Static"),
            Self::Managed => write!(f, "Managed"),
            Self::DhcpV4 => write!(f, "DHCPv4"),
            Self::DhcpV6 => write!(f, "DHCPv6"),
            Self::Slaac => write!(f, "SLAAC"),
            Self::NdpArp => write!(f, "NDP/ARP"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

const fn is_ula(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}
