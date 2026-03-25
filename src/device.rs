use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::SystemTime;

use crate::dhcp::v6::duid::Duid;

// ---------------------------------------------------------------------------
// Helpers for Serde
// ---------------------------------------------------------------------------

pub fn serialize_time_opt<S>(time: &Option<SystemTime>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
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
    S: serde::Serializer,
{
    let elapsed = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    serializer.serialize_u64(elapsed.as_secs())
}

// ---------------------------------------------------------------------------
// MacAddr
// ---------------------------------------------------------------------------

/// Endereço MAC de 6 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MacAddr(
    #[serde(serialize_with = "serialize_mac", deserialize_with = "deserialize_mac")] pub [u8; 6],
);

fn deserialize_mac<'de, D>(deserializer: D) -> Result<[u8; 6], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    MacAddr::parse(&s)
        .map(|m| m.0)
        .ok_or_else(|| serde::de::Error::custom(format!("Invalid MAC address: {}", s)))
}

fn serialize_mac<S>(mac: &[u8; 6], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    ))
}

impl MacAddr {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 6 {
            return None;
        }
        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            bytes[i] = u8::from_str_radix(part, 16).ok()?;
        }
        Some(Self(bytes))
    }

    pub const fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 6 {
            let mut arr = [0u8; 6];
            // arr.copy_from_slice(bytes); // not const
            arr[0] = bytes[0];
            arr[1] = bytes[1];
            arr[2] = bytes[2];
            arr[3] = bytes[3];
            arr[4] = bytes[4];
            arr[5] = bytes[5];
            Some(Self(arr))
        } else {
            None
        }
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(arr: [u8; 6]) -> Self {
        Self(arr)
    }
}

impl FromStr for MacAddr {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| format!("Invalid MAC address: {}", s))
    }
}

impl AsRef<[u8; 6]> for MacAddr {
    fn as_ref(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

// ---------------------------------------------------------------------------
// Origin
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Origin {
    Toml,
    Cli,
    #[default]
    Dynamic,
}

impl Origin {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Toml => "toml",
            Self::Cli => "cli",
            Self::Dynamic => "dynamic",
        }
    }

    pub const fn is_static(&self) -> bool {
        !matches!(self, Self::Dynamic)
    }
}

// ---------------------------------------------------------------------------
// Address States
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V4Lease {
    pub ip: Ipv4Addr,
    #[serde(serialize_with = "serialize_time")]
    pub expires: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V6Lease {
    pub ip: Ipv6Addr,
    #[serde(serialize_with = "serialize_time")]
    pub expires: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V6PrefixLease {
    pub prefix: Ipv6Addr,
    pub len: u8,
    #[serde(serialize_with = "serialize_time")]
    pub expires: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IPv4State {
    Static(Ipv4Addr),
    Dynamic(V4Lease),
    None,
}

impl IPv4State {
    pub fn ip(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Static(ip) => Some(*ip),
            Self::Dynamic(lease) => Some(lease.ip),
            Self::None => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IPv6State {
    Static(Ipv6AddrOrSuffix),
    Dynamic(V6Lease),
    Slaac(Ipv6Addr),
}

impl IPv6State {
    pub fn ip(&self) -> Option<Ipv6Addr> {
        match self {
            Self::Dynamic(lease) => Some(lease.ip),
            Self::Slaac(ip) => Some(*ip),
            Self::Static(Ipv6AddrOrSuffix::Full(ip)) => Some(*ip),
            Self::Static(Ipv6AddrOrSuffix::Suffix(_)) => None, // Needs prefix to resolve
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Ipv6AddrOrSuffix {
    Full(Ipv6Addr),
    Suffix([u8; 8]),
}

impl Ipv6AddrOrSuffix {
    pub fn parse(s: &str) -> Option<Self> {
        if s.is_empty() {
            return None;
        }
        if let Ok(ip) = s.parse::<Ipv6Addr>() {
            // Se for um endereço completo mas que começa com ::, pode ser um sufixo mal formatado no TOML?
            // "::1" parses as Ipv6Addr. We should decide if it's Full or Suffix.
            // Regra: se tem mais que 4 grupos ou não começa com ::, é Full.
            // Mas Ipv6Addr::parse é guloso.
            // Vamos checar se o endereço tem zero nos primeiros 64 bits.
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

        // Caso "1", "beef", "dead:beef" (sem o ::)
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() > 4 {
            return None;
        }

        let full_s = format!("::{}", s);
        if let Ok(ip) = full_s.parse::<Ipv6Addr>() {
            let segs = ip.segments();
            let mut bytes = [0u8; 8];
            bytes[0..2].copy_from_slice(&segs[4].to_be_bytes());
            bytes[2..4].copy_from_slice(&segs[5].to_be_bytes());
            bytes[4..6].copy_from_slice(&segs[6].to_be_bytes());
            bytes[6..8].copy_from_slice(&segs[7].to_be_bytes());
            Some(Self::Suffix(bytes))
        } else {
            None
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

// ---------------------------------------------------------------------------
// Device
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub mac: MacAddr,
    pub hostname: String,
    pub origin: Origin,

    #[serde(serialize_with = "serialize_time_opt")]
    pub managed_at: Option<SystemTime>,

    pub v4: IPv4State,
    pub v6: Vec<IPv6State>,
    pub v6_prefix: Option<V6PrefixLease>,

    /// Endereços IPv4 observados via ARP/Netlink (não necessariamente leases).
    pub seen_v4: Vec<Ipv4Addr>,

    #[serde(serialize_with = "serialize_time")]
    pub last_seen: SystemTime,

    pub duid: Option<Duid>,
}

impl Device {
    pub fn is_static(&self) -> bool {
        self.origin.is_static()
    }
}
