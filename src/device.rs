use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

    pub const fn symbol(&self) -> &'static str {
        match self {
            Self::Toml => "★",
            Self::Cli => "·",
            Self::Dynamic => "–",
        }
    }
}

impl FromStr for Origin {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "toml" | "static" => Ok(Self::Toml),
            "cli" | "managed_cli" => Ok(Self::Cli),
            "dynamic" => Ok(Self::Dynamic),
            _ => Err(()),
        }
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
    pub iaid: u32,
    #[serde(serialize_with = "serialize_time")]
    pub expires: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V6PrefixLease {
    pub prefix: Ipv6Addr,
    pub len: u8,
    pub iaid: u32,
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
// IP Classification and Scoring (ULA > IPv4 > GUA)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IpClassification {
    Ula = 0,
    Ipv4 = 1,
    Gua = 2,
    LinkLocal = 3,
    Loopback = 4,
    Other = 10,
}

impl IpClassification {
    pub fn score(&self) -> u8 {
        *self as u8
    }
}

pub fn classify_ip(addr: &IpAddr) -> IpClassification {
    match addr {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                IpClassification::Loopback
            } else {
                IpClassification::Ipv4
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                IpClassification::Loopback
            } else if is_ula(v6) {
                IpClassification::Ula
            } else if (v6.segments()[0] & 0xe000) == 0x2000 {
                // GUA: 2000::/3 (RFC 4291)
                IpClassification::Gua
            } else if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                // Link-Local: fe80::/10
                IpClassification::LinkLocal
            } else {
                IpClassification::Other
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
    pub v6_prefixes: Vec<V6PrefixLease>,

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

// ---------------------------------------------------------------------------
// Formatting and Selection Helpers
// ---------------------------------------------------------------------------

impl Device {
    pub fn display_hostname(&self) -> &str {
        if self.hostname.is_empty() {
            "?"
        } else {
            &self.hostname
        }
    }

    pub fn is_online(&self) -> bool {
        self.last_seen
            .elapsed()
            .map(|d| d.as_secs() < 300)
            .unwrap_or(false)
    }

    pub fn display_v4(&self) -> String {
        match &self.v4 {
            IPv4State::Static(ip) => ip.to_string(),
            IPv4State::Dynamic(lease) => lease.ip.to_string(),
            IPv4State::None => {
                if let Some(seen) = self.seen_v4.first() {
                    format!("{} ?", seen)
                } else {
                    "—".to_string()
                }
            }
        }
    }

    /// Returns the primary IPv6 address based on following priority:
    /// 1. ULA (Static or Dynamic Lease)
    /// 2. SLAAC (any)
    /// 3. GUA (Static or Dynamic Lease)
    pub fn primary_v6(&self) -> Option<Ipv6Addr> {
        // 1. Check for ULA in leases/static
        for state in &self.v6 {
            if let Some(ip) = state.ip()
                && is_ula(&ip)
            {
                return Some(ip);
            }
        }

        // 2. Check for SLAAC
        for state in &self.v6 {
            if let IPv6State::Slaac(ip) = state {
                return Some(*ip);
            }
        }

        // 3. Fallback to GUA (leases/static)
        for state in &self.v6 {
            if let Some(ip) = state.ip() {
                return Some(ip);
            }
        }

        None
    }

    pub fn display_v6(&self) -> String {
        self.primary_v6()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "—".to_string())
    }

    /// Returns ALL available IP addresses (v4 and v6) sorted by priority:
    /// ULA (0) > IPv4 (1) > GUA (2) > others
    #[cfg(test)]
    pub fn all_addresses_sorted(&self) -> Vec<IpAddr> {
        let mut addrs = Vec::new();

        // IPv4
        if let Some(ip) = self.v4.ip() {
            addrs.push(IpAddr::V4(ip));
        }
        for ip in &self.seen_v4 {
            addrs.push(IpAddr::V4(*ip));
        }

        // IPv6
        for state in &self.v6 {
            if let Some(ip) = state.ip() {
                addrs.push(IpAddr::V6(ip));
            }
        }

        // De-duplicate while preserving some form of "original" order before sorting
        // (Actually, HashSet would be faster but we might want to keep it simple first)
        let mut unique = std::collections::HashSet::new();
        addrs.retain(|ip| unique.insert(*ip));

        // Sort by classification score
        addrs.sort_by_cached_key(|ip| classify_ip(ip).score());

        addrs
    }
}

fn is_ula(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_ip() {
        assert_eq!(
            classify_ip(&"127.0.0.1".parse().unwrap()),
            IpClassification::Loopback
        );
        assert_eq!(
            classify_ip(&"1.1.1.1".parse().unwrap()),
            IpClassification::Ipv4
        );
        assert_eq!(
            classify_ip(&"fd00::1".parse().unwrap()),
            IpClassification::Ula
        );
        assert_eq!(
            classify_ip(&"2001:db8::1".parse().unwrap()),
            IpClassification::Gua
        );
        assert_eq!(
            classify_ip(&"fe80::1".parse().unwrap()),
            IpClassification::LinkLocal
        );
        assert_eq!(
            classify_ip(&"::1".parse().unwrap()),
            IpClassification::Loopback
        );
    }

    #[test]
    fn test_all_addresses_sorted() {
        let dev = Device {
            hostname: "test".to_string(),
            mac: MacAddr([0, 0, 0, 0, 0, 0]),
            origin: Origin::Dynamic,
            managed_at: None,
            duid: None,
            v4: IPv4State::Static("192.168.1.1".parse().unwrap()),
            v6: vec![
                IPv6State::Slaac("2001:db8::1".parse().unwrap()),
                IPv6State::Slaac("fd00::1".parse().unwrap()),
            ],
            v6_prefixes: Vec::new(),
            seen_v4: Vec::new(),
            last_seen: SystemTime::now(),
        };

        let sorted = dev.all_addresses_sorted();
        // Priority: ULA (fd00::1) > IPv4 (192.168.1.1) > GUA (2001:db8::1)
        assert_eq!(sorted[0], "fd00::1".parse::<IpAddr>().unwrap());
        assert_eq!(sorted[1], "192.168.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(sorted[2], "2001:db8::1".parse::<IpAddr>().unwrap());
    }
}
