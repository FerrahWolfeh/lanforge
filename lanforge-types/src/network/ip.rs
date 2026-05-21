use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(try_from = "String", into = "String")]
pub enum Ipv6AddrOrSuffix {
    Full(Ipv6Addr),
    Suffix([u8; 8]),
}

impl FromStr for Ipv6AddrOrSuffix {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s).ok_or_else(|| format!("Invalid IPv6 address or suffix: {s}"))
    }
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

#[must_use]
pub const fn is_ula(v6: &Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xfe00) == 0xfc00
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv6Prefix {
    pub segments: [u16; 4],
    pub group: IpClassification,
}

impl From<Ipv6Addr> for Ipv6Prefix {
    fn from(addr: Ipv6Addr) -> Self {
        Self::from_addr(addr)
    }
}

impl From<Ipv6Prefix> for Ipv6Addr {
    fn from(prefix: Ipv6Prefix) -> Self {
        prefix.to_addr()
    }
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

impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/64", self.to_addr())
    }
}
