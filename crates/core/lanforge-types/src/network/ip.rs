use serde::{Deserialize, Serialize};
use std::fmt::{self, Display};
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ipv6Suffix(pub [u8; 8]);

impl Ipv6Suffix {
    /// Combina com um prefixo /64 para produzir um endereço completo.
    #[must_use]
    pub fn resolve(&self, prefix: Ipv6Addr) -> Ipv6Addr {
        let mut bytes = prefix.octets();
        bytes[8..16].copy_from_slice(&self.0);
        Ipv6Addr::from(bytes)
    }

    /// Extrai o sufixo de um endereço completo (os últimos 64 bits).
    #[must_use]
    pub fn from_addr(addr: Ipv6Addr) -> Self {
        let oct = addr.octets();
        let mut s = [0u8; 8];
        s.copy_from_slice(&oct[8..16]);
        Self(s)
    }

    /// Compara o sufixo com os últimos 64 bits de um endereço.
    #[must_use]
    pub fn matches(&self, addr: Ipv6Addr) -> bool {
        addr.octets()[8..16] == self.0
    }
}

impl FromStr for Ipv6Suffix {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err("Empty IPv6 suffix".to_string());
        }
        let full_s = if s.contains("::") {
            s.to_string()
        } else {
            format!("::{s}")
        };
        let ip = full_s
            .parse::<Ipv6Addr>()
            .map_err(|_| format!("Invalid IPv6 suffix: {s}"))?;
        let segs = ip.segments();
        if segs[0] != 0 || segs[1] != 0 || segs[2] != 0 || segs[3] != 0 {
            return Err(format!("Not a suffix (has prefix bits set): {s}"));
        }
        Ok(Self::from_addr(ip))
    }
}

impl fmt::Display for Ipv6Suffix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ip = Ipv6Addr::new(
            0,
            0,
            0,
            0,
            u16::from_be_bytes([self.0[0], self.0[1]]),
            u16::from_be_bytes([self.0[2], self.0[3]]),
            u16::from_be_bytes([self.0[4], self.0[5]]),
            u16::from_be_bytes([self.0[6], self.0[7]]),
        );
        ip.fmt(f)
    }
}

impl TryFrom<String> for Ipv6Suffix {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::from_str(&s)
    }
}

impl From<Ipv6Suffix> for String {
    fn from(val: Ipv6Suffix) -> Self {
        val.to_string()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(try_from = "String", into = "String")]
pub enum Ipv6AddrOrSuffix {
    Full(Ipv6Addr),
    Suffix(Ipv6Suffix),
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
            Self::Suffix(suffix) => suffix.matches(addr),
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
                return Some(Self::Suffix(Ipv6Suffix::from_addr(ip)));
            }
            return Some(Self::Full(ip));
        }

        if s.split(':').count() > 4 {
            return None;
        }

        let full_s = format!("::{s}");
        full_s.parse::<Ipv6Addr>().map_or(None, |ip| {
            let segs = ip.segments();
            if segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 {
                Some(Self::Suffix(Ipv6Suffix::from_addr(ip)))
            } else {
                None
            }
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
                bytes[8..16].copy_from_slice(&s.0);
                u128::from_be_bytes(bytes)
            }
        }
    }
}

impl fmt::Display for Ipv6AddrOrSuffix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full(ip) => ip.fmt(f),
            Self::Suffix(s) => s.fmt(f),
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

impl Display for IpClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ula => write!(f, "ULA"),
            Self::Ipv4 => write!(f, "IPv4"),
            Self::Gua => write!(f, "GUA"),
            Self::LinkLocal => write!(f, "Link-local"),
            Self::Loopback => write!(f, "Loopback"),
            Self::Other => write!(f, "Other"),
        }
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

    #[must_use]
    pub const fn prefix_len(&self) -> u8 {
        64
    }

    #[must_use]
    pub fn matches(&self, addr: &Ipv6Addr) -> bool {
        let segs = addr.segments();
        self.segments == [segs[0], segs[1], segs[2], segs[3]]
    }

    #[must_use]
    pub fn combine_suffix(&self, suffix: [u8; 8]) -> Ipv6Addr {
        let mut octets = [0u8; 16];
        for i in 0..4 {
            let be = self.segments[i].to_be_bytes();
            octets[i * 2] = be[0];
            octets[i * 2 + 1] = be[1];
        }
        octets[8..16].copy_from_slice(&suffix);
        Ipv6Addr::from(octets)
    }
}

impl From<super::snapshot::Ipv6Net> for Ipv6Prefix {
    fn from(net: super::snapshot::Ipv6Net) -> Self {
        Self::from_addr(net.addr)
    }
}

impl fmt::Display for Ipv6Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/64", self.to_addr())
    }
}
