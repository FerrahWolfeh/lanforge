use crate::network::subnet::IpSubnet;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::net::{Ipv4Addr, Ipv6Addr};

/// L3 WAN operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WanState {
    #[default]
    Down,
    Up,
}

/// Zeros out the host bits of an IPv6 address based on the prefix length using a bitwise mask.
#[must_use]
pub const fn mask_ipv6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    if prefix_len >= 128 {
        return addr;
    }
    if prefix_len == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let mask = !0u128 << (128 - prefix_len);
    let ip_u128 = u128::from_be_bytes(addr.octets());
    Ipv6Addr::from_bits(ip_u128 & mask)
}

/// IPv6 network prefix with prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv6Net {
    pub addr: Ipv6Addr,
    pub prefix_len: u8,
}

impl Ipv6Net {
    #[must_use]
    pub const fn new(addr: Ipv6Addr, prefix_len: u8) -> Self {
        Self {
            addr: mask_ipv6(addr, prefix_len),
            prefix_len,
        }
    }
}

impl std::fmt::Display for Ipv6Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl From<crate::network::Ipv6Prefix> for Ipv6Net {
    fn from(prefix: crate::network::Ipv6Prefix) -> Self {
        Self {
            addr: prefix.to_addr(),
            prefix_len: 64,
        }
    }
}

/// Point-in-time snapshot of the effective WAN L3 connectivity.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WanSnapshot {
    pub state: WanState,
    pub ifindex: Option<u32>,
    pub ifname: Option<String>,
    pub v4: Option<(Ipv4Addr, u8)>,
    pub v6_prefixes: SmallVec<[Ipv6Net; 2]>,
    pub generation: u64,
}

impl WanSnapshot {
    #[must_use]
    pub const fn is_up(&self) -> bool {
        matches!(self.state, WanState::Up)
    }
}

/// Network link physical and address state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkInfo {
    pub ifindex: u32,
    pub name: String,
    pub carrier: bool,
    pub addrs: SmallVec<[IpSubnet; 4]>,
}

/// Point-in-time snapshot of all discovered network interfaces.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct InterfaceSnapshot {
    pub links: SmallVec<[LinkInfo; 8]>,
    pub generation: u64,
}

impl InterfaceSnapshot {
    /// Returns `true` if a link with the given interface name exists.
    #[must_use]
    pub fn has_link(&self, name: &str) -> bool {
        self.links.iter().any(|l| l.name == name)
    }

    /// Finds link details by interface name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<&LinkInfo> {
        self.links.iter().find(|l| l.name == name)
    }

    /// Finds link details by OS ifindex.
    #[must_use]
    pub fn find_by_index(&self, ifindex: u32) -> Option<&LinkInfo> {
        self.links.iter().find(|l| l.ifindex == ifindex)
    }
}

/// Point-in-time snapshot of low-level network transport metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TransportSnapshot {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub dropped: u64,
    pub rate_limited: u64,
    pub errors: u64,
    pub last_error_age_secs: Option<u64>,
}
