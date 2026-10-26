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

/// IPv6 network prefix with prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv6Net {
    pub addr: Ipv6Addr,
    pub prefix_len: u8,
}

impl Ipv6Net {
    #[must_use]
    pub const fn new(addr: Ipv6Addr, prefix_len: u8) -> Self {
        Self { addr, prefix_len }
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
