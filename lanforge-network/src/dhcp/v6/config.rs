use std::net::Ipv6Addr;

use lanforge_core::device::Ipv6AddrOrSuffix;

/// Configuration for a single DHCPv6 address pool.
#[derive(Clone, Debug)]
pub struct Dhcpv6PoolConfig {
    pub range_start: Option<Ipv6AddrOrSuffix>,
    pub range_end: Option<Ipv6AddrOrSuffix>,
    pub address: Option<String>,
}

/// `DHCPv6` server configuration — built from the `[dhcp.v6]` TOML section.
#[derive(Clone, Debug)]
pub struct Dhcpv6Config {
    /// Whether the DHCPv6 service is enabled.
    pub enabled: bool,
    /// Network interface to listen on.
    pub iface: String,
    /// Lease time in seconds.
    pub lease_time: u32,
    /// Local Unique Address (ULA) prefix to announce.
    pub ula_prefix: Option<Ipv6Addr>,
    /// Prefix length of the ULA.
    pub ula_prefix_len: u8,
    /// UDP port to listen on (default: 547).
    pub port: u16,
    /// Multiple pools for address assignment (new).
    pub pools: Vec<Dhcpv6PoolConfig>,
}

impl Default for Dhcpv6Config {
    fn default() -> Self {
        Self {
            enabled: true,
            iface: "end0".into(),
            lease_time: 86400,
            ula_prefix: None,
            ula_prefix_len: 64,
            port: 547,
            pools: Vec::new(),
        }
    }
}
