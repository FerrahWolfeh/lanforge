//! `DHCPv6` server configuration.

use std::net::Ipv6Addr;

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
    /// Start of the dynamic range (optional).
    pub range_start: Option<Ipv6Addr>,
    /// End of the dynamic range (optional).
    pub range_end: Option<Ipv6Addr>,
    /// UDP port to listen on (default: 547).
    pub port: u16,
}

impl Default for Dhcpv6Config {
    fn default() -> Self {
        Self {
            enabled: true,
            iface: "end0".into(),
            lease_time: 86400,
            ula_prefix: None,
            ula_prefix_len: 64,
            range_start: None,
            range_end: None,
            port: 547,
        }
    }
}
