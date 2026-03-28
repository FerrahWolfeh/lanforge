//! `DHCPv4` server configuration.

use std::net::Ipv4Addr;

/// `DHCPv4` server configuration — built from the `[dhcp.v4]` TOML section.
#[derive(Debug, Clone)]
pub struct Dhcpv4Config {
    /// Network interface to listen on.
    pub iface: String,
    /// Server IP (our LAN address — used as `server_id` and `siaddr`).
    pub server_id: Ipv4Addr,
    /// Start of the dynamic IP range.
    pub range_start: Ipv4Addr,
    /// End of the dynamic IP range (inclusive).
    pub range_end: Ipv4Addr,
    /// Lease time in seconds.
    pub lease_time: u32,
    /// Default gateway announced to clients.
    pub router: Ipv4Addr,
    /// DNS servers announced to clients.
    pub dns: Vec<Ipv4Addr>,
    /// Subnet mask (default: 255.255.255.0).
    pub subnet_mask: Ipv4Addr,
    /// Domain name (optional).
    pub domain_name: Option<String>,
}

impl Default for Dhcpv4Config {
    fn default() -> Self {
        Self {
            iface: "end0".into(),
            server_id: Ipv4Addr::new(192, 168, 0, 1),
            range_start: Ipv4Addr::new(192, 168, 0, 100),
            range_end: Ipv4Addr::new(192, 168, 0, 254),
            lease_time: 86400,
            router: Ipv4Addr::new(192, 168, 0, 1),
            dns: vec![Ipv4Addr::new(192, 168, 0, 1)],
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            domain_name: None,
        }
    }
}
