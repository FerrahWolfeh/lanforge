//! `DHCPv4` server configuration.
//!
//! Defines the `LAN` interface, address pool range, and `DHCP` options
//! (`router`, `DNS`, `domain name`, `search domains`).

use std::net::Ipv4Addr;

/// `DHCPv4` server configuration — built from the `[dhcp.v4]` TOML section.
#[derive(Debug, Clone)]
pub struct Dhcpv4Config {
    /// Network interface to listen on (e.g., `"eth0"`).
    pub iface: String,
    /// Server IP — used as `server_id` (Option 54) and `siaddr` in replies.
    pub server_id: Ipv4Addr,
    /// Start of the dynamic IP range (inclusive).
    pub range_start: Ipv4Addr,
    /// End of the dynamic IP range (inclusive).
    pub range_end: Ipv4Addr,
    /// Lease time in seconds (default: 86400 = 24h).
    pub lease_time: u32,
    /// Default gateway announced to clients (Option 3 — Router).
    pub router: Ipv4Addr,
    /// DNS servers announced to clients (Option 6).
    pub dns: Vec<Ipv4Addr>,
    /// Subnet mask announced to clients (Option 1, default: 255.255.255.0).
    pub subnet_mask: Ipv4Addr,
    /// Domain name (Option 15, optional).
    pub domain_name: Option<String>,
    /// Search domains (Option 119 — Domain Search).
    pub search_domains: Vec<String>,
    /// UDP port to listen on (default: 67).
    pub port: u16,
    /// TFTP server address (Option 66).
    pub tftp_server: Option<String>,
    /// Boot file name (Option 67).
    pub boot_file: Option<String>,
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
            search_domains: Vec::new(),
            port: 67,
            tftp_server: None,
            boot_file: None,
        }
    }
}
