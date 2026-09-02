//! `DHCPv4` server configuration.
//!
//! Defines the `LAN` interface, address pool range, and `DHCP` options
//! (`router`, `DNS`, `domain name`, `search domains`).

use lanforge_macros::ServiceConfig;
use lanforge_types::network::dhcp::Dhcpv4Pool;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;

/// `DHCPv4` server configuration — built from the `[dhcp.v4]` TOML section.
#[derive(Debug, Clone, Serialize, Deserialize, ServiceConfig)]
#[config(key = "dhcp.v4")]
#[serde(default)]
pub struct Dhcpv4Config {
    /// Whether the `DHCPv4` service is enabled.
    pub enabled: bool,
    /// Network interface to listen on (e.g., `"eth0"`). If omitted, defaults to system LAN interface.
    #[serde(default)]
    pub iface: String,
    /// Server IP — used as `server_id` (Option 54) and `siaddr` in replies.
    #[serde(skip)]
    pub server_id: Ipv4Addr,

    /// Legacy: Start of the dynamic IP range (inclusive).
    pub range_start: Option<Ipv4Addr>,
    /// Legacy: End of the dynamic IP range (inclusive).
    pub range_end: Option<Ipv4Addr>,

    /// Multiple pools for address assignment.
    pub pools: Vec<Dhcpv4Pool>,

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
    /// Custom DHCP options (key = option number, value = hex string).
    pub options: HashMap<u8, String>,
    /// NTP servers announced to clients (Option 42).
    pub ntp_servers: Vec<Ipv4Addr>,
}

impl Default for Dhcpv4Config {
    fn default() -> Self {
        Self {
            enabled: false,
            iface: String::new(),
            server_id: Ipv4Addr::new(192, 168, 0, 1),
            range_start: None,
            range_end: None,
            pools: Vec::new(),
            lease_time: 86400,
            router: Ipv4Addr::new(192, 168, 0, 1),
            dns: vec![Ipv4Addr::new(192, 168, 0, 1)],
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            domain_name: None,
            search_domains: Vec::new(),
            port: 67,
            tftp_server: None,
            boot_file: None,
            options: HashMap::new(),
            ntp_servers: vec![
                Ipv4Addr::new(162, 159, 200, 1), // time.cloudflare.com
                Ipv4Addr::new(216, 239, 35, 0),  // time.google.com
            ],
        }
    }
}

impl Dhcpv4Config {
    /// Returns all configured pools, including the legacy range if present.
    #[must_use]
    pub fn get_effective_pools(&self) -> Vec<Dhcpv4Pool> {
        let mut pools = self.pools.clone();
        if let (Some(start), Some(end)) = (self.range_start, self.range_end) {
            pools.push(Dhcpv4Pool {
                range_start: start,
                range_end: end,
                ..Default::default()
            });
        }
        pools
    }
}
