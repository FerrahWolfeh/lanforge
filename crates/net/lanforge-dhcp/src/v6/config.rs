//! `DHCPv6` server and pool configuration.
//!
//! Supports multi-prefix operation (`ULA` + `GUA`) with flexible pool definitions:
//! fixed ranges, floating suffix ranges, or single static addresses.

use lanforge_types::network::dhcp::{Dhcpv6Options, Dhcpv6Pool};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv6Addr;

/// `DHCPv6` server configuration — built from the `[dhcp.v6]` TOML section.
///
/// Supports both `IA_NA` (non-temporary addresses) and `IA_PD` (prefix delegation).
/// The `ula_prefix` enables Unique Local Address assignment in addition to
/// Global Unicast Addresses learned from RA.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Dhcpv6Config {
    /// Whether the `DHCPv6` service is enabled.
    pub enabled: bool,
    /// Network interface to listen on. If omitted, defaults to system LAN interface.
    #[serde(default)]
    pub iface: String,
    /// Lease time in seconds.
    pub lease_time: u32,
    /// Local Unique Address (ULA) prefix (`fd00::/8`) to announce.
    #[serde(skip)]
    pub ula_prefix: Option<Ipv6Addr>,
    /// Prefix length of the ULA (typically 64).
    #[serde(skip)]
    pub ula_prefix_len: u8,
    /// UDP port to listen on (default: 547, per RFC 8415).
    #[serde(skip)]
    pub port: u16,
    /// Multiple pools for address assignment (ULA + GUA).
    pub pools: Vec<Dhcpv6Pool>,
    /// DNS servers to announce to clients (`DHCPv6` Option 23).
    pub dns_servers: Vec<Ipv6Addr>,
    /// Search domains to announce to clients (`DHCPv6` Option 24).
    pub search_domains: Vec<String>,
    /// Global boot file name (Option 59).
    pub boot_file: Option<String>,
    /// Custom `DHCPv6` options (key = option number, value = hex string).
    pub options: HashMap<u16, String>,
    /// NTP servers to announce to clients (Option 56).
    pub ntp_servers: Vec<String>,
}

impl Dhcpv6Config {
    /// This start-up configuration with the live `[dhcp.v6]` options over it, at every start
    /// and on every live change (a restart must not fall back to the boot values). `self`'s
    /// search domains are the site's (`[system] search_domains`, else `lan`): they apply when
    /// the options name none. No DNS server = this router, decided per reply.
    #[must_use]
    pub fn with_options(&self, opts: &Dhcpv6Options) -> Self {
        let mut cfg = self.clone();
        cfg.dns_servers.clone_from(&opts.dns_servers);
        if !opts.search_domains.is_empty() {
            cfg.search_domains.clone_from(&opts.search_domains);
        }
        cfg.ntp_servers.clone_from(&opts.ntp_servers);
        cfg.boot_file.clone_from(&opts.boot_file);
        cfg.options.clone_from(&opts.raw_options);
        if opts.lease_time > 0 {
            cfg.lease_time = opts.lease_time;
        }
        cfg
    }
}

impl Default for Dhcpv6Config {
    fn default() -> Self {
        Self {
            enabled: true,
            // Empty: inherits `system.iface` when the TOML does not set one (same as DHCPv4).
            iface: String::new(),
            lease_time: 86400,
            ula_prefix: None,
            ula_prefix_len: 64,
            port: 547,
            pools: Vec::new(),
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            boot_file: None,
            options: HashMap::new(),
            ntp_servers: vec![
                "time.cloudflare.com".to_string(),
                "time.google.com".to_string(),
            ],
        }
    }
}
