//! `DHCPv6` server and pool configuration.
//!
//! Supports multi-prefix operation (`ULA` + `GUA`) with flexible pool definitions:
//! fixed ranges, floating suffix ranges, or single static addresses.

use std::net::Ipv6Addr;
use serde::{Deserialize, Serialize};
use lanforge_macros::ServiceConfig;

use lanforge_core::device::Ipv6AddrOrSuffix;

/// Configuration for a single `DHCPv6` address pool.
///
/// Pools can be defined as:
/// - **Fixed range**: explicit `range_start`/`range_end` suffixes
/// - **Single address**: static `address` string (CIDR notation)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dhcpv6PoolConfig {
    /// Lower bound suffix for the pool range (relative to prefix).
    pub range_start: Option<Ipv6AddrOrSuffix>,
    /// Upper bound suffix for the pool range (relative to prefix).
    pub range_end: Option<Ipv6AddrOrSuffix>,
    /// Static CIDR address (alternative to range-based pools).
    pub address: Option<String>,
}

/// `DHCPv6` server configuration — built from the `[dhcp.v6]` TOML section.
///
/// Supports both `IA_NA` (non-temporary addresses) and `IA_PD` (prefix delegation).
/// The `ula_prefix` enables Unique Local Address assignment in addition to
/// Global Unicast Addresses learned from RA.
#[derive(Clone, Debug, Serialize, Deserialize, ServiceConfig)]
#[config(key = "dhcp.v6")]
#[serde(default)]
pub struct Dhcpv6Config {
    /// Whether the `DHCPv6` service is enabled.
    pub enabled: bool,
    /// Network interface to listen on.
    #[serde(skip)]
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
    pub pools: Vec<Dhcpv6PoolConfig>,
    /// DNS servers to announce to clients (`DHCPv6` Option 23).
    pub dns_servers: Vec<Ipv6Addr>,
    /// Search domains to announce to clients (`DHCPv6` Option 24).
    pub search_domains: Vec<String>,
    /// Global boot file name (Option 59).
    pub boot_file: Option<String>,
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
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            boot_file: None,
        }
    }
}
