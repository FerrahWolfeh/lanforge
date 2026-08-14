//! DHCP (Dynamic Host Configuration Protocol) address pool types.
//!
//! This module provides configuration structures for both `DHCPv4` and `DHCPv6`
//! dynamic address pools.
//!
//! # Concepts
//!
//! ## `DHCPv4`
//! Under `DHCPv4` (RFC 2131), the server assigns IPv4 addresses from a defined range
//! (`range_start` to `range_end` inclusive). Clients request leases, which remain valid
//! for a duration defined by `lease_time` (or a global default).
//!
//! ## `DHCPv6`
//! Under `DHCPv6` (RFC 8415), address pools can be defined dynamically relative to an
//! advertised prefix.
//! * **Relative Suffix Ranges:** By using [`Ipv6AddrOrSuffix::Suffix`], the pool range is
//!   specified via the lower 64 bits of the address. The actual address pool range is computed
//!   by combining these suffixes with the active network prefix. This is particularly useful
//!   when the prefix is dynamic (e.g., via `DHCPv6` Prefix Delegation).
//! * **Absolute Ranges:** Alternatively, pool boundaries can be defined using absolute
//!   IPv6 addresses via [`Ipv6AddrOrSuffix::Full`].
//! * **Static Allocation:** A static network segment or subnet CIDR can be specified via
//!   the `address` field.

use crate::network::Ipv6AddrOrSuffix;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Configuration for a single `DHCPv4` address pool.
///
/// Defines a contiguous range of IPv4 addresses that the `DHCPv4` server is permitted to lease
/// dynamically to clients on the local network link.
///
/// # Example
///
/// ```
/// # use std::net::Ipv4Addr;
/// # use lanforge_types::network::dhcp::Dhcpv4Pool;
/// let pool = Dhcpv4Pool {
///     range_start: Ipv4Addr::new(192, 168, 1, 100),
///     range_end: Ipv4Addr::new(192, 168, 1, 200),
///     lease_time: Some(86400), // 24 hours
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dhcpv4Pool {
    /// Optional descriptive name for this scope.
    #[serde(default)]
    pub name: Option<String>,
    /// Start of the dynamic IP range (inclusive).
    pub range_start: Ipv4Addr,
    /// End of the dynamic IP range (inclusive).
    pub range_end: Ipv4Addr,
    /// Subnet mask override for this pool.
    #[serde(default)]
    pub subnet_mask: Option<Ipv4Addr>,
    /// Gateway / Router (Option 3) override for this pool.
    #[serde(default)]
    pub router: Option<Ipv4Addr>,
    /// DNS servers (Option 6) override for this pool.
    #[serde(default)]
    pub dns_servers: Vec<Ipv4Addr>,
    /// Domain name (Option 15) override for this pool.
    #[serde(default)]
    pub domain_name: Option<String>,
    /// Domain search list (Option 119) override for this pool.
    #[serde(default)]
    pub search_domains: Vec<String>,
    /// NTP time servers (Option 42) override for this pool.
    #[serde(default)]
    pub ntp_servers: Vec<Ipv4Addr>,
    /// Custom lease time for this pool in seconds.
    #[serde(default)]
    pub lease_time: Option<u32>,
    /// Boot file name (Option 67) override.
    #[serde(default)]
    pub boot_file: Option<String>,
    /// TFTP next-server (Option 66 / siaddr) override.
    #[serde(default)]
    pub tftp_server: Option<String>,
}

impl Default for Dhcpv4Pool {
    fn default() -> Self {
        Self {
            name: None,
            range_start: Ipv4Addr::UNSPECIFIED,
            range_end: Ipv4Addr::UNSPECIFIED,
            subnet_mask: None,
            router: None,
            dns_servers: Vec::new(),
            domain_name: None,
            search_domains: Vec::new(),
            ntp_servers: Vec::new(),
            lease_time: None,
            boot_file: None,
            tftp_server: None,
        }
    }
}

/// Configuration for a single `DHCPv6` address pool.
///
/// In IPv6 networks, `DHCPv6` can be operated in stateful mode to allocate addresses dynamically from
/// a pool (analogous to `DHCPv4`). Unlike `DHCPv4`, the pool ranges can be defined relative to the active
/// prefix using suffix boundaries, allowing the pool to shift dynamically when the prefix changes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct Dhcpv6Pool {
    /// Optional descriptive name for this scope.
    pub name: Option<String>,
    /// Lower bound suffix or full address for the pool range (inclusive).
    pub range_start: Option<Ipv6AddrOrSuffix>,
    /// Upper bound suffix or full address for the pool range (inclusive).
    pub range_end: Option<Ipv6AddrOrSuffix>,
    /// Static CIDR address or prefix (alternative to range-based pools).
    pub address: Option<String>,
    /// DNS recursive servers (Option 23) override for this pool.
    pub dns_servers: Vec<std::net::Ipv6Addr>,
    /// Domain search list (Option 24) override for this pool.
    pub search_domains: Vec<String>,
    /// NTP time servers (Option 56) override for this pool.
    pub ntp_servers: Vec<String>,
    /// Custom lease time for this pool in seconds.
    pub lease_time: Option<u32>,
    /// Boot file URL (Option 59) override.
    pub boot_file: Option<String>,
}

/// Scope options and parameters for `DHCPv4` service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Dhcpv4Options {
    pub enabled: bool,
    pub lease_time: u32,
    pub router: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub domain_name: Option<String>,
    pub search_domains: Vec<String>,
    pub ntp_servers: Vec<Ipv4Addr>,
    pub tftp_server: Option<String>,
    pub boot_file: Option<String>,
    pub raw_options: std::collections::HashMap<u8, String>,
}

impl Default for Dhcpv4Options {
    fn default() -> Self {
        Self {
            enabled: true,
            lease_time: 86400,
            router: Some(Ipv4Addr::new(192, 168, 0, 1)),
            subnet_mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            dns_servers: vec![Ipv4Addr::new(192, 168, 0, 1)],
            domain_name: None,
            search_domains: Vec::new(),
            ntp_servers: vec![
                Ipv4Addr::new(162, 159, 200, 1),
                Ipv4Addr::new(216, 239, 35, 0),
            ],
            tftp_server: None,
            boot_file: None,
            raw_options: std::collections::HashMap::new(),
        }
    }
}

/// Scope options and parameters for `DHCPv6` service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Dhcpv6Options {
    pub enabled: bool,
    pub lease_time: u32,
    pub dns_servers: Vec<std::net::Ipv6Addr>,
    pub search_domains: Vec<String>,
    pub ntp_servers: Vec<String>,
    pub boot_file: Option<String>,
    pub raw_options: std::collections::HashMap<u16, String>,
}

impl Default for Dhcpv6Options {
    fn default() -> Self {
        Self {
            enabled: true,
            lease_time: 86400,
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            ntp_servers: vec![
                "time.cloudflare.com".to_string(),
                "time.google.com".to_string(),
            ],
            boot_file: None,
            raw_options: std::collections::HashMap::new(),
        }
    }
}

/// Parameters for the TFTP / PXE service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TftpOptions {
    pub enabled: bool,
    pub listen_addr: String,
    pub root_dir: String,
    pub block_size: u16,
    pub timeout: u64,
    pub max_retries: u8,
}

impl Default for TftpOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: "0.0.0.0:69".to_string(),
            root_dir: "/var/lib/lanforge/tftp".to_string(),
            block_size: 512,
            timeout: 5,
            max_retries: 3,
        }
    }
}

/// Aggregate DHCP & TFTP options configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(default)]
pub struct DhcpOptionsConfig {
    pub v4: Dhcpv4Options,
    pub v6: Dhcpv6Options,
    pub tftp: TftpOptions,
}
