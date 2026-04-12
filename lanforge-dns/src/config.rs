//! DNS server configuration.
//!
//! Contains all settings required to run the authoritative and recursive
//! DNS service, including listen address, upstream resolver, search domains,
//! and IPv6 prefix settings.

use std::net::{Ipv6Addr, SocketAddr};

/// Configuration for the DNS service.
///
/// # Key Fields
///
/// | Field | Purpose |
/// | :--- | :--- |
/// | `listen` | Socket address to bind UDP/TCP listeners |
/// | `upstream` | Upstream resolver for non-local queries (e.g., Unbound) |
/// | `search_domain` | Local domain suffix (e.g., `"lan"`) |
/// | `ula_prefix` / `gua_prefix` | IPv6 prefixes for address generation fallback |
/// | `multi_search_labels` | Multiple domain support (list of label lists) |
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// Whether the DNS service is enabled.
    pub enabled: bool,
    /// Socket address to listen on for both UDP and TCP (e.g., `0.0.0.0:53`).
    pub listen: SocketAddr,
    /// Upstream resolver address (e.g., Unbound at `127.0.0.1:5335`).
    /// If `None`, non-local queries return `REFUSED`.
    pub upstream: Option<SocketAddr>,
    /// Local search domain suffix (e.g., `"lan"`). Queries for `host.lan`
    /// are resolved locally; others are forwarded upstream.
    pub search_domain: String,
    /// ULA (Unique Local Address) prefix for IPv6 resolution (e.g., `fd00::`).
    /// Used to construct full addresses from 8-byte suffixes.
    pub ula_prefix: Option<Ipv6Addr>,
    /// GUA (Global Unicast Address) prefix for IPv6 resolution (e.g., `2001:db8::`).
    pub gua_prefix: Option<Ipv6Addr>,
    /// Default TTL (in seconds) for locally generated DNS records.
    pub ttl: u32,
    /// Pre-parsed search domain labels for zero-allocation hostname matching.
    /// Default: `[[b"lan"]]`.
    pub multi_search_labels: Vec<Vec<Vec<u8>>>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "0.0.0.0:53".parse().unwrap(),
            upstream: None,
            search_domain: "lan".into(),
            ula_prefix: None,
            gua_prefix: None,
            ttl: 60,
            multi_search_labels: vec![vec![b"lan".to_vec()]],
        }
    }
}
