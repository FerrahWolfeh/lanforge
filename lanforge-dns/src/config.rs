//! DNS server configuration.
//!
//! Contains all settings required to run the authoritative and recursive
//! DNS service, including listen address, upstream resolver, search domains,
//! and IPv6 prefix settings.

use std::net::{Ipv6Addr, SocketAddr};

/// Supported protocols for upstream DNS forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProtocol {
    /// Standard DNS over UDP (with TCP fallback).
    Udp,
    /// DNS over TLS (`DoT`).
    Tls,
}

/// An upstream resolver target with protocol and optional hostname for verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    /// The IP address and port of the upstream resolver.
    pub addr: SocketAddr,
    /// The protocol to use for forwarding.
    pub protocol: UpstreamProtocol,
    /// Optional hostname for TLS SNI and certificate validation (required for `DoT`).
    pub hostname: Option<String>,
}

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
    /// Upstream resolver target (IP, protocol, hostname).
    /// If `None`, non-local queries return `REFUSED`.
    pub upstream: Option<UpstreamTarget>,
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
    #[cfg(feature = "adblock")]
    /// Whether the micro-adblocker is enabled.
    pub adblock_enabled: bool,
    #[cfg(feature = "adblock")]
    /// List of URLs to fetch blocklists from.
    pub adblock_urls: Vec<String>,
    /// How many days a device can be offline before its DNS entry is hidden.
    pub last_seen_threshold_days: u32,

    /// Optional socket address to listen for DNS-over-TLS (`DoT`).
    pub dot_listen: Option<SocketAddr>,
    /// Path to the TLS certificate for `DoT`.
    pub tls_cert: Option<String>,
    /// Path to the TLS private key for `DoT`.
    pub tls_key: Option<String>,
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
            #[cfg(feature = "adblock")]
            adblock_enabled: false,
            #[cfg(feature = "adblock")]
            adblock_urls: Vec::new(),
            last_seen_threshold_days: 7,
            dot_listen: None,
            tls_cert: None,
            tls_key: None,
        }
    }
}
