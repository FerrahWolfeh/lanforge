//! DNS server configuration.
//!
//! Contains all settings required to run the authoritative and recursive
//! DNS service, including listen address, upstream resolver, search domains,
//! and IPv6 prefix settings.

use crate::resolver::recursive::UpstreamMode;
use lanforge_types::network::{
    ListenConfig,
    dns::{
        adblock::{AdblockRuleEntry, BlockingMode, RewriteRule, TimeOfDay},
        upstream::UpstreamEntry,
    },
};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// Configuration for DNS query logging.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct QueryLogConfig {
    /// Whether query logging is enabled.
    pub enabled: bool,
    /// Size of the in-memory ring buffer.
    pub ring_size: usize,
    /// Whether to persist logs to the database.
    pub persist: bool,
    /// How often to flush logs to disk (if supported/needed).
    pub flush_interval_secs: u32,
    /// Retention in hours for persisted logs.
    pub retention_hours: u32,
    /// Maximum entries in the database.
    pub max_entries: u32,
    /// Clients (MAC address, IP address, or hostname) to ignore from query logs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore_clients: Vec<String>,
}

impl Default for QueryLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ring_size: 1000,
            persist: false,
            flush_interval_secs: 30,
            retention_hours: 168, // 7 days
            max_entries: 500_000,
            ignore_clients: Vec::new(),
        }
    }
}

/// Configuration for the DNS service.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsConfig {
    /// Whether the DNS service is enabled.
    pub enabled: bool,
    /// Socket address(es) to listen on for both UDP and TCP (e.g., `[::]:53` or `["192.168.1.1:53", "[fd00::1]:53"]`).
    pub listen: ListenConfig,
    /// Upstream resolver targets.
    /// If empty, non-local queries return `REFUSED`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<UpstreamEntry>,
    /// Strategy for choosing an upstream resolver.
    pub upstream_mode: UpstreamMode,
    /// Local search domain suffixes (e.g., `["lan", "home.arpa"]`). Queries for
    /// these domains are resolved locally; others are forwarded upstream.
    pub search_domains: Vec<String>,

    /// Used to construct full addresses from 8-byte suffixes.
    pub ula_prefix: Option<Ipv6Addr>,
    /// GUA (Global Unicast Address) prefix for IPv6 resolution (e.g., `2001:db8::`).
    pub gua_prefix: Option<Ipv6Addr>,
    /// Default TTL (in seconds) for locally generated DNS records.
    pub ttl: u32,

    // ------------------------------------------------------ INTERNAL CONFIG
    /// Pre-parsed search domain labels for zero-allocation hostname matching.
    /// Default: `[[b"lan"]]`.
    #[serde(skip)]
    pub multi_search_labels: Vec<Vec<Vec<u8>>>,

    /// Whether the micro-adblocker is enabled.
    pub adblock_enabled: bool,
    /// Directory to store adblock cache files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adblock_cache_dir: Option<String>,
    /// List of URLs to fetch blocklists from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub adblock_urls: Vec<String>,
    /// List of URLs to fetch allowlists from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub adblock_allowlist_urls: Vec<String>,
    /// Local time of day to perform daily blocklist update check.
    #[serde(default)]
    pub adblock_refresh_time: TimeOfDay,
    /// How to respond to blocked queries.
    pub blocking_mode: BlockingMode,
    /// Custom IPv4 address for `BlockingMode::CustomIp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_ip_v4: Option<Ipv4Addr>,
    /// Custom IPv6 address for `BlockingMode::CustomIp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_ip_v6: Option<Ipv6Addr>,
    /// Manual DNS rewrite rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rewrites: Vec<RewriteRule>,
    /// Domains that are never blocked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowlist: Vec<String>,
    /// Custom user adblock rules (blacklist / whitelist).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub adblock_rules: Vec<AdblockRuleEntry>,

    /// How many days a device can be offline before its DNS entry is hidden.
    pub last_seen_threshold_days: u32,

    /// Optional socket address to listen for DNS-over-TLS (`DoT`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dot_listen: Option<SocketAddr>,
    /// Whether `DoT` is explicitly enabled.
    pub dot_enabled: bool,
    /// Path to the TLS certificate for `DoT`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
    /// Path to the TLS private key for `DoT`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
    /// Optional socket address to listen for DNS-over-QUIC (`DoQ`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doq_listen: Option<SocketAddr>,
    /// Whether `DoQ` is explicitly enabled.
    pub doq_enabled: bool,

    /// Query logging configuration.
    pub query_log: QueryLogConfig,
    /// Maximum number of entries in the DNS cache.
    pub cache_size: u64,
    /// Minimum TTL for cached records.
    pub cache_min_ttl: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: ListenConfig::dual_stack(53),
            upstreams: Vec::new(),
            upstream_mode: UpstreamMode::Sequential,
            search_domains: vec!["lan".to_string()],
            ula_prefix: None,
            gua_prefix: None,
            ttl: 60,
            multi_search_labels: vec![vec![b"lan".to_vec()]],
            adblock_enabled: false,
            adblock_cache_dir: None,
            adblock_urls: Vec::new(),
            adblock_allowlist_urls: Vec::new(),
            adblock_refresh_time: TimeOfDay::DEFAULT,
            blocking_mode: BlockingMode::default(),
            blocking_ip_v4: None,
            blocking_ip_v6: None,
            rewrites: Vec::new(),
            allowlist: Vec::new(),
            adblock_rules: Vec::new(),
            last_seen_threshold_days: 7,
            dot_listen: None,
            dot_enabled: false,
            tls_cert: None,
            tls_key: None,
            doq_listen: None,
            doq_enabled: false,
            query_log: QueryLogConfig::default(),
            cache_size: 5000,
            cache_min_ttl: 30,
        }
    }
}
