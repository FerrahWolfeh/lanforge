//! DNS server configuration.
//!
//! Contains all settings required to run the authoritative and recursive
//! DNS service, including listen address, upstream resolver, search domains,
//! and IPv6 prefix settings.

use crate::strategy::UpstreamMode;
use lanforge_macros::ServiceConfig;
use serde::{Deserialize, Serialize};
use std::net::{Ipv6Addr, SocketAddr};
use std::str::FromStr;

/// Supported protocols for upstream DNS forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    /// Standard DNS over UDP (with TCP fallback).
    Udp,
    /// DNS over TLS (`DoT`).
    Tls,
    /// DNS over QUIC (`DoQ`).
    Quic,
}

/// An upstream resolver target with protocol and optional hostname for verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UpstreamTarget {
    /// The IP address and port of the upstream resolver.
    pub addr: SocketAddr,
    /// The protocol to use for forwarding.
    pub protocol: UpstreamProtocol,
    /// Optional hostname for TLS SNI and certificate validation (required for `DoT`).
    pub hostname: Option<String>,
}

/// An upstream target with an associated priority for failover/load-balancing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrioritizedUpstream {
    /// The target resolver.
    pub target: UpstreamTarget,
    /// Priority (lower is higher priority).
    pub priority: u32,
}

impl FromStr for UpstreamTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(stripped) = s.strip_prefix("tls://") {
            let (hostname, addr_str) = stripped.find(':').map_or_else(
                || (Some(stripped.to_string()), stripped),
                |pos| {
                    let (h, _) = stripped.split_at(pos);
                    (Some(h.to_string()), stripped)
                },
            );

            let addr = addr_str
                .parse()
                .map_err(|e| format!("Invalid TLS address '{addr_str}': {e}"))?;
            Ok(Self {
                addr,
                protocol: UpstreamProtocol::Tls,
                hostname,
            })
        } else if let Some(stripped) = s.strip_prefix("quic://") {
            let addr = stripped
                .parse()
                .map_err(|e| format!("Invalid QUIC address '{stripped}': {e}"))?;
            Ok(Self {
                addr,
                protocol: UpstreamProtocol::Quic,
                hostname: None,
            })
        } else {
            let addr_str = s.strip_prefix("udp://").unwrap_or(s);
            let addr = addr_str
                .parse()
                .map_err(|e| format!("Invalid UDP address '{addr_str}': {e}"))?;
            Ok(Self {
                addr,
                protocol: UpstreamProtocol::Udp,
                hostname: None,
            })
        }
    }
}

impl From<UpstreamTarget> for String {
    fn from(target: UpstreamTarget) -> Self {
        match target.protocol {
            UpstreamProtocol::Tls => format!("tls://{}", target.addr),
            UpstreamProtocol::Quic => format!("quic://{}", target.addr),
            UpstreamProtocol::Udp => format!("udp://{}", target.addr),
        }
    }
}

impl TryFrom<String> for UpstreamTarget {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

/// Configuration for the DNS service.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize, ServiceConfig)]
#[config(key = "dns")]
#[serde(default)]
pub struct DnsConfig {
    /// Whether the DNS service is enabled.
    pub enabled: bool,
    /// Socket address to listen on for both UDP and TCP (e.g., `0.0.0.0:53`).
    pub listen: SocketAddr,
    /// Upstream resolver targets with priorities.
    /// If empty, non-local queries return `REFUSED`.
    pub upstreams: Vec<PrioritizedUpstream>,
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

    /// Pre-parsed search domain labels for zero-allocation hostname matching.
    /// Default: `[[b"lan"]]`.
    #[serde(skip)]
    pub multi_search_labels: Vec<Vec<Vec<u8>>>,

    /// Whether the micro-adblocker is enabled.
    pub adblock_enabled: bool,
    /// List of URLs to fetch blocklists from.
    pub adblock_urls: Vec<String>,

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
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "0.0.0.0:53".parse().unwrap(),
            upstreams: Vec::new(),
            upstream_mode: UpstreamMode::Sequential,
            search_domains: vec!["lan".to_string()],
            ula_prefix: None,
            gua_prefix: None,
            ttl: 60,
            multi_search_labels: vec![vec![b"lan".to_vec()]],
            adblock_enabled: false,
            adblock_urls: Vec::new(),
            last_seen_threshold_days: 7,
            dot_listen: None,
            dot_enabled: false,
            tls_cert: None,
            tls_key: None,
            doq_listen: None,
            doq_enabled: false,
        }
    }
}
