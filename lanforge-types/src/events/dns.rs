use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub enum DnsEvent {
    #[cfg(feature = "adblock")]
    AdblockToggle {
        enabled: bool,
        duration_secs: Option<u64>,
    },
    #[cfg(feature = "adblock")]
    AdblockReload,
    #[cfg(feature = "adblock")]
    AdblockBlock(String),
    #[cfg(feature = "adblock")]
    AdblockAllow(String),
    #[cfg(feature = "adblock")]
    QueryBlocked {
        src_addr: std::net::IpAddr,
        domain: String,
    },
    /// A DNS query was resolved.
    QueryResolved(crate::network::QueryLogEntry),
    /// Flush the DNS cache.
    #[default]
    CacheFlush,
    /// DNS rewrite rules changed in the database.
    ConfigRewritesChanged,
    /// DNS allowlist changed in the database.
    ConfigAllowlistChanged,
    /// Adblock configuration changed in the database.
    ConfigAdblockChanged,
    /// DNS upstreams changed in the database.
    ConfigUpstreamsChanged,
}
