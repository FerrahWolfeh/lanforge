use serde::{Deserialize, Serialize};
#[cfg(feature = "adblock")]

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
    QueryBlocked {
        src_addr: std::net::IpAddr,
        domain: String,
    },
    /// A DNS query was resolved.
    QueryResolved(crate::network::QueryLogEntry),
    /// Flush the DNS cache.
    #[default]
    CacheFlush,
}
