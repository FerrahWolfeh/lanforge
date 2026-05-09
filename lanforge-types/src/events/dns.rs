use serde::{Deserialize, Serialize};
#[cfg(feature = "adblock")]
use std::net::IpAddr;

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
    QueryBlocked { src_addr: IpAddr, domain: String },
    /// Flush the DNS cache.
    #[default]
    CacheFlush,
}
