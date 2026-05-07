use serde::{Deserialize, Serialize};
#[cfg(feature = "adblock")]
use std::net::IpAddr;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct DnsRecordEntry {
    pub name: String,
    pub kind: String,
    pub data: String,
    pub ttl: u32,
}

impl std::fmt::Display for DnsRecordEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:<5} {:<20} -> {}", self.kind, self.name, self.data)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    CacheFlush,
}
