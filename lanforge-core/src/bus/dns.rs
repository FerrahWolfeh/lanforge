#[cfg(feature = "adblock")]
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

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
    /// A diagnostic query requested via API.
    DiagnosticQuery {
        query_id: u32,
        name: String,
        record_type: String,
    },
    /// Response to a diagnostic query.
    DiagnosticResponse {
        query_id: u32,
        records: Vec<DnsRecordEntry>,
        latency_ms: u64,
        authoritative: bool,
    },
    /// Flush the DNS cache.
    CacheFlush,
    /// Request a DNS cache dump.
    CacheDumpQuery { query_id: u32 },
    /// DNS cache dump response.
    CacheDumpResponse {
        query_id: u32,
        entries: Vec<(String, String, String, u64)>, // (name, kind, data, expires_in)
    },
}
