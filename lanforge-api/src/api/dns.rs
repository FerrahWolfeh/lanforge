use std::collections::HashMap;

use lanforge_types::network::{
    DnsRecordEntry, DnsRecordType, UpstreamHealthSnapshot, dns::adblock::RewriteRule,
};
use serde::{Deserialize, Serialize};

/// A snapshot of DNS resolver statistics.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsStatsResponse {
    /// Total requests received.
    pub total_requests: u64,
    /// Number of cache hits.
    pub cache_hits: u64,
    /// Number of cache misses.
    pub cache_misses: u64,
    /// Number of upstream errors encountered.
    pub upstream_errors: u64,
    /// Number of authoritative queries resolved locally.
    pub auth_queries: u64,
    /// Number of recursive queries forwarded.
    pub recursions: u64,
    /// Number of queries blocked by the adblocker.
    pub blocked_queries: u64,
    /// Number of queries successfully resolved.
    pub resolved_total: u64,
    /// Number of queries that failed to resolve.
    pub failed_total: u64,
    /// Current number of entries in the DNS cache.
    pub cache_entries: u64,
    /// Maximum capacity of the DNS cache.
    pub cache_capacity: u64,
}

/// A single entry in the top domains list.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TopDomainEntry {
    pub domain: String,
    pub count: u64,
}

/// A single entry in the query types list.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QueryTypeEntry {
    pub qtype: String,
    pub count: u64,
}

/// A single entry in the query rate timeline.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QueryRateEntry {
    pub timestamp: u64,
    pub count: u64,
}

/// A single entry in the protocol distribution list.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProtocolStatEntry {
    pub protocol: String,
    pub count: u64,
    pub percentage: f32,
}

/// Response containing aggregated DNS analytics.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsAnalyticsResponse {
    pub top_domains: Vec<TopDomainEntry>,
    pub query_types: Vec<QueryTypeEntry>,
    pub query_rate: Vec<QueryRateEntry>,
    pub top_clients: Vec<TopClientEntry>,
    pub protocol_stats: Vec<ProtocolStatEntry>,
}

/// A single entry in the top clients list.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TopClientEntry {
    pub ip: String,
    pub hostname: Option<String>,
    pub count: u64,
}

/// A response containing status for all configured DNS upstreams.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsUpstreamsResponse {
    pub upstreams: Vec<UpstreamHealthSnapshot>,
}

/// Results of a DNS diagnostic query.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsQueryResponse {
    /// The resolved records.
    pub records: Vec<DnsRecordEntry>,
    /// Query latency in milliseconds.
    pub latency_ms: u64,
    /// Whether the result was authoritative.
    pub authoritative: bool,
}

/// DNS cache dump entry.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsCacheResponse {
    pub entries: Vec<DnsCacheEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsCacheEntry {
    pub name: String,
    pub kind: DnsRecordType,
    pub data: String,
    pub expires_in_secs: u64,
}

/// A single entry in the detailed DNS query log.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsQueryLogEntry {
    pub timestamp: u64,
    pub src_ip: String,
    pub src_mac: Option<String>,
    pub src_hostname: Option<String>,
    pub domain: String,
    pub qtype: DnsRecordType,
    pub result: String,
    pub upstream_us: u32,
    pub cached: bool,
    pub answer: Option<String>,
}

/// A response containing recent DNS query logs.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsQueryLogResponse {
    pub entries: Vec<DnsQueryLogEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsAdblockStatusResponse {
    pub enabled: bool,
    pub disabled_until: Option<u64>,
    pub remaining_secs: Option<u64>,
    pub blocklist_size: usize,
    pub allowlist_size: usize,
}

/// Response containing all DNS rewrite rules.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsRewritesResponse {
    pub rewrites: Vec<RewriteRule>,
}

/// A single entry in the DNS allowlist.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AllowlistEntry {
    pub id: i64,
    pub domain: String,
}

/// Response containing the DNS allowlist.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsAllowlistResponse {
    pub allowlist: Vec<AllowlistEntry>,
}


/// Response containing adblock source URLs.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsAdblockUrlsResponse {
    pub urls: Vec<AdblockUrlEntry>,
}

/// A single adblock source URL entry.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdblockUrlEntry {
    pub id: Option<i64>,
    pub url: String,
    pub kind: String,
}

/// In-depth DNS cache statistics.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsCacheStatsExtResponse {
    pub total_entries: u64,
    pub entries_by_type: HashMap<DnsRecordType, u64>,
    pub memory_usage_bytes: u64,
    pub average_ttl_secs: u64,
}
