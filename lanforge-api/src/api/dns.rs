
pub use lanforge_types::network::dns::{
    AdblockUrlEntry, DnsAdblockStatusResponse, DnsCacheEntry, DnsCacheResponse,
    DnsCacheStatsExtResponse, DnsStatsResponse,
};
use lanforge_types::network::{
    DnsRecordEntry, DnsRecordType, UpstreamHealthSnapshot, dns::adblock::RewriteRule,
};
use serde::{Deserialize, Serialize};

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
    /// Detailed resolution outcome (e.g., "Rewritten", "Local", "Cached", "Forwarded", "Blocked").
    pub result: String,
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
    pub total: usize,
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

