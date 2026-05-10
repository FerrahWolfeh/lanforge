use serde::{Deserialize, Serialize};

/// Serializable snapshot of upstream health metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamHealthSnapshot {
    pub target: String,
    pub protocol: String,
    pub rtt_ewma_us: u32,
    pub last_rtt_us: u32,
    pub total_queries: u64,
    pub total_successes: u64,
    pub total_failures: u64,
    pub status: String,
    pub last_success_secs_ago: Option<u64>,
}

/// The result of a DNS query resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueryResult {
    /// Answered authoritatively from local state.
    Local,
    /// Forwarded to upstream and got a response.
    Forwarded,
    /// Blocked by the filter engine.
    Blocked,
    /// NXDOMAIN (host not found anywhere).
    NxDomain,
    /// Upstream error or timeout.
    Error,
    /// Answered from the upstream cache.
    Cached,
    /// Answered via a DNS rewrite rule.
    Rewritten,
}

/// A single DNS query log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryLogEntry {
    /// Unix epoch seconds.
    pub timestamp: u64,
    /// Client IP address.
    pub src_ip: std::net::IpAddr,
    /// Domain name queried.
    pub domain: String,
    /// Query type (A, AAAA, PTR, etc.).
    pub qtype: u16,
    /// Outcome of the query.
    pub result: QueryResult,
    /// Time spent in microseconds (0 for local/cached).
    pub upstream_us: u32,
    /// Whether the response came from the upstream cache.
    pub cached: bool,
}

/// A single DNS record entry.
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
