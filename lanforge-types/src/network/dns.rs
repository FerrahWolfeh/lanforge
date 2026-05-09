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
