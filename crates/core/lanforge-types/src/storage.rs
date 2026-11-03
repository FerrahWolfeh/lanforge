//! Storage data types for persistence, analytics, and telemetry.

use crate::network::dns::{QueryLogEntry, QueryResult};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;

/// Detailed bucket metrics for DNS query activity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsQueryRateBucket {
    pub timestamp: u64,
    pub total: u64,
    pub cached: u64,
    pub forwarded: u64,
    pub blocked: u64,
    pub local: u64,
    pub rewritten: u64,
    pub record_types: HashMap<String, u32>,
    pub outcome_types: HashMap<String, HashMap<String, u32>>,
}

impl DnsQueryRateBucket {
    /// Counts one query-log line: the `repeats` queries it stands for, by outcome and type.
    pub fn add(&mut self, entry: &QueryLogEntry) {
        let n = entry.repeats;
        let n64 = u64::from(n);
        self.total += n64;
        let outcome = match entry.result {
            QueryResult::Blocked | QueryResult::CachedBlock => {
                self.blocked += n64;
                "blocked"
            }
            QueryResult::Cached | QueryResult::Coalesced => {
                self.cached += n64;
                "cached"
            }
            QueryResult::Local => {
                self.local += n64;
                "local"
            }
            QueryResult::Rewritten => {
                self.rewritten += n64;
                "rewritten"
            }
            _ => {
                self.forwarded += n64;
                "forwarded"
            }
        };
        let qtype = entry
            .qtype
            .as_static_str()
            .map_or_else(|| Cow::Owned(entry.qtype.to_string()), Cow::Borrowed);
        Self::bump(&mut self.record_types, &qtype, n);
        let per_outcome = if let Some(map) = self.outcome_types.get_mut(outcome) {
            map
        } else {
            self.outcome_types.entry(outcome.to_owned()).or_default()
        };
        Self::bump(per_outcome, &qtype, n);
    }

    fn bump(map: &mut HashMap<String, u32>, key: &str, n: u32) {
        if let Some(count) = map.get_mut(key) {
            *count = count.saturating_add(n);
        } else {
            map.insert(key.to_owned(), n);
        }
    }
}

/// Consolidated DNS analytics snapshot returned by the storage layer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsAnalyticsData {
    pub top_domains: Vec<(String, u64)>,
    pub query_types: Vec<(u16, u64)>,
    pub detailed_rates: Vec<DnsQueryRateBucket>,
    pub top_clients: Vec<(String, u64, u64)>,
    pub protocol_stats: Vec<(String, u64)>,
    pub top_blocked_domains: Vec<(String, u64)>,
    pub top_blocked_clients: Vec<(String, u64)>,
    pub blocked_query_rate: Vec<(u64, u64)>,
}
