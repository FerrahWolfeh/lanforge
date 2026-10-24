//! Storage data types for persistence, analytics, and telemetry.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

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
