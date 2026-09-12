use std::collections::HashMap;
use std::net::SocketAddr;

use super::common::{
    CacheMeta, HttpDataResponse, HttpPaginatedResponse, HttpWrappedResponse, LogMeta,
};
pub use lanforge_types::network::dns::{
    AdblockUrlEntry, DnsAdblockStatusResponse, DnsCacheEntry, DnsCacheResponse,
    DnsCacheStatsExtResponse, DnsStatsResponse,
};
use lanforge_types::network::{
    DnsRecordEntry, DnsRecordType, DnsReverseResolver, UpstreamHealthSnapshot,
    dns::{adblock::RewriteRule, upstream::UpstreamProtocol},
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
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct QueryRateEntry {
    pub timestamp: u64,
    pub count: u64,
    #[serde(default)]
    pub cached: u64,
    #[serde(default)]
    pub forwarded: u64,
    #[serde(default)]
    pub blocked: u64,
    #[serde(default)]
    pub local: u64,
    #[serde(default)]
    pub rewritten: u64,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub record_types: HashMap<String, u32>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub outcome_types: HashMap<String, HashMap<String, u32>>,
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
    pub top_blocked_domains: Vec<TopDomainEntry>,
    pub top_blocked_clients: Vec<TopClientEntry>,
    pub blocked_query_rate: Vec<QueryRateEntry>,
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

pub use lanforge_types::network::dns::adblock::AdblockRuleEntry;

/// Response containing custom adblock rules.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsAdblockRulesResponse {
    pub rules: Vec<AdblockRuleEntry>,
}

/// A configured DNS upstream entry.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DnsUpstreamConfig {
    pub addr: SocketAddr,
    pub protocol: UpstreamProtocol,
    pub domain: Option<String>,
}

/// Response containing all DNS reverse resolvers.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsReverseResolversResponse {
    pub resolvers: Vec<DnsReverseResolver>,
}

impl HttpWrappedResponse for DnsStatsResponse {
    type Wrapper = HttpDataResponse<DnsStatsResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for DnsAnalyticsResponse {
    type Wrapper = HttpDataResponse<DnsAnalyticsResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for DnsUpstreamsResponse {
    type Wrapper = HttpDataResponse<DnsUpstreamsResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for DnsQueryResponse {
    type Wrapper = HttpDataResponse<DnsQueryResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for DnsCacheResponse {
    type Wrapper = HttpPaginatedResponse<Vec<DnsCacheEntry>, CacheMeta>;

    fn wrap(self) -> Self::Wrapper {
        HttpPaginatedResponse {
            data: self.entries,
            meta: CacheMeta {
                total: self.total,
                limit: 50,
                offset: 0,
            },
        }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        Self {
            entries: wrapper.data,
            total: wrapper.meta.total,
        }
    }
}

impl HttpWrappedResponse for DnsCacheStatsExtResponse {
    type Wrapper = HttpDataResponse<DnsCacheStatsExtResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for DnsAdblockStatusResponse {
    type Wrapper = HttpDataResponse<DnsAdblockStatusResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for DnsAdblockUrlsResponse {
    type Wrapper = HttpDataResponse<DnsAdblockUrlsResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for DnsAdblockRulesResponse {
    type Wrapper = HttpDataResponse<DnsAdblockRulesResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for DnsAllowlistResponse {
    type Wrapper = HttpDataResponse<DnsAllowlistResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for DnsRewritesResponse {
    type Wrapper = HttpDataResponse<DnsRewritesResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for DnsQueryLogResponse {
    type Wrapper = HttpPaginatedResponse<Vec<DnsQueryLogEntry>, LogMeta>;

    fn wrap(self) -> Self::Wrapper {
        HttpPaginatedResponse {
            data: self.entries,
            meta: LogMeta {
                total: self.total,
                limit: 100,
                offset: 0,
            },
        }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        Self {
            entries: wrapper.data,
            total: wrapper.meta.total,
        }
    }
}

impl HttpWrappedResponse for DnsReverseResolversResponse {
    type Wrapper = HttpDataResponse<DnsReverseResolversResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}
