//! Storage actor query and response types for persistence decoupled via message passing.

use std::collections::HashMap;
use std::net::SocketAddr;
use serde::{Deserialize, Serialize};

use crate::auth::{ApiScopes, ApiTokenEntry, UserEntry, UserRole};
use crate::network::dns::adblock::{
    AdblockRuleAction, AdblockSourceFormat, AdblockUrlKind, RewriteAnswer,
};
use crate::network::dns::upstream::{UpstreamProtocol, UpstreamTarget};
use crate::network::dns::DnsRecordType;
use crate::network::{IpSubnet, QueryLogEntry, QueryResult};

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

/// Consolidated DNS analytics snapshot returned by the storage actor.
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

/// Request queries and commands directed to the storage persistence actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageQuery {
    // --- Auth (Tokens & Users) ---
    StoreApiToken {
        token: String,
        name: String,
        scopes: ApiScopes,
        expires_at: Option<i64>,
        now: i64,
    },
    LoadApiTokens,
    DeleteApiToken(String),
    DeleteApiTokenByIdOrName(String),
    GetApiTokenInfo(String),

    CreateUser {
        username: String,
        password_hash: String,
        role: UserRole,
        now: i64,
    },
    GetUserByUsername(String),
    ListUsers,
    UpdateUserPassword {
        username: String,
        new_hash: String,
        now: i64,
    },
    UpdateUserRole {
        username: String,
        new_role: UserRole,
        now: i64,
    },
    DeleteUser(String),
    CountUsers,

    // --- Onboarding / Provisioning ---
    IsProvisioned,
    SetProvisioned(bool),

    // --- Maintenance ---
    PruneZombies,
    PruneLogs { before: i64 },
    ClearLogs,
    ResetDb,

    // --- Leases / Logs History ---
    GetLogHistory(usize),

    // --- DNS Logs & Analytics ---
    GetDnsQueryHistory {
        limit: usize,
        offset: Option<usize>,
        client: Option<String>,
        domain: Option<String>,
        qtype: Option<DnsRecordType>,
        result: Option<QueryResult>,
    },
    GetDnsAnalytics {
        limit: usize,
        client: Option<String>,
    },

    // --- DNS Dynamic Rules & Filters ---
    UpsertDnsRewrite {
        domain: String,
        rtype: DnsRecordType,
        answer: RewriteAnswer,
    },
    DeleteDnsRewrite(i64),
    ClearDnsRewrites,

    AddDnsAllowlist(String),
    RemoveDnsAllowlist(String),
    ClearDnsAllowlist,

    SetAdblockConfigValue {
        key: String,
        value: String,
    },
    AddAdblockUrl {
        url: String,
        kind: AdblockUrlKind,
        #[serde(default)]
        format: AdblockSourceFormat,
    },
    RemoveAdblockUrl(String),
    ClearAdblockUrls,

    AddAdblockRule {
        domain: String,
        action: AdblockRuleAction,
    },
    RemoveAdblockRule(i64),
    UpdateAdblockRuleStatus {
        id: i64,
        enabled: bool,
    },
    ClearAdblockRules,

    AddDnsUpstream {
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<String>,
    },
    RemoveDnsUpstream {
        addr: SocketAddr,
        protocol: UpstreamProtocol,
        domain: Option<String>,
    },
    ClearDnsUpstreams,
    GetDnsUpstreamMode,
    SetDnsUpstreamMode(crate::network::dns::UpstreamMode),

    AddReverseResolver {
        subnet: IpSubnet,
        resolver: UpstreamTarget,
    },
    RemoveReverseResolver(IpSubnet),
    ClearReverseResolvers,
}

/// Response types produced by the storage persistence actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageQueryResult {
    Success,
    Id(i64),
    Count(usize),
    Boolean(bool),
    ApiTokens(Vec<ApiTokenEntry>),
    ApiTokenInfo(Option<(String, ApiScopes, Option<i64>)>),
    User(Option<UserEntry>),
    Users(Vec<UserEntry>),
    DnsQueryHistory {
        queries: Vec<QueryLogEntry>,
        total: usize,
    },
    DnsAnalytics(DnsAnalyticsData),
    LogHistory(Vec<crate::events::TimedEvent>),
    DnsUpstreamMode(Option<crate::network::dns::UpstreamMode>),
}
