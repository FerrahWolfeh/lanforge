use lanforge_core::bus::TimedEvent;
use lanforge_core::context::state::State;
use serde::{Deserialize, Serialize};

pub mod common;
pub mod devices;
pub mod dhcp;
pub mod dns;
pub mod system;

pub use common::*;
pub use devices::*;
pub use dhcp::*;
pub use dns::*;
pub use system::*;

/// Represents a response sent from the daemon to a client.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    /// Detailed system status.
    Status(Box<StatusResponse>),
    /// List of managed devices.
    Devices(DevicesResponse),
    /// List of manually configured hosts.
    Hosts(HostsResponse),
    /// Generic error message.
    Error {
        /// Human-readable error description.
        error: String,
    },
    /// Generic success indicator.
    Success(SimpleSuccess),
    /// A live event from the internal bus (for 'watch' or 'log' commands).
    Event(TimedEvent),
    /// Response for a Whois query.
    Whois(Box<WhoisResponse>),
    /// Response for DNS statistics.
    DnsStats(DnsStatsResponse),
    /// Response for DNS analytics.
    DnsAnalytics(DnsAnalyticsResponse),
    /// Response for DNS upstreams status.
    DnsUpstreams(DnsUpstreamsResponse),
    /// Response for a DNS diagnostic query.
    DnsQuery(DnsQueryResponse),
    /// Response for DNS query logs.
    DnsQueryLog(DnsQueryLogResponse),
    /// Response for DNS adblock status.
    DnsAdblockStatus(DnsAdblockStatusResponse),
    /// Response for DHCP pool utilization.
    DhcpPools(DhcpPoolsResponse),
    /// Response for DNS cache dump.
    DnsCache(DnsCacheResponse),
    /// Response for a full context dump.
    ContextDump(Box<State>),
    /// List of active DHCP leases.
    Leases(LeasesResponse),
    /// Hierarchical physical topology.
    Topology(TopologyResponse),
    /// List of DNS rewrite rules.
    DnsRewrites(DnsRewritesResponse),
    /// List of DNS allowlist entries.
    DnsAllowlist(DnsAllowlistResponse),
    /// List of adblock source URLs.
    DnsAdblockUrls(DnsAdblockUrlsResponse),
}
