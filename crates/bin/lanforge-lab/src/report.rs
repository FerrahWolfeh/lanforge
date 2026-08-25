use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use serde::{Deserialize, Serialize};

/// Result of a single DHCP DORA cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoraResult {
    pub client_mac: String,
    pub hostname: Option<String>,
    pub offered_ip: Option<Ipv4Addr>,
    pub assigned_ip: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    pub router: Option<Ipv4Addr>,
    pub dns_servers: Vec<Ipv4Addr>,
    pub lease_time_secs: Option<u32>,
    pub discover_to_offer_ms: f64,
    pub request_to_ack_ms: f64,
    pub total_time_ms: f64,
    pub success: bool,
    pub error: Option<String>,
}

/// Statistics and percentiles for a DHCP Storm benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpStormReport {
    pub total_clients: usize,
    pub successful_leases: usize,
    pub failed_leases: usize,
    pub duration_secs: f64,
    pub throughput_dora_per_sec: f64,
    pub min_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub max_latency_ms: f64,
}

/// Result of a single DNS query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryResult {
    pub query_domain: String,
    pub query_type: String,
    pub rcode: String,
    pub answers: Vec<String>,
    pub latency_us: u64,
    pub is_blocked: bool,
    pub resolved_ip: Option<IpAddr>,
}

/// Statistics for a DNS Flood benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsFloodReport {
    pub total_queries: usize,
    pub successful_queries: usize,
    pub failed_queries: usize,
    pub duration_secs: f64,
    pub actual_qps: f64,
    pub min_latency_us: u64,
    pub p50_latency_us: u64,
    pub p95_latency_us: u64,
    pub p99_latency_us: u64,
    pub max_latency_us: u64,
    pub blocked_count: usize,
}

/// Decoded Router Advertisement information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaDecodedInfo {
    pub router_ip: Ipv6Addr,
    pub cur_hop_limit: u8,
    pub managed_flag: bool,
    pub other_config_flag: bool,
    pub router_lifetime_secs: u16,
    pub reachable_time_ms: u32,
    pub retrans_timer_ms: u32,
    pub prefixes: Vec<RaPrefixReport>,
    pub rdnss_servers: Vec<Ipv6Addr>,
    pub dnssl_domains: Vec<String>,
    pub latency_ms: f64,
}

/// Prefix information inside a Router Advertisement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaPrefixReport {
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub on_link: bool,
    pub auto_config: bool,
    pub valid_lifetime_secs: u32,
    pub preferred_lifetime_secs: u32,
}

/// Aggregated regression test suite report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteReport {
    pub dhcp_dora_passed: bool,
    pub dhcp_result: Option<DoraResult>,
    pub dns_local_passed: bool,
    pub dns_adblock_passed: bool,
    pub dns_upstream_passed: bool,
    pub dns_results: Vec<DnsQueryResult>,
    pub all_passed: bool,
}
