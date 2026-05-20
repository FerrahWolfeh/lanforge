use lanforge_api::api::{
    DevicesResponse, DhcpPoolsResponse, DnsAdblockStatusResponse, DnsAdblockUrlsResponse,
    DnsAllowlistResponse, DnsAnalyticsResponse, DnsCacheStatsExtResponse, DnsQueryLogResponse,
    DnsRewritesResponse, DnsStatsResponse, DnsUpstreamsResponse, LeasesResponse,
    ServiceBannersResponse, StatusResponse, TopologyResponse, WhoisResponse,
};
use lanforge_types::events::TimedEvent;
use std::collections::VecDeque;

pub struct TuiState {
    pub status: Option<StatusResponse>,
    pub service_banners: Option<ServiceBannersResponse>,
    pub dns_stats: Option<DnsStatsResponse>,
    pub dns_analytics: Option<DnsAnalyticsResponse>,
    pub dns_upstreams: Option<DnsUpstreamsResponse>,
    pub dns_query_log: Option<DnsQueryLogResponse>,
    pub dns_cache_stats: Option<DnsCacheStatsExtResponse>,
    pub dns_adblock_status: Option<DnsAdblockStatusResponse>,
    pub dns_rewrites: Option<DnsRewritesResponse>,
    pub dns_adblock_urls: Option<DnsAdblockUrlsResponse>,
    pub dns_allowlist: Option<DnsAllowlistResponse>,
    pub devices: Option<DevicesResponse>,
    pub topology: Option<TopologyResponse>,
    pub leases: Option<LeasesResponse>,
    pub dhcp_pools: Option<DhcpPoolsResponse>,
    pub events: VecDeque<TimedEvent>,
    pub selected_whois: Option<WhoisResponse>,
    pub connected: bool,
    pub connection_error: Option<String>,
}

impl Default for TuiState {
    fn default() -> Self {
        Self::new()
    }
}

impl TuiState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            status: None,
            service_banners: None,
            dns_stats: None,
            dns_analytics: None,
            dns_upstreams: None,
            dns_query_log: None,
            dns_cache_stats: None,
            dns_adblock_status: None,
            dns_rewrites: None,
            dns_adblock_urls: None,
            dns_allowlist: None,
            devices: None,
            topology: None,
            leases: None,
            dhcp_pools: None,
            events: VecDeque::with_capacity(500),
            selected_whois: None,
            connected: false,
            connection_error: None,
        }
    }

    pub fn apply_event(&mut self, event: TimedEvent) {
        if self.events.len() >= 500 {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }
}
