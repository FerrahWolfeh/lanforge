use lanforge_api::api::{
    DevicesResponse, DnsAdblockStatusResponse, DnsAnalyticsResponse, DnsQueryLogResponse,
    DnsStatsResponse, DnsUpstreamsResponse, StatusResponse, TopologyResponse,
};
use lanforge_types::events::TimedEvent;
use std::collections::VecDeque;

pub struct TuiState {
    pub status: Option<StatusResponse>,
    pub dns_stats: Option<DnsStatsResponse>,
    pub dns_analytics: Option<DnsAnalyticsResponse>,
    pub dns_upstreams: Option<DnsUpstreamsResponse>,
    pub dns_query_log: Option<DnsQueryLogResponse>,
    pub dns_adblock_status: Option<DnsAdblockStatusResponse>,
    pub devices: Option<DevicesResponse>,
    pub topology: Option<TopologyResponse>,
    pub events: VecDeque<TimedEvent>,
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
            dns_stats: None,
            dns_analytics: None,
            dns_upstreams: None,
            dns_query_log: None,
            dns_adblock_status: None,
            devices: None,
            topology: None,
            events: VecDeque::with_capacity(500),
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
