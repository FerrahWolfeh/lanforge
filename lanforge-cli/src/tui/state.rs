use lanforge_api::api::{DnsStatsResponse, StatusResponse};
use lanforge_core::bus::TimedEvent;
use lanforge_core::context::state::State;
use std::collections::VecDeque;

pub struct TuiState {
    pub status: Option<StatusResponse>,
    pub state: Option<State>,
    pub dns_stats: Option<DnsStatsResponse>,
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
            state: None,
            dns_stats: None,
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
