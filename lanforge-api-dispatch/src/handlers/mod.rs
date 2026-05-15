pub mod auth;
pub mod db;
pub mod devices;
pub mod dhcp;
pub mod dns;
pub mod host;
pub mod system;

use crate::ClientContext;
use chrono::{DateTime, SecondsFormat, Utc};
use lanforge_types::device::IPv6State;

impl ClientContext {
    // Utility functions shared across handlers
    pub fn last_seen_secs_ago(&self, last_seen: std::time::SystemTime) -> u64 {
        last_seen.elapsed().unwrap_or_default().as_secs()
    }
}

pub fn format_iso8601(t: std::time::SystemTime) -> String {
    let datetime: DateTime<Utc> = t.into();
    datetime.to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn get_v6_kind(state: &IPv6State, _gua_prefix: Option<&str>) -> String {
    match state {
        IPv6State::Static(..) => "Static".to_string(),
        IPv6State::Dynamic(_) => "Dynamic".to_string(),
        IPv6State::Slaac(..) => "SLAAC".to_string(),
        IPv6State::Discovery(..) => "Discovery".to_string(),
        IPv6State::LinkLocal(..) => "LinkLocal".to_string(),
    }
}
