pub mod auth;
pub mod db;
pub mod devices;
pub mod dhcp;
pub mod dns;
pub mod host;
pub mod system;

use lanforge_core::types::IPv6State;
use std::time::SystemTime;

/// Formats a `SystemTime` into an ISO 8601 string.
#[must_use]
pub fn format_iso8601(st: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = st.into();
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[must_use]
pub fn get_v6_kind(state: &IPv6State, _gua_prefix: Option<&str>) -> String {
    match state {
        IPv6State::Static(_, _) => "static".to_string(),
        IPv6State::Dynamic(_) => "dynamic".to_string(),
        IPv6State::Slaac(_, _) => "slaac".to_string(),
        IPv6State::Discovery(_, _) => "discovery".to_string(),
        IPv6State::LinkLocal(_, _) => "link-local".to_string(),
    }
}
