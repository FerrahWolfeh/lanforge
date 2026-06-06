pub mod auth;
pub mod db;
pub mod devices;
pub mod dhcp;
pub mod dns;
pub mod host;
pub mod system;

use std::time::{SystemTime, UNIX_EPOCH};

use crate::ClientContext;
use chrono::{DateTime, SecondsFormat, Utc};

impl ClientContext {
    // Utility functions shared across handlers
    pub fn last_seen_secs_ago(&self, last_seen: SystemTime) -> u64 {
        last_seen.elapsed().unwrap_or_default().as_secs()
    }
}

pub fn format_iso8601(t: SystemTime) -> String {
    let datetime: DateTime<Utc> = t.into();
    datetime.to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn duration_since_epoch_u64(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}
