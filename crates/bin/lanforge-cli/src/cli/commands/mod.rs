pub mod auth;
pub mod config;
pub mod db;
pub mod devices;
pub mod dhcp;
pub mod dns;
pub mod host;
pub mod lease;
pub mod pppoe;
pub mod service;
pub mod user;

pub mod simple;
pub mod status;
#[cfg(feature = "tui")]
pub mod tui;
pub mod whois;
pub mod wol;

use chrono::{DateTime, Utc};

#[must_use]
pub fn format_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{secs}s")
    }
}

#[must_use]
pub fn format_short_relative(secs: u64) -> String {
    if secs == 0 {
        return "never".to_string();
    }
    if let Some(dt) = DateTime::<Utc>::from_timestamp(secs.cast_signed(), 0) {
        let now = Utc::now();
        let diff = dt.signed_duration_since(now);

        let mut diff_secs = diff.num_seconds();
        if diff_secs > 0 {
            return "now".to_string();
        }
        diff_secs = -diff_secs;

        if diff_secs < 60 {
            return "now".to_string();
        }

        let m = diff_secs / 60;
        let h = diff_secs / 3600;
        let d = diff_secs / 86400;
        let w = diff_secs / 604_800;

        if w > 0 {
            return format!("{w}w");
        }
        if d > 0 {
            return format!("{d}d");
        }
        if h > 0 {
            return format!("{h}h");
        }
        return format!("{m}m");
    }
    "—".to_string()
}

#[must_use]
pub fn format_relative_iso8601(secs: u64) -> String {
    if secs == 0 {
        return "never".to_string();
    }
    if let Some(dt) = DateTime::<Utc>::from_timestamp(secs.cast_signed(), 0) {
        let now = Utc::now();
        let diff = dt.signed_duration_since(now);

        let mut diff_secs = diff.num_seconds();
        let is_future = diff_secs > 0;
        if !is_future {
            diff_secs = -diff_secs;
        }

        let d = diff_secs / 86400;
        let h = (diff_secs % 86400) / 3600;

        if is_future {
            if d > 0 {
                return "until tomorrow".to_string(); // Simplification
            }
            if h > 0 {
                return format!("expires in {h}h");
            }
            return format!("expires in {}m", (diff_secs % 3600) / 60);
        }
        if d > 0 {
            return format!("{d} days ago");
        }
        if h > 0 {
            return format!("{h}h ago");
        }
        let m = (diff_secs % 3600) / 60;
        if m > 0 {
            return format!("{m}m ago");
        }
        return format!("{diff_secs}s ago");
    }
    "—".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_uptime() {
        assert_eq!(format_uptime(30), "30s");
        assert_eq!(format_uptime(60), "1m");
        assert_eq!(format_uptime(3600), "1h 0m");
        assert_eq!(format_uptime(86400 + 3600), "1d 1h 0m");
    }
}
