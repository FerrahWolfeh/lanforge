use chrono::{DateTime, Local, Utc};

/// Returns an emoji icon for a device class string.
#[must_use]
pub fn get_class_icon(class: &str) -> &'static str {
    match class.to_lowercase().as_str() {
        "computer" | "pc" | "server" => "💻",
        "mobile" | "phone" | "tablet" => "📱",
        "printer" | "scanner" => "🖨️",
        "media" | "tv" | "audio" | "speaker" => "📺",
        "iot" | "smarthome" | "sensor" => "🏠",
        "network" | "switch" | "router" | "ap" => "🌐",
        _ => "❓",
    }
}

/// Parses an ISO 8601 date string and formats it as a relative duration (e.g. "5m ago").
#[must_use]
pub fn parse_iso_relative(iso: &str) -> String {
    if iso == "never" || iso.is_empty() || iso == "—" || iso == "?" {
        return "never".to_string();
    }
    DateTime::parse_from_rfc3339(iso).map_or_else(
        |_| iso.to_string(),
        |dt| {
            let now = Utc::now();
            let dt_utc = dt.with_timezone(&Utc);
            let duration = now.signed_duration_since(dt_utc);
            let secs = duration.num_seconds();
            if secs < 0 {
                "future".to_string()
            } else if secs < 5 {
                "now".to_string()
            } else if secs < 60 {
                format!("{secs}s ago")
            } else if secs < 3600 {
                format!("{}m ago", secs / 60)
            } else if secs < 86400 {
                format!("{}h ago", secs / 3600)
            } else {
                format!("{}d ago", secs / 86400)
            }
        },
    )
}

/// Parses an ISO 8601 date string and formats it as an absolute local timestamp (HH:MM:SS).
#[must_use]
pub fn parse_iso_absolute(iso: &str) -> String {
    DateTime::parse_from_rfc3339(iso).map_or_else(
        |_| iso.to_string(),
        |dt| {
            let local_dt = dt.with_timezone(&Local);
            local_dt.format("%H:%M:%S").to_string()
        },
    )
}

/// Formats uptime seconds into a concise string (e.g. "1h 23m").
#[must_use]
pub fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

/// Formats remaining seconds into a concise duration string (e.g. "23h 15m" or "expired").
#[must_use]
pub fn format_remaining_secs(secs: i64) -> String {
    if secs < 0 {
        return "expired".to_string();
    }
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}
