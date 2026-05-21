use chrono::{DateTime, Local, Utc};
use lanforge_types::device::DeviceClass;

/// Returns an emoji icon for a device class string.
#[must_use]
pub const fn get_class_icon(class: DeviceClass) -> &'static str {
    match class {
        DeviceClass::Computer => "💻",
        DeviceClass::Mobile => "📱",
        DeviceClass::Printer => "🖨️",
        DeviceClass::Media => "📺",
        DeviceClass::IoT => "🏠",
        DeviceClass::Network => "🌐",
        DeviceClass::None => "❓",
    }
}

/// Formats a Unix timestamp (seconds since epoch) as a relative duration (e.g. "5m ago").
#[must_use]
pub fn parse_iso_relative(secs: u64) -> String {
    if secs == 0 {
        return "never".to_string();
    }
    DateTime::<Utc>::from_timestamp(secs.cast_signed(), 0).map_or_else(
        || "never".to_string(),
        |dt| {
            let now = Utc::now();
            let duration = now.signed_duration_since(dt);
            let diff_secs = duration.num_seconds();
            if diff_secs < 0 {
                "future".to_string()
            } else if diff_secs < 5 {
                "now".to_string()
            } else if diff_secs < 60 {
                format!("{diff_secs}s ago")
            } else if diff_secs < 3600 {
                format!("{}m ago", diff_secs / 60)
            } else if diff_secs < 86400 {
                format!("{}h ago", diff_secs / 3600)
            } else {
                format!("{}d ago", diff_secs / 86400)
            }
        },
    )
}

/// Formats a Unix timestamp (seconds since epoch) as an absolute local timestamp (HH:MM:SS).
#[must_use]
pub fn parse_iso_absolute(secs: u64) -> String {
    if secs == 0 {
        return "never".to_string();
    }
    DateTime::<Utc>::from_timestamp(secs.cast_signed(), 0).map_or_else(
        || "never".to_string(),
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
