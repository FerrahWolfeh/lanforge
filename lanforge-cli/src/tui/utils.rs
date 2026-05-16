use chrono::{DateTime, Local};
use lanforge_types::{
    device::{DeviceClass, IPv6State},
    update::{InterfaceState, StaticEntry},
};
use std::time::SystemTime;

/// Returns an emoji icon for a device class.
#[must_use]
pub const fn get_class_icon(class: DeviceClass) -> &'static str {
    match class {
        DeviceClass::None => "❓",
        DeviceClass::Computer => "💻",
        DeviceClass::Mobile => "📱",
        DeviceClass::Printer => "🖨️",
        DeviceClass::Media => "📺",
        DeviceClass::IoT => "🏠",
        DeviceClass::Network => "🌐",
    }
}

/// Formats `SystemTime` into a human-readable relative duration string (e.g., "2m ago")
/// or "now" if very recent.
#[must_use]
pub fn format_relative_time(st: SystemTime) -> String {
    if st == SystemTime::UNIX_EPOCH {
        return "never".to_string();
    }
    let now = SystemTime::now();
    now.duration_since(st).map_or_else(
        |_| "future".to_string(),
        |d| {
            if d.as_secs() < 5 {
                "now".to_string()
            } else if d.as_secs() < 60 {
                format!("{}s ago", d.as_secs())
            } else if d.as_secs() < 3600 {
                format!("{}m ago", d.as_secs() / 60)
            } else if d.as_secs() < 86400 {
                format!("{}h ago", d.as_secs() / 3600)
            } else {
                format!("{}d ago", d.as_secs() / 86400)
            }
        },
    )
}

/// Formats `SystemTime` into an absolute timestamp (HH:MM:SS).
#[must_use]
pub fn format_absolute_time(st: SystemTime) -> String {
    let dt: DateTime<Local> = st.into();
    dt.format("%H:%M:%S").to_string()
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

/// Formats an `IPv6State` into a clean string.
#[must_use]
pub fn format_v6_state(state: &IPv6State) -> String {
    match state {
        IPv6State::Static(s, _) => format!("Static({s})"),
        IPv6State::Dynamic(lease) => format!("DHCP({})", lease.ip),
        IPv6State::Slaac(ip, _) => format!("SLAAC({ip})"),
        IPv6State::LinkLocal(ip, _) => format!("LinkLocal({ip})"),
        IPv6State::Discovery(ip, _) => format!("Discovered({ip})"),
    }
}

/// Formats a `StaticEntry` into a clean string.
#[must_use]
pub fn format_static_entry(entry: &StaticEntry) -> String {
    let mut parts = Vec::new();
    parts.push(format!("host: {}", entry.hostname));
    if let Some(v4) = entry.v4_static {
        parts.push(format!("v4: {v4}"));
    }
    if let Some(v6) = &entry.v6_suffix {
        parts.push(format!("v6: {v6}"));
    }
    parts.push(format!("origin: {:?}", entry.origin));
    format!("{{ {} }}", parts.join(", "))
}

/// Formats `InterfaceState` into a clean string.
#[must_use]
pub fn format_interface_state(state: &InterfaceState) -> String {
    let mut parts = Vec::new();
    if let Some((ip, mask)) = state.v4 {
        parts.push(format!("v4: {ip}/{mask}"));
    }
    if let Some(ll) = state.link_local {
        parts.push(format!("ll: {ll}"));
    }
    if let Some(gua) = state.gua {
        parts.push(format!("gua: {gua}"));
    }
    if let Some(ula) = state.ula {
        parts.push(format!("ula: {ula}"));
    }
    format!("{{ {} }}", parts.join(", "))
}
