use chrono::Utc;
use color_eyre::Result;
use colored::Colorize;
use comfy_table::{Table, presets};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct Printer {
    pub json: bool,
    pub no_color: bool,
    pub ascii: bool,
}

impl Printer {
    #[must_use]
    pub const fn new(json: bool, no_color: bool, ascii: bool) -> Self {
        Self {
            json,
            no_color,
            ascii,
        }
    }

    /// Prints a serializable struct as formatted JSON to stdout.
    pub fn print_json<T: Serialize>(&self, data: &T) -> Result<()> {
        let json_str = serde_json::to_string_pretty(data)?;
        println!("{json_str}");
        Ok(())
    }

    /// Returns a pre-configured `comfy_table::Table` tailored to terminal preferences.
    #[must_use]
    pub fn new_table(&self) -> Table {
        let mut table = Table::new();
        if self.ascii {
            table.load_preset(presets::ASCII_BORDERS_ONLY);
        } else {
            table.load_preset(presets::UTF8_FULL_CONDENSED);
        }
        table
    }

    /// Status badge for device or connection (ONLINE / OFFLINE).
    #[must_use]
    pub fn status_badge(&self, online: bool) -> String {
        if self.no_color {
            if online { "[ONLINE]".to_string() } else { "[OFFLINE]".to_string() }
        } else if online {
            "[ONLINE]".green().bold().to_string()
        } else {
            "[OFFLINE]".bright_black().to_string()
        }
    }

    /// Badge for service state (Online, Inactive, Failing, etc.)
    #[must_use]
    pub fn service_badge(&self, state: &str) -> String {
        let normalized = state.to_lowercase();
        if self.no_color {
            return format!("[{}]", state.to_uppercase());
        }

        match normalized.as_str() {
            "online" | "running" | "active" => {
                format!("[{}]", state.to_uppercase()).green().bold().to_string()
            }
            "inactive" | "disabled" | "stopped" => {
                format!("[{}]", state.to_uppercase()).bright_black().to_string()
            }
            "starting" | "initializing" => {
                format!("[{}]", state.to_uppercase()).cyan().bold().to_string()
            }
            "failing" | "failed" | "error" => {
                format!("[{}]", state.to_uppercase()).red().bold().to_string()
            }
            "backoff" | "reconnecting" => {
                format!("[{}]", state.to_uppercase()).yellow().bold().to_string()
            }
            _ => format!("[{}]", state.to_uppercase()).white().to_string(),
        }
    }

    /// Colored status bullet for services (● active, ○ inactive, ▲ degraded, ✖ error).
    #[must_use]
    pub fn service_dot(&self, state: &str) -> String {
        let normalized = state.to_lowercase();
        if self.no_color {
            return match normalized.as_str() {
                "online" | "running" | "active" => if self.ascii { "*" } else { "●" }.to_string(),
                "inactive" | "disabled" | "stopped" | "offline" => if self.ascii { "o" } else { "○" }.to_string(),
                "starting" | "initializing" | "degraded" | "backoff" => if self.ascii { "^" } else { "▲" }.to_string(),
                _ => if self.ascii { "x" } else { "✖" }.to_string(),
            };
        }

        match normalized.as_str() {
            "online" | "running" | "active" => {
                let dot = if self.ascii { "*" } else { "●" };
                dot.green().bold().to_string()
            }
            "inactive" | "disabled" | "stopped" | "offline" => {
                let dot = if self.ascii { "o" } else { "○" };
                dot.bright_black().to_string()
            }
            "starting" | "initializing" => {
                let dot = if self.ascii { "^" } else { "▲" };
                dot.cyan().bold().to_string()
            }
            "degraded" | "backoff" | "reconnecting" => {
                let dot = if self.ascii { "^" } else { "▲" };
                dot.yellow().bold().to_string()
            }
            _ => {
                let dot = if self.ascii { "x" } else { "✖" };
                dot.red().bold().to_string()
            }
        }
    }

    /// Prints a stylized section title with an optional decorative divider.
    pub fn section_header(&self, title: &str) {
        if self.json {
            return;
        }
        if self.no_color {
            println!("\n=== {title} ===");
        } else {
            let symbol = if self.ascii { ">" } else { "◆" };
            println!("\n{} {}", symbol.cyan().bold(), title.bold().white());
        }
    }

    /// Prints an informational message.
    pub fn info(&self, msg: &str) {
        if self.json {
            return;
        }
        if self.no_color {
            println!("INFO: {msg}");
        } else {
            println!("{} {msg}", "ℹ".cyan().bold());
        }
    }

    /// Prints a success message.
    pub fn success(&self, msg: &str) {
        if self.json {
            return;
        }
        if self.no_color {
            println!("SUCCESS: {msg}");
        } else {
            println!("{} {msg}", "✓".green().bold());
        }
    }

    /// Prints a warning message.
    pub fn warning(&self, msg: &str) {
        if self.json {
            return;
        }
        if self.no_color {
            println!("WARN: {msg}");
        } else {
            println!("{} {msg}", "⚠".yellow().bold());
        }
    }

    /// Prints an error message.
    pub fn error(&self, msg: &str) {
        if self.json {
            return;
        }
        if self.no_color {
            eprintln!("ERROR: {msg}");
        } else {
            eprintln!("{} {msg}", "✗".red().bold());
        }
    }
}

/// Format bytes count into human-readable representation (e.g. 1.25 MiB, 4.00 GiB).
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    bytesize::ByteSize::b(bytes).to_string()
}

/// Format a duration in seconds into a compact human-readable string (e.g. "3d 4h", "12m 30s").
#[must_use]
pub fn format_duration_secs(secs: u64) -> String {
    if secs == 0 {
        return "0s".to_string();
    }

    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let rem_secs = secs % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 && days == 0 {
        parts.push(format!("{minutes}m"));
    }
    if rem_secs > 0 && days == 0 && hours == 0 {
        parts.push(format!("{rem_secs}s"));
    }

    if parts.is_empty() {
        "0s".to_string()
    } else {
        parts.join(" ")
    }
}

/// Format a timestamp (Unix seconds) as a relative time description (e.g. "2m ago", "just now").
#[must_use]
pub fn format_time_ago(timestamp_secs: i64) -> String {
    let now = Utc::now().timestamp();
    let diff = now - timestamp_secs;

    if diff < 0 {
        return "in the future".to_string();
    }
    if diff < 10 {
        return "just now".to_string();
    }
    if diff < 60 {
        return format!("{diff}s ago");
    }
    if diff < 3600 {
        return format!("{}m ago", diff / 60);
    }
    if diff < 86400 {
        return format!("{}h ago", diff / 3600);
    }
    format!("{}d ago", diff / 86400)
}
