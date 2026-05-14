pub mod config;
pub mod db;
pub mod devices;
pub mod dhcp;
pub mod dns;
pub mod host;
pub mod lease;
pub mod log;
pub mod query;
pub mod simple;
pub mod status;
pub mod topology;
pub mod tui;
pub mod whois;
pub mod wol;

use chrono::{DateTime, Datelike, Utc};
use color_eyre::eyre::Result;
use lanforge_api::api::Command as ControlCommand;
use lanforge_api::api::Response;

pub trait CliCommand: Send {
    /// Builds the request to be sent to the daemon.
    fn prepare(&mut self) -> Result<ControlCommand>;

    /// Handles the response from the daemon.
    /// Returns `Ok(Some(Command))` if another command should be sent immediately.
    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        match response {
            Response::Error { error } => {
                println!("Error: {error}");
            }
            Response::Success(success) => {
                println!("✓ {}", success.message);
            }
            Response::Event(e) => {
                println!("Event: {e:?}");
            }
            _ => {
                println!("Unexpected response: {response:?}");
            }
        }
        Ok(None)
    }

    /// Indicates if this command expects a stream of responses (e.g. watch, log).
    fn is_streaming(&self) -> bool {
        false
    }
}

pub struct GenericHandler {
    pub cmd: ControlCommand,
    pub streaming: bool,
}

impl CliCommand for GenericHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        Ok(self.cmd.clone())
    }

    fn is_streaming(&self) -> bool {
        self.streaming
    }
}

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
pub fn format_short_relative(iso: &str) -> String {
    if let Ok(dt) = DateTime::parse_from_rfc3339(iso) {
        if dt.year() <= 1970 {
            return "never".to_string();
        }
        let now = Utc::now();
        let diff = dt.with_timezone(&Utc).signed_duration_since(now);

        let mut secs = diff.num_seconds();
        if secs > 0 {
            return "now".to_string();
        }
        secs = -secs;

        if secs < 60 {
            return "now".to_string();
        }

        let m = secs / 60;
        let h = secs / 3600;
        let d = secs / 86400;
        let w = secs / 604_800;

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
pub fn format_relative_iso8601(iso: &str) -> String {
    if let Ok(dt) = DateTime::parse_from_rfc3339(iso) {
        if dt.year() <= 1970 {
            return "never".to_string();
        }
        let now = Utc::now();
        let diff = dt.with_timezone(&Utc).signed_duration_since(now);

        let mut secs = diff.num_seconds();
        let is_future = secs > 0;
        if !is_future {
            secs = -secs;
        }

        let d = secs / 86400;
        let h = (secs % 86400) / 3600;

        if is_future {
            if d > 0 {
                return "until tomorrow".to_string(); // Simplification
            }
            if h > 0 {
                return format!("expires in {h}h");
            }
            return format!("expires in {}m", (secs % 3600) / 60);
        }
        if d > 0 {
            return format!("{d} days ago");
        }
        if h > 0 {
            return format!("{h}h ago");
        }
        let m = (secs % 3600) / 60;
        if m > 0 {
            return format!("{m}m ago");
        }
        return format!("{secs}s ago");
    }
    iso.to_string()
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
