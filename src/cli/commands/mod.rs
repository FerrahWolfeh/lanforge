pub mod db;
pub mod devices;
pub mod host;
pub mod lease;
pub mod log;
pub mod status;

use crate::control::{Command as ControlCommand, Response};
use anyhow::Result;
use chrono::{DateTime, Utc};

pub trait CliCommand {
    /// Builds the request to be sent to the daemon.
    fn prepare(&mut self) -> Result<ControlCommand>;

    /// Handles the response from the daemon.
    fn on_response(&self, response: &Response) -> Result<()> {
        match response {
            Response::Error { error } => {
                println!("Erro: {error}");
            }
            Response::Success(success) => {
                println!("✓ {}", success.message);
            }
            Response::Event(e) => {
                println!("Event: {e:?}");
            }
            _ => {
                println!("Resposta inesperada: {response:?}");
            }
        }
        Ok(())
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

pub fn format_relative_iso8601(iso: &str) -> String {
    if let Ok(dt) = DateTime::parse_from_rfc3339(iso) {
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
                return "até amanhã".to_string(); // Simplification
            }
            if h > 0 {
                return format!("expira em {h}h");
            }
            return format!("expira em {}m", (secs % 3600) / 60);
        }
        if d > 0 {
            return format!("há {d} dias");
        }
        if h > 0 {
            return format!("há {h}h");
        }
        let m = (secs % 3600) / 60;
        if m > 0 {
            return format!("há {m}m");
        }
        return format!("há {secs}s");
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
