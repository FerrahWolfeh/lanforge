use color_eyre::Result;
use color_eyre::eyre::eyre;
use lanforge_api::api::SetLogLevelRequest;
use lanforge_api::config_file::HumanDuration;
use lanforge_types::logging::{LogFilter, LogLevelStatus, LogSource};

use crate::client::LanforgeClient;
use crate::output::{Printer, format_duration_secs};

/// Without arguments, shows the filter in force. A new filter is saved (kept across
/// restarts) unless `--for` limits it; `trace` always needs `--for` (at most 1h) and an admin.
#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct LogArgs {
    /// New filter: `info`, `debug` (lanforge's modules), `debug-all` (libraries too), `trace`,
    /// `trace-all`, `warn`, or per module: `info,lanforge_dns=debug`
    pub filter: Option<String>,
    /// Apply the filter only this long (`30m`, `2h`, `1d`), then return to the saved one
    #[arg(long = "for", value_name = "DURATION", requires = "filter")]
    pub duration: Option<String>,
    /// Drop the saved and any temporary filter: back to `RUST_LOG`
    #[arg(long, conflicts_with_all = ["filter", "duration"])]
    pub reset: bool,
}

impl LogArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        let status = if self.reset {
            client
                .set_log_level(SetLogLevelRequest {
                    filter: None,
                    duration_secs: None,
                })
                .await?
        } else if let Some(filter) = &self.filter {
            let filter: LogFilter = filter.parse().map_err(|e: String| eyre!("{e}"))?;
            let duration_secs = self
                .duration
                .as_deref()
                .map(|d| {
                    d.parse::<HumanDuration>()
                        .map(u64::from)
                        .map_err(|e| eyre!("{e}"))
                })
                .transpose()?;
            filter
                .check_duration(duration_secs)
                .map_err(|e| eyre!("{e}"))?;
            client
                .set_log_level(SetLogLevelRequest {
                    filter: Some(filter),
                    duration_secs,
                })
                .await?
        } else {
            client.log_level().await?
        };

        if printer.json {
            return printer.print_json(&status);
        }
        print_status(&status, printer, self.reset || self.filter.is_some());
        Ok(())
    }
}

fn print_status(status: &LogLevelStatus, printer: &Printer, changed: bool) {
    let origin = match status.source {
        LogSource::Default => "default".to_string(),
        LogSource::Env => "RUST_LOG".to_string(),
        LogSource::Saved => "saved".to_string(),
        LogSource::Temporary => format!(
            "temporary, {} left",
            format_duration_secs(status.expires_in_secs.unwrap_or(0))
        ),
    };
    let line = format!("Log filter: {} ({origin})", status.active);
    if changed {
        printer.success(&line);
    } else {
        printer.info(&line);
    }
    if status.source == LogSource::Temporary {
        let after = status.saved.as_ref().unwrap_or(&status.boot);
        printer.info(&format!("Then: {after}"));
    } else if status.source == LogSource::Saved {
        printer.info(&format!("RUST_LOG / default: {}", status.boot));
    }
}
