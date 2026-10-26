use color_eyre::eyre::{Result, bail};
use colored::Colorize;
use comfy_table::Cell;

use crate::client::LanforgeClient;
use crate::output::{Printer, format_duration_secs};
use lanforge_api::api::ServiceBannersResponse;
use lanforge_types::system::ServiceAction;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub subcommand: Option<ServiceSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ServiceSubcommand {
    /// List all registered background services
    List,
    /// Restart a specific daemon service
    Restart {
        /// ID of the service to restart (e.g. '`dhcp_v4`', 'dns', 'pppoe', 'firewall')
        id: String,
    },
    /// Start a stopped service
    Start {
        /// ID of the service to start
        id: String,
    },
    /// Stop a running service
    Stop {
        /// ID of the service to stop
        id: String,
    },
    /// Show detailed telemetry metrics for a specific service
    Show {
        /// ID or name of the service
        id: String,
    },
}

impl ServiceArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(ServiceSubcommand::List) {
            ServiceSubcommand::List => list_services(client, printer).await,
            ServiceSubcommand::Restart { id } => {
                control_service(client, printer, &id, ServiceAction::Restart).await
            }
            ServiceSubcommand::Start { id } => {
                control_service(client, printer, &id, ServiceAction::Start).await
            }
            ServiceSubcommand::Stop { id } => {
                control_service(client, printer, &id, ServiceAction::Stop).await
            }
            ServiceSubcommand::Show { id } => show_service(client, printer, &id).await,
        }
    }
}

async fn list_services(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let resp = client.service_banners().await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    render_services_table(&resp, printer);
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn render_services_table(resp: &ServiceBannersResponse, printer: &Printer) {
    if resp.banners.is_empty() {
        println!("No background services registered in daemon.");
        return;
    }

    let mut table = printer.new_table();
    table.set_header(vec![
        "Service",
        "ID",
        "State",
        "Uptime",
        "Metrics & Details",
    ]);

    for banner in &resp.banners {
        let mut parts = Vec::new();
        if let Some(ref t) = banner.transport
            && (t.rx_packets > 0 || t.tx_packets > 0)
        {
            parts.push(format!(
                "RX: {} · TX: {}",
                format_bytes(t.rx_bytes),
                format_bytes(t.tx_bytes)
            ));
        }
        for (k, v) in banner.stats.iter().take(2) {
            parts.push(format!("{k}: {v}"));
        }
        let metrics_summary = if parts.is_empty() {
            "-".to_string()
        } else {
            parts.join(" · ")
        };

        let uptime_str = if banner.state.as_str() == "inactive" || banner.uptime_secs == 0 {
            "-".to_string()
        } else {
            format_duration_secs(banner.uptime_secs)
        };

        table.add_row(vec![
            Cell::new(&banner.name),
            Cell::new(banner.id),
            Cell::new(printer.service_badge(banner.state.as_str())),
            Cell::new(uptime_str),
            Cell::new(metrics_summary),
        ]);
    }

    println!("{table}");
}

async fn control_service(
    client: &LanforgeClient,
    printer: &Printer,
    id: &str,
    action: ServiceAction,
) -> Result<()> {
    let resp = client.service_control(id.to_string(), action).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    let action_str = match action {
        ServiceAction::Start => "started",
        ServiceAction::Stop => "stopped",
        ServiceAction::Restart => "restarted",
    };

    printer.success(&format!("Service '{id}' {action_str}: {}", resp.message));
    Ok(())
}

async fn show_service(client: &LanforgeClient, printer: &Printer, id: &str) -> Result<()> {
    let resp = client.service_banners().await?;
    let target = id.to_lowercase();

    let banner = resp.banners.iter().find(|b| {
        b.id.as_str().eq_ignore_ascii_case(&target) || b.name.to_lowercase().contains(&target)
    });

    let Some(banner) = banner else {
        bail!("Service '{id}' not found. Run 'lanforge service' to see all available services.");
    };

    if printer.json {
        return printer.print_json(&banner);
    }

    println!();
    let dot = printer.service_dot(banner.state.as_str());
    println!(
        " {} {}  {}  {}",
        dot,
        banner.name.bold().white(),
        format!("[{}]", banner.id).dimmed(),
        printer.service_badge(banner.state.as_str())
    );

    if banner.uptime_secs > 0 {
        println!(
            "    {:<18} {}",
            "Uptime:".dimmed(),
            format_duration_secs(banner.uptime_secs)
        );
    }

    if banner.stats.is_empty() {
        println!("    No metrics reported for this service.");
    } else {
        println!("\n  {}", "Metrics & State:".bold().cyan());
        for (k, v) in &banner.stats {
            println!("    {:<24} {}", format!("{k}:").dimmed(), v.white());
        }
    }

    if let Some(ref t) = banner.transport
        && (t.rx_packets > 0
            || t.tx_packets > 0
            || t.errors > 0
            || t.rate_limited > 0
            || t.dropped > 0)
    {
        println!("\n  {}", "Transport Telemetry:".bold().cyan());
        println!(
            "    {:<24} {} ({})",
            "RX Traffic:".dimmed(),
            format!("{} packets", t.rx_packets).white(),
            format_bytes(t.rx_bytes).dimmed()
        );
        println!(
            "    {:<24} {} ({})",
            "TX Traffic:".dimmed(),
            format!("{} packets", t.tx_packets).white(),
            format_bytes(t.tx_bytes).dimmed()
        );
        if t.rate_limited > 0 {
            println!(
                "    {:<24} {}",
                "Rate-limited:".dimmed(),
                format!("{} packets", t.rate_limited).yellow()
            );
        }
        if t.dropped > 0 {
            println!(
                "    {:<24} {}",
                "Dropped:".dimmed(),
                format!("{} packets", t.dropped).red()
            );
        }
        if t.errors > 0 {
            let err_str = t.last_error_age_secs.map_or_else(
                || format!("{} errors", t.errors),
                |age| format!("{} errors (last error {}s ago)", t.errors, age),
            );
            println!("    {:<24} {}", "Transport Errors:".dimmed(), err_str.red());
        }
    }
    println!();

    Ok(())
}
