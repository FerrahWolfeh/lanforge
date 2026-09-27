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
            ServiceSubcommand::Restart { id } => control_service(client, printer, &id, ServiceAction::Restart).await,
            ServiceSubcommand::Start { id } => control_service(client, printer, &id, ServiceAction::Start).await,
            ServiceSubcommand::Stop { id } => control_service(client, printer, &id, ServiceAction::Stop).await,
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

fn render_services_table(resp: &ServiceBannersResponse, printer: &Printer) {
    if resp.banners.is_empty() {
        println!("No background services registered in daemon.");
        return;
    }

    let mut table = printer.new_table();
    table.set_header(vec!["Service", "ID", "State", "Uptime", "Metrics & Details"]);

    for banner in &resp.banners {
        let metrics_summary = if banner.stats.is_empty() {
            "-".to_string()
        } else {
            banner
                .stats
                .iter()
                .take(3)
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join(" · ")
        };

        let uptime_str = if banner.state.as_str() == "inactive" || banner.uptime_secs == 0 {
            "-".to_string()
        } else {
            format_duration_secs(banner.uptime_secs)
        };

        table.add_row(vec![
            Cell::new(&banner.name),
            Cell::new(&banner.id),
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
        b.id.eq_ignore_ascii_case(&target) || b.name.to_lowercase().contains(&target)
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
        println!("    {:<18} {}", "Uptime:".dimmed(), format_duration_secs(banner.uptime_secs));
    }

    if banner.stats.is_empty() {
        println!("    No metrics reported for this service.");
    } else {
        println!("\n  {}", "Metrics & State:".bold().cyan());
        for (k, v) in &banner.stats {
            println!("    {:<24} {}", format!("{k}:").dimmed(), v.white());
        }
    }
    println!();

    Ok(())
}
