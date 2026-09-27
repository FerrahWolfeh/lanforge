use color_eyre::Result;
use colored::Colorize;

use crate::client::LanforgeClient;
use crate::output::{Printer, format_duration_secs};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct FirewallArgs {
    #[command(subcommand)]
    pub subcommand: Option<FirewallSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum FirewallSubcommand {
    /// Show active nftables firewall status, mode, interfaces, and rules summary
    Status,
    /// Recompile and apply firewall rulesets in-place via Netlink (~5ms)
    Reload,
}

impl FirewallArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(FirewallSubcommand::Status) {
            FirewallSubcommand::Status => show_status(client, printer).await,
            FirewallSubcommand::Reload => {
                let resp = client.firewall_reload().await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success(&format!(
                    "Firewall rules recompiled and reloaded in-place: {}",
                    resp.message
                ));
                Ok(())
            }
        }
    }
}

async fn show_status(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let status = client.firewall_status().await?;

    if printer.json {
        return printer.print_json(&status);
    }

    println!();
    let badge = if status.enabled {
        "[ENABLED]".green().bold().to_string()
    } else {
        "[DISABLED]".yellow().bold().to_string()
    };

    println!(
        " {} {}  {}",
        printer.status_badge(status.enabled),
        "Firewall & NAT Orchestrator (nftables)".bold().white(),
        badge
    );

    println!(
        "    {:<20} {:?}",
        "Firewall Mode:".dimmed(),
        status.mode
    );

    println!(
        "    {:<20} {}",
        "NFTables Table:".dimmed(),
        status.table.bold().white()
    );

    let wan_str = status.active_wan.as_deref().unwrap_or("none");
    println!(
        "    {:<20} {}",
        "Active WAN:".dimmed(),
        wan_str.bold().yellow()
    );

    let lan_str = if status.lan_ifaces.is_empty() {
        "none".to_string()
    } else {
        status.lan_ifaces.join(", ")
    };
    println!("    {:<20} {}", "LAN Interfaces:".dimmed(), lan_str);

    let offload_str = if status.flow_offload_active {
        "active".green()
    } else {
        "inactive".dimmed()
    };
    println!("    {:<20} {}", "Flowtable Offload:".dimmed(), offload_str);

    let drop_str = if status.default_drop_active {
        "active (drop all unsolicited WAN traffic)".green()
    } else {
        "inactive".yellow()
    };
    println!("    {:<20} {}", "Default WAN Policy:".dimmed(), drop_str);

    println!(
        "    {:<20} {}",
        "Open Host Ports:".dimmed(),
        status.open_ports_count.to_string().cyan()
    );

    println!(
        "    {:<20} {}",
        "Active Rules:".dimmed(),
        status.rules_count.to_string().cyan()
    );

    let applied_str = status
        .last_applied_secs_ago
        .map_or_else(|| "never".to_string(), |s| format!("{} ago", format_duration_secs(s)));
    println!("    {:<20} {}", "Last Applied:".dimmed(), applied_str);

    println!();
    Ok(())
}
