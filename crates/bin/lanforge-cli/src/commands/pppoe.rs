use color_eyre::Result;
use colored::Colorize;

use crate::client::LanforgeClient;
use crate::output::{Printer, format_duration_secs};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct PppoeArgs {
    #[command(subcommand)]
    pub subcommand: Option<PppoeSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum PppoeSubcommand {
    /// Show current `PPPoE` WAN session status and addressing
    Status,
    /// Cooperatively disconnect and reconnect the `PPPoE` WAN session
    Reconnect,
    /// Disconnect and terminate the active `PPPoE` WAN session
    Disconnect,
}

impl PppoeArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(PppoeSubcommand::Status) {
            PppoeSubcommand::Status => show_status(client, printer).await,
            PppoeSubcommand::Reconnect => {
                let resp = client.pppoe_reconnect().await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success(&format!("PPPoE reconnection dispatched: {}", resp.message));
                Ok(())
            }
            PppoeSubcommand::Disconnect => {
                let resp = client.pppoe_disconnect().await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success(&format!("PPPoE disconnection dispatched: {}", resp.message));
                Ok(())
            }
        }
    }
}

async fn show_status(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let status = client.pppoe_status().await?;

    if printer.json {
        return printer.print_json(&status);
    }

    println!();
    let state_str = format!("{:?}", status.state);
    let is_connected = state_str.eq_ignore_ascii_case("connected");

    let badge = if is_connected {
        "[CONNECTED]".green().bold().to_string()
    } else {
        format!("[{state_str}]").yellow().bold().to_string()
    };

    println!(
        " {} {}  {}",
        printer.status_badge(is_connected),
        "PPPoE WAN Session".bold().white(),
        badge
    );

    if !status.enabled {
        println!("    PPPoE WAN client is currently disabled in configuration.");
        return Ok(());
    }

    let ip_str = status.local_ip.map_or_else(|| "none".to_string(), |ip| ip.to_string());
    let peer_str = status.peer_ip.map_or_else(|| "none".to_string(), |ip| ip.to_string());
    let iface = status.interface.as_deref().unwrap_or("ppp0");
    let physical = status.wan_iface.as_deref().unwrap_or("wan0");
    let ac = status.ac_name.as_deref().unwrap_or("unknown AC");

    println!("    {:<18} {}", "WAN Interface:".dimmed(), format!("{iface} (via {physical})").white());
    println!("    {:<18} {}", "IPv4 Address:".dimmed(), ip_str.bold().yellow());
    println!("    {:<18} {}", "Gateway / Peer:".dimmed(), peer_str);
    println!("    {:<18} {}", "Access Conc. (AC):".dimmed(), ac);

    if let Some(uptime) = status.uptime_secs {
        println!("    {:<18} {}", "Session Uptime:".dimmed(), format_duration_secs(uptime));
    }

    if !status.dns_servers.is_empty() {
        let dns_str = status.dns_servers.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
        println!("    {:<18} {}", "DNS Resolvers:".dimmed(), dns_str);
    }

    if status.reconnect_attempts > 0 {
        println!("    {:<18} {}", "Retry Attempts:".dimmed(), status.reconnect_attempts.to_string().yellow());
    }

    if let Some(err) = &status.last_error {
        println!("    {:<18} {}", "Last Error:".dimmed(), err.red());
    }

    println!();
    Ok(())
}
