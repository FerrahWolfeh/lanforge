use color_eyre::Result;
use colored::Colorize;

use crate::client::LanforgeClient;
use crate::output::{Printer, format_duration_secs};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct RaArgs {
    #[command(subcommand)]
    pub subcommand: Option<RaSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum RaSubcommand {
    /// Show active Router Advertisement service metrics, prefixes, and timers
    Status,
    /// Trigger an immediate unsolicited Router Advertisement multicast to all-nodes (`ff02::1`)
    Trigger,
}

impl RaArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(RaSubcommand::Status) {
            RaSubcommand::Status => show_status(client, printer).await,
            RaSubcommand::Trigger => {
                let resp = client.ra_trigger().await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success(&format!("Router Advertisement dispatched: {}", resp.message));
                Ok(())
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn show_status(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let status = client.ra_status().await?;

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
        "IPv6 Router Advertisement Daemon (RA)".bold().white(),
        badge
    );

    let iface = status.interface.as_deref().unwrap_or("none");
    println!("    {:<20} {}", "Interface:".dimmed(), iface.bold().white());

    if let Some(ll) = status.link_local {
        println!("    {:<20} {}", "Link-Local IPv6:".dimmed(), ll.to_string().cyan());
    }

    if let Some(gua) = status.active_gua_prefix {
        println!("    {:<20} {}", "Active GUA Prefix:".dimmed(), format!("{gua}/64").yellow());
    }

    if let Some(ula) = status.active_ula_prefix {
        println!("    {:<20} {}", "Active ULA Prefix:".dimmed(), format!("{ula}/64").magenta());
    }

    if !status.rdnss.is_empty() {
        let mut rdnss_addrs = Vec::new();
        for rdnss in &status.rdnss {
            for addr in &rdnss.servers {
                rdnss_addrs.push(addr.to_string());
            }
        }
        if !rdnss_addrs.is_empty() {
            println!("    {:<20} {}", "Advertised RDNSS:".dimmed(), rdnss_addrs.join(", "));
        }
    }

    if !status.dnssl.is_empty() {
        let mut dnssl_domains = Vec::new();
        for dnssl in &status.dnssl {
            for domain in &dnssl.domains {
                dnssl_domains.push(domain.clone());
            }
        }
        if !dnssl_domains.is_empty() {
            println!("    {:<20} {}", "DNS Search List:".dimmed(), dnssl_domains.join(", "));
        }
    }

    if !status.deprecated_prefixes.is_empty() {
        let dep_str = status
            .deprecated_prefixes
            .iter()
            .map(|(p, rem)| format!("{p}/64 (valid: {rem}s)"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("    {:<20} {}", "Deprecated Prefixes:".dimmed(), dep_str.red());
    }

    let flags = format!(
        "Managed (M): {} · Other (O): {}",
        if status.managed { "true".yellow() } else { "false".dimmed() },
        if status.other_config { "true".yellow() } else { "false".dimmed() }
    );
    println!("    {:<20} {}", "Operating Flags:".dimmed(), flags);

    let mtu_str = status.mtu.map_or_else(|| "default".to_string(), |m| m.to_string());
    println!(
        "    {:<20} Hop Limit: {} · Priority: {:?} · Link MTU: {}",
        "Parameters:".dimmed(),
        status.hop_limit,
        status.priority,
        mtu_str
    );

    println!(
        "    {:<20} Min: {}s · Max: {}s · Lifetime: {}s",
        "Intervals:".dimmed(),
        status.min_interval_secs,
        status.max_interval_secs,
        status.router_lifetime_secs
    );

    let sent_stats = format!(
        "{} multicast · {} unicast",
        status.sent_multicast_ras.to_string().cyan(),
        status.sent_unicast_ras.to_string().cyan()
    );
    println!("    {:<20} {}", "Advertisements Sent:".dimmed(), sent_stats);

    let rs_stats = format!(
        "{} received · {} ignored",
        status.received_solicitations.to_string().green(),
        if status.ignored_solicitations > 0 {
            status.ignored_solicitations.to_string().yellow()
        } else {
            "0".dimmed()
        }
    );
    println!("    {:<20} {}", "Router Solicitations:".dimmed(), rs_stats);

    if let Some(next) = status.next_ra_in_secs {
        let last_sent = status
            .last_ra_sent_secs_ago
            .map_or_else(|| "never".to_string(), |s| format!("{s}s ago"));
        println!(
            "    {:<20} in {} (last sent {})",
            "Next Periodic RA:".dimmed(),
            format_duration_secs(next).white(),
            last_sent
        );
    }

    if let Some(uptime) = status.uptime_secs {
        println!("    {:<20} {}", "Service Uptime:".dimmed(), format_duration_secs(uptime));
    }

    println!();
    Ok(())
}
