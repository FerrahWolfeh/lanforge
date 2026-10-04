use color_eyre::Result;
use colored::Colorize;

use crate::client::LanforgeClient;
use crate::output::{Printer, format_duration_secs};

use lanforge_types::network::dns::adblock::{AdblockSourceFormat, AdblockUrlKind};
use lanforge_types::network::dns::{FilterAction, FilterOrigin};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DnsArgs {
    #[command(subcommand)]
    pub subcommand: Option<DnsSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsSubcommand {
    /// Show DNS resolver metrics, cache performance, and adblock filter status
    Status,
    /// Flush DNS resolver in-memory record cache
    Flush,
    /// Add a domain to the adblock blocklist
    Block {
        /// Fully qualified domain name to block (e.g. ads.example.com)
        domain: String,
    },
    /// Add a domain to the adblock allowlist (whitelist)
    Allow {
        /// Fully qualified domain name to allow (e.g. tracking.example.com)
        domain: String,
    },
    /// Check whether a domain is blocked or allowed by adblock rules and sources
    Check {
        /// Fully qualified domain name to check (e.g. ads.example.com)
        domain: String,
    },
    /// List all configured adblock filter sources and compilation status
    Sources,
    /// Add an adblock source URL
    SourceAdd {
        /// URL of the blocklist or allowlist
        url: String,
        /// Source format (auto, adblock, hosts, domains, wildcard-domains)
        #[arg(short, long)]
        format: Option<AdblockSourceFormat>,
        /// List kind: 'blocklist' or 'allowlist'
        #[arg(short, long, default_value = "blocklist")]
        kind: AdblockUrlKind,
    },
    /// Remove an adblock source URL
    SourceRemove {
        /// URL to remove
        url: String,
    },
    /// Temporarily or indefinitely pause DNS adblocking
    Pause {
        /// Optional duration in seconds to pause (e.g. 300 for 5 minutes). If omitted, pauses indefinitely until resumed.
        #[arg(short, long)]
        duration: Option<u64>,
    },
    /// Re-enable and resume DNS adblocking
    Resume,
}

impl DnsArgs {
    #[allow(clippy::too_many_lines)]
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(DnsSubcommand::Status) {
            DnsSubcommand::Status => show_status(client, printer).await,
            DnsSubcommand::Flush => {
                let resp = client.dns_cache_flush().await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success("DNS resolver cache flushed successfully.");
                Ok(())
            }
            DnsSubcommand::Block { domain } => {
                let resp = client.dns_block(domain.clone()).await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success(&format!("Domain '{domain}' added to blocklist: {}", resp.message));
                Ok(())
            }
            DnsSubcommand::Allow { domain } => {
                let resp = client.dns_allow(domain.clone()).await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success(&format!("Domain '{domain}' added to allowlist: {}", resp.message));
                Ok(())
            }
            DnsSubcommand::Check { domain } => {
                let resp = client.dns_adblock_check(domain.clone()).await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                println!();
                if let Some(ref m) = resp.filter {
                    let action_str = match m.action {
                        FilterAction::Block => "BLOCKED".red().bold(),
                        FilterAction::Allow => "ALLOWED".green().bold(),
                    };
                    println!("  Domain:    {}", resp.domain.bold());
                    println!("  Verdict:   {action_str}");
                    let origin_str = match m.origin {
                        FilterOrigin::UserRule => "Custom User Rule".to_string(),
                        FilterOrigin::UserAllowlist => "User Allowlist".to_string(),
                        FilterOrigin::List { source_id } => {
                            format!("Filter List #{source_id}")
                        }
                    };
                    println!("  Origin:    {}", origin_str.cyan());
                    if let Some(ref rule) = m.rule {
                        println!("  Matched:   {} (inherited rule)", rule.yellow());
                    }
                    if m.important {
                        println!("  Important: {}", "yes ($important flag)".yellow());
                    }
                    if !resp.source_matches.is_empty() {
                        println!("\n  Sources:");
                        for sm in &resp.source_matches {
                            println!("    - [{}] {}", sm.action.as_str().to_uppercase(), sm.url);
                        }
                    }
                } else {
                    println!("  Domain:    {}", resp.domain.bold());
                    println!("  Verdict:   {}", "NOT BLOCKED (default pass)".green());
                }
                println!();
                Ok(())
            }
            DnsSubcommand::Sources => {
                let resp = client.dns_adblock_sources().await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                if resp.sources.is_empty() {
                    printer.info("No adblock sources configured.");
                    return Ok(());
                }
                let mut table = printer.new_table();
                table.set_header(vec![
                    "ID",
                    "Format",
                    "Blocks",
                    "Exceptions",
                    "Status",
                    "URL",
                ]);
                for s in &resp.sources {
                    let fmt_str = match s.format_detected {
                        Some(d) if d != s.format => format!("{} ({})", s.format.as_str(), d.as_str()),
                        _ => s.format.as_str().to_string(),
                    };

                    let status_str = if s.consecutive_failures > 0 {
                        format!("FAIL ({})", s.consecutive_failures).red().to_string()
                    } else if s.last_success.is_some() {
                        "OK".green().to_string()
                    } else {
                        "PENDING".yellow().to_string()
                    };

                    table.add_row(vec![
                        s.id.to_string(),
                        fmt_str,
                        s.blocks.to_string(),
                        s.exceptions.to_string(),
                        status_str,
                        s.url.clone(),
                    ]);
                }
                println!("{table}");
                Ok(())
            }
            DnsSubcommand::SourceAdd { url, format, kind } => {
                let resp = client.dns_adblock_url_add(url.clone(), kind, format).await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success(&format!("Added adblock source URL: {url}"));
                Ok(())
            }
            DnsSubcommand::SourceRemove { url } => {
                let resp = client.dns_adblock_url_remove(url.clone()).await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success(&format!("Removed adblock source URL: {url}"));
                Ok(())
            }
            DnsSubcommand::Pause { duration } => {
                let resp = client.dns_adblock_set(false, duration).await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                let dur_str = duration.map_or_else(
                    || "indefinitely".to_string(),
                    |d| format!("for {}", format_duration_secs(d)),
                );
                printer.success(&format!("DNS adblocking paused {dur_str}: {}", resp.message));
                Ok(())
            }
            DnsSubcommand::Resume => {
                let resp = client.dns_adblock_set(true, None).await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success(&format!("DNS adblocking resumed: {}", resp.message));
                Ok(())
            }
        }
    }
}

#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
async fn show_status(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let stats_res = client.dns_stats().await;
    let adblock_res = client.dns_adblock_status().await;

    if printer.json {
        let stats = stats_res.ok();
        let adblock = adblock_res.ok();
        return printer.print_json(&serde_json::json!({
            "stats": stats,
            "adblock": adblock,
        }));
    }

    println!();
    println!(
        " {} {}",
        printer.status_badge(true),
        "DNS Resolver & Adblock Subsystem".bold().white()
    );

    if let Ok(stats) = stats_res {
        let total = stats.total_requests;
        let resolved = stats.resolved_total;
        let blocked = stats.blocked_queries;

        let blocked_pct = if total > 0 {
            format!("{:.1}%", (blocked as f64 / total as f64) * 100.0)
        } else {
            "0.0%".to_string()
        };

        let resolved_pct = if total > 0 {
            format!("{:.1}%", (resolved as f64 / total as f64) * 100.0)
        } else {
            "0.0%".to_string()
        };

        println!("    {:<20} {}", "Total Queries:".dimmed(), total.to_string().bold());
        println!(
            "    {:<20} {} ({})",
            "Resolved:".dimmed(),
            resolved.to_string().green(),
            resolved_pct
        );
        println!(
            "    {:<20} {} ({})",
            "Blocked (Adblock):".dimmed(),
            blocked.to_string().yellow(),
            blocked_pct
        );

        let hit_rate = if (stats.cache_hits + stats.cache_misses) > 0 {
            format!(
                "{:.1}%",
                (stats.cache_hits as f64 / (stats.cache_hits + stats.cache_misses) as f64) * 100.0
            )
        } else {
            "0.0%".to_string()
        };

        let cache_stats = format!(
            "{} hits ({hit_rate} hit rate) · {} misses",
            stats.cache_hits.to_string().cyan(),
            stats.cache_misses.to_string().dimmed()
        );
        println!("    {:<20} {}", "Cache Performance:".dimmed(), cache_stats);
        println!(
            "    {:<20} {} entries (capacity: {}) · {} evictions",
            "Cache Capacity:".dimmed(),
            stats.cache_entries.to_string().cyan(),
            stats.cache_capacity,
            stats.cache_evictions
        );

        if stats.upstream_errors > 0 || stats.failed_total > 0 {
            println!(
                "    {:<20} {} upstream errors · {} failed queries",
                "Errors:".dimmed(),
                stats.upstream_errors.to_string().red(),
                stats.failed_total.to_string().red()
            );
        }
    }

    if let Ok(adblock) = adblock_res {
        println!();
        let adblock_badge = if adblock.enabled {
            "[ACTIVE]".green().bold().to_string()
        } else if adblock.remaining_secs.is_some() {
            "[PAUSED TEMPORARILY]".yellow().bold().to_string()
        } else {
            "[DISABLED]".dimmed().to_string()
        };

        println!("    {:<20} {}", "Adblock Status:".dimmed(), adblock_badge);
        if let Some(rem) = adblock.remaining_secs {
            println!(
                "    {:<20} {}",
                "Pause Remaining:".dimmed(),
                format_duration_secs(rem).yellow()
            );
        }

        println!(
            "    {:<20} {} blocked · {} allowed",
            "Adblock Rules:".dimmed(),
            adblock.blocklist_size.to_string().red(),
            adblock.allowlist_size.to_string().green()
        );
        println!(
            "    {:<20} {:?}",
            "Blocking Mode:".dimmed(),
            adblock.blocking_mode
        );
    }

    println!();
    Ok(())
}
