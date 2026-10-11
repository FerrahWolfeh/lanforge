use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use color_eyre::Result;
use color_eyre::eyre::{bail, eyre};
use colored::Colorize;
use inquire::{Confirm, Select, Text};

use lanforge_api::api::{DeviceListQuery, DnsQueryLogEntry};
use lanforge_api::rpc::RpcResponse;
use lanforge_types::events::{DnsEvent, LanforgeEvent};
#[cfg(feature = "remote")]
use lanforge_types::events::TimedEvent;
use lanforge_types::network::dns::adblock::{
    AdblockSourceFormat, AdblockUrlKind, BlockingMode, FilterAction, FilterOrigin, RewriteAnswer,
    RewriteRule, TimeOfDay,
};
use lanforge_types::network::dns::upstream::UpstreamProtocol;
use lanforge_types::network::dns::QueryResult;
use lanforge_types::network::DnsRecordType;

use crate::client::LanforgeClient;
use crate::output::{Printer, format_duration_secs};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsArgs {
    #[command(subcommand)]
    pub subcommand: Option<DnsSubcommand>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsSubcommand {
    /// Show DNS resolver health, query metrics, cache performance, and adblock status (default)
    Status,
    /// Top queried domains, top blocked domains, active clients, and query type distribution
    #[command(alias = "top", alias = "stats")]
    Analytics(DnsAnalyticsArgs),
    /// Perform an interactive diagnostic query through the local Lanforge DNS resolver
    #[command(alias = "lookup", alias = "resolve")]
    Query(DnsQueryArgs),
    /// Real-time or historical DNS query audit logs with client, domain, and outcome filters
    #[command(alias = "log", alias = "tail")]
    Logs(DnsLogsArgs),
    /// Inspect, monitor, or flush the in-memory DNS record cache
    Cache(DnsCacheArgs),
    /// Manage multi-protocol upstream forwarding resolvers (UDP, TLS/DoT, QUIC/DoQ, HTTPS/DoH)
    #[command(alias = "upstream", alias = "resolvers")]
    Upstreams(DnsUpstreamsArgs),
    /// Manage local DNS overrides, dynamic device tracking, and homelab SRV service discovery
    #[command(alias = "rewrite", alias = "records")]
    Rewrites(DnsRewritesArgs),
    /// Comprehensive adblocking, custom blocklists, allowlists, and filter source compilation
    #[command(alias = "block", alias = "filter")]
    Adblock(DnsAdblockArgs),
    /// Manage reverse resolver routing mappings (e.g. for Tailscale or subnet reverse lookups)
    #[command(alias = "reverse-resolver", alias = "rev")]
    Reverse(DnsReverseArgs),
    /// Flush DNS resolver in-memory record cache immediately
    Flush,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsAnalyticsArgs {
    /// Limit number of items in top tables
    #[arg(short = 'n', long, default_value = "10")]
    pub limit: usize,

    /// Filter analytics for a specific client IP or hostname
    #[arg(short, long)]
    pub client: Option<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsQueryArgs {
    /// Domain name to test (e.g. google.com, router.lan, ads.example.com)
    pub name: Option<String>,

    /// DNS record type to query (A, AAAA, CNAME, MX, TXT, SRV, HTTPS, PTR, ANY)
    #[arg(short = 't', long = "type")]
    pub record_type: Option<DnsRecordType>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsLogsArgs {
    /// Number of recent query entries to display
    #[arg(short = 'n', long, default_value = "25")]
    pub limit: usize,

    /// Filter query log by client IP or hostname
    #[arg(short, long)]
    pub client: Option<String>,

    /// Filter query log by domain substring
    #[arg(short, long)]
    pub domain: Option<String>,

    /// Show only blocked queries
    #[arg(short, long)]
    pub blocked: bool,

    /// Offset pagination start
    #[arg(long)]
    pub offset: Option<usize>,

    /// Continuously stream live query resolution events (Ctrl+C to stop)
    #[arg(short, long)]
    pub follow: bool,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsCacheArgs {
    #[command(subcommand)]
    pub action: Option<DnsCacheAction>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsCacheAction {
    /// View extended cache telemetry (capacity, memory, average TTL, breakdown by type)
    Status,
    /// List cached DNS entries with TTL and resolved targets
    #[command(alias = "list")]
    Dump(DnsCacheDumpArgs),
    /// Flush all in-memory cache records immediately
    #[command(alias = "clear")]
    Flush {
        /// Bypass interactive confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsCacheDumpArgs {
    /// Filter cache entries by domain substring
    #[arg(short = 'q', long)]
    pub search: Option<String>,

    /// Filter cache entries by record type
    #[arg(short = 't', long = "type")]
    pub kind: Option<DnsRecordType>,

    /// Maximum entries to return
    #[arg(short = 'n', long, default_value = "50")]
    pub limit: usize,

    /// Pagination offset
    #[arg(long)]
    pub offset: Option<usize>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsUpstreamsArgs {
    #[command(subcommand)]
    pub action: Option<DnsUpstreamsAction>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsUpstreamsAction {
    /// List configured upstream resolvers and health status (default)
    List,
    /// Add an upstream forwarding resolver
    Add(DnsUpstreamAddArgs),
    /// Remove an upstream forwarding resolver
    Remove(DnsUpstreamRemoveArgs),
    /// Remove all configured upstream resolvers
    Clear {
        /// Bypass interactive confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsUpstreamAddArgs {
    /// Resolver socket address (e.g. `1.1.1.1:53`, `1.1.1.1:853`, `[2606:4700:4700::1111]:853`)
    pub addr: Option<String>,

    /// Transport protocol (`udp`, `tls`, `quic`, `https`) - auto-inferred from port if omitted
    #[arg(short, long)]
    pub protocol: Option<UpstreamProtocol>,

    /// Optional split-DNS domain filter suffix (e.g. corp.internal, home.arpa)
    #[arg(short, long)]
    pub domain: Option<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsUpstreamRemoveArgs {
    /// Resolver socket address to remove
    pub addr: Option<String>,

    /// Transport protocol of the upstream
    #[arg(short, long)]
    pub protocol: Option<UpstreamProtocol>,

    /// Domain filter suffix of the upstream
    #[arg(short, long)]
    pub domain: Option<String>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsRewritesArgs {
    #[command(subcommand)]
    pub action: Option<DnsRewritesAction>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsRewritesAction {
    /// List active DNS rewrite rules (default)
    List,
    /// Add a DNS rewrite rule (supports IP, CNAME, `dev:<mac_or_host>`, `srv:<service>:<proto>:<dev>:<port>`)
    Add(DnsRewriteAddArgs),
    /// Remove a rewrite rule by numerical ID or domain name
    Remove {
        /// Rule ID or domain name to remove
        target: Option<String>,
    },
    /// Clear all DNS rewrite rules
    Clear {
        /// Bypass interactive confirmation prompt
        #[arg(short = 'y', long)]
        yes: bool,
    },
    /// Export all rewrite rules to a JSON file
    Export {
        /// Output file path (e.g. rewrites.json)
        file: String,
    },
    /// Import rewrite rules from a JSON file
    Import {
        /// Input file path (e.g. rewrites.json)
        file: String,
    },
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsRewriteAddArgs {
    /// Fully qualified domain name to rewrite (e.g. nas.lan, _minecraft._tcp.lan)
    pub domain: Option<String>,

    /// Answer target (e.g. `192.168.1.50`, `fd00::50`, `dev:00:11:22:33:44:55`, `srv:minecraft:tcp:nas:25565`, target.lan)
    pub answer: Option<String>,

    /// Explicit record type (A, AAAA, CNAME, Device, Service) - auto-inferred if omitted
    #[arg(short = 't', long = "type")]
    pub record_type: Option<DnsRecordType>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsAdblockArgs {
    #[command(subcommand)]
    pub action: Option<DnsAdblockAction>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsAdblockAction {
    /// Show adblocking engine status, rule counts, mode, and pause timers (default)
    Status,
    /// Add a domain to the custom blocklist
    Block {
        /// Domain name to block (e.g. tracker.example.com)
        domain: Option<String>,
    },
    /// Add a domain to the custom allowlist (whitelist)
    #[command(alias = "whitelist")]
    Allow {
        /// Domain name to allow (e.g. analytics.example.com)
        domain: Option<String>,
    },
    /// Remove a domain from the custom allowlist
    Unallow {
        /// Domain name to remove from allowlist
        domain: Option<String>,
    },
    /// List all custom allowlist entries
    #[command(alias = "whitelisted")]
    Allowlist,
    /// Test domain filter attribution (shows whether blocked, origin source, and matching rule)
    Check {
        /// Domain name to check
        domain: Option<String>,
    },
    /// Manage remote adblock filter list sources
    #[command(alias = "lists")]
    Sources(DnsAdblockSourcesArgs),
    /// Configure adblock blocking mode and sinkhole IP targets
    Config(DnsAdblockConfigArgs),
    /// Temporarily or indefinitely pause DNS adblocking
    Pause {
        /// Duration to pause (e.g. "300", "5m", "1h"). If omitted, pauses indefinitely until resumed.
        duration: Option<String>,
    },
    /// Re-enable and resume DNS adblocking immediately
    Resume,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsAdblockSourcesArgs {
    #[command(subcommand)]
    pub action: Option<DnsAdblockSourcesAction>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsAdblockSourcesAction {
    /// List configured adblock sources, formats, rule counts, and health status (default)
    List,
    /// Add an adblock source URL
    Add {
        /// URL of the blocklist or allowlist
        url: Option<String>,
        /// Source list format (auto, adblock, hosts, domains, wildcard-domains)
        #[arg(short, long)]
        format: Option<AdblockSourceFormat>,
        /// List kind ('blocklist' or 'allowlist')
        #[arg(short, long, default_value = "blocklist")]
        kind: AdblockUrlKind,
    },
    /// Remove an adblock source URL
    Remove {
        /// URL to remove
        url: Option<String>,
    },
    /// Trigger immediate re-download and re-compilation of all filter sources
    #[command(alias = "update")]
    Reload,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsAdblockConfigArgs {
    /// Blocking response mode (nxdomain, null-ip, custom-ip, refused)
    #[arg(short, long)]
    pub mode: Option<BlockingMode>,

    /// Custom IPv4 address sinkhole target (when mode is custom-ip)
    #[arg(long = "ip-v4")]
    pub ip_v4: Option<Ipv4Addr>,

    /// Custom IPv6 address sinkhole target (when mode is custom-ip)
    #[arg(long = "ip-v6")]
    pub ip_v6: Option<Ipv6Addr>,

    /// Daily scheduled update check time (HH:MM in 24h format, e.g. 03:00)
    #[arg(long = "refresh-time")]
    pub refresh_time: Option<TimeOfDay>,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsReverseArgs {
    #[command(subcommand)]
    pub action: Option<DnsReverseAction>,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsReverseAction {
    /// List configured reverse resolvers (default)
    List,
    /// Add a reverse resolver mapping for a subnet CIDR
    Add {
        /// Subnet CIDR (e.g. 100.64.0.0/10, 10.0.0.0/8)
        subnet: Option<String>,
        /// Upstream resolver URI (e.g. `udp://100.100.100.100:53`)
        resolver: Option<String>,
    },
    /// Remove a reverse resolver mapping
    Remove {
        /// Subnet CIDR to remove
        subnet: Option<String>,
    },
}

impl DnsArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand.unwrap_or(DnsSubcommand::Status) {
            DnsSubcommand::Status => show_status(client, printer).await,
            DnsSubcommand::Analytics(args) => show_analytics(args, client, printer).await,
            DnsSubcommand::Query(args) => execute_query(args, client, printer).await,
            DnsSubcommand::Logs(args) => execute_logs(args, client, printer).await,
            DnsSubcommand::Cache(args) => execute_cache(args, client, printer).await,
            DnsSubcommand::Upstreams(args) => execute_upstreams(args, client, printer).await,
            DnsSubcommand::Rewrites(args) => execute_rewrites(args, client, printer).await,
            DnsSubcommand::Adblock(args) => execute_adblock(args, client, printer).await,
            DnsSubcommand::Reverse(args) => execute_reverse(args, client, printer).await,
            DnsSubcommand::Flush => {
                let resp = client.dns_cache_flush().await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success("DNS resolver in-memory cache flushed successfully.");
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 1. Status Dashboard
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
async fn show_status(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let stats_res = client.dns_stats().await;
    let adblock_res = client.dns_adblock_status().await;
    let upstreams_res = client.dns_upstreams().await;

    if printer.json {
        return printer.print_json(&serde_json::json!({
            "stats": stats_res.ok(),
            "adblock": adblock_res.ok(),
            "upstreams": upstreams_res.ok().map(|u| u.upstreams),
        }));
    }

    println!();
    println!(
        " {} {}",
        printer.status_badge(true),
        "DNS Resolver & Adblock Subsystem".bold().white()
    );

    if let Ok(ref stats) = stats_res {
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

        println!("    {:<22} {}", "Total Queries:".dimmed(), total.to_string().bold());
        println!(
            "    {:<22} {} ({resolved_pct})",
            "Resolved:".dimmed(),
            resolved.to_string().green()
        );
        println!(
            "    {:<22} {} ({blocked_pct})",
            "Blocked (Adblock):".dimmed(),
            blocked.to_string().yellow()
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
        println!("    {:<22} {}", "Cache Performance:".dimmed(), cache_stats);
        println!(
            "    {:<22} {} entries (capacity: {}) · {} evictions",
            "Cache Capacity:".dimmed(),
            stats.cache_entries.to_string().cyan(),
            stats.cache_capacity,
            stats.cache_evictions
        );

        if stats.upstream_errors > 0 || stats.failed_total > 0 {
            println!(
                "    {:<22} {} upstream errors · {} failed queries",
                "Errors:".dimmed(),
                stats.upstream_errors.to_string().red(),
                stats.failed_total.to_string().red()
            );
        }
    }

    if let Ok(ref adblock) = adblock_res {
        println!();
        let adblock_badge = if adblock.enabled {
            "[ACTIVE]".green().bold().to_string()
        } else if adblock.remaining_secs.is_some() {
            "[PAUSED TEMPORARILY]".yellow().bold().to_string()
        } else {
            "[DISABLED]".dimmed().to_string()
        };

        println!("    {:<22} {}", "Adblock Engine:".dimmed(), adblock_badge);
        if let Some(rem) = adblock.remaining_secs {
            println!(
                "    {:<22} {}",
                "Pause Remaining:".dimmed(),
                format_duration_secs(rem).yellow()
            );
        }

        println!(
            "    {:<22} {} blocked rules · {} allowed",
            "Filter Rules:".dimmed(),
            adblock.blocklist_size.to_string().red(),
            adblock.allowlist_size.to_string().green()
        );
        println!(
            "    {:<22} {:?}",
            "Blocking Mode:".dimmed(),
            adblock.blocking_mode
        );
    }

    if let Ok(ref upstreams) = upstreams_res
        && !upstreams.upstreams.is_empty()
    {
        println!();
        println!("  {}", "Configured Forwarding Upstreams:".bold());
        let mut table = printer.new_table();
        table.set_header(vec!["Target", "Protocol", "Domain Scope", "Health", "Latency"]);
        for u in &upstreams.upstreams {
            let health_str = if u.status.is_healthy() {
                "Healthy".green().to_string()
            } else {
                "Failing".red().to_string()
            };
            let latency_str = if u.rtt_ewma_us > 0 {
                format!("{:.1}ms", f64::from(u.rtt_ewma_us) / 1000.0)
            } else {
                "—".dimmed().to_string()
            };
            let domain_str = u.domain.as_deref().unwrap_or("Global (*)");
            table.add_row(vec![
                u.target.to_string(),
                u.protocol.to_string(),
                domain_str.to_string(),
                health_str,
                latency_str,
            ]);
        }
        println!("{table}");
    }

    println!();
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Analytics Dashboard
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
async fn show_analytics(args: DnsAnalyticsArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let analytics = client.dns_analytics(Some(args.limit), args.client.clone()).await?;

    if printer.json {
        return printer.print_json(&analytics);
    }

    println!();
    println!(
        " {} {} {}",
        printer.status_badge(true),
        "DNS Resolver Analytics".bold().white(),
        args.client.as_deref().map_or_else(String::new, |c| format!("(Filter: {c})").dimmed().to_string())
    );

    // Top Domains Table
    let total_top_queries: u64 = analytics.top_domains.iter().map(|d| d.count).sum();
    if !analytics.top_domains.is_empty() {
        println!();
        println!("  {}", "Top Queried Domains:".bold());
        let mut table = printer.new_table();
        table.set_header(vec!["Domain", "Queries", "Share"]);
        for d in analytics.top_domains.iter().take(args.limit) {
            let share = if total_top_queries > 0 {
                format!("{:.1}%", (d.count as f64 / total_top_queries as f64) * 100.0)
            } else {
                "—".to_string()
            };
            table.add_row(vec![d.domain.clone(), d.count.to_string(), share]);
        }
        println!("{table}");
    }

    // Top Blocked Domains Table
    let total_blocked_queries: u64 = analytics.top_blocked_domains.iter().map(|d| d.count).sum();
    if !analytics.top_blocked_domains.is_empty() {
        println!();
        println!("  {}", "Top Blocked Domains:".bold());
        let mut table = printer.new_table();
        table.set_header(vec!["Domain", "Blocked Count", "Share"]);
        for d in analytics.top_blocked_domains.iter().take(args.limit) {
            let share = if total_blocked_queries > 0 {
                format!("{:.1}%", (d.count as f64 / total_blocked_queries as f64) * 100.0)
            } else {
                "—".to_string()
            };
            table.add_row(vec![
                d.domain.clone(),
                d.count.to_string().red().to_string(),
                share,
            ]);
        }
        println!("{table}");
    }

    // Top Active Clients Table
    if !analytics.top_clients.is_empty() {
        println!();
        println!("  {}", "Top Active Clients:".bold());
        let mut table = printer.new_table();
        table.set_header(vec!["Client IP", "Hostname", "Queries", "Blocked"]);
        for c in analytics.top_clients.iter().take(args.limit) {
            let host = c.hostname.as_deref().unwrap_or("—");
            let blocked_str = if c.blocked_count > 0 {
                c.blocked_count.to_string().red().to_string()
            } else {
                "0".dimmed().to_string()
            };
            table.add_row(vec![
                c.ip.clone(),
                host.to_string(),
                c.count.to_string(),
                blocked_str,
            ]);
        }
        println!("{table}");
    }

    // Record Types Table
    if !analytics.query_types.is_empty() {
        println!();
        println!("  {}", "Query Record Types:".bold());
        let mut table = printer.new_table();
        table.set_header(vec!["Type", "Queries"]);
        for q in &analytics.query_types {
            table.add_row(vec![q.qtype.clone(), q.count.to_string()]);
        }
        println!("{table}");
    }

    // Protocol Stats Table
    if !analytics.protocol_stats.is_empty() {
        println!();
        println!("  {}", "Protocol Distribution:".bold());
        let mut table = printer.new_table();
        table.set_header(vec!["Protocol", "Queries", "Share"]);
        for p in &analytics.protocol_stats {
            table.add_row(vec![
                p.protocol.clone(),
                p.count.to_string(),
                format!("{:.1}%", p.percentage),
            ]);
        }
        println!("{table}");
    }

    println!();
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Diagnostic Query Tool
// ---------------------------------------------------------------------------

fn ip_to_arpa(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let nibbles: Vec<u8> = v6
                .octets()
                .iter()
                .flat_map(|b| vec![b >> 4, b & 0xf])
                .collect();
            let mut arpa = String::new();
            for n in nibbles.iter().rev() {
                let _ = write!(arpa, "{n:x}.");
            }
            arpa.push_str("ip6.arpa");
            arpa
        }
    }
}

async fn execute_query(mut args: DnsQueryArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let name = match args.name.take() {
        Some(n) => n,
        None => Text::new("Domain name to query:").prompt()?,
    };

    let (final_name, record_type) = if let Ok(ip) = name.parse::<IpAddr>() {
        (ip_to_arpa(ip), args.record_type.or(Some(DnsRecordType::PTR)))
    } else {
        (name, args.record_type.or(Some(DnsRecordType::A)))
    };

    let resp = client.dns_query(final_name.clone(), record_type).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    println!();
    let auth_str = if resp.authoritative {
        format!("Authoritative ({})", resp.result).green().bold().to_string()
    } else {
        format!("Non-Authoritative ({})", resp.result).yellow().to_string()
    };

    println!(
        " {} Query for {} (Type: {:?})",
        printer.status_badge(true),
        final_name.bold().white(),
        record_type.unwrap_or(DnsRecordType::A)
    );
    println!(
        "    {:<18} {}ms  ·  {}",
        "Outcome:".dimmed(),
        resp.latency_ms.to_string().yellow(),
        auth_str
    );

    if resp.result == "Blocked" || resp.result == "CachedBlock" {
        println!("    {}", "Domain was blocked by adblock content filter.".red().bold());
    } else if resp.records.is_empty() {
        println!("    {}", "No DNS records returned.".yellow());
    } else {
        println!();
        let mut table = printer.new_table();
        table.set_header(vec!["Record", "Name", "TTL", "Answer / Target"]);
        for r in &resp.records {
            table.add_row(vec![
                r.kind.to_string().cyan().to_string(),
                r.name.clone(),
                format!("{}s", r.ttl),
                r.data.green().to_string(),
            ]);
        }
        println!("{table}");
    }

    println!();
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Query Logs & Live Follow
// ---------------------------------------------------------------------------

async fn fetch_device_map(client: &LanforgeClient) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(dev_resp) = client.list_devices(DeviceListQuery::default()).await {
        for dev in dev_resp.devices {
            if !dev.hostname.is_empty() && dev.hostname != "<unknown>" {
                if let Some(v4) = dev.v4 {
                    map.insert(v4.ip.to_string(), dev.hostname.clone());
                }
                for ip in dev.seen_v4 {
                    map.insert(ip.to_string(), dev.hostname.clone());
                }
                if let Some(v6) = dev.v6 {
                    map.insert(v6.ip.to_string(), dev.hostname.clone());
                }
                for ip in dev.ipv6_addrs {
                    map.insert(ip.addr.to_string(), dev.hostname.clone());
                }
            }
        }
    }
    map
}

#[allow(clippy::cast_precision_loss)]
fn format_log_entry(entry: &DnsQueryLogEntry, ip_to_host: &HashMap<String, String>, printer: &Printer) -> Vec<String> {
    use chrono::{DateTime, Local, Utc};
    let time_str = DateTime::<Utc>::from_timestamp(entry.timestamp.cast_signed(), 0)
        .map(|utc| DateTime::<Local>::from(utc).format("%H:%M:%S").to_string())
        .unwrap_or_default();

    let client_ip = entry.src_ip.to_string();
    let client_display = entry
        .src_hostname
        .as_deref()
        .or_else(|| ip_to_host.get(&client_ip).map(String::as_str))
        .unwrap_or(&client_ip);

    let answer_display = entry.answer.as_deref().unwrap_or("—");

    if printer.no_color {
        let latency_str = if entry.upstream_us == 0 {
            "0ms".to_string()
        } else {
            let ms = f64::from(entry.upstream_us) / 1000.0;
            format!("{ms:.1}ms")
        };
        vec![
            time_str,
            client_display.to_string(),
            entry.qtype.to_string(),
            entry.domain.to_string(),
            entry.result.to_string(),
            answer_display.to_string(),
            latency_str,
        ]
    } else {
        let outcome_str = match entry.result {
            QueryResult::Blocked => "Blocked".red().bold().to_string(),
            QueryResult::CachedBlock => "CachedBlock".yellow().bold().to_string(),
            QueryResult::Rewritten => "Rewritten".cyan().bold().to_string(),
            QueryResult::Local => "Local".green().to_string(),
            QueryResult::Forwarded => "Forwarded".green().to_string(),
            QueryResult::Cached => "Cached".cyan().to_string(),
            QueryResult::NxDomain => "NxDomain".yellow().to_string(),
            QueryResult::Error => "Error".red().to_string(),
        };

        let latency_str = if entry.upstream_us == 0 {
            "0ms".dimmed().to_string()
        } else {
            let ms = f64::from(entry.upstream_us) / 1000.0;
            if ms >= 10.0 {
                format!("{ms:.1}ms").yellow().to_string()
            } else {
                format!("{ms:.1}ms").dimmed().to_string()
            }
        };

        vec![
            time_str.dimmed().to_string(),
            client_display.bright_blue().to_string(),
            entry.qtype.to_string().cyan().to_string(),
            entry.domain.to_string(),
            outcome_str,
            answer_display.to_string(),
            latency_str,
        ]
    }
}

async fn execute_logs(args: DnsLogsArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    if !args.follow {
        let result_filter = if args.blocked {
            Some(QueryResult::Blocked)
        } else {
            None
        };
        let resp = client
            .dns_query_log(
                false,
                Some(args.limit),
                args.client,
                args.domain.clone(),
                None,
                result_filter,
                args.offset,
            )
            .await?;

        if printer.json {
            return printer.print_json(&resp);
        }

        if resp.entries.is_empty() {
            printer.info("No DNS query logs recorded.");
            return Ok(());
        }

        let ip_to_host = fetch_device_map(client).await;
        let mut table = printer.new_table();
        table.set_header(vec![
            "Time", "Client", "Type", "Domain", "Outcome", "Answer / Target", "Latency",
        ]);

        for entry in &resp.entries {
            if args.blocked && entry.result != QueryResult::Blocked && entry.result != QueryResult::CachedBlock {
                continue;
            }
            if let Some(ref d_filter) = args.domain
                && !entry.domain.contains(d_filter.as_str())
            {
                continue;
            }
            table.add_row(format_log_entry(entry, &ip_to_host, printer));
        }

        println!("{table}");
        return Ok(());
    }

    // Follow live streaming
    follow_dns_logs(args, client, printer).await
}

#[allow(clippy::too_many_lines)]
async fn follow_dns_logs(args: DnsLogsArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let ip_to_host = fetch_device_map(client).await;

    #[cfg(feature = "remote")]
    if let Some(base) = &client.remote {
        use futures::StreamExt;

        let mut params = vec!["follow=true".to_string()];
        if let Some(ref c) = args.client {
            params.push(format!("client={c}"));
        }
        if let Some(ref d) = args.domain {
            params.push(format!("domain={d}"));
        }
        if args.blocked {
            params.push("result=blocked".to_string());
        }
        let url = format!("{base}/api/v1/dns/logs?{}", params.join("&"));
        let mut stream = client.http_stream_url(&url).await?;
        println!("Streaming DNS queries from remote gateway (Ctrl+C to stop)...");
        while let Some(chunk) = stream.next().await {
            if let Ok(bytes) = chunk {
                let s = String::from_utf8_lossy(&bytes);
                for line in s.lines() {
                    if let Some(json_str) = line.strip_prefix("data: ")
                        && let Ok(timed_event) = serde_json::from_str::<TimedEvent>(json_str)
                        && let LanforgeEvent::Dns(DnsEvent::QueryResolved(q)) = timed_event.event
                    {
                        if args.blocked && q.result != QueryResult::Blocked && q.result != QueryResult::CachedBlock {
                            continue;
                        }
                        if let Some(ref d_filter) = args.domain
                            && !q.domain.contains(d_filter.as_str())
                        {
                            continue;
                        }
                        let entry = DnsQueryLogEntry {
                            timestamp: q.timestamp,
                            src_ip: q.src_ip,
                            domain: q.domain.clone(),
                            src_hostname: None,
                            answer: q.answer.clone(),
                            src_mac: q.src_mac,
                            result: q.result,
                            cached: q.cached,
                            qtype: q.qtype,
                            upstream_us: q.upstream_us,
                            filter: None,
                        };
                        let cols = format_log_entry(&entry, &ip_to_host, printer);
                        println!("{}", cols.join(" │ "));
                    }
                }
            }
        }
        return Ok(());
    }

    // Local UDS stream
    let mut rpc = client.connect_rpc().await?;
    let result_filter = if args.blocked {
        Some(QueryResult::Blocked)
    } else {
        None
    };
    let _ = rpc
        .dns_query_log(
            true,
            Some(args.limit),
            args.client,
            args.domain.clone(),
            None,
            result_filter,
            args.offset,
        )
        .await?;

    println!("Streaming live DNS queries from local daemon (Ctrl+C to stop)...");
    loop {
        match rpc.next_response().await {
            Ok(RpcResponse::Event(event)) => {
                if let LanforgeEvent::Dns(DnsEvent::QueryResolved(q)) = event.event {
                    if args.blocked && q.result != QueryResult::Blocked && q.result != QueryResult::CachedBlock {
                        continue;
                    }
                    if let Some(ref d_filter) = args.domain
                        && !q.domain.contains(d_filter.as_str())
                    {
                        continue;
                    }
                    let entry = DnsQueryLogEntry {
                        timestamp: q.timestamp,
                        src_ip: q.src_ip,
                        domain: q.domain.clone(),
                        src_hostname: None,
                        answer: q.answer.clone(),
                        src_mac: q.src_mac,
                        result: q.result,
                        cached: q.cached,
                        qtype: q.qtype,
                        upstream_us: q.upstream_us,
                        filter: None,
                    };
                    let cols = format_log_entry(&entry, &ip_to_host, printer);
                    println!("{}", cols.join(" │ "));
                }
            }
            Ok(_) => {}
            Err(e) => {
                if e.to_string().contains("UnexpectedEof") || e.to_string().contains("early eof") {
                    break;
                }
                bail!("RPC Stream Error: {e}");
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 5. In-Memory Cache Management
// ---------------------------------------------------------------------------

async fn execute_cache(args: DnsCacheArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    match args.action.unwrap_or(DnsCacheAction::Status) {
        DnsCacheAction::Status => show_cache_status(client, printer).await,
        DnsCacheAction::Dump(dump_args) => dump_cache(dump_args, client, printer).await,
        DnsCacheAction::Flush { yes } => flush_cache(yes, client, printer).await,
    }
}

async fn show_cache_status(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let ext = client.dns_cache_stats_ext().await?;

    if printer.json {
        return printer.print_json(&ext);
    }

    println!();
    println!(
        " {} {}",
        printer.status_badge(true),
        "DNS In-Memory Cache Telemetry".bold().white()
    );
    println!("    {:<22} {}", "Total Entries:".dimmed(), ext.total_entries.to_string().bold());
    println!("    {:<22} {} bytes", "Memory Usage:".dimmed(), ext.memory_usage_bytes.to_string().cyan());
    println!("    {:<22} {}s", "Average TTL:".dimmed(), ext.average_ttl_secs.to_string().yellow());

    if !ext.entries_by_type.is_empty() {
        println!();
        println!("  {}", "Entries Cached by Record Type:".bold());
        let mut table = printer.new_table();
        table.set_header(vec!["Record Type", "Count"]);
        for (rtype, count) in &ext.entries_by_type {
            table.add_row(vec![format!("{rtype:?}"), count.to_string()]);
        }
        println!("{table}");
    }

    println!();
    Ok(())
}

async fn dump_cache(args: DnsCacheDumpArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let cache = client
        .dns_cache_dump(Some(args.limit), args.offset, args.search, args.kind)
        .await?;

    if printer.json {
        return printer.print_json(&cache);
    }

    if cache.entries.is_empty() {
        printer.info("DNS record cache is currently empty.");
        return Ok(());
    }

    println!();
    println!(
        " {} Cache Dump ({} total entries)",
        printer.status_badge(true),
        cache.total
    );

    let mut table = printer.new_table();
    table.set_header(vec!["Domain", "Type", "Expires In", "Cached Answer"]);
    for e in &cache.entries {
        table.add_row(vec![
            e.name.clone(),
            format!("{:?}", e.kind).cyan().to_string(),
            format!("{}s", e.expires_in_secs).yellow().to_string(),
            e.data.green().to_string(),
        ]);
    }
    println!("{table}");
    println!();
    Ok(())
}

async fn flush_cache(yes: bool, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    if !yes && !printer.yes {
        let confirmed = Confirm::new("Are you sure you want to flush the DNS resolver cache?")
            .with_default(false)
            .prompt()?;
        if !confirmed {
            printer.info("Cache flush cancelled.");
            return Ok(());
        }
    }

    let resp = client.dns_cache_flush().await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success("DNS record cache flushed successfully.");
    Ok(())
}

// ---------------------------------------------------------------------------
// 6. Upstreams Forwarding Resolvers
// ---------------------------------------------------------------------------

#[must_use]
pub fn infer_upstream_protocol(addr: &str, proto: Option<UpstreamProtocol>) -> UpstreamProtocol {
    if let Some(p) = proto {
        return p;
    }
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        match sa.port() {
            853 => return UpstreamProtocol::Tls,
            443 => return UpstreamProtocol::Https,
            _ => return UpstreamProtocol::Udp,
        }
    }
    UpstreamProtocol::Udp
}

async fn execute_upstreams(args: DnsUpstreamsArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    match args.action.unwrap_or(DnsUpstreamsAction::List) {
        DnsUpstreamsAction::List => list_upstreams(client, printer).await,
        DnsUpstreamsAction::Add(add_args) => add_upstream(add_args, client, printer).await,
        DnsUpstreamsAction::Remove(rem_args) => remove_upstream(rem_args, client, printer).await,
        DnsUpstreamsAction::Clear { yes } => clear_upstreams(yes, client, printer).await,
    }
}

async fn list_upstreams(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let resp = client.dns_upstreams().await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    if resp.upstreams.is_empty() {
        printer.info("No DNS upstreams configured.");
        return Ok(());
    }

    println!();
    println!(
        " {} {}",
        printer.status_badge(true),
        "DNS Forwarding Upstreams".bold().white()
    );

    let mut table = printer.new_table();
    table.set_header(vec!["Target", "Protocol", "Domain Scope", "Health", "Avg Latency"]);
    for u in &resp.upstreams {
        let health_str = if u.status.is_healthy() {
            "Healthy".green().to_string()
        } else {
            "Failing".red().to_string()
        };
        let latency_str = if u.rtt_ewma_us > 0 {
            format!("{:.1}ms", f64::from(u.rtt_ewma_us) / 1000.0)
        } else {
            "—".dimmed().to_string()
        };
        let domain_str = u.domain.as_deref().unwrap_or("Global (*)");
        table.add_row(vec![
            u.target.to_string(),
            u.protocol.to_string(),
            domain_str.to_string(),
            health_str,
            latency_str,
        ]);
    }
    println!("{table}");
    println!();
    Ok(())
}

async fn add_upstream(mut args: DnsUpstreamAddArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let addr_str = match args.addr.take() {
        Some(a) => a,
        None => Text::new("Upstream socket address (IP:Port):").prompt()?,
    };

    let addr: SocketAddr = if let Ok(sa) = addr_str.parse() {
        sa
    } else if let Ok(ip) = addr_str.parse::<IpAddr>() {
        SocketAddr::new(ip, 53)
    } else {
        bail!("Invalid socket address '{addr_str}'. Expected format IP:PORT (e.g. 1.1.1.1:53).");
    };

    let proto = infer_upstream_protocol(&addr_str, args.protocol);

    let resp = client.dns_upstream_add(addr, proto, args.domain.clone()).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    let domain_info = args.domain.as_deref().map_or_else(
        || "globally".to_string(),
        |d| format!("for domain '{d}'"),
    );
    printer.success(&format!("Added DNS upstream {addr} ({proto}) {domain_info}."));
    Ok(())
}

async fn remove_upstream(mut args: DnsUpstreamRemoveArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let (addr, proto, domain) = if let (Some(a), Some(p)) = (args.addr.take(), args.protocol.take()) {
        let parsed_addr: SocketAddr = a.parse().map_err(|e| eyre!("Invalid address: {e}"))?;
        (parsed_addr, p, args.domain.take())
    } else {
        let resp = client.dns_upstreams().await?;
        if resp.upstreams.is_empty() {
            bail!("No configured upstreams to remove.");
        }
        let items: Vec<String> = resp
            .upstreams
            .iter()
            .map(|u| {
                let d = u.domain.as_deref().unwrap_or("Global");
                format!("{} ({}) [{}]", u.target, u.protocol, d)
            })
            .collect();
        let selected = Select::new("Select upstream to remove:", items).prompt()?;
        let chosen = resp
            .upstreams
            .into_iter()
            .find(|u| {
                let d = u.domain.as_deref().unwrap_or("Global");
                format!("{} ({}) [{}]", u.target, u.protocol, d) == selected
            })
            .ok_or_else(|| eyre!("Selection error"))?;
        (chosen.target, chosen.protocol, chosen.domain)
    };

    let resp = client.dns_upstream_remove(addr, proto, domain.clone()).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    printer.success(&format!("Removed DNS upstream {addr} ({proto})."));
    Ok(())
}

async fn clear_upstreams(yes: bool, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    if !yes && !printer.yes {
        let confirmed = Confirm::new("Are you sure you want to remove ALL configured DNS upstreams?")
            .with_default(false)
            .prompt()?;
        if !confirmed {
            printer.info("Operation cancelled.");
            return Ok(());
        }
    }

    let resp = client.dns_upstream_clear().await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success("All configured DNS upstreams cleared successfully.");
    Ok(())
}

// ---------------------------------------------------------------------------
// 7. Rewrites & Local Records
// ---------------------------------------------------------------------------

pub fn infer_rewrite_type_and_answer(
    domain: &str,
    answer_str: &str,
    explicit_type: Option<DnsRecordType>,
) -> Result<(DnsRecordType, RewriteAnswer)> {
    let parsed_answer: RewriteAnswer = answer_str
        .parse()
        .map_err(|e: String| eyre!("Invalid answer format '{answer_str}': {e}"))?;

    let inferred_rtype = match &parsed_answer {
        RewriteAnswer::A(_) => DnsRecordType::A,
        RewriteAnswer::Aaaa(_) => DnsRecordType::AAAA,
        RewriteAnswer::Cname(_) => DnsRecordType::CNAME,
        RewriteAnswer::Device { .. } => DnsRecordType::Device,
        RewriteAnswer::Service { .. } => DnsRecordType::SRV,
    };

    let final_rtype = explicit_type.unwrap_or(inferred_rtype);
    let _ = domain; // used in context
    Ok((final_rtype, parsed_answer))
}

async fn execute_rewrites(args: DnsRewritesArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    match args.action.unwrap_or(DnsRewritesAction::List) {
        DnsRewritesAction::List => list_rewrites(client, printer).await,
        DnsRewritesAction::Add(add_args) => add_rewrite(add_args, client, printer).await,
        DnsRewritesAction::Remove { target } => remove_rewrite(target, client, printer).await,
        DnsRewritesAction::Clear { yes } => clear_rewrites(yes, client, printer).await,
        DnsRewritesAction::Export { file } => export_rewrites(file, client, printer).await,
        DnsRewritesAction::Import { file } => import_rewrites(file, client, printer).await,
    }
}

async fn list_rewrites(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let resp = client.dns_rewrites().await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    if resp.rewrites.is_empty() {
        printer.info("No DNS rewrite rules configured.");
        return Ok(());
    }

    println!();
    println!(
        " {} {}",
        printer.status_badge(true),
        "DNS Rewrites & Local Overrides".bold().white()
    );

    let mut table = printer.new_table();
    table.set_header(vec!["ID", "Domain", "Type", "Target / Answer"]);
    for r in &resp.rewrites {
        let id_str = r.id.map_or_else(|| "—".to_string(), |id| id.to_string());
        table.add_row(vec![
            id_str,
            r.domain.clone(),
            r.rtype.to_string().cyan().to_string(),
            r.answer.to_string().green().to_string(),
        ]);
    }
    println!("{table}");
    println!();
    Ok(())
}

async fn add_rewrite(mut args: DnsRewriteAddArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let domain = match args.domain.take() {
        Some(d) => d,
        None => Text::new("Domain name to rewrite (e.g. nas.lan):").prompt()?,
    };

    let answer_str = match args.answer.take() {
        Some(a) => a,
        None => Text::new("Answer target (IP, CNAME, dev:MAC, srv:SVC:PROTO:DEV:PORT):").prompt()?,
    };

    let (rtype, answer) = infer_rewrite_type_and_answer(&domain, &answer_str, args.record_type)?;

    let rule = RewriteRule {
        id: None,
        domain: domain.clone(),
        rtype,
        answer,
    };

    let resp = client.dns_rewrite_add(rule).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    printer.success(&format!("Added rewrite rule: {domain} -> {answer_str} ({rtype})"));
    Ok(())
}

async fn remove_rewrite(target: Option<String>, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let resp = client.dns_rewrites().await?;
    if resp.rewrites.is_empty() {
        bail!("No rewrite rules to remove.");
    }

    let rule_id = if let Some(ref t) = target {
        if let Ok(id) = t.parse::<i64>() {
            id
        } else if let Some(rule) = resp.rewrites.iter().find(|r| r.domain == *t) {
            rule.id.ok_or_else(|| eyre!("Rule has no ID"))?
        } else {
            bail!("Rewrite rule for '{t}' not found.");
        }
    } else {
        let items: Vec<String> = resp
            .rewrites
            .iter()
            .map(|r| {
                let id = r.id.unwrap_or(0);
                format!("#{id} {} -> {}", r.domain, r.answer)
            })
            .collect();
        let selected = Select::new("Select rewrite rule to remove:", items).prompt()?;
        let chosen = resp
            .rewrites
            .into_iter()
            .find(|r| {
                let id = r.id.unwrap_or(0);
                format!("#{id} {} -> {}", r.domain, r.answer) == selected
            })
            .ok_or_else(|| eyre!("Selection error"))?;
        chosen.id.ok_or_else(|| eyre!("Rule has no ID"))?
    };

    let remove_resp = client.dns_rewrite_remove(rule_id).await?;

    if printer.json {
        return printer.print_json(&remove_resp);
    }

    printer.success(&format!("Removed DNS rewrite rule #{rule_id}."));
    Ok(())
}

async fn clear_rewrites(yes: bool, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    if !yes && !printer.yes {
        let confirmed = Confirm::new("Are you sure you want to clear ALL DNS rewrite rules?")
            .with_default(false)
            .prompt()?;
        if !confirmed {
            printer.info("Operation cancelled.");
            return Ok(());
        }
    }

    let resp = client.dns_rewrite_clear().await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success("All DNS rewrite rules cleared successfully.");
    Ok(())
}

async fn export_rewrites(file: String, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let resp = client.dns_rewrites().await?;
    let json = serde_json::to_string_pretty(&resp.rewrites)?;
    std::fs::write(&file, json)?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success(&format!(
        "Exported {} rewrite rules to '{}'.",
        resp.rewrites.len(),
        file
    ));
    Ok(())
}

async fn import_rewrites(file: String, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let content = std::fs::read_to_string(&file)?;
    let rules: Vec<RewriteRule> = serde_json::from_str(&content)?;
    let count = rules.len();
    let resp = client.dns_rewrite_import(rules).await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success(&format!("Imported {count} rewrite rules from '{file}'."));
    Ok(())
}

// ---------------------------------------------------------------------------
// 8. Adblock & Filter Engine
// ---------------------------------------------------------------------------

pub fn parse_pause_duration(s: &str) -> Result<u64> {
    let trimmed = s.trim();
    if let Ok(secs) = trimmed.parse::<u64>() {
        return Ok(secs);
    }
    if let Ok(d) = duration_str::parse_std(trimmed) {
        return Ok(d.as_secs());
    }
    bail!("Invalid duration format '{s}'. Expected seconds (e.g. 300) or duration string (e.g. 5m, 1h).");
}

async fn execute_adblock(args: DnsAdblockArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    match args.action.unwrap_or(DnsAdblockAction::Status) {
        DnsAdblockAction::Status => show_adblock_status(client, printer).await,
        DnsAdblockAction::Block { domain } => add_adblock_block(domain, client, printer).await,
        DnsAdblockAction::Allow { domain } => add_adblock_allow(domain, client, printer).await,
        DnsAdblockAction::Unallow { domain } => remove_adblock_allow(domain, client, printer).await,
        DnsAdblockAction::Allowlist => show_adblock_allowlist(client, printer).await,
        DnsAdblockAction::Check { domain } => check_adblock_domain(domain, client, printer).await,
        DnsAdblockAction::Sources(src_args) => execute_adblock_sources(src_args, client, printer).await,
        DnsAdblockAction::Config(cfg_args) => execute_adblock_config(cfg_args, client, printer).await,
        DnsAdblockAction::Pause { duration } => pause_adblock(duration, client, printer).await,
        DnsAdblockAction::Resume => resume_adblock(client, printer).await,
    }
}

async fn show_adblock_status(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let status = client.dns_adblock_status().await?;

    if printer.json {
        return printer.print_json(&status);
    }

    println!();
    println!(
        " {} {}",
        printer.status_badge(true),
        "DNS Adblock Engine Status".bold().white()
    );

    let badge = if status.enabled {
        "[ENABLED]".green().bold().to_string()
    } else if status.remaining_secs.is_some() {
        "[PAUSED TEMPORARILY]".yellow().bold().to_string()
    } else {
        "[DISABLED]".dimmed().to_string()
    };

    println!("    {:<22} {badge}", "Engine State:".dimmed());
    if let Some(rem) = status.remaining_secs {
        println!(
            "    {:<22} {}",
            "Remaining Pause:".dimmed(),
            format_duration_secs(rem).yellow()
        );
    }

    println!(
        "    {:<22} {} blocked rules · {} allowed",
        "Rule Counts:".dimmed(),
        status.blocklist_size.to_string().red(),
        status.allowlist_size.to_string().green()
    );
    println!("    {:<22} {:?}", "Blocking Mode:".dimmed(), status.blocking_mode);
    if let Some(v4) = status.blocking_ip_v4 {
        println!("    {:<22} {v4}", "Sinkhole IPv4:".dimmed());
    }
    if let Some(v6) = status.blocking_ip_v6 {
        println!("    {:<22} {v6}", "Sinkhole IPv6:".dimmed());
    }

    println!();
    Ok(())
}

async fn add_adblock_block(domain_opt: Option<String>, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let domain = match domain_opt {
        Some(d) => d,
        None => Text::new("Domain name to block:").prompt()?,
    };

    let resp = client.dns_block(domain.clone()).await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success(&format!("Domain '{domain}' added to blocklist: {}", resp.message));
    Ok(())
}

async fn add_adblock_allow(domain_opt: Option<String>, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let domain = match domain_opt {
        Some(d) => d,
        None => Text::new("Domain name to allow:").prompt()?,
    };

    let resp = client.dns_allow(domain.clone()).await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success(&format!("Domain '{domain}' added to allowlist: {}", resp.message));
    Ok(())
}

async fn remove_adblock_allow(domain_opt: Option<String>, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let domain = if let Some(d) = domain_opt {
        d
    } else {
        let resp = client.dns_allowlist().await?;
        if resp.allowlist.is_empty() {
            bail!("No allowlist entries configured.");
        }
        let items: Vec<String> = resp
            .allowlist
            .iter()
            .map(|e| format!("{} (ID #{})", e.domain, e.id))
            .collect();
        let selected = Select::new("Select allowlist entry to remove:", items).prompt()?;
        let parts: Vec<&str> = selected.split_whitespace().collect();
        parts[0].to_string()
    };

    let resp = client.dns_unallow(domain.clone()).await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success(&format!("Removed domain '{domain}' from allowlist."));
    Ok(())
}

async fn show_adblock_allowlist(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let resp = client.dns_allowlist().await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    if resp.allowlist.is_empty() {
        printer.info("DNS allowlist is currently empty.");
        return Ok(());
    }

    println!();
    println!(
        " {} Custom DNS Allowlist ({} entries)",
        printer.status_badge(true),
        resp.allowlist.len()
    );

    let mut table = printer.new_table();
    table.set_header(vec!["ID", "Domain"]);
    for a in &resp.allowlist {
        table.add_row(vec![a.id.to_string(), a.domain.clone()]);
    }
    println!("{table}");
    println!();
    Ok(())
}

async fn check_adblock_domain(domain_opt: Option<String>, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let domain = match domain_opt {
        Some(d) => d,
        None => Text::new("Domain name to check:").prompt()?,
    };

    let resp = client.dns_adblock_check(domain.clone()).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    println!();
    println!(" {} Filter Check for {}", printer.status_badge(true), domain.bold().white());

    if let Some(ref m) = resp.filter {
        let action_str = match m.action {
            FilterAction::Block => "BLOCKED".red().bold(),
            FilterAction::Allow => "ALLOWED".green().bold(),
        };
        println!("    {:<18} {action_str}", "Verdict:".dimmed());

        let origin_str = match m.origin {
            FilterOrigin::UserRule => "Custom User Rule".to_string(),
            FilterOrigin::UserAllowlist => "User Allowlist".to_string(),
            FilterOrigin::List { source_id } => format!("Filter Source #{source_id}"),
        };
        println!("    {:<18} {}", "Origin:".dimmed(), origin_str.cyan());

        if let Some(ref rule) = m.rule {
            println!("    {:<18} {} (matched pattern)", "Rule:".dimmed(), rule.yellow());
        }
        if m.important {
            println!("    {:<18} {}", "Important:".dimmed(), "yes ($important flag)".yellow());
        }

        if !resp.source_matches.is_empty() {
            println!();
            println!("  {}", "Matching Filter Sources:".bold());
            for sm in &resp.source_matches {
                println!("    - [{}] {}", sm.action.as_str().to_uppercase().cyan(), sm.url);
            }
        }
    } else {
        println!("    {:<18} {}", "Verdict:".dimmed(), "NOT BLOCKED (default pass)".green().bold());
    }

    println!();
    Ok(())
}

async fn execute_adblock_sources(args: DnsAdblockSourcesArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    match args.action.unwrap_or(DnsAdblockSourcesAction::List) {
        DnsAdblockSourcesAction::List => list_adblock_sources(client, printer).await,
        DnsAdblockSourcesAction::Add { url, format, kind } => add_adblock_source(url, format, kind, client, printer).await,
        DnsAdblockSourcesAction::Remove { url } => remove_adblock_source(url, client, printer).await,
        DnsAdblockSourcesAction::Reload => reload_adblock_sources(client, printer).await,
    }
}

async fn list_adblock_sources(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let resp = client.dns_adblock_sources().await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    if resp.sources.is_empty() {
        printer.info("No adblock sources configured.");
        return Ok(());
    }

    println!();
    println!(
        " {} Filter List Sources ({} total)",
        printer.status_badge(true),
        resp.sources.len()
    );

    let mut table = printer.new_table();
    table.set_header(vec!["ID", "Format", "Blocks", "Exceptions", "Status", "URL"]);
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
    println!();
    Ok(())
}

async fn add_adblock_source(
    url_opt: Option<String>,
    format: Option<AdblockSourceFormat>,
    kind: AdblockUrlKind,
    client: &LanforgeClient,
    printer: &Printer,
) -> Result<()> {
    let url = match url_opt {
        Some(u) => u,
        None => Text::new("Filter source URL:").prompt()?,
    };

    let resp = client.dns_adblock_url_add(url.clone(), kind, format).await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success(&format!("Added adblock source URL: {url}"));
    Ok(())
}

async fn remove_adblock_source(url_opt: Option<String>, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let url = if let Some(u) = url_opt {
        u
    } else {
        let resp = client.dns_adblock_sources().await?;
        if resp.sources.is_empty() {
            bail!("No adblock sources configured.");
        }
        let items: Vec<String> = resp.sources.iter().map(|s| s.url.clone()).collect();
        Select::new("Select adblock source to remove:", items).prompt()?
    };

    let resp = client.dns_adblock_url_remove(url.clone()).await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success(&format!("Removed adblock source URL: {url}"));
    Ok(())
}

async fn reload_adblock_sources(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let resp = client.dns_adblock_reload().await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success("Adblock filter lists reloaded and recompiled successfully.");
    Ok(())
}

async fn execute_adblock_config(args: DnsAdblockConfigArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    if args.mode.is_none() && args.ip_v4.is_none() && args.ip_v6.is_none() && args.refresh_time.is_none() {
        let status = client.dns_adblock_status().await?;
        if printer.json {
            return printer.print_json(&serde_json::json!({
                "blocking_mode": status.blocking_mode,
                "blocking_ip_v4": status.blocking_ip_v4,
                "blocking_ip_v6": status.blocking_ip_v6,
            }));
        }
        println!();
        println!(" {} Adblock Configuration", printer.status_badge(true));
        println!("    {:<20} {:?}", "Blocking Mode:", status.blocking_mode);
        if let Some(ip) = status.blocking_ip_v4 {
            println!("    {:<20} {ip}", "Sinkhole IPv4:");
        }
        if let Some(ip) = status.blocking_ip_v6 {
            println!("    {:<20} {ip}", "Sinkhole IPv6:");
        }
        println!();
        return Ok(());
    }

    let resp = client
        .dns_adblock_config_set(args.mode, args.ip_v4, args.ip_v6, args.refresh_time)
        .await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    printer.success("Adblock configuration updated successfully.");
    Ok(())
}

async fn pause_adblock(duration_opt: Option<String>, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let duration = match duration_opt {
        Some(ref d) => Some(parse_pause_duration(d)?),
        None => None,
    };

    let resp = client.dns_adblock_set(false, duration).await?;
    if printer.json {
        return printer.print_json(&resp);
    }

    let dur_str = duration.map_or_else(
        || "indefinitely".to_string(),
        |d| format!("for {}", format_duration_secs(d)),
    );
    printer.success(&format!("DNS adblocking paused {dur_str}."));
    Ok(())
}

async fn resume_adblock(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let resp = client.dns_adblock_set(true, None).await?;
    if printer.json {
        return printer.print_json(&resp);
    }
    printer.success("DNS adblocking resumed successfully.");
    Ok(())
}

// ---------------------------------------------------------------------------
// 9. Reverse Resolvers
// ---------------------------------------------------------------------------

async fn execute_reverse(args: DnsReverseArgs, client: &LanforgeClient, printer: &Printer) -> Result<()> {
    match args.action.unwrap_or(DnsReverseAction::List) {
        DnsReverseAction::List => list_reverse_resolvers(client, printer).await,
        DnsReverseAction::Add { subnet, resolver } => add_reverse_resolver(subnet, resolver, client, printer).await,
        DnsReverseAction::Remove { subnet } => remove_reverse_resolver(subnet, client, printer).await,
    }
}

async fn list_reverse_resolvers(client: &LanforgeClient, printer: &Printer) -> Result<()> {
    let resp = client.dns_reverse_resolver_list().await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    if resp.resolvers.is_empty() {
        printer.info("No reverse resolvers configured.");
        return Ok(());
    }

    println!();
    println!(
        " {} Reverse Resolver Mappings",
        printer.status_badge(true)
    );

    let mut table = printer.new_table();
    table.set_header(vec!["Subnet CIDR", "Resolver URI"]);
    for r in &resp.resolvers {
        table.add_row(vec![r.subnet.to_string(), r.resolver.to_string()]);
    }
    println!("{table}");
    println!();
    Ok(())
}

async fn add_reverse_resolver(
    subnet_opt: Option<String>,
    resolver_opt: Option<String>,
    client: &LanforgeClient,
    printer: &Printer,
) -> Result<()> {
    let subnet = match subnet_opt {
        Some(s) => s,
        None => Text::new("Subnet CIDR (e.g. 100.64.0.0/10):").prompt()?,
    };

    let resolver = match resolver_opt {
        Some(r) => r,
        None => Text::new("Resolver URI (e.g. udp://100.100.100.100:53):").prompt()?,
    };

    let resp = client.dns_reverse_resolver_add(subnet.clone(), resolver.clone()).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    printer.success(&format!("Added reverse resolver: {subnet} -> {resolver}"));
    Ok(())
}

async fn remove_reverse_resolver(
    subnet_opt: Option<String>,
    client: &LanforgeClient,
    printer: &Printer,
) -> Result<()> {
    let subnet = if let Some(s) = subnet_opt {
        s
    } else {
        let resp = client.dns_reverse_resolver_list().await?;
        if resp.resolvers.is_empty() {
            bail!("No reverse resolvers configured to remove.");
        }
        let items: Vec<String> = resp
            .resolvers
            .iter()
            .map(|r| format!("{} ({})", r.subnet, r.resolver))
            .collect();
        let selected = Select::new("Select reverse resolver to remove:", items).prompt()?;
        let parts: Vec<&str> = selected.split_whitespace().collect();
        parts[0].to_string()
    };

    let resp = client.dns_reverse_resolver_remove(subnet.clone()).await?;

    if printer.json {
        return printer.print_json(&resp);
    }

    printer.success(&format!("Removed reverse resolver for subnet '{subnet}'."));
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_upstream_protocol() {
        assert_eq!(
            infer_upstream_protocol("1.1.1.1:853", None),
            UpstreamProtocol::Tls
        );
        assert_eq!(
            infer_upstream_protocol("1.1.1.1:443", None),
            UpstreamProtocol::Https
        );
        assert_eq!(
            infer_upstream_protocol("1.1.1.1:53", None),
            UpstreamProtocol::Udp
        );
        assert_eq!(
            infer_upstream_protocol("1.1.1.1:853", Some(UpstreamProtocol::Quic)),
            UpstreamProtocol::Quic
        );
    }

    #[test]
    fn test_infer_rewrite_type_and_answer() {
        // IPv4 -> A
        let (rtype, ans) = infer_rewrite_type_and_answer("lan.test", "192.168.1.10", None).unwrap();
        assert_eq!(rtype, DnsRecordType::A);
        assert_eq!(ans.to_string(), "192.168.1.10");

        // IPv6 -> AAAA
        let (rtype, ans) = infer_rewrite_type_and_answer("lan.test", "2001:db8::1", None).unwrap();
        assert_eq!(rtype, DnsRecordType::AAAA);
        assert_eq!(ans.to_string(), "2001:db8::1");

        // CNAME -> CNAME
        let (rtype, ans) = infer_rewrite_type_and_answer("alias.test", "target.lan", None).unwrap();
        assert_eq!(rtype, DnsRecordType::CNAME);
        assert_eq!(ans.to_string(), "target.lan");

        // Device -> dev:...
        let (rtype, ans) = infer_rewrite_type_and_answer("my-pc.lan", "dev:00:11:22:33:44:55", None).unwrap();
        assert_eq!(rtype, DnsRecordType::Device);
        assert_eq!(ans.to_string(), "dev:00:11:22:33:44:55");

        // SRV -> srv:...
        let (rtype, ans) = infer_rewrite_type_and_answer(
            "_minecraft._tcp.lan",
            "srv:minecraft:tcp:nas:25565",
            None,
        )
        .unwrap();
        assert_eq!(rtype, DnsRecordType::SRV);
        assert_eq!(ans.to_string(), "srv:minecraft:tcp:nas:25565");
    }

    #[test]
    fn test_parse_pause_duration() {
        assert_eq!(parse_pause_duration("300").unwrap(), 300);
        assert_eq!(parse_pause_duration("5m").unwrap(), 300);
        assert_eq!(parse_pause_duration("1h").unwrap(), 3600);
        assert_eq!(parse_pause_duration("2d").unwrap(), 172_800);
        assert!(parse_pause_duration("invalid-duration").is_err());
    }

    #[test]
    fn test_ip_to_arpa() {
        let v4: IpAddr = "192.168.1.10".parse().unwrap();
        assert_eq!(ip_to_arpa(v4), "10.1.168.192.in-addr.arpa");

        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let arpa6 = ip_to_arpa(v6);
        assert!(arpa6.ends_with(".ip6.arpa"));
        assert!(arpa6.starts_with("1.0.0.0."));
    }

    #[test]
    fn test_format_log_entry() {
        let entry = DnsQueryLogEntry {
            timestamp: 1_700_000_000,
            src_ip: "192.168.1.50".parse().unwrap(),
            domain: "example.com".into(),
            src_hostname: Some("my-pc".to_string()),
            answer: Some("93.184.216.34".to_string()),
            src_mac: None,
            result: QueryResult::Forwarded,
            cached: false,
            qtype: DnsRecordType::A,
            upstream_us: 15_400,
            filter: None,
        };
        let host_map = HashMap::new();
        let printer = Printer::new(false, true, false);
        let cols = format_log_entry(&entry, &host_map, &printer);
        assert_eq!(cols[1], "my-pc");
        assert_eq!(cols[2], "A");
        assert_eq!(cols[3], "example.com");
        assert_eq!(cols[4], "Forwarded");
        assert_eq!(cols[5], "93.184.216.34");
        assert_eq!(cols[6], "15.4ms");
    }

    #[test]
    fn test_infer_rewrite_type_explicit_override() {
        let (rtype, ans) = infer_rewrite_type_and_answer(
            "device.lan",
            "dev:00:11:22:33:44:55",
            Some(DnsRecordType::Device),
        )
        .unwrap();
        assert_eq!(rtype, DnsRecordType::Device);
        assert_eq!(ans.to_string(), "dev:00:11:22:33:44:55");
    }
}
