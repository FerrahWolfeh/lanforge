use crate::cli::commands::CliCommand;
use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::Result;
use colored::Colorize;
use iocraft::prelude::*;
use lanforge_api::api::{DnsAdblockStatusResponse, DnsAdblockUrlsResponse,
    DnsAllowlistResponse, DnsCacheResponse, DnsQueryLogResponse, DnsQueryResponse,
    DnsRewritesResponse, DnsStatsResponse, DnsUpstreamsResponse,
};
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
use lanforge_types::network::{QueryLogEntry, QueryResult};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DnsArgs {
    #[command(subcommand)]
    pub action: DnsAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsAction {
    /// Show resolver performance and cache statistics
    Stats,
    /// List upstream DNS servers and their health/latency
    Upstreams,
    /// Perform a DNS lookup through the Lanforge resolver
    Query {
        /// Domain name to query
        name: String,
        /// Record type (A, AAAA, MX, etc.)
        #[arg(default_value = "A")]
        record_type: String,
    },
    /// Manage the domain-based adblocker
    Adblock {
        #[command(subcommand)]
        action: AdblockAction,
    },
    /// Manage local DNS rewrites
    Rewrite {
        #[command(subcommand)]
        action: RewriteAction,
    },
    /// Manage the DNS cache
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// View or follow the DNS query log
    Log {
        /// Follow new queries in real-time
        #[arg(short, long)]
        follow: bool,
        /// Limit the number of historical entries shown
        #[arg(short, long, default_value = "50")]
        limit: usize,
        /// Filter by client IP or MAC
        #[arg(short, long)]
        client: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum AdblockAction {
    /// Show current adblocker status and blocklist size
    Status,
    /// Enable the adblocker globally
    Enable,
    /// Disable the adblocker (optionally for a duration)
    Disable {
        /// Duration to stay disabled (ex: 5m, 1h)
        duration: Option<String>,
    },
    /// Reload blocklists from sources
    Reload,
    /// Force-block a specific domain (local blocklist)
    Block { domain: String },
    /// Force-allow a specific domain (local allowlist)
    Allow { domain: String },
    /// Remove a domain from the local allowlist
    Unallow { domain: String },
    /// List all domains in the local allowlist
    Allowlist,
    /// Manage blocklist sources (URLs)
    Sources {
        #[command(subcommand)]
        action: SourceAction,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum SourceAction {
    /// Add a new blocklist URL
    Add {
        url: String,
        #[arg(short, long, default_value = "blocklist")]
        kind: String,
    },
    /// Remove a blocklist URL
    Remove { url: String },
    /// List all configured blocklist sources
    List,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum RewriteAction {
    /// Add a local DNS rewrite (A/AAAA/CNAME)
    Add { domain: String, answer: String },
    /// Remove a local DNS rewrite
    Remove { domain: String },
    /// List all local DNS rewrites
    List,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum CacheAction {
    /// Clear all entries from the DNS cache
    Flush,
    /// Dump all current DNS cache entries
    Dump,
}

impl Execute for DnsArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        client
            .execute_handler(Box::new(DnsCommand {
                action: self.action,
            }))
            .await
    }
}

pub struct DnsCommand {
    pub action: DnsAction,
}

use tokio::net::UnixStream;
use lanforge_api::rpc::{LanforgeRpcClient, RpcResponse};

#[async_trait::async_trait]
impl CliCommand for DnsCommand {
    #[allow(clippy::too_many_lines)]
    async fn execute_rpc(
        &mut self,
        client: &mut LanforgeRpcClient<UnixStream>,
    ) -> Result<()> {
        match &self.action {
                DnsAction::Stats => {
                    let res = client.dns_stats().await?;
                    Self::render_stats(&res);
                }
                DnsAction::Upstreams => {
                    let res = client.dns_upstreams().await?;
                    Self::render_upstreams(&res);
                }
                DnsAction::Query { name, record_type } => {
                    let res = client.dns_query(name.clone(), Some(record_type.clone())).await?;
                    Self::render_query(&res);
                }
                DnsAction::Adblock { action } => match action {
                    AdblockAction::Status => {
                        let res = client.dns_adblock_status().await?;
                        Self::render_adblock_status(&res);
                    }
                    AdblockAction::Enable => {
                        let res = client.dns_adblock_set(true, None).await?;
                        println!("{}", res.message);
                    }
                    AdblockAction::Disable { duration } => {
                        let secs = duration
                            .as_ref()
                            .and_then(|d| duration_str::parse_std(d).ok())
                            .map(|d| d.as_secs());
                        let res = client.dns_adblock_set(false, secs).await?;
                        println!("{}", res.message);
                    }
                    AdblockAction::Reload => {
                        let res = client.dns_adblock_reload().await?;
                        println!("{}", res.message);
                    }
                    AdblockAction::Block { domain } => {
                        let res = client.dns_block(domain.clone()).await?;
                        println!("{}", res.message);
                    }
                    AdblockAction::Allow { domain } => {
                        let res = client.dns_allow(domain.clone()).await?;
                        println!("{}", res.message);
                    }
                    AdblockAction::Unallow { domain } => {
                        let res = client.dns_unallow(domain.clone()).await?;
                        println!("{}", res.message);
                    }
                    AdblockAction::Allowlist => {
                        let res = client.dns_allowlist().await?;
                        Self::render_allowlist(&res);
                    }
                    AdblockAction::Sources { action } => match action {
                        SourceAction::Add { url, kind } => {
                            let res = client.dns_adblock_url_add(url.clone(), kind.clone()).await?;
                            println!("{}", res.message);
                        }
                        SourceAction::Remove { url } => {
                            let res = client.dns_adblock_url_remove(url.clone()).await?;
                            println!("{}", res.message);
                        }
                        SourceAction::List => {
                            let res = client.dns_adblock_url_list().await?;
                            Self::render_adblock_urls(&res);
                        }
                    },
                },
                DnsAction::Rewrite { action } => match action {
                    RewriteAction::Add { domain, answer } => {
                        let res = client.dns_rewrite_add(domain.clone(), answer.clone()).await?;
                        println!("{}", res.message);
                    }
                    RewriteAction::Remove { domain } => {
                        let res = client.dns_rewrite_remove(domain.clone()).await?;
                        println!("{}", res.message);
                    }
                    RewriteAction::List => {
                        let res = client.dns_rewrites().await?;
                        Self::render_rewrites(&res);
                    }
                },
                DnsAction::Cache { action } => match action {
                    CacheAction::Flush => {
                        let res = client.dns_cache_flush().await?;
                        println!("{}", res.message);
                    }
                    CacheAction::Dump => {
                        let res = client.dns_cache_dump().await?;
                        Self::render_cache(&res);
                    }
                },
                DnsAction::Log {
                    limit,
                    client: filter,
                    follow,
                } => {
                    let log = client.dns_query_log(Some(*limit), filter.clone(), *follow).await?;
                    Self::render_logs(&log);
                    if *follow {
                        loop {
                            match client.next_response().await {
                                Ok(RpcResponse::Event(timed_event)) => {
                                    if let LanforgeEvent::Dns(DnsEvent::QueryResolved(entry)) =
                                        &timed_event.event
                                    {
                                        Self::print_log_line(entry);
                                    }
                                }
                                Ok(RpcResponse::Error(e)) => eprintln!("Error: {e}"),
                                Ok(_) => {}
                                Err(lanforge_api::rpc::LanforgeRpcError::Io(e))
                                    if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                                {
                                    break;
                                }
                                Err(e) => return Err(e.into()),
                            }
                        }
                    }
                }
            }
            Ok(())
    }
}

impl DnsCommand {
    fn render_stats(stats: &DnsStatsResponse) {
        element! {
            View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
                View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                    Text(content: " DNS RESOLVER STATS ", color: Color::White, weight: Weight::Bold)
                }
                View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
                    StatLine(label: "Total Requests", value: stats.total_requests.to_string())
                    StatLine(label: "Cache Hits", value: stats.cache_hits.to_string(), color: Color::Green)
                    StatLine(label: "Cache Misses", value: stats.cache_misses.to_string(), color: Color::Yellow)
                    StatLine(label: "Upstream Errors", value: stats.upstream_errors.to_string(), color: Color::Red)
                    StatLine(label: "Auth Queries", value: stats.auth_queries.to_string())
                    StatLine(label: "Recursions", value: stats.recursions.to_string())
                    StatLine(label: "Blocked Queries", value: stats.blocked_queries.to_string(), color: Color::Cyan)
                    StatLine(label: "Resolved Total", value: stats.resolved_total.to_string(), color: Color::Green)
                    StatLine(label: "Failed Total", value: stats.failed_total.to_string(), color: Color::Red)
                }
            }
        }.print();
    }

    fn render_upstreams(resp: &DnsUpstreamsResponse) {
        element! {
            View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
                View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                    Text(content: " DNS UPSTREAM HEALTH ", color: Color::White, weight: Weight::Bold)
                }
                View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey) {
                    View(flex_direction: FlexDirection::Row, padding_left: 2, padding_right: 2, margin_bottom: 1) {
                        Text(content: format!("{:<25}", "UPSTREAM"), color: Color::DarkGrey, weight: Weight::Bold)
                        Text(content: format!("{:<10}", "PROTO"), color: Color::DarkGrey, weight: Weight::Bold)
                        Text(content: format!("{:<10}", "RTT"), color: Color::DarkGrey, weight: Weight::Bold)
                        Text(content: format!("{:<15}", "SUCCESS RATE"), color: Color::DarkGrey, weight: Weight::Bold)
                        Text(content: format!("{:<10}", "STATUS"), color: Color::DarkGrey, weight: Weight::Bold)
                    }
                    #(resp.upstreams.iter().map(|u| {
                        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
                        let success_rate = if u.total_queries > 0 {
                            (u.total_successes as f32 / u.total_queries as f32) * 100.0
                        } else {
                            0.0
                        };
                        let status_color = if u.status == "Healthy" { Color::Green } else { Color::Red };
                        element! {
                            View(flex_direction: FlexDirection::Row, padding_left: 2, padding_right: 2) {
                                Text(content: format!("{:<25}", u.target))
                                Text(content: format!("{:<10}", u.protocol), color: Color::Cyan)
                                Text(content: format!("{:<10}", format!("{}ms", u.rtt_ewma_us / 1000)), color: Color::Yellow)
                                Text(content: format!("{:<15}", format!("{:.1}%", success_rate)))
                                Text(content: format!("{:<10}", u.status), color: status_color)
                            }
                        }
                    }))
                }
            }
        }.print();
    }

    fn render_query(query: &DnsQueryResponse) {
        element! {
            View(flex_direction: FlexDirection::Column, padding_left: 2, margin_top: 1) {
                View(flex_direction: FlexDirection::Row) {
                    Text(content: " QUERY RESULT ", color: Color::White, weight: Weight::Bold)
                    Text(content: format!("  latency: {}ms", query.latency_ms), color: Color::DarkGrey)
                    #(query.authoritative.then(|| element! {
                        Text(content: "  (Authoritative)", color: Color::Cyan)
                    }))
                }
                View(margin_top: 1) {
                    QueryResults(query: query.clone())
                }
            }
        }.print();
    }

    fn render_cache(cache: &DnsCacheResponse) {
        element! {
            View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
                View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                    Text(content: " DNS CACHE DUMP ", color: Color::White, weight: Weight::Bold)
                }
                View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey) {
                    #(cache.entries.iter().map(|e| element! {
                        View(flex_direction: FlexDirection::Row, padding_left: 2, padding_right: 2) {
                            Text(content: format!("{:<5}", e.kind), color: Color::Cyan)
                            Text(content: format!(" {:<30}", e.name))
                            Text(content: " -> ", color: Color::DarkGrey)
                            Text(content: e.data.clone())
                            View(flex_grow: 1.0)
                            Text(content: format!("{}s", e.expires_in_secs), color: Color::Yellow)
                        }
                    }))
                }
            }
        }.print();
    }

    fn render_logs(log: &DnsQueryLogResponse) {
        use chrono::{DateTime, Local, Utc};
        element! {
            View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
                View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                    Text(content: " DNS QUERY LOG ", color: Color::White, weight: Weight::Bold)
                }
                View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey) {
                    View(flex_direction: FlexDirection::Row, padding_left: 2, padding_right: 2, margin_bottom: 1) {
                        Text(content: format!("{:<10}", "TIME"), color: Color::DarkGrey, weight: Weight::Bold)
                        Text(content: format!("{:<18}", "CLIENT"), color: Color::DarkGrey, weight: Weight::Bold)
                        Text(content: format!("{:<6}", "TYPE"), color: Color::DarkGrey, weight: Weight::Bold)
                        Text(content: format!("{:<30}", "DOMAIN"), color: Color::DarkGrey, weight: Weight::Bold)
                        Text(content: format!("{:<10}", "RESULT"), color: Color::DarkGrey, weight: Weight::Bold)
                        Text(content: format!("{:<25}", "ANSWER"), color: Color::DarkGrey, weight: Weight::Bold)
                        Text(content: format!("{:<8}", "LATENCY"), color: Color::DarkGrey, weight: Weight::Bold)
                    }
                    #(log.entries.iter().rev().map(|e| {
                        let dt = DateTime::<Utc>::from_timestamp(e.timestamp.cast_signed(), 0).unwrap_or_default();
                        let local_dt: DateTime<Local> = DateTime::from(dt);
                        let time_str = local_dt.format("%H:%M:%S").to_string();
                        
                        let result_color = match e.result.as_str() {
                            "blocked" | "Blocked" => Color::Red,
                            "local" | "Local" | "rewritten" | "Rewritten" => Color::Green,
                            "cached" | "Cached" => Color::Cyan,
                            "nxdomain" | "NxDomain" => Color::Yellow,
                            _ => Color::White,
                        };

                        let client_str = e.src_hostname.as_ref().map_or_else(|| format!("{:<18}", e.src_ip), |host| format!("{host:<18}"));

                        let answer_str = e.answer.as_deref().unwrap_or("-");

                        element! {
                            View(flex_direction: FlexDirection::Row, padding_left: 2, padding_right: 2) {
                                Text(content: format!("{:<10}", time_str), color: Color::DarkGrey)
                                Text(content: client_str)
                                Text(content: format!("{:<6}", e.qtype), color: Color::Cyan)
                                Text(content: format!("{:<30}", e.domain))
                                Text(content: format!("{:<10}", e.result), color: result_color)
                                Text(content: format!("{:<25}", answer_str), color: Color::DarkGrey)
                                Text(content: format!("{:<8}", format!("{}ms", e.upstream_us / 1000)), color: Color::Yellow)
                            }
                        }
                    }))
                }
            }
        }.print();
    }

    fn render_adblock_status(status: &DnsAdblockStatusResponse) {
        element! {
            View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
                View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                    Text(content: " DNS ADBLOCK STATUS ", color: Color::White, weight: Weight::Bold)
                }
                View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey, padding_left: 2, padding_right: 2) {
                    StatLine(
                        label: "Status",
                        value: if status.enabled { "Enabled".to_string() } else { "Disabled".to_string() },
                        color: if status.enabled { Color::Green } else { Color::Red }
                    )
                    #(status.remaining_secs.map(|s| element! {
                         StatLine(label: "Remaining", value: format!("{}s", s), color: Color::Yellow)
                    }))
                    StatLine(label: "Blocklist Size", value: status.blocklist_size.to_string())
                    StatLine(label: "Allowlist Size", value: status.allowlist_size.to_string())
                }
            }
        }.print();
    }

    fn render_rewrites(resp: &DnsRewritesResponse) {
        element! {
            View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
                View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                    Text(content: " DNS REWRITE RULES ", color: Color::White, weight: Weight::Bold)
                }
                View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey) {
                    #(resp.rewrites.iter().map(|r| element! {
                        View(flex_direction: FlexDirection::Row, padding_left: 2, padding_right: 2) {
                            Text(content: format!("{:<30}", r.domain), color: Color::Cyan)
                            Text(content: " -> ", color: Color::DarkGrey)
                            Text(content: r.answer.clone())
                        }
                    }))
                }
            }
        }.print();
    }

    fn render_allowlist(resp: &DnsAllowlistResponse) {
        element! {
            View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
                View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                    Text(content: " DNS PERMANENT ALLOWLIST ", color: Color::White, weight: Weight::Bold)
                }
                View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey) {
                    #(resp.allowlist.iter().map(|domain| element! {
                        View(flex_direction: FlexDirection::Row, padding_left: 2, padding_right: 2) {
                            Text(content: "● ", color: Color::Green)
                            Text(content: domain.clone())
                        }
                    }))
                }
            }
        }.print();
    }

    fn render_adblock_urls(resp: &DnsAdblockUrlsResponse) {
        element! {
            View(flex_direction: FlexDirection::Column, padding: 1, padding_left: 2) {
                View(flex_direction: FlexDirection::Row, margin_bottom: 1) {
                    Text(content: " DNS ADBLOCK SOURCES ", color: Color::White, weight: Weight::Bold)
                }
                View(flex_direction: FlexDirection::Column, border_style: BorderStyle::Round, border_color: Color::DarkGrey) {
                    #(resp.urls.iter().map(|u| element! {
                        View(flex_direction: FlexDirection::Row, padding_left: 2, padding_right: 2) {
                            Text(content: format!("{:<10}", u.kind.to_uppercase()), color: if u.kind == "allowlist" { Color::Green } else { Color::Red })
                            Text(content: format!(" {:<50}", u.url))
                        }
                    }))
                }
            }
        }.print();
    }

    fn print_log_line(e: &QueryLogEntry) {
        use chrono::{DateTime, Local, Utc};
        let dt = DateTime::<Utc>::from_timestamp(e.timestamp.cast_signed(), 0).unwrap_or_default();
        let local_dt: DateTime<Local> = DateTime::from(dt);
        let time_str = local_dt.format("%H:%M:%S").to_string();

        let result_str = format!("{:?}", e.result);
        let result_colored = match e.result {
            QueryResult::Blocked => result_str.red(),
            QueryResult::Local => result_str.green(),
            QueryResult::Cached => result_str.cyan(),
            _ => result_str.white(),
        };

        println!(
            "{}  {:<16}  {:<30}  {:<8}  {}ms",
            time_str.dimmed(),
            e.src_ip,
            e.domain,
            result_colored,
            (e.upstream_us / 1000).to_string().yellow()
        );
    }
}

#[component]
fn StatLine(props: &StatLineProps) -> impl Into<AnyElement<'_>> {
    let color = props.color.unwrap_or(Color::White);
    element! {
        View(flex_direction: FlexDirection::Row) {
            Text(content: format!("{:<20}", props.label), color: Color::DarkGrey)
            Text(content: props.value.clone(), color: color)
        }
    }
}

#[derive(Props, Default)]
struct StatLineProps {
    pub label: String,
    pub value: String,
    pub color: Option<Color>,
}
#[component]
fn QueryResults(props: &QueryResultsProps) -> impl Into<AnyElement<'_>> {
    let query = &props.query;
    if query.records.is_empty() {
        element! { Text(content: "No records found.", color: Color::Red) }.into_any()
    } else {
        element! {
            View(flex_direction: FlexDirection::Column) {
                #(query.records.iter().map(|r| element! {
                    View(flex_direction: FlexDirection::Row) {
                        Text(content: "● ", color: Color::Green)
                        Text(content: r.to_string())
                    }
                }))
            }
        }
        .into_any()
    }
}

#[derive(Props, Clone, Default)]
struct QueryResultsProps {
    pub query: DnsQueryResponse,
}
