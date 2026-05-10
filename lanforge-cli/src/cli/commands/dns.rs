use crate::{args, cli::commands::CliCommand};
use color_eyre::eyre::Result;
use colored::Colorize;
use iocraft::prelude::*;
use lanforge_api::api::{
    Command as ControlCommand, CommandAction, DnsCacheResponse, DnsQueryLogResponse,
    DnsQueryResponse, DnsStatsResponse, DnsUpstreamsResponse, Response,
};
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
use lanforge_core::types::network::{QueryLogEntry, QueryResult};

pub struct DnsCommand {
    pub action: args::DnsCommand,
}

impl CliCommand for DnsCommand {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match &self.action {
            args::DnsCommand::Stats => Ok(ControlCommand::new(CommandAction::DnsStats)),
            args::DnsCommand::Upstreams => Ok(ControlCommand::new(CommandAction::DnsUpstreams)),
            args::DnsCommand::Query { name, record_type } => {
                Ok(ControlCommand::new(CommandAction::DnsQuery {
                    name: name.clone(),
                    record_type: record_type.clone(),
                }))
            }
            args::DnsCommand::Adblock { action } => match action {
                args::AdblockAction::Enable => {
                    Ok(ControlCommand::new(CommandAction::DnsAdblockSet {
                        enabled: true,
                        duration_secs: None,
                    }))
                }
                args::AdblockAction::Disable { duration } => {
                    let secs = duration
                        .as_ref()
                        .and_then(|d| duration_str::parse_std(d).ok())
                        .map(|d| d.as_secs());
                    Ok(ControlCommand::new(CommandAction::DnsAdblockSet {
                        enabled: false,
                        duration_secs: secs,
                    }))
                }
                args::AdblockAction::Reload => {
                    Ok(ControlCommand::new(CommandAction::DnsAdblockReload))
                }
            },
            args::DnsCommand::Cache { action } => match action {
                args::CacheAction::Flush => Ok(ControlCommand::new(CommandAction::DnsCacheFlush)),
                args::CacheAction::Dump => Ok(ControlCommand::new(CommandAction::DnsCacheDump)),
            },
            args::DnsCommand::Log { limit, client, .. } => {
                Ok(ControlCommand::new(CommandAction::DnsQueryLog {
                    limit: Some(*limit),
                    client: client.clone(),
                }))
            }
        }
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        match response {
            Response::DnsStats(stats) => Self::render_stats(stats),
            Response::DnsUpstreams(resp) => Self::render_upstreams(resp),
            Response::DnsQuery(query) => Self::render_query(query),
            Response::DnsCache(cache) => Self::render_cache(cache),
            Response::DnsQueryLog(log) => Self::render_logs(log),
            Response::Event(timed_event) => {
                if let LanforgeEvent::Dns(DnsEvent::QueryResolved(entry)) = &timed_event.event {
                    Self::print_log_line(entry);
                }
            }
            Response::Error { error } => {
                println!("Error: {error}");
            }
            Response::Success(msg) => {
                println!("{}", msg.message);
            }
            _ => {
                println!("Unexpected response: {response:?}");
            }
        }
        Ok(None)
    }

    fn is_streaming(&self) -> bool {
        if let args::DnsCommand::Log { follow, .. } = &self.action {
            *follow
        } else {
            false
        }
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
                    StatLine(label: "Total Requests", value: stats.total_requests)
                    StatLine(label: "Cache Hits", value: stats.cache_hits, color: Color::Green)
                    StatLine(label: "Cache Misses", value: stats.cache_misses, color: Color::Yellow)
                    StatLine(label: "Upstream Errors", value: stats.upstream_errors, color: Color::Red)
                    StatLine(label: "Auth Queries", value: stats.auth_queries)
                    StatLine(label: "Recursions", value: stats.recursions)
                    StatLine(label: "Blocked Queries", value: stats.blocked_queries, color: Color::Cyan)
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
                        Text(content: format!("{:<16}", "CLIENT"), color: Color::DarkGrey, weight: Weight::Bold)
                        Text(content: format!("{:<30}", "DOMAIN"), color: Color::DarkGrey, weight: Weight::Bold)
                        Text(content: format!("{:<8}", "RESULT"), color: Color::DarkGrey, weight: Weight::Bold)
                        Text(content: format!("{:<8}", "LATENCY"), color: Color::DarkGrey, weight: Weight::Bold)
                    }
                    #(log.entries.iter().rev().map(|e| {
                        let dt = DateTime::<Utc>::from_timestamp(e.timestamp.cast_signed(), 0).unwrap_or_default();
                        let local_dt: DateTime<Local> = DateTime::from(dt);
                        let time_str = local_dt.format("%H:%M:%S").to_string();
                        let result_color = match e.result {
                            QueryResult::Blocked => Color::Red,
                            QueryResult::Local => Color::Green,
                            QueryResult::Cached => Color::Cyan,
                            _ => Color::White,
                        };
                        element! {
                            View(flex_direction: FlexDirection::Row, padding_left: 2, padding_right: 2) {
                                Text(content: format!("{:<10}", time_str), color: Color::DarkGrey)
                                Text(content: format!("{:<16}", e.src_ip))
                                Text(content: format!("{:<30}", e.domain))
                                Text(content: format!("{:<8?}", e.result), color: result_color)
                                Text(content: format!("{:<8}", format!("{}ms", e.upstream_us / 1000)), color: Color::Yellow)
                            }
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
            Text(content: props.value.to_string(), color: color)
        }
    }
}

#[derive(Props, Default)]
struct StatLineProps {
    pub label: String,
    pub value: u64,
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
