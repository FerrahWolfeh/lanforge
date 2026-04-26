use crate::{args, cli::commands::CliCommand};
use color_eyre::eyre::Result;
use iocraft::prelude::*;
use lanforge_api::api::{Command as ControlCommand, CommandAction, DnsQueryResponse, Response};

pub struct DnsCommand {
    pub action: args::DnsCommand,
}

impl CliCommand for DnsCommand {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match &self.action {
            args::DnsCommand::Stats => Ok(ControlCommand::new(CommandAction::DnsStats)),
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
        }
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        match response {
            Response::DnsStats(stats) => {
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
            Response::DnsQuery(query) => {
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
            Response::Error { error } => {
                println!("Error: {}", error);
            }
            Response::Success(msg) => {
                println!("{}", msg.message);
            }
            _ => {
                println!("Unexpected response: {:?}", response);
            }
        }
        Ok(None)
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
