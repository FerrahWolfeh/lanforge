use crate::cli::commands::CliCommand;
use color_eyre::eyre::Result;
use lanforge_api::api::{Command as ControlCommand, Response};
use tabled::{Table, Tabled};

pub struct DnsCommand {
    pub action: crate::args::DnsCommand,
}

#[derive(Tabled)]
struct DnsStatsRow {
    #[tabled(rename = "Metric")]
    metric: &'static str,
    #[tabled(rename = "Value")]
    value: u64,
}

impl CliCommand for DnsCommand {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match &self.action {
            crate::args::DnsCommand::Stats => Ok(ControlCommand::DnsStats),
            crate::args::DnsCommand::Query { name, record_type } => Ok(ControlCommand::DnsQuery {
                name: name.clone(),
                record_type: record_type.clone(),
            }),
        }
    }

    fn on_response(&self, response: &Response) -> Result<()> {
        match response {
            Response::DnsStats(stats) => {
                let rows = vec![
                    DnsStatsRow {
                        metric: "Total Requests",
                        value: stats.total_requests,
                    },
                    DnsStatsRow {
                        metric: "Cache Hits",
                        value: stats.cache_hits,
                    },
                    DnsStatsRow {
                        metric: "Cache Misses",
                        value: stats.cache_misses,
                    },
                    DnsStatsRow {
                        metric: "Upstream Errors",
                        value: stats.upstream_errors,
                    },
                    DnsStatsRow {
                        metric: "Auth Queries",
                        value: stats.auth_queries,
                    },
                    DnsStatsRow {
                        metric: "Recursions",
                        value: stats.recursions,
                    },
                ];
                println!("{}", Table::new(rows));
            }
            Response::DnsQuery(query) => {
                println!("Dns Query Result ({}ms):", query.latency_ms);
                if query.authoritative {
                    println!("(Authoritative)");
                }
                if query.records.is_empty() {
                    println!("No records found.");
                } else {
                    for r in &query.records {
                        println!("- {}", r);
                    }
                }
            }
            Response::Error { error } => {
                println!("Erro: {}", error);
            }
            _ => {
                println!("Resposta inesperada: {:?}", response);
            }
        }
        Ok(())
    }
}
