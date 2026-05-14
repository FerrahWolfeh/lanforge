use super::CliCommand;
use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::Result;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct QueryArgs {
    #[command(subcommand)]
    pub target: QueryAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum QueryAction {
    /// Return the full status object as JSON
    Status,
    /// Return the device list as JSON
    Devices,
    /// Return the host configuration list as JSON
    Hosts,
    /// Return the internal context state as JSON
    State {
        /// Only dump the device table
        #[arg(long)]
        only_devices: bool,
        /// Only dump orphaned records (no IP/Host)
        #[arg(long)]
        only_orphans: bool,
    },
    /// Return the active lease list as JSON
    Leases {
        /// Only return the number of active leases
        #[arg(short, long)]
        count: bool,
        /// Return as plain-text table instead of JSON
        #[arg(short, long)]
        plain: bool,
    },
    /// Return the network topology (interfaces/addresses) as JSON
    Topology,
}

impl Execute for QueryArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        client
            .execute_handler(Box::new(QueryHandler {
                target: self.target,
            }))
            .await
    }
}

pub struct QueryHandler {
    pub target: QueryAction,
}

use lanforge_api::rpc::LanforgeRpcClient;
use tokio::net::UnixStream;

#[async_trait::async_trait]
impl CliCommand for QueryHandler {
    async fn execute_rpc(&mut self, client: &mut LanforgeRpcClient<UnixStream>) -> Result<()> {
        match &self.target {
            QueryAction::Status => {
                let res = client.status().await?;
                println!("{}", serde_json::to_string_pretty(&res)?);
            }
            QueryAction::Devices => {
                let res = client.list_devices(None, None, None, None).await?;
                println!("{}", serde_json::to_string_pretty(&res)?);
            }
            QueryAction::Hosts => {
                let res = client.host_list().await?;
                println!("{}", serde_json::to_string_pretty(&res)?);
            }
            QueryAction::State {
                only_devices,
                only_orphans,
            } => {
                let res = client.context_dump(*only_devices, *only_orphans).await?;
                println!("{}", serde_json::to_string_pretty(&res)?);
            }
            QueryAction::Leases { count, plain } => {
                let res = client.leases(*count).await?;
                if *plain {
                    if *count {
                        println!("{}", res.leases.len());
                    } else {
                        for lease in &res.leases {
                            println!(
                                "{} {} {} {:?} {}",
                                lease.mac,
                                lease.hostname,
                                lease.address,
                                lease.kind,
                                lease.remaining_secs
                            );
                        }
                    }
                } else if *count {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "count": res.leases.len()
                        }))?
                    );
                } else {
                    println!("{}", serde_json::to_string_pretty(&res)?);
                }
            }
            QueryAction::Topology => {
                let res = client.topology().await?;
                println!("{}", serde_json::to_string_pretty(&res)?);
            }
        }
        Ok(())
    }
}
