use super::CliCommand;
use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::Result;
use lanforge_api::api::{Command as ControlCommand, CommandAction, Response};

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

impl CliCommand for QueryHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match self.target {
            QueryAction::Status => Ok(ControlCommand::new(CommandAction::Status)),
            QueryAction::Devices => Ok(ControlCommand::new(CommandAction::Devices {
                filter: None,
                vendor: None,
                method: None,
                format: None,
            })),
            QueryAction::Hosts => Ok(ControlCommand::new(CommandAction::HostList)),
            QueryAction::State {
                only_devices,
                only_orphans,
            } => Ok(ControlCommand::new(CommandAction::ContextDump {
                only_devices,
                only_orphans,
            })),
            QueryAction::Leases { count, .. } => {
                Ok(ControlCommand::new(CommandAction::Leases { count }))
            }
            QueryAction::Topology => Ok(ControlCommand::new(CommandAction::Topology)),
        }
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        if let QueryAction::Leases { count, plain } = &self.target
            && let Response::Leases(res) = response
        {
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
                return Ok(None);
            } else if *count {
                serde_json::to_writer(
                    std::io::stdout(),
                    &serde_json::json!({ "count": res.leases.len() }),
                )?;
                println!();
                return Ok(None);
            }
        }

        serde_json::to_writer(std::io::stdout(), response)?;
        println!();
        Ok(None)
    }
}
