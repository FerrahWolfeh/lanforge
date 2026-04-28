use super::CliCommand;
use crate::args::QueryTarget;
use color_eyre::eyre::Result;
use lanforge_api::api::{Command as ControlCommand, CommandAction, Response};

pub struct QueryHandler {
    pub target: QueryTarget,
}

impl CliCommand for QueryHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match self.target {
            QueryTarget::Status => Ok(ControlCommand::new(CommandAction::Status)),
            QueryTarget::Devices => Ok(ControlCommand::new(CommandAction::Devices {
                filter: None,
                vendor: None,
                method: None,
                format: None,
            })),
            QueryTarget::Hosts => Ok(ControlCommand::new(CommandAction::HostList)),
            QueryTarget::State {
                only_devices,
                only_orphans,
            } => Ok(ControlCommand::new(CommandAction::ContextDump {
                only_devices,
                only_orphans,
            })),
            QueryTarget::Leases { count, .. } => {
                Ok(ControlCommand::new(CommandAction::Leases { count }))
            }
            QueryTarget::Topology => Ok(ControlCommand::new(CommandAction::Topology)),
        }
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        if let QueryTarget::Leases { count, plain } = &self.target
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
