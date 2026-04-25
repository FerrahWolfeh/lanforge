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
            QueryTarget::State => Ok(ControlCommand::new(CommandAction::ContextDump)),
        }
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        serde_json::to_writer(std::io::stdout(), response)?;
        println!();
        Ok(None)
    }
}
