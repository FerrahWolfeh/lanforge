use super::CliCommand;
use crate::args::QueryTarget;
use color_eyre::eyre::Result;
use lanforge_api::api::Command as ControlCommand;
use lanforge_api::api::Response;

pub struct QueryHandler {
    pub target: QueryTarget,
}

impl CliCommand for QueryHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match self.target {
            QueryTarget::Status => Ok(ControlCommand::Status),
            QueryTarget::Devices => Ok(ControlCommand::Devices {
                filter: None,
                vendor: None,
                method: None,
                format: None,
            }),
            QueryTarget::Hosts => Ok(ControlCommand::HostList),
            QueryTarget::State => Ok(ControlCommand::DbDump),
        }
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        let json = serde_json::to_string(response)?;
        println!("{}", json);
        Ok(None)
    }
}
