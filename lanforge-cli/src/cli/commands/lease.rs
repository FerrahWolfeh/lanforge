use super::CliCommand;
use crate::args::LeaseCommand;
use color_eyre::eyre::Result;
use lanforge_api::api::Command as ControlCommand;

pub struct LeaseHandler {
    pub action: LeaseCommand,
}

impl CliCommand for LeaseHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match &self.action {
            LeaseCommand::Renew { mac } => Ok(ControlCommand::LeaseRenew { mac: mac.clone() }),
            LeaseCommand::Release { mac } => Ok(ControlCommand::LeaseRelease { mac: mac.clone() }),
        }
    }
}
