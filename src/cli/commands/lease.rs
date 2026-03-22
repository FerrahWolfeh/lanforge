use anyhow::Result;
use crate::config::LeaseCommand;
use crate::control::Command as ControlCommand;
use super::CliCommand;

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
