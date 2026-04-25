use super::CliCommand;
use crate::args::LeaseCommand;
use color_eyre::eyre::Result;
use lanforge_api::api::{Command as ControlCommand, CommandAction};

pub struct LeaseHandler {
    pub action: LeaseCommand,
}

impl CliCommand for LeaseHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match &self.action {
            LeaseCommand::Renew { mac } => Ok(ControlCommand::new(CommandAction::LeaseRenew {
                mac: mac.clone(),
                target: None,
            })),
            LeaseCommand::Release { mac } => Ok(ControlCommand::new(CommandAction::LeaseRelease {
                mac: mac.clone(),
                target: None,
            })),
        }
    }
}
