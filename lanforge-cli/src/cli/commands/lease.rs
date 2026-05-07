use super::CliCommand;
use crate::args::LeaseCommand;
use color_eyre::eyre::Result;
use lanforge_api::api::{Command as ControlCommand, CommandAction, Response};
use lanforge_types::LeaseTarget;

pub struct LeaseHandler {
    pub action: LeaseCommand,
}

impl CliCommand for LeaseHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match &self.action {
            LeaseCommand::Renew { mac, v6 } => Ok(ControlCommand::new(CommandAction::LeaseRenew {
                mac: mac.clone(),
                target: Some(if *v6 {
                    LeaseTarget::V6 { iaid: 0 }
                } else {
                    LeaseTarget::V4
                }),
            })),
            LeaseCommand::Release { mac, v6 } => {
                Ok(ControlCommand::new(CommandAction::LeaseRelease {
                    mac: mac.clone(),
                    target: Some(if *v6 {
                        LeaseTarget::V6 { iaid: 0 }
                    } else {
                        LeaseTarget::V4
                    }),
                }))
            }
        }
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        match response {
            Response::Success(s) => {
                println!("✓ {}", s.message);
            }
            Response::Error { error } => {
                println!("✗ Error: {error}");
            }
            _ => {
                println!("Unexpected response: {response:?}");
            }
        }
        Ok(None)
    }
}
