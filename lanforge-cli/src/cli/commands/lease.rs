use super::CliCommand;
use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::Result;
use lanforge_api::api::{Command as ControlCommand, CommandAction, Response};
use lanforge_core::types::LeaseTarget;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct LeaseArgs {
    #[command(subcommand)]
    pub action: LeaseAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum LeaseAction {
    /// Forces a renew of a specific lease.
    Renew {
        /// Target device MAC
        mac: String,
        /// Trigger IPv6 renew instead of IPv4
        #[arg(short = '6', long)]
        v6: bool,
    },
    /// Forces a release of a specific lease.
    Release {
        /// Target device MAC
        mac: String,
        /// Trigger IPv6 release instead of IPv4
        #[arg(short = '6', long)]
        v6: bool,
    },
}

impl Execute for LeaseArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        client
            .execute_handler(Box::new(LeaseHandler {
                action: self.action,
            }))
            .await
    }
}

pub struct LeaseHandler {
    pub action: LeaseAction,
}

impl CliCommand for LeaseHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match &self.action {
            LeaseAction::Renew { mac, v6 } => Ok(ControlCommand::new(CommandAction::LeaseRenew {
                mac: mac.clone(),
                target: Some(if *v6 {
                    LeaseTarget::V6 { iaid: 0 }
                } else {
                    LeaseTarget::V4
                }),
            })),
            LeaseAction::Release { mac, v6 } => {
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
