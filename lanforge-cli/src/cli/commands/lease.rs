use super::CliCommand;
use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::Result;
use lanforge_types::LeaseTarget;

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

use lanforge_api::rpc::LanforgeRpcClient;
use tokio::net::UnixStream;

#[async_trait::async_trait]
impl CliCommand for LeaseHandler {
    async fn execute_rpc(&mut self, client: &mut LanforgeRpcClient<UnixStream>) -> Result<()> {
        match &self.action {
            LeaseAction::Renew { mac, v6 } => {
                let target = if *v6 {
                    LeaseTarget::V6 { iaid: 0 }
                } else {
                    LeaseTarget::V4
                };
                let resp = client.lease_renew(mac.clone(), Some(target)).await?;
                println!("✓ {}", resp.message);
            }
            LeaseAction::Release { mac, v6 } => {
                let target = if *v6 {
                    LeaseTarget::V6 { iaid: 0 }
                } else {
                    LeaseTarget::V4
                };
                let resp = client.lease_release(mac.clone(), Some(target)).await?;
                println!("✓ {}", resp.message);
            }
        }
        Ok(())
    }
}
