use crate::cli::commands::CliCommand;
use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::Result;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ConfigAction {
    /// Update the administrative password for remote API access
    SetPassword { password: String },
}

impl Execute for ConfigArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        client
            .execute_handler(Box::new(ConfigHandler {
                action: self.action,
            }))
            .await
    }
}

pub struct ConfigHandler {
    pub action: ConfigAction,
}

use lanforge_api::rpc::LanforgeRpcClient;
use tokio::net::UnixStream;

#[async_trait::async_trait]
impl CliCommand for ConfigHandler {
    async fn execute_rpc(&mut self, client: &mut LanforgeRpcClient<UnixStream>) -> Result<()> {
        match &self.action {
            ConfigAction::SetPassword { password } => {
                let resp = client.config_set_password(password.clone()).await?;
                println!("✅ {}", resp.message);
            }
        }
        Ok(())
    }
}
