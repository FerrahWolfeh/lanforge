use super::CliCommand;
use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::Result;
use colored::Colorize;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DbArgs {
    #[command(subcommand)]
    pub action: DbAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DbAction {
    /// Perform a `SQLite` VACUUM operation
    Vacuum,
    /// Clear the transient system log database
    LogClean,
    /// Remove 'zombie' entries (dynamic devices with no IP nor hostname)
    Prune,
    /// Generate a diagnostic snapshot of the in-memory state as JSON
    Snapshot,
    /// Completely reset and re-seed the database (FACTORY RESET)
    Reset,
}

impl Execute for DbArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        client
            .execute_handler(Box::new(DbHandler {
                action: self.action,
            }))
            .await
    }
}

pub struct DbHandler {
    pub action: DbAction,
}

use lanforge_api::rpc::LanforgeRpcClient;
use tokio::net::UnixStream;

#[async_trait::async_trait]
impl CliCommand for DbHandler {
    async fn execute_rpc(&mut self, client: &mut LanforgeRpcClient<UnixStream>) -> Result<()> {
        match self.action {
            DbAction::Vacuum => {
                let resp = client.db_vacuum().await?;
                println!("{} {}", "✓".green().bold(), resp.message.bright_green());
            }
            DbAction::LogClean => {
                let resp = client.db_log_clean().await?;
                println!("{} {}", "✓".green().bold(), resp.message.bright_green());
            }
            DbAction::Prune => {
                let resp = client.db_prune().await?;
                println!("{} {}", "✓".green().bold(), resp.message.bright_green());
            }
            DbAction::Snapshot => {
                let resp = client.context_dump(false, false).await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            DbAction::Reset => {
                let resp = client.db_reset().await?;
                println!("{} {}", "✓".green().bold(), resp.message.bright_green());
            }
        }
        Ok(())
    }
}
