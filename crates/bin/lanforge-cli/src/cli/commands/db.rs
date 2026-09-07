use crate::cli::{
    Execute, LanforgeClient,
    wizard::{confirm_destructive, confirm_wipe},
};
use clap::Subcommand;
use color_eyre::eyre::Result;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DbArgs {
    #[command(subcommand)]
    pub action: DbAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DbAction {
    /// Perform a database compact / vacuum operation
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
        match self.action {
            DbAction::Vacuum => {
                let resp = client.db_vacuum().await?;
                println!("✓ {}", resp.message);
            }
            DbAction::LogClean => {
                let resp = client.db_log_clean().await?;
                println!("✓ {}", resp.message);
            }
            DbAction::Prune => {
                if !confirm_destructive(client, "Are you sure you want to prune zombie entries?")? {
                    return Ok(());
                }
                let resp = client.db_prune().await?;
                println!("✓ {}", resp.message);
            }
            DbAction::Snapshot => {
                let resp = client.context_dump(false, false).await?;
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
            DbAction::Reset => {
                if !confirm_wipe(client)? {
                    return Ok(());
                }
                let resp = client.db_reset().await?;
                println!("✓ {}", resp.message);
            }
        }
        Ok(())
    }
}
