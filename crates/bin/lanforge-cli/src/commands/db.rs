use color_eyre::Result;

use crate::client::LanforgeClient;
use crate::output::Printer;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DbArgs {
    #[command(subcommand)]
    pub subcommand: DbSubcommand,
}

#[derive(clap::Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DbSubcommand {
    /// Compact embedded redb database pages and reclaim unused disk space
    Vacuum,
    /// Prune expired dynamic leases, offline temporary devices, and stale records
    Prune,
    /// Clean system and audit log buffers from persistent database storage
    Clean,
}

impl DbArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        match self.subcommand {
            DbSubcommand::Vacuum => {
                let resp = client.db_vacuum().await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success(&format!("Database compacted: {}", resp.message));
                Ok(())
            }
            DbSubcommand::Prune => {
                let resp = client.db_prune().await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success(&format!("Database pruned: {}", resp.message));
                Ok(())
            }
            DbSubcommand::Clean => {
                let resp = client.db_log_clean().await?;
                if printer.json {
                    return printer.print_json(&resp);
                }
                printer.success(&format!("Database log buffers cleaned: {}", resp.message));
                Ok(())
            }
        }
    }
}
