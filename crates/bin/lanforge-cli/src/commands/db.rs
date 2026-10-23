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
    /// Prune expired dynamic leases, offline temporary devices, and stale records
    Prune,
    /// Clean system and audit log buffers from persistent database storage
    Clean,
}

impl DbArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        let (resp, action_desc) = match self.subcommand {
            DbSubcommand::Prune => (client.db_prune().await?, "pruned"),
            DbSubcommand::Clean => (client.db_log_clean().await?, "log buffers cleaned"),
        };

        if printer.json {
            return printer.print_json(&resp);
        }

        printer.success(&format!("Database {action_desc}: {}", resp.message));
        Ok(())
    }
}
