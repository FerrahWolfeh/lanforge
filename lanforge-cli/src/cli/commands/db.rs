use super::CliCommand;
use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::Result;
use colored::Colorize;
use lanforge_api::api::{Command as ControlCommand, CommandAction, Response};

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

impl CliCommand for DbHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match self.action {
            DbAction::Vacuum => Ok(ControlCommand::new(CommandAction::DbVacuum)),
            DbAction::LogClean => Ok(ControlCommand::new(CommandAction::DbLogClean)),
            DbAction::Prune => Ok(ControlCommand::new(CommandAction::DbPrune)),
            DbAction::Snapshot => Ok(ControlCommand::new(CommandAction::ContextDump {
                only_devices: false,
                only_orphans: false,
            })),
            DbAction::Reset => Ok(ControlCommand::new(CommandAction::DbReset)),
        }
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        match response {
            Response::ContextDump(state) => {
                println!("{}", serde_json::to_string_pretty(&state)?);
            }
            Response::Success(s) => {
                println!("{} {}", "✓".green().bold(), s.message.bright_green());
            }
            Response::Error { error } => {
                eprintln!("{} {}", "✘".red().bold(), error.red());
            }
            _ => {}
        }
        Ok(None)
    }
}
