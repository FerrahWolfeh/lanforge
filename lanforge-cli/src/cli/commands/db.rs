use super::CliCommand;
use crate::args::DbCommand;
use color_eyre::eyre::Result;
use colored::*;
use lanforge_api::api::{Command as ControlCommand, Response};

pub struct DbHandler {
    pub action: DbCommand,
}

impl CliCommand for DbHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match self.action {
            DbCommand::Vacuum => Ok(ControlCommand::DbVacuum),
            DbCommand::LogClean => Ok(ControlCommand::DbLogClean),
            DbCommand::Prune => Ok(ControlCommand::DbPrune),
            DbCommand::Snapshot => Ok(ControlCommand::ContextDump),
            DbCommand::Reset => Ok(ControlCommand::DbReset),
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
