use super::CliCommand;
use crate::args::DbCommand;
use color_eyre::eyre::Result;
use colored::Colorize;
use lanforge_api::api::{Command as ControlCommand, CommandAction, Response};

pub struct DbHandler {
    pub action: DbCommand,
}

impl CliCommand for DbHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match self.action {
            DbCommand::Vacuum => Ok(ControlCommand::new(CommandAction::DbVacuum)),
            DbCommand::LogClean => Ok(ControlCommand::new(CommandAction::DbLogClean)),
            DbCommand::Prune => Ok(ControlCommand::new(CommandAction::DbPrune)),
            DbCommand::Snapshot => Ok(ControlCommand::new(CommandAction::ContextDump {
                only_devices: false,
                only_orphans: false,
            })),
            DbCommand::Reset => Ok(ControlCommand::new(CommandAction::DbReset)),
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
