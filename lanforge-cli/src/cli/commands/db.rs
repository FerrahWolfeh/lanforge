use super::CliCommand;
use crate::args::DbCommand;
use color_eyre::eyre::Result;
use lanforge_api::api::Command as ControlCommand;

pub struct DbHandler {
    pub action: DbCommand,
}

impl CliCommand for DbHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match self.action {
            DbCommand::Vacuum => Ok(ControlCommand::DbVacuum),
            DbCommand::LogClean => Ok(ControlCommand::DbLogClean),
        }
    }
}
