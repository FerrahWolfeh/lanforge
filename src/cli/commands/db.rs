use anyhow::Result;
use crate::config::DbCommand;
use crate::control::Command as ControlCommand;
use super::CliCommand;

pub struct DbHandler {
    pub action: DbCommand,
}

impl CliCommand for DbHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match self.action {
            DbCommand::Vacuum => Ok(ControlCommand::DbVacuum),
        }
    }
}
