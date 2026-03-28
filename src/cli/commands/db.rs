use super::CliCommand;
use crate::config::DbCommand;
use anyhow::Result;
use lanforge_api::api::Command as ControlCommand;

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
