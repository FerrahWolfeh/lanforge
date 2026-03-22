use anyhow::Result;
use crate::control::Command as ControlCommand;
use super::CliCommand;

pub struct LogHandler {
    pub follow: bool,
}

impl CliCommand for LogHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        Ok(ControlCommand::Log { follow: self.follow })
    }

    fn is_streaming(&self) -> bool {
        self.follow
    }
}
