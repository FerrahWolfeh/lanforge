use crate::args::ConfigCommand;
use crate::cli::commands::CliCommand;
use color_eyre::eyre::Result;
use lanforge_api::api::{Command, CommandAction, Response};

pub struct ConfigHandler {
    pub action: ConfigCommand,
}

impl CliCommand for ConfigHandler {
    fn prepare(&mut self) -> Result<Command> {
        match &self.action {
            ConfigCommand::SetPassword { password } => {
                Ok(Command::new(CommandAction::ConfigSetPassword {
                    password: password.clone(),
                }))
            }
        }
    }

    fn on_response(&self, response: &Response) -> Result<Option<Command>> {
        match response {
            Response::Success(s) => {
                println!("✅ {}", s.message);
            }
            Response::Error { error } => {
                println!("❌ Error: {error}");
            }
            _ => println!("Unexpected response: {response:?}"),
        }
        Ok(None)
    }
}
