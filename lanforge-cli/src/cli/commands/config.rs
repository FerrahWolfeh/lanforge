use crate::cli::commands::CliCommand;
use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::Result;
use lanforge_api::api::{Command, CommandAction, Response};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ConfigAction {
    /// Update the administrative password for remote API access
    SetPassword { password: String },
}

impl Execute for ConfigArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        client
            .execute_handler(Box::new(ConfigHandler {
                action: self.action,
            }))
            .await
    }
}

pub struct ConfigHandler {
    pub action: ConfigAction,
}

impl CliCommand for ConfigHandler {
    fn prepare(&mut self) -> Result<Command> {
        match &self.action {
            ConfigAction::SetPassword { password } => {
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
