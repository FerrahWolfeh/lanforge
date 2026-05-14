use crate::cli::commands::GenericHandler;
use crate::cli::{Execute, LanforgeClient};
use lanforge_api::api::{Command, CommandAction};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ScanArgs {}

impl Execute for ScanArgs {
    async fn execute(self, client: &LanforgeClient) -> color_eyre::eyre::Result<()> {
        client
            .execute_handler(Box::new(GenericHandler {
                cmd: Command::new(CommandAction::Scan),
                streaming: false,
            }))
            .await
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ReloadArgs {}

impl Execute for ReloadArgs {
    async fn execute(self, client: &LanforgeClient) -> color_eyre::eyre::Result<()> {
        client
            .execute_handler(Box::new(GenericHandler {
                cmd: Command::new(CommandAction::Reload),
                streaming: false,
            }))
            .await
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct PurgeArgs {
    pub mac: String,
}

impl Execute for PurgeArgs {
    async fn execute(self, client: &LanforgeClient) -> color_eyre::eyre::Result<()> {
        client
            .execute_handler(Box::new(GenericHandler {
                cmd: Command::new(CommandAction::Purge { mac: self.mac }),
                streaming: false,
            }))
            .await
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct WatchArgs {}

impl Execute for WatchArgs {
    async fn execute(self, client: &LanforgeClient) -> color_eyre::eyre::Result<()> {
        client
            .execute_handler(Box::new(GenericHandler {
                cmd: Command::new(CommandAction::Watch),
                streaming: true,
            }))
            .await
    }
}
