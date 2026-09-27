use color_eyre::eyre::Result;

use crate::cli::{Execute, LanforgeClient};
use std::sync::Arc;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct TuiArgs {}

impl Execute for TuiArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        #[cfg(feature = "tui")]
        {
            let arc_client = Arc::new(LanforgeClient {
                socket: client.socket.clone(),
                #[cfg(feature = "remote")]
                remote: client.remote.clone(),
                #[cfg(feature = "remote")]
                token: client.token.clone(),
                json: client.json,
                no_color: client.no_color,
                ascii: client.ascii,
                yes: client.yes,
                #[cfg(feature = "remote")]
                http_client: client.http_client.clone(),
            });
            crate::tui::run_tui(arc_client).await
        }
        #[cfg(not(feature = "tui"))]
        {
            let _ = client;
            Err(color_eyre::eyre::eyre!("TUI feature not enabled"))
        }
    }
}
