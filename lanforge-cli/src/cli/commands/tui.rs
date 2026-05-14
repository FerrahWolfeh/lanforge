use crate::cli::{Execute, LanforgeClient};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct TuiArgs {}

impl Execute for TuiArgs {
    async fn execute(self, client: &LanforgeClient) -> color_eyre::eyre::Result<()> {
        #[cfg(feature = "tui")]
        {
            #[cfg(feature = "remote")]
            if let Some(remote_url) = &client.remote {
                use lanforge_http::RemoteClient;
                let mut http_client = RemoteClient::new(remote_url.clone(), client.token.clone());
                if let Some(pwd) = &client.password {
                    http_client
                        .login(pwd)
                        .await
                        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
                }
                return crate::tui::run_tui(None, Some(http_client)).await;
            }

            crate::tui::run_tui(Some(client.socket.clone()), None).await
        }
        #[cfg(not(feature = "tui"))]
        {
            let _ = client;
            Err(color_eyre::eyre::eyre!("TUI feature not enabled"))
        }
    }
}
