use crate::cli::commands::CliCommand;
use color_eyre::eyre::{Context, Result};
use tokio::net::UnixStream;

use lanforge_api::rpc::LanforgeRpcClient;

pub struct LanforgeClient {
    pub socket: String,
    #[cfg(feature = "remote")]
    pub remote: Option<String>,
    #[cfg(feature = "remote")]
    pub token: Option<String>,
    #[cfg(feature = "remote")]
    pub password: Option<String>,
}

impl LanforgeClient {
    pub async fn connect_rpc(&self) -> Result<LanforgeRpcClient<UnixStream>> {
        let stream = UnixStream::connect(&self.socket).await.with_context(|| {
            format!(
                "Failed to connect to daemon at '{}'. Is the daemon running?",
                self.socket
            )
        })?;
        Ok(LanforgeRpcClient::new(stream))
    }

    pub async fn execute_handler(&self, mut handler: Box<dyn CliCommand>) -> Result<()> {
        let mut rpc = self.connect_rpc().await?;
        handler.execute_rpc(&mut rpc).await
    }
}
