use crate::cli::{Execute, LanforgeClient};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ScanArgs {}

impl Execute for ScanArgs {
    async fn execute(self, client: &LanforgeClient) -> color_eyre::eyre::Result<()> {
        let mut rpc = client.connect_rpc().await?;
        let resp = rpc.scan().await?;
        println!("✓ {}", resp.message);
        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct ReloadArgs {}

impl Execute for ReloadArgs {
    async fn execute(self, client: &LanforgeClient) -> color_eyre::eyre::Result<()> {
        let mut rpc = client.connect_rpc().await?;
        let resp = rpc.reload().await?;
        println!("✓ {}", resp.message);
        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct PurgeArgs {
    pub mac: String,
}

impl Execute for PurgeArgs {
    async fn execute(self, client: &LanforgeClient) -> color_eyre::eyre::Result<()> {
        let mut rpc = client.connect_rpc().await?;
        let resp = rpc.purge(self.mac).await?;
        println!("✓ {}", resp.message);
        Ok(())
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct WatchArgs {}

impl Execute for WatchArgs {
    async fn execute(self, client: &LanforgeClient) -> color_eyre::eyre::Result<()> {
        client.execute_handler(Box::new(WatchHandler)).await
    }
}

pub struct WatchHandler;
use lanforge_api::rpc::{LanforgeRpcClient, RpcResponse};
use tokio::net::UnixStream;

#[async_trait::async_trait]
impl crate::cli::commands::CliCommand for WatchHandler {
    async fn execute_rpc(
        &mut self,
        client: &mut LanforgeRpcClient<UnixStream>,
    ) -> color_eyre::eyre::Result<()> {
        client.watch().await?;
        println!("Watching for events... (Ctrl+C to stop)");
        loop {
            match client.next_response().await {
                Ok(RpcResponse::Event(event)) => {
                    // For watch mode, we just print the event for now
                    // In the future, we might want to use the same formatting as Log
                    println!("Event: {event:?}");
                }
                Ok(RpcResponse::Error(e)) => eprintln!("Error: {e}"),
                Ok(_) => {}
                Err(lanforge_api::rpc::LanforgeRpcError::Io(e))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }


}
