use crate::cli::commands::CliCommand;
use crate::cli::{Execute, LanforgeClient};
use color_eyre::eyre::Result;
use inquire::Select;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct WolArgs {
    /// Target device MAC or Hostname. Run without target for interactive menu.
    pub target: Option<String>,
}

impl Execute for WolArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        client
            .execute_handler(Box::new(WolCommand {
                target: self.target,
            }))
            .await
    }
}

pub struct WolCommand {
    pub target: Option<String>,
}

use lanforge_api::rpc::LanforgeRpcClient;
use tokio::net::UnixStream;

#[async_trait::async_trait]
impl CliCommand for WolCommand {
    async fn execute_rpc(&mut self, client: &mut LanforgeRpcClient<UnixStream>) -> Result<()> {
        let target = if let Some(t) = &self.target {
            t.clone()
        } else {
            let resp = client.list_devices(None, None, None, None).await?;
            if resp.devices.is_empty() {
                println!("No devices found in the table for interactive Wake-on-LAN.");
                return Ok(());
            }

            let options: Vec<String> = resp
                .devices
                .iter()
                .map(|d| format!("{} - {}", d.mac, d.hostname))
                .collect();

            let selection = Select::new("Select a device to wake up:", options.clone()).prompt()?;
            let index = options.iter().position(|s| s == &selection).unwrap();
            resp.devices[index].mac.clone()
        };

        println!("Triggering Wake-on-LAN for {target}...");
        let res = client.wol(target).await?;
        println!("✓ {}", res.message);
        Ok(())
    }
}
