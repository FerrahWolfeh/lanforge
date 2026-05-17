use crate::cli::{Execute, LanforgeClient};
use color_eyre::eyre::Result;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct WolArgs {
    /// Target device MAC or Hostname. Run without target for interactive menu.
    pub target: Option<String>,
}

impl Execute for WolArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let target = match self.target {
            Some(t) => t,
            None => {
                let dev =
                    crate::cli::wizard::fuzzy_select_device(client, "Select device to wake up:")
                        .await?;
                dev.mac
            }
        };

        println!("Triggering Wake-on-LAN for {target}...");
        let res = client.wol(target.clone()).await?;
        println!("✓ {}", res.message);
        Ok(())
    }
}
