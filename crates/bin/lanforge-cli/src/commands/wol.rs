use color_eyre::Result;

use crate::client::LanforgeClient;
use crate::output::Printer;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct WolArgs {
    /// MAC address or hostname of the target device to wake
    pub target: String,
}

impl WolArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        let resp = client.wol(self.target.clone()).await?;

        if printer.json {
            return printer.print_json(&resp);
        }

        printer.success(&format!("Magic packet sent to '{}': {}", self.target, resp.message));
        Ok(())
    }
}
