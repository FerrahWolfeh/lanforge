use color_eyre::Result;

use crate::client::LanforgeClient;
use crate::output::Printer;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct ReloadArgs {}

impl ReloadArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        let resp = client.reload().await?;

        if printer.json {
            return printer.print_json(&resp);
        }

        printer.success(&resp.message);
        Ok(())
    }
}
