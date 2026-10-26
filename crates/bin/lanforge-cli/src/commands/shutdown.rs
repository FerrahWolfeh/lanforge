use color_eyre::Result;
use inquire::Confirm;

use crate::client::LanforgeClient;
use crate::output::Printer;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct ShutdownArgs {
    /// Skip interactive confirmation prompt
    #[arg(short = 'y', long)]
    pub yes: bool,
}

impl ShutdownArgs {
    pub async fn execute(self, client: &LanforgeClient, printer: &Printer) -> Result<()> {
        if !printer.yes && !self.yes {
            let confirmed =
                Confirm::new("Are you sure you want to gracefully shut down the Lanforge daemon?")
                    .with_default(false)
                    .prompt()?;
            if !confirmed {
                printer.info("Shutdown aborted.");
                return Ok(());
            }
        }

        let resp = client.shutdown().await?;
        if printer.json {
            return printer.print_json(&resp);
        }

        printer.success(&resp.message);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_args_default() {
        let args = ShutdownArgs::default();
        assert!(!args.yes);
    }
}
