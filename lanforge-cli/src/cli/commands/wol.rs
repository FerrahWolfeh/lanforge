use crate::cli::commands::CliCommand;
use crate::cli::{Execute, LanforgeClient};
use color_eyre::eyre::Result;
use inquire::Select;
use lanforge_api::api::{Command as ControlCommand, CommandAction, Response};

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

impl CliCommand for WolCommand {
    fn prepare(&mut self) -> Result<ControlCommand> {
        self.target.as_ref().map_or_else(
            || {
                Ok(ControlCommand::new(CommandAction::Devices {
                    filter: None,
                    vendor: None,
                    method: None,
                    format: None,
                }))
            },
            |target| {
                Ok(ControlCommand::new(CommandAction::Wol {
                    target: target.clone(),
                }))
            },
        )
    }

    fn on_response(&self, response: &Response) -> Result<Option<ControlCommand>> {
        match response {
            Response::Devices(resp) if self.target.is_none() => {
                if resp.devices.is_empty() {
                    println!("No devices found in the table for interactive Wake-on-LAN.");
                    return Ok(None);
                }

                let options: Vec<String> = resp
                    .devices
                    .iter()
                    .map(|d| {
                        // Skip OUI resolution for speed as requested
                        format!("{} - {}", d.mac, d.hostname)
                    })
                    .collect();

                let selection =
                    Select::new("Select a device to wake up:", options.clone()).prompt()?;
                let index = options.iter().position(|s| s == &selection).unwrap();
                let mac = &resp.devices[index].mac;

                println!("Triggering Wake-on-LAN for {mac}...");

                return Ok(Some(ControlCommand::new(CommandAction::Wol {
                    target: mac.clone(),
                })));
            }
            Response::Success(s) => {
                println!("✓ {}", s.message);
            }
            Response::Error { error } => {
                println!("Error: {error}");
            }
            _ => {
                println!("Unexpected response: {response:?}");
            }
        }
        Ok(None)
    }
}
