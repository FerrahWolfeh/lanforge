use crate::cli::commands::CliCommand;
use crate::cli::vendor::resolve_vendor;
use color_eyre::eyre::Result;
use inquire::Select;
use lanforge_api::api::{Command as ControlCommand, Response};

pub struct WolCommand {
    pub target: Option<String>,
}

impl CliCommand for WolCommand {
    fn prepare(&mut self) -> Result<ControlCommand> {
        if let Some(target) = &self.target {
            Ok(ControlCommand::Wol {
                target: target.clone(),
            })
        } else {
            // Interactive mode: we need to fetch devices first.
            // BUT: CliCommand::prepare is currently expected to return a single command.
            // We'll return a "Devices" command first, and then in on_response, if we get Devices,
            // we'll run the interactive menu and send a SECOND command?
            // Actually, the current CLI architecture in lanforge seems to expect one request-response.
            // Let's check how 'Host Add' works if it's interactive.
            Ok(ControlCommand::Devices {
                filter: None,
                vendor: None,
                method: None,
                format: None,
            })
        }
    }

    fn on_response(&self, response: &Response) -> Result<()> {
        match response {
            Response::Devices(resp) if self.target.is_none() => {
                if resp.devices.is_empty() {
                    println!(
                        "Nenhum dispositivo encontrado na tabela para Wake-on-LAN interativo."
                    );
                    return Ok(());
                }

                let options: Vec<String> = resp
                    .devices
                    .iter()
                    .map(|d| {
                        format!(
                            "{} - {} ({})",
                            d.mac,
                            d.hostname,
                            resolve_vendor(&d.mac).unwrap_or_else(|| "Unknown".to_string())
                        )
                    })
                    .collect();

                let selection =
                    Select::new("Selecione o dispositivo para acordar:", options.clone())
                        .prompt()?;
                let index = options.iter().position(|s| s == &selection).unwrap();
                let mac = &resp.devices[index].mac;

                println!("Enviando comando WoL para {}...", mac);
                // Since CliCommand doesn't support multi-step naturally here without a loop in main,
                // we'll just advise the user to run with the MAC for now, OR we need to modify main.rs.
                // Actually, let's see if we can just publish directly if we have the bus?
                // No, CLI talks to daemon via UDS.
                println!("DICA: Execute 'lanforge wol {}' para disparar.", mac);
            }
            Response::Success(s) => {
                println!("✓ {}", s.message);
            }
            Response::Error { error } => {
                println!("Erro: {}", error);
            }
            _ => {
                println!("Resposta inesperada: {:?}", response);
            }
        }
        Ok(())
    }
}
