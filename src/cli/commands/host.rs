use anyhow::Result;
use inquire::{Confirm, Select, Text as InquireText};
use crate::config::HostCommand;
use crate::control::Command as ControlCommand;
use super::CliCommand;

pub struct HostHandler {
    pub action: HostCommand,
}

impl CliCommand for HostHandler {
    fn prepare(&mut self) -> Result<ControlCommand> {
        match &self.action {
            HostCommand::Add {
                mac,
                hostname,
                v4,
                v6_suffix,
            } => {
                let final_mac = if let Some(m) = mac {
                    m.clone()
                } else {
                    let ans = InquireText::new("MAC address:").prompt()?;
                    if ans.trim().is_empty() {
                        // user skipped, we probably want to return an error or a dummy command handled gracefully.
                        // Actually, if it's empty, returning an error exits early.
                        anyhow::bail!("MAC address is required");
                    }
                    ans.trim().to_string()
                };

                let final_hostname = if let Some(h) = hostname {
                    h.clone()
                } else {
                    let ans = InquireText::new("Hostname:").prompt()?;
                    if ans.trim().is_empty() {
                        anyhow::bail!("Hostname is required");
                    }
                    ans.trim().to_string()
                };

                let mut final_v4 = v4.clone();
                let mut final_v6 = v6_suffix.clone();

                if v4.is_none() && v6_suffix.is_none() {
                    let opts = vec![
                        "[1] Só hostname (IP dinâmico do pool)",
                        "[2] Hostname + IPv4 fixo",
                        "[3] Hostname + IPv4 fixo + sufixo ULA",
                    ];
                    let choice = Select::new("Nível de configuração:", opts).prompt()?;
                    if choice.starts_with("[2]") || choice.starts_with("[3]") {
                        let ans = InquireText::new("IPv4 fixo:").prompt()?;
                        if !ans.trim().is_empty() {
                            final_v4 = Some(ans.trim().to_string());
                        }
                    }
                    if choice.starts_with("[3]") {
                        let ans = InquireText::new("Sufixo ULA (ex: ::1234):").prompt()?;
                        if !ans.trim().is_empty() {
                            final_v6 = Some(ans.trim().to_string());
                        }
                    }

                    println!("\nConfirmar?");
                    println!("  MAC       {final_mac}");
                    println!("  hostname  {final_hostname}");
                    if let Some(ref v) = final_v4 {
                        println!("  V4 fixo   {v}");
                    }
                    if let Some(ref v) = final_v6 {
                        println!("  V6 sufixo {v}");
                    }
                    println!();

                    let confirm = Confirm::new("Confirmar adição?")
                        .with_default(true)
                        .prompt()?;
                    if !confirm {
                        anyhow::bail!("Cancelado.");
                    }
                }

                Ok(ControlCommand::HostAdd {
                    mac: Some(final_mac),
                    hostname: Some(final_hostname),
                    v4: final_v4,
                    v6_suffix: final_v6,
                })
            }
            HostCommand::Set { mac, field, value } => {
                Ok(ControlCommand::HostSet {
                    mac: mac.clone(),
                    field: field.clone(),
                    value: value.clone(),
                })
            }
            HostCommand::Remove { mac } => {
                Ok(ControlCommand::HostRemove { mac: mac.clone() })
            }
            HostCommand::List => Ok(ControlCommand::HostList),
        }
    }

    fn on_response(&self, response: &crate::control::Response) -> Result<()> {
        match response {
            crate::control::Response::Devices(resp) => {
                super::devices::render_devices(resp, false);
                Ok(())
            }
            _ => {
                // Delegate to default implementation? We can't easily, so we duplicate the basic ones.
                match response {
                    crate::control::Response::Error { error } => {
                        println!("Erro: {error}");
                    }
                    crate::control::Response::Success(success) => {
                        println!("✓ {}", success.message);
                    }
                    crate::control::Response::Event(e) => {
                        println!("Event: {e:?}");
                    }
                    _ => {
                        println!("Resposta inesperada: {response:?}");
                    }
                }
                Ok(())
            }
        }
    }
}

