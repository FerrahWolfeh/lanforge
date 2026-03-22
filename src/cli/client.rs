use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use inquire::{Confirm, Select, Text as InquireText};

use crate::cli::render::{render_devices, render_status};
use crate::config::Command;
use crate::control::{Command as ControlCommand, Response};

pub async fn run_client(command: Command, socket_path: &str) -> Result<()> {
    let mut stream = UnixStream::connect(socket_path).await.with_context(|| {
        format!("Falha ao conectar no daemon em '{socket_path}'. O daemon está rodando?")
    })?;

    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let is_streaming = matches!(command, Command::Watch | Command::Log { .. });

    let json_req = match &command {
        Command::Status => serde_json::to_string(&ControlCommand::Status)?,
        Command::Devices { filter, format, .. } => {
            serde_json::to_string(&ControlCommand::Devices {
                filter: filter.clone(),
                format: format.clone(),
            })?
        }
        Command::Reload => serde_json::to_string(&ControlCommand::Reload)?,
        Command::Watch => serde_json::to_string(&ControlCommand::Watch)?,
        Command::Log { follow } => serde_json::to_string(&ControlCommand::Log { follow: *follow })?,
        Command::Scan => serde_json::to_string(&ControlCommand::Scan)?,
        Command::Shutdown => serde_json::to_string(&ControlCommand::Shutdown)?,
        Command::Host { action } => match action {
            crate::config::HostCommand::Add {
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
                        return Ok(());
                    }
                    ans.trim().to_string()
                };

                let final_hostname = if let Some(h) = hostname {
                    h.clone()
                } else {
                    let ans = InquireText::new("Hostname:").prompt()?;
                    if ans.trim().is_empty() {
                        return Ok(());
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
                        println!("Cancelado.");
                        return Ok(());
                    }
                }

                serde_json::to_string(&ControlCommand::HostAdd {
                    mac: Some(final_mac),
                    hostname: Some(final_hostname),
                    v4: final_v4,
                    v6_suffix: final_v6,
                })?
            }
            crate::config::HostCommand::Set { mac, field, value } => {
                serde_json::to_string(&ControlCommand::HostSet {
                    mac: mac.clone(),
                    field: field.clone(),
                    value: value.clone(),
                })?
            }
            crate::config::HostCommand::Remove { mac } => {
                serde_json::to_string(&ControlCommand::HostRemove { mac: mac.clone() })?
            }
            crate::config::HostCommand::List => serde_json::to_string(&ControlCommand::HostList)?,
        },
        Command::Lease { action } => match action {
            crate::config::LeaseCommand::Renew { mac } => {
                serde_json::to_string(&ControlCommand::LeaseRenew { mac: mac.clone() })?
            }
            crate::config::LeaseCommand::Release { mac } => {
                serde_json::to_string(&ControlCommand::LeaseRelease { mac: mac.clone() })?
            }
        },
        Command::Db { action } => match action {
            crate::config::DbCommand::Vacuum => serde_json::to_string(&ControlCommand::DbVacuum)?,
        },
        Command::Run { .. } => {
            println!("Este comando ainda não está implementado na CLI.");
            return Ok(());
        }
    };

    writer.write_all(json_req.as_bytes()).await?;
    writer.write_all(b"\n").await?;

    let mut response_line = String::new();
    let chars_read = reader.read_line(&mut response_line).await?;
    if chars_read == 0 {
        return Ok(());
    }

    let response: Response = serde_json::from_str(&response_line)
        .with_context(|| format!("Falha ao analisar a resposta do daemon: {response_line}"))?;

    match response {
        Response::Error { error } => {
            println!("Erro: {error}");
            return Ok(());
        }
        Response::Success(success) => {
            println!("✓ {}", success.message);
            // Continua se for streaming
        }
        Response::Status(status) => {
            render_status(&status);
            return Ok(());
        }
        Response::Devices(devices_resp) => {
            let is_verbose = match command {
                Command::Devices { verbose, .. } => verbose,
                _ => false,
            };
            render_devices(&devices_resp, is_verbose);
            return Ok(());
        }
        Response::Event(e) => {
            println!("Event: {e:?}");
            return Ok(());
        }
    }

    if is_streaming {
        loop {
            response_line.clear();
            if reader.read_line(&mut response_line).await? == 0 {
                break;
            }
            if response_line.trim().is_empty() {
                continue;
            }
            let resp: Result<Response, _> = serde_json::from_str(&response_line);
            match resp {
                Ok(Response::Event(e)) => println!("{e:?}"),
                Ok(Response::Error { error }) => {
                    println!("Erro no stream: {error}");
                    break;
                }
                Ok(other) => println!("Resposta inesperada: {other:?}"),
                Err(_) => println!("JSON malformado no stream: {response_line}"),
            }
        }
    }

    Ok(())
}
