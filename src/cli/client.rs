use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::cli::commands::CliCommand;
use crate::cli::commands::GenericHandler;
use crate::config::Command;
use lanforge_api::api::Response;

pub async fn run_client(command: Command, socket_path: &str) -> Result<()> {
    let mut stream = UnixStream::connect(socket_path).await.with_context(|| {
        format!("Falha ao conectar no daemon em '{socket_path}'. O daemon está rodando?")
    })?;

    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let mut handler: Box<dyn CliCommand> = match command {
        Command::Status => Box::new(crate::cli::commands::status::StatusHandler),
        Command::Devices {
            verbose,
            filter,
            format,
        } => Box::new(crate::cli::commands::devices::DevicesHandler {
            verbose,
            filter,
            format,
        }),
        Command::Host { action } => Box::new(crate::cli::commands::host::HostHandler { action }),
        Command::Lease { action } => Box::new(crate::cli::commands::lease::LeaseHandler { action }),
        Command::Db { action } => Box::new(crate::cli::commands::db::DbHandler { action }),
        Command::Log { follow } => Box::new(crate::cli::commands::log::LogHandler { follow }),
        Command::Reload => Box::new(GenericHandler {
            cmd: lanforge_api::api::Command::Reload,
            streaming: false,
        }),
        Command::Watch => Box::new(GenericHandler {
            cmd: lanforge_api::api::Command::Watch,
            streaming: true,
        }),
        Command::Scan => Box::new(GenericHandler {
            cmd: lanforge_api::api::Command::Scan,
            streaming: false,
        }),
        Command::Shutdown => Box::new(GenericHandler {
            cmd: lanforge_api::api::Command::Shutdown,
            streaming: false,
        }),
        Command::Purge { mac } => Box::new(GenericHandler {
            cmd: lanforge_api::api::Command::Purge { mac },
            streaming: false,
        }),
        Command::Run { .. } => {
            println!("Este comando ainda não está implementado na CLI.");
            return Ok(());
        }
    };

    let control_cmd = match handler.prepare() {
        Ok(cmd) => cmd,
        Err(e) => {
            // If the user aborts an interactive prompt, we just exit gracefully
            if e.to_string() == "Cancelado." || e.to_string().contains("is required") {
                return Ok(());
            }
            return Err(e);
        }
    };

    let json_req = serde_json::to_string(&control_cmd)?;
    writer.write_all(json_req.as_bytes()).await?;
    writer.write_all(b"\n").await?;

    let mut response_line = String::new();
    let chars_read = reader.read_line(&mut response_line).await?;
    if chars_read == 0 {
        return Ok(());
    }

    let response: Response = serde_json::from_str(&response_line)
        .with_context(|| format!("Falha ao analisar a resposta do daemon: {response_line}"))?;

    handler.on_response(&response)?;

    if handler.is_streaming() {
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
                Ok(r) => {
                    handler.on_response(&r)?;
                }
                Err(_) => println!("JSON malformado no stream: {response_line}"),
            }
        }
    }

    Ok(())
}
