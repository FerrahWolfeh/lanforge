use color_eyre::eyre::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::args::Command;
use crate::cli::commands::CliCommand;
use crate::cli::commands::GenericHandler;
use crate::cli::commands::db::DbHandler;
use crate::cli::commands::devices::DevicesHandler;
use crate::cli::commands::dns::DnsCommand;
use crate::cli::commands::host::HostHandler;
use crate::cli::commands::lease::LeaseHandler;
use crate::cli::commands::log::LogHandler;
use crate::cli::commands::status::StatusHandler;
use crate::cli::commands::whois::WhoisHandler;
use crate::cli::commands::wol::WolCommand;
use lanforge_api::api::Response;

pub async fn run_client(command: Command, socket_path: &str) -> Result<()> {
    let mut stream = UnixStream::connect(socket_path).await.with_context(|| {
        format!("Failed to connect to daemon at '{socket_path}'. Is the daemon running?")
    })?;

    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);

    let mut handler: Box<dyn CliCommand> = match command {
        Command::Status => Box::new(StatusHandler),
        Command::Devices {
            verbose,
            filter,
            vendor,
            method,
            format,
            sort,
        } => Box::new(DevicesHandler {
            verbose,
            filter,
            vendor,
            method,
            format,
            sort,
        }),
        Command::Host { action } => Box::new(HostHandler { action }),
        Command::Lease { action } => Box::new(LeaseHandler { action }),
        Command::Db { action } => Box::new(DbHandler { action }),
        Command::Log { follow, verbose } => Box::new(LogHandler { follow, verbose }),
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
        Command::Purge { mac } => Box::new(GenericHandler {
            cmd: lanforge_api::api::Command::Purge { mac },
            streaming: false,
        }),
        Command::Wol { target } => Box::new(WolCommand { target }),
        Command::Whois { target } => Box::new(WhoisHandler { target }),
        Command::Dns { action } => Box::new(DnsCommand { action }),
    };

    let mut control_cmd = match handler.prepare() {
        Ok(cmd) => cmd,
        Err(e) => {
            // If the user aborts an interactive prompt, we just exit gracefully
            if e.to_string() == "Cancelled." || e.to_string().contains("is required") {
                return Ok(());
            }
            return Err(e);
        }
    };

    loop {
        let json_req = serde_json::to_string(&control_cmd)?;
        writer.write_all(json_req.as_bytes()).await?;
        writer.write_all(b"\n").await?;

        let mut response_line = String::new();
        let chars_read = reader.read_line(&mut response_line).await?;
        if chars_read == 0 {
            break;
        }

        let response: Response = serde_json::from_str(&response_line)
            .with_context(|| format!("Failed to parse response from daemon: {response_line}"))?;

        if let Some(next_cmd) = handler.on_response(&response)? {
            control_cmd = next_cmd;
            continue;
        }

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
                        let _ = handler.on_response(&r)?;
                    }
                    Err(_) => println!("Malformed JSON in stream: {response_line}"),
                }
            }
        }
        break;
    }

    Ok(())
}
