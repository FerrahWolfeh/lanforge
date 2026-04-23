mod args;
mod cli;

use crate::args::{Cli, Command};
use clap::Parser;
use color_eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    match cli {
        Cli::Lanforge(args) => {
            if let Some(cmd) = args.command {
                cli::run_client(cmd, &args.socket).await?;
            } else {
                println!("Nenhum comando especificado. Use --help para ver as opções.");
            }
        }
        Cli::Wake { target, socket } => {
            cli::run_client(Command::Wol { target }, &socket).await?;
        }
        Cli::LfStatus { socket } => {
            cli::run_client(Command::Status, &socket).await?;
        }
        Cli::LfDevices {
            verbose,
            filter,
            vendor,
            method,
            format,
            sort,
            socket,
        } => {
            cli::run_client(
                Command::Devices {
                    verbose,
                    filter,
                    vendor,
                    method,
                    format,
                    sort,
                },
                &socket,
            )
            .await?;
        }
        Cli::LfScan { socket } => {
            cli::run_client(Command::Scan, &socket).await?;
        }
    }

    Ok(())
}
