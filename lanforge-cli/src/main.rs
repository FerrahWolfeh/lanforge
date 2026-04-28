mod args;
mod cli;
#[cfg(feature = "tui")]
mod tui;

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
                #[cfg(feature = "tui")]
                if cmd == Command::Tui {
                    return crate::tui::run_tui(&args.socket).await;
                }

                cli::run_client(
                    cmd,
                    &args.socket,
                    cli::ClientOptions {
                        bincode: args.bincode,
                        no_compress: args.no_compress,
                    },
                )
                .await?;
            } else {
                println!("Nenhum comando especificado. Use --help para ver as opções.");
            }
        }
        Cli::Wake { target, socket } => {
            cli::run_client(
                Command::Wol { target },
                &socket,
                cli::ClientOptions {
                    bincode: false,
                    no_compress: false,
                },
            )
            .await?;
        }
        Cli::LfStatus { socket } => {
            cli::run_client(
                Command::Status,
                &socket,
                cli::ClientOptions {
                    bincode: false,
                    no_compress: false,
                },
            )
            .await?;
        }
        Cli::LfDevices {
            verbose,
            filter,
            vendor,
            method,
            format,
            sort,
            show_vendor,
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
                    show_vendor,
                },
                &socket,
                cli::ClientOptions {
                    bincode: false,
                    no_compress: false,
                },
            )
            .await?;
        }
        Cli::LfScan { socket } => {
            cli::run_client(
                Command::Scan,
                &socket,
                cli::ClientOptions {
                    bincode: false,
                    no_compress: false,
                },
            )
            .await?;
        }
        Cli::LfTopology { socket } => {
            cli::run_client(
                Command::Topology,
                &socket,
                cli::ClientOptions {
                    bincode: false,
                    no_compress: false,
                },
            )
            .await?;
        }
    }

    Ok(())
}
