mod args;
mod cli;
mod format;
#[cfg(feature = "tui")]
mod tui;

use crate::args::{Cli, Command};
use clap::Parser;
use color_eyre::Result;

use crate::cli::Execute;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    // Initialize Crypto Provider (Rustls 0.23+ requirement)
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // Ignore if already installed

    let cli = Cli::parse();

    match cli {
        Cli::Lanforge(args) => {
            if let Some(cmd) = args.command {
                let client = cli::LanforgeClient {
                    socket: args.socket,
                    opts: cli::ClientOptions {
                        bincode: args.bincode,
                        no_compress: args.no_compress,
                    },
                    #[cfg(feature = "remote")]
                    remote: args.remote,
                    #[cfg(feature = "remote")]
                    token: args.token,
                    #[cfg(feature = "remote")]
                    password: args.password,
                };
                cmd.execute(&client).await?;
            } else {
                println!("No command specified. Use --help to see available options.");
            }
        }
        Cli::Wake { target, socket } => {
            let client = cli::LanforgeClient {
                socket,
                opts: cli::ClientOptions {
                    bincode: false,
                    no_compress: false,
                },
                #[cfg(feature = "remote")]
                remote: None,
                #[cfg(feature = "remote")]
                token: None,
                #[cfg(feature = "remote")]
                password: None,
            };
            let cmd = Command::Wol(crate::cli::commands::wol::WolArgs { target });
            cmd.execute(&client).await?;
        }
        Cli::LfStatus { socket } => {
            let client = cli::LanforgeClient {
                socket,
                opts: cli::ClientOptions {
                    bincode: false,
                    no_compress: false,
                },
                #[cfg(feature = "remote")]
                remote: None,
                #[cfg(feature = "remote")]
                token: None,
                #[cfg(feature = "remote")]
                password: None,
            };
            let cmd = Command::Status(crate::cli::commands::status::StatusArgs {});
            cmd.execute(&client).await?;
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
            let client = cli::LanforgeClient {
                socket,
                opts: cli::ClientOptions {
                    bincode: false,
                    no_compress: false,
                },
                #[cfg(feature = "remote")]
                remote: None,
                #[cfg(feature = "remote")]
                token: None,
                #[cfg(feature = "remote")]
                password: None,
            };
            let cmd = Command::Devices(crate::cli::commands::devices::DevicesArgs {
                verbose,
                filter,
                vendor,
                method,
                format,
                sort,
                show_vendor,
            });
            cmd.execute(&client).await?;
        }
        Cli::LfScan { socket } => {
            let client = cli::LanforgeClient {
                socket,
                opts: cli::ClientOptions {
                    bincode: false,
                    no_compress: false,
                },
                #[cfg(feature = "remote")]
                remote: None,
                #[cfg(feature = "remote")]
                token: None,
                #[cfg(feature = "remote")]
                password: None,
            };
            let cmd = Command::Scan(crate::cli::commands::simple::ScanArgs {});
            cmd.execute(&client).await?;
        }
        Cli::LfTopology { socket } => {
            let client = cli::LanforgeClient {
                socket,
                opts: cli::ClientOptions {
                    bincode: false,
                    no_compress: false,
                },
                #[cfg(feature = "remote")]
                remote: None,
                #[cfg(feature = "remote")]
                token: None,
                #[cfg(feature = "remote")]
                password: None,
            };
            let cmd = Command::Topology(crate::cli::commands::topology::TopologyArgs {});
            cmd.execute(&client).await?;
        }
    }

    Ok(())
}
