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
                if let Some(remote_url) = &args.remote {
                    #[cfg(feature = "remote")]
                    {
                        use crate::cli::remote::RemoteClient;
                        let mut client = RemoteClient::new(remote_url.clone(), args.token.clone());
                        if let Some(pwd) = &args.password {
                            client.login(pwd).await?;
                        }

                        #[cfg(feature = "tui")]
                        if cmd == Command::Tui {
                            return crate::tui::run_tui(None, Some(client)).await;
                        }

                        let mut handler = match cmd {
                            #[cfg(feature = "tui")]
                            Command::Tui => unreachable!("TUI handled above"),
                            c => c.to_handler(),
                        };

                        let control_cmd = handler.prepare()?;
                        let resp = client.send(control_cmd).await?;
                        let _ = handler.on_response(&resp)?;
                        return Ok(());
                    }
                    #[cfg(not(feature = "remote"))]
                    {
                        let _ = remote_url;
                        return Err(color_eyre::eyre::eyre!(
                            "Remote support not enabled. Recompile with --features remote."
                        ));
                    }
                }

                #[cfg(feature = "tui")]
                if cmd == Command::Tui {
                    return crate::tui::run_tui(
                        Some(args.socket.clone()),
                        #[cfg(feature = "remote")]
                        None,
                    )
                    .await;
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
