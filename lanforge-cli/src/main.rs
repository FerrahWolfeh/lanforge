use clap::Parser;
use color_eyre::Result;
use inquire::InquireError;
use lanforge_cli::args::Cli;
#[cfg(feature = "tui")]
use lanforge_cli::args::Command;
use lanforge_cli::cli::{Execute, LanforgeClient};

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
            let client = LanforgeClient::from_args(&args)?;
            if let Some(cmd) = args.command {
                if let Err(e) = cmd.execute(&client).await {
                    if let Some(inquire_err) = e.downcast_ref::<InquireError>() {
                        match inquire_err {
                            InquireError::OperationInterrupted => std::process::exit(130),
                            InquireError::OperationCanceled => std::process::exit(1),
                            _ => return Err(e),
                        }
                    }
                    return Err(e);
                }
            } else {
                println!("No command specified. Use --help to see available options.");
            }
        }
        #[cfg(feature = "tui")]
        Cli::LanforgeTui(args) => {
            use lanforge_cli::cli::commands::tui::TuiArgs;

            let client = LanforgeClient::from_args(&args)?;
            let cmd = Command::Tui(TuiArgs {});
            if let Err(e) = cmd.execute(&client).await {
                if let Some(inquire_err) = e.downcast_ref::<InquireError>() {
                    match inquire_err {
                        InquireError::OperationInterrupted => std::process::exit(130),
                        InquireError::OperationCanceled => std::process::exit(1),
                        _ => return Err(e),
                    }
                }
                return Err(e);
            }
        }
    }

    Ok(())
}
