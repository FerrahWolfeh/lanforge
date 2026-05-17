use clap::Parser;
use color_eyre::Result;
use lanforge_cli::{
    args::{Cli, Command},
    cli::{Execute, LanforgeClient},
};

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
                cmd.execute(&client).await?;
            } else {
                println!("No command specified. Use --help to see available options.");
            }
        }
        #[cfg(feature = "tui")]
        Cli::LanforgeTui(args) => {
            use lanforge_cli::cli::commands::tui::TuiArgs;

            let client = LanforgeClient::from_args(&args)?;
            let cmd = Command::Tui(TuiArgs {});
            cmd.execute(&client).await?;
        }
    }

    Ok(())
}
