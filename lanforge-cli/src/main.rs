mod args;
mod cli;

use crate::args::CliArgs;
use clap::Parser;
use color_eyre::Result;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let args = CliArgs::parse();

    if let Some(cmd) = args.command {
        // We'll need to adapt the Command enum from args to what run_client expects
        // or just update run_client to use the new Command enum.
        cli::run_client(cmd, &args.socket).await?;
    } else {
        println!("Nenhum comando especificado. Use --help para ver as opções.");
    }

    Ok(())
}
