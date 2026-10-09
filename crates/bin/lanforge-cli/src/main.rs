use clap::Parser;
use color_eyre::Result;
use lanforge_cli::args::{Cli, Command};
use lanforge_cli::client::LanforgeClient;
use lanforge_cli::commands::StatusArgs;
use lanforge_cli::output::Printer;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    if cli.no_color {
        colored::control::set_override(false);
    }

    let printer = Printer::new(cli.json, cli.no_color, cli.ascii).with_yes(cli.yes);

    #[cfg(feature = "remote")]
    let client = LanforgeClient::new(cli.socket, cli.remote, cli.token)?;

    #[cfg(not(feature = "remote"))]
    let client = LanforgeClient::new(cli.socket, None, None)?;

    match cli.command {
        Some(Command::Status(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Service(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Watch(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Devices(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Host(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Wol(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Reload(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Pppoe(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Ra(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Dns(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Dhcp(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Firewall(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Traffic(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Db(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Config(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::User(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Auth(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Setup(args)) => {
            args.execute(&client, &printer).await?;
        }
        None => {
            // Default behavior when no subcommand is specified: show router status dashboard
            StatusArgs::default().execute(&client, &printer).await?;
        }
    }

    Ok(())
}
