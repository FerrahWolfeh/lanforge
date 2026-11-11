#![allow(
    unused_crate_dependencies,
    reason = "binary target uses dependencies via library target"
)]

use std::env;
use std::process::ExitCode;

use clap::Parser;
use color_eyre::config::{HookBuilder, Theme};
use color_eyre::{Report, Result};
use colored::control;
use lanforge_cli::args::{Cli, Command};
use lanforge_cli::client::LanforgeClient;
use lanforge_cli::commands::StatusArgs;
use lanforge_cli::output::Printer;

#[tokio::main]
async fn main() -> ExitCode {
    // Rust ignores SIGPIPE, so printing into a closed pipe (`lanforge status | head`) panicked,
    // and with `panic = "abort"` that dumped core. Die quietly like any Unix tool instead.
    // SAFETY: restores the default disposition of one signal before any thread prints.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();

    let no_color = cli.colors_off();
    // The hook still formats panics and the `RUST_BACKTRACE` report.
    let hook = if no_color {
        control::set_override(false);
        HookBuilder::new().theme(Theme::new()).install()
    } else {
        color_eyre::install()
    };
    hook.expect("the error hook is installed once, here");

    match run(cli, no_color).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report(&e);
            ExitCode::FAILURE
        }
    }
}

/// A failed command is one line, like any Unix tool: `error: <what>: <cause>`. A daemon refusal
/// is an answer, not a crash, so the source location and backtrace hint are only shown when
/// `RUST_BACKTRACE` asks for the debug report.
fn report(e: &Report) {
    if env::var_os("RUST_BACKTRACE").is_some() {
        eprintln!("{e:?}");
    } else {
        eprintln!("error: {e:#}");
    }
}

async fn run(cli: Cli, no_color: bool) -> Result<()> {
    let printer = Printer::new(cli.json, no_color, cli.ascii).with_yes(cli.yes);

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
        Some(Command::Shutdown(args)) => {
            args.execute(&client, &printer).await?;
        }
        Some(Command::Login(args)) => {
            args.execute(&client, &printer).await?;
        }
        None => {
            // Default behavior when no subcommand is specified: show router status dashboard
            StatusArgs::default().execute(&client, &printer).await?;
        }
    }

    Ok(())
}
