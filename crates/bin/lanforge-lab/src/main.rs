use clap::Parser;
use color_eyre::Result;
use lanforge_lab::cli::args::{Cli, Commands, ModeArg};
use lanforge_lab::cli::runner::CliRunner;
use lanforge_lab::harness::LabHarness;
use lanforge_lab::netns::NetnsConfig;
use lanforge_lab::tui::run_tui;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Run(run_args)) => {
            CliRunner::run_scenario(
                run_args,
                cli.mode,
                cli.dhcp_server,
                cli.dns_server,
                cli.iface,
            )
            .await?;
        }
        Some(Commands::Bench(bench_args)) => {
            CliRunner::run_bench(
                bench_args,
                cli.mode,
                cli.dhcp_server,
                cli.dns_server,
                cli.iface,
            )
            .await?;
        }
        Some(Commands::Suite(suite_args)) => {
            CliRunner::run_suite(
                suite_args,
                cli.mode,
                cli.dhcp_server,
                cli.dns_server,
                cli.iface,
            )
            .await?;
        }
        Some(Commands::Tui) | None => {
            let harness = match cli.mode {
                ModeArg::Auto => LabHarness::auto()?,
                ModeArg::Direct => LabHarness::setup_direct()?,
                ModeArg::Netns => LabHarness::setup_netns(NetnsConfig::default())?,
                ModeArg::Interface => {
                    let if_name = cli.iface.as_deref().unwrap_or("veth-lf-host");
                    LabHarness::targeting_interface(
                        if_name,
                        cli.dhcp_server.port(),
                        cli.dns_server.port(),
                    )
                }
            };

            let harness = harness.with_endpoints(cli.dhcp_server, cli.dns_server);
            run_tui(harness).await?;
        }
    }

    Ok(())
}
