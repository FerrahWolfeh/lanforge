use super::CliCommand;
use crate::cli::{Execute, LanforgeClient};
use chrono::DateTime;
use chrono::Local;
use color_eyre::eyre::Result;
use colored::Colorize;
use lanforge_core::bus::TimedEvent;

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct LogArgs {
    #[arg(long)]
    pub follow: bool,
    /// Show more detailed events (like ARP/NDP activity)
    #[arg(short, long)]
    pub verbose: bool,
    /// Number of historical lines to show
    #[arg(short = 'n', long, default_value = "50")]
    pub lines: usize,
}

impl Execute for LogArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        client
            .execute_handler(Box::new(LogHandler {
                follow: self.follow,
                verbose: self.verbose,
                lines: self.lines,
            }))
            .await
    }
}

use crate::format::CliFormat;

pub struct LogHandler {
    pub follow: bool,
    pub verbose: bool,
    pub lines: usize,
}

use lanforge_api::rpc::{LanforgeRpcClient, RpcResponse};
use tokio::net::UnixStream;

#[async_trait::async_trait]
impl CliCommand for LogHandler {
    async fn execute_rpc(&mut self, client: &mut LanforgeRpcClient<UnixStream>) -> Result<()> {
        client.log(self.follow, Some(self.lines), None).await?;
        loop {
            match client.next_response().await {
                Ok(RpcResponse::Event(event)) => self.print_event(&event),
                Ok(RpcResponse::Error(e)) => eprintln!("Error: {e}"),
                Ok(_) => {}
                Err(lanforge_api::rpc::LanforgeRpcError::Io(e))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

impl LogHandler {
    fn print_event(&self, timed_event: &TimedEvent) {
        let now = DateTime::<Local>::from(timed_event.timestamp)
            .format("%H:%M:%S")
            .to_string();

        timed_event
            .event
            .format_cli(&now.dimmed().to_string(), self.verbose);
    }
}
