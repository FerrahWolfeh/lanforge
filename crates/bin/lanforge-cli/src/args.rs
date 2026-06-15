use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "lanforge",
    version,
    about = "Lanforge Control CLI",
    multicall = true
)]
pub enum Cli {
    /// Standard lanforge command
    #[command(name = "lanforge")]
    Lanforge(LanforgeArgs),

    /// Shortcut for TUI dashboard
    #[cfg(feature = "tui")]
    #[command(name = "lanforge-tui")]
    LanforgeTui(LanforgeArgs),
}

#[derive(Args, Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct LanforgeArgs {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Path to the Unix domain socket for daemon control.
    #[arg(
        short,
        long,
        env = "LANFORGE_CONTROL_SOCKET",
        default_value = "/run/lanforge/control.sock",
        global = true
    )]
    pub socket: String,

    /// Remote URL of the Lanforge daemon (e.g. <https://192.168.1.1:8080>). Switches to JSON/REST mode.
    #[cfg(feature = "remote")]
    #[arg(long, env = "LANFORGE_REMOTE_URL", global = true)]
    pub remote: Option<String>,

    /// Authentication token for remote connection. Falls back to `$XDG_DATA_DIR/lanforge/login.json`.
    #[cfg(feature = "remote")]
    #[arg(long, env = "LANFORGE_TOKEN", global = true)]
    pub token: Option<String>,

    /// Disable response compression.
    #[arg(long, global = true)]
    pub no_compress: bool,

    /// Output raw API JSON. No formatting, no colors.
    #[arg(long, global = true)]
    pub json: bool,

    /// Disable ANSI colors.
    #[arg(long, env = "NO_COLOR", global = true)]
    pub no_color: bool,

    /// Replace Unicode box-drawing, symbols, and emoji with ASCII equivalents.
    #[arg(long, global = true)]
    pub ascii: bool,

    /// Skip all confirmation prompts.
    #[arg(short, long, global = true)]
    pub yes: bool,
}

#[cfg(feature = "tui")]
use crate::cli::commands::tui::TuiArgs;
use crate::cli::commands::{
    auth::AuthArgs, config::ConfigArgs, db::DbArgs, devices::DevicesArgs, dhcp::DhcpArgs,
    dns::DnsArgs, host::HostArgs, lease::LeaseArgs, service::ServiceArgs, simple::ContextArgs,
    simple::LoginArgs, simple::PurgeArgs, simple::ReloadArgs, simple::ShutdownArgs,
    simple::WatchArgs, status::ServicesArgs, status::StatusArgs, whois::WhoisArgs, wol::WolArgs,
};

use crate::cli::{Execute, LanforgeClient};
use color_eyre::eyre::Result;

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Service health and general status
    Status(StatusArgs),
    /// Detailed deep-dive service metrics and status banners
    Services(ServicesArgs),
    /// List known devices
    Devices(DevicesArgs),
    /// Detailed aggregated information for a device
    Whois(WhoisArgs),
    /// Wake-on-LAN magic packet
    Wol(WolArgs),
    /// Reactive live view via stream (no polling)
    Watch(WatchArgs),
    /// Authenticate and save remote token
    Login(LoginArgs),
    /// Send reload signal to running daemon (reloads static config from TOML)
    Reload(ReloadArgs),
    /// Send shutdown signal to running daemon
    Shutdown(ShutdownArgs),
    /// Forcefully purge a device from memory and database by its MAC
    Purge(PurgeArgs),
    /// Dump internal daemon context
    Context(ContextArgs),
    /// Persistence management
    Db(DbArgs),
    /// Custom device management
    Host(HostArgs),
    /// Lease management (renew/release)
    Lease(LeaseArgs),
    /// DHCP server management
    Dhcp(DhcpArgs),
    /// Authentication management (tokens)
    Auth(AuthArgs),
    /// DNS resolver statistics and diagnostics
    Dns(DnsArgs),
    /// System configuration import/export
    Config(ConfigArgs),
    /// Manage daemon background services (start, stop, restart)
    Service(ServiceArgs),
    /// Interactive TUI dashboard
    #[cfg(feature = "tui")]
    Tui(TuiArgs),
}

impl Execute for Command {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self {
            Self::Status(args) => args.execute(client).await,
            Self::Services(args) => args.execute(client).await,
            Self::Devices(args) => args.execute(client).await,
            Self::Whois(args) => args.execute(client).await,
            Self::Wol(args) => args.execute(client).await,
            Self::Watch(args) => args.execute(client).await,
            Self::Login(args) => args.execute(client).await,
            Self::Reload(args) => args.execute(client).await,
            Self::Shutdown(args) => args.execute(client).await,
            Self::Purge(args) => args.execute(client).await,
            Self::Context(args) => args.execute(client).await,
            Self::Db(args) => args.execute(client).await,
            Self::Host(args) => args.execute(client).await,
            Self::Lease(args) => args.execute(client).await,
            Self::Dhcp(args) => args.execute(client).await,
            Self::Auth(args) => args.execute(client).await,
            Self::Dns(args) => args.execute(client).await,
            Self::Config(args) => args.execute(client).await,
            Self::Service(args) => args.execute(client).await,
            #[cfg(feature = "tui")]
            Self::Tui(args) => args.execute(client).await,
        }
    }
}
