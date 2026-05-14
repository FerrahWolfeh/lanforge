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

    /// Quick Wake-on-LAN (alias for 'lanforge wol')
    #[command(name = "wake", hide = true)]
    Wake {
        /// Target device MAC or Hostname
        target: Option<String>,
        #[arg(
            short,
            long,
            env = "LANFORGE_CONTROL_SOCKET",
            default_value = "/run/lanforge/control.sock"
        )]
        socket: String,
    },

    /// Show service status (alias for 'lanforge status')
    #[command(name = "lf-status", hide = true)]
    LfStatus {
        #[arg(
            short,
            long,
            env = "LANFORGE_CONTROL_SOCKET",
            default_value = "/run/lanforge/control.sock"
        )]
        socket: String,
    },

    /// List devices (alias for 'lanforge devices')
    #[command(name = "lf-devices", hide = true)]
    LfDevices {
        #[arg(short, long)]
        verbose: bool,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        vendor: Option<String>,
        #[arg(long)]
        method: Option<String>,
        #[arg(long)]
        format: Option<String>,
        #[arg(short, long, value_enum, default_value_t = SortMode::LastSeen)]
        sort: SortMode,
        #[arg(long)]
        show_vendor: bool,
        #[arg(
            short,
            long,
            env = "LANFORGE_CONTROL_SOCKET",
            default_value = "/run/lanforge/control.sock"
        )]
        socket: String,
    },

    /// Force network scan (alias for 'lanforge scan')
    #[command(name = "lf-scan", hide = true)]
    LfScan {
        #[arg(
            short,
            long,
            env = "LANFORGE_CONTROL_SOCKET",
            default_value = "/run/lanforge/control.sock"
        )]
        socket: String,
    },

    /// View network topology hierarchically
    #[command(name = "lf-topology", hide = true)]
    LfTopology {
        #[arg(
            short,
            long,
            env = "LANFORGE_CONTROL_SOCKET",
            default_value = "/run/lanforge/control.sock"
        )]
        socket: String,
    },
}

#[derive(Args, Debug, Clone)]
pub struct LanforgeArgs {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Use Bincode binary protocol instead of JSON.
    #[arg(long, global = true)]
    pub bincode: bool,

    /// Disable response compression.
    #[arg(long, global = true)]
    pub no_compress: bool,

    /// Path to the Unix domain socket for daemon control.
    #[arg(
        short,
        long,
        env = "LANFORGE_CONTROL_SOCKET",
        default_value = "/run/lanforge/control.sock"
    )]
    pub socket: String,

    /// Remote URL of the Lanforge daemon (e.g. <https://192.168.1.1:8080>)
    #[cfg(feature = "remote")]
    #[arg(long, global = true, env = "LANFORGE_REMOTE_URL")]
    pub remote: Option<String>,

    /// Authentication token for remote connection.
    #[cfg(feature = "remote")]
    #[arg(long, global = true, env = "LANFORGE_TOKEN")]
    pub token: Option<String>,

    /// Password for remote connection (used to obtain a token).
    #[cfg(feature = "remote")]
    #[arg(long, global = true, env = "LANFORGE_PASSWORD")]
    pub password: Option<String>,
}

use crate::cli::commands::{
    config::ConfigArgs, db::DbArgs, devices::DevicesArgs, dhcp::DhcpArgs, dns::DnsArgs,
    host::HostArgs, lease::LeaseArgs, log::LogArgs, query::QueryArgs, simple::PurgeArgs,
    simple::ReloadArgs, simple::ScanArgs, simple::WatchArgs, status::StatusArgs,
    topology::TopologyArgs, tui::TuiArgs, whois::WhoisArgs, wol::WolArgs,
};

use crate::cli::{Execute, LanforgeClient};
use color_eyre::eyre::Result;

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// List known devices
    Devices(DevicesArgs),
    /// Reactive live view via socket (no polling)
    Watch(WatchArgs),
    /// Interactive TUI dashboard
    #[cfg(feature = "tui")]
    Tui(TuiArgs),
    /// Service health and general status
    Status(StatusArgs),
    /// Internal real-time `EventBus`
    Log(LogArgs),
    /// Lease management (renew/release)
    Lease(LeaseArgs),
    /// Triggers immediate NDP cycle with feedback
    Scan(ScanArgs),
    /// Custom device management
    Host(HostArgs),
    /// Send reload signal to running daemon (reloads static config from TOML)
    Reload(ReloadArgs),
    /// Persistence management
    Db(DbArgs),
    /// Forcefully purge a device from memory and database by its MAC
    Purge(PurgeArgs),
    /// Wake-on-LAN magic packet
    Wol(WolArgs),
    /// Detailed aggregated information for a device
    Whois(WhoisArgs),
    /// DNS resolver statistics and diagnostics
    Dns(DnsArgs),
    /// DHCP server management
    Dhcp(DhcpArgs),
    /// Script-friendly data querying (outputs raw JSON)
    Query(QueryArgs),
    /// View network topology hierarchically
    Topology(TopologyArgs),
    /// Daemon configuration management
    Config(ConfigArgs),
}

impl Execute for Command {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self {
            Self::Devices(args) => args.execute(client).await,
            Self::Watch(args) => args.execute(client).await,
            #[cfg(feature = "tui")]
            Self::Tui(args) => args.execute(client).await,
            Self::Status(args) => args.execute(client).await,
            Self::Log(args) => args.execute(client).await,
            Self::Lease(args) => args.execute(client).await,
            Self::Scan(args) => args.execute(client).await,
            Self::Host(args) => args.execute(client).await,
            Self::Reload(args) => args.execute(client).await,
            Self::Db(args) => args.execute(client).await,
            Self::Purge(args) => args.execute(client).await,
            Self::Wol(args) => args.execute(client).await,
            Self::Whois(args) => args.execute(client).await,
            Self::Dns(args) => args.execute(client).await,
            Self::Dhcp(args) => args.execute(client).await,
            Self::Query(args) => args.execute(client).await,
            Self::Topology(args) => args.execute(client).await,
            Self::Config(args) => args.execute(client).await,
        }
    }
}

use crate::cli::commands::devices::SortMode;
