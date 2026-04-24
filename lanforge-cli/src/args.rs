use clap::{Args, Parser, Subcommand, ValueEnum};

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
    #[command(name = "wake")]
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
    #[command(name = "lf-status")]
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
    #[command(name = "lf-devices")]
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
        #[arg(
            short,
            long,
            env = "LANFORGE_CONTROL_SOCKET",
            default_value = "/run/lanforge/control.sock"
        )]
        socket: String,
    },

    /// Force network scan (alias for 'lanforge scan')
    #[command(name = "lf-scan")]
    LfScan {
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

    /// Path to the Unix domain socket for daemon control.
    #[arg(
        short,
        long,
        env = "LANFORGE_CONTROL_SOCKET",
        default_value = "/run/lanforge/control.sock"
    )]
    pub socket: String,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// List known devices
    Devices {
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
    },
    /// Live view reativo via socket (sem polling)
    Watch,
    /// Service health and general status
    Status,
    /// `EventBus` interno em tempo real
    Log {
        #[arg(long)]
        follow: bool,
        /// Show more detailed events (like ARP/NDP activity)
        #[arg(short, long)]
        verbose: bool,
    },
    /// Gerenciamento de leases (renew/release)
    Lease {
        #[command(subcommand)]
        action: LeaseCommand,
    },
    /// Dispara ciclo NDP imediato com feedback
    Scan,
    /// Gerenciamento de devices customizados
    Host {
        #[command(subcommand)]
        action: HostCommand,
    },
    /// Send reload signal to running daemon (recarrega config estática do TOML)
    Reload,
    /// Gerenciamento de persistência
    Db {
        #[command(subcommand)]
        action: DbCommand,
    },
    /// Forcefully purge a device from memory and database by its MAC
    Purge {
        /// MAC address of the device to purge
        mac: String,
    },
    /// Wake-on-LAN magic packet
    Wol {
        /// Target device MAC or Hostname. Run without target for interactive menu.
        target: Option<String>,
    },
    /// Detailed aggregated information for a device
    Whois {
        /// Target MAC, IP, or Hostname
        target: String,
    },
    /// DNS resolver statistics and diagnostics
    Dns {
        #[command(subcommand)]
        action: DnsCommand,
    },
    /// Script-friendly data querying (outputs raw JSON)
    Query {
        #[command(subcommand)]
        target: QueryTarget,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum QueryTarget {
    /// Dump full system status as JSON
    Status,
    /// Dump all devices as JSON
    Devices,
    /// Dump configured hosts as JSON
    Hosts,
    /// Dump full in-memory state as JSON
    State,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsCommand {
    /// Show resolver performance statistics
    Stats,
    /// Perform a diagnostic query
    Query {
        /// Name to resolve
        name: String,
        /// Optional record type (A, AAAA, etc.)
        #[arg(short = 't', long)]
        record_type: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum LeaseCommand {
    Renew { mac: String },
    Release { mac: String },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum HostCommand {
    Add {
        /// Prefix MAC with this argument, or run interactively
        mac: Option<String>,
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        v4: Option<String>,
        #[arg(long)]
        v6_suffix: Option<String>,
    },
    Set {
        mac: String,
        field: String,
        value: String,
    },
    List,
    Remove {
        mac: String,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DbCommand {
    /// Perform a SQLite VACUUM operation
    Vacuum,
    /// Clear the transient system log database
    LogClean,
    /// Remove 'zombie' entries (dynamic devices with no IP nor hostname)
    Prune,
    /// Dump the full in-memory state as JSON
    Dump,
    /// Completely reset and re-seed the database (FACTORY RESET)
    Reset,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortMode {
    /// Sort by MAC address
    Mac,
    /// Sort by hostname
    Host,
    /// Sort by last seen timestamp
    LastSeen,
    /// Sort by IPv4 address
    Ip,
    /// Sort by IPv6 address
    Ipv6,
    /// Sort by online status
    Online,
}
