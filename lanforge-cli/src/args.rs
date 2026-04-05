use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "lanforge-cli", version, about = "Lanforge Control CLI", long_about = None)]
pub struct CliArgs {
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
    },
    /// Live view reativo via socket (sem polling)
    Watch,
    /// Service health and general status
    Status,
    /// `EventBus` interno em tempo real
    Log {
        #[arg(long)]
        follow: bool,
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
    Vacuum,
}
