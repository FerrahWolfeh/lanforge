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

use lanforge_macros::CliHandler;

#[derive(Subcommand, Debug, Clone, PartialEq, Eq, CliHandler)]
pub enum Command {
    /// List known devices
    #[handler(DevicesHandler { .. })]
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
        /// Resolve and display vendor names (can be slow)
        #[arg(long)]
        show_vendor: bool,
    },
    /// Live view reativo via socket (sem polling)
    #[handler(generic(Watch, true))]
    Watch,
    /// Interactive TUI dashboard
    #[cfg(feature = "tui")]
    Tui,
    /// Service health and general status
    #[handler(StatusHandler)]
    Status,
    /// `EventBus` interno em tempo real
    #[handler(LogHandler { .. })]
    Log {
        #[arg(long)]
        follow: bool,
        /// Show more detailed events (like ARP/NDP activity)
        #[arg(short, long)]
        verbose: bool,
        /// Number of historical lines to show
        #[arg(short = 'n', long, default_value = "50")]
        lines: usize,
    },
    /// Gerenciamento de leases (renew/release)
    #[handler(LeaseHandler { .. })]
    Lease {
        #[command(subcommand)]
        action: LeaseCommand,
    },
    /// Dispara ciclo NDP imediato com feedback
    #[handler(generic(Scan, false))]
    Scan,
    /// Gerenciamento de devices customizados
    #[handler(HostHandler { .. })]
    Host {
        #[command(subcommand)]
        action: HostCommand,
    },
    /// Send reload signal to running daemon (recarrega config estática do TOML)
    #[handler(generic(Reload, false))]
    Reload,
    /// Gerenciamento de persistência
    #[handler(DbHandler { .. })]
    Db {
        #[command(subcommand)]
        action: DbCommand,
    },
    /// Forcefully purge a device from memory and database by its MAC
    #[handler(generic(Purge, { mac }, false))]
    Purge {
        /// MAC address of the device to purge
        mac: String,
    },
    /// Wake-on-LAN magic packet
    #[handler(WolCommand { .. })]
    Wol {
        /// Target device MAC or Hostname. Run without target for interactive menu.
        target: Option<String>,
    },
    /// Detailed aggregated information for a device
    #[handler(WhoisHandler { .. })]
    Whois {
        /// Target MAC, IP, or Hostname
        target: String,
    },
    /// DNS resolver statistics and diagnostics
    #[handler(DnsCommand { .. })]
    Dns {
        #[command(subcommand)]
        action: DnsCommand,
    },
    /// DHCP server management
    #[handler(DhcpHandler { .. })]
    Dhcp {
        #[command(subcommand)]
        action: DhcpCommand,
    },
    /// Script-friendly data querying (outputs raw JSON)
    #[handler(QueryHandler { .. })]
    Query {
        #[command(subcommand)]
        target: QueryTarget,
    },
    /// View network topology hierarchically
    #[handler(TopologyHandler)]
    Topology,
    /// Gerenciamento de configurações do daemon
    #[handler(ConfigHandler { .. })]
    Config {
        #[command(subcommand)]
        action: ConfigCommand,
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
    State {
        /// Only include the main device table
        #[arg(long)]
        only_devices: bool,
        /// Only include orphaned entries (no MAC resolved yet)
        #[arg(long)]
        only_orphans: bool,
    },
    /// Dump current DHCP leases as JSON
    Leases {
        /// Only print the count of leases
        #[arg(short, long)]
        count: bool,
        /// Print the result plainly to stdout (instead of JSON)
        #[arg(short, long)]
        plain: bool,
    },
    /// Dump the hierarchical network topology as JSON
    Topology,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsCommand {
    /// Show resolver performance statistics
    Stats,
    /// Show upstream resolver health and status
    Upstreams,
    /// View recent query logs
    Log {
        /// Number of entries to show
        #[arg(short = 'n', long, default_value = "50")]
        limit: usize,
        /// Filter by client IP address
        #[arg(short, long)]
        client: Option<String>,
        /// Watch for new queries in real-time
        #[arg(short, long)]
        follow: bool,
    },
    /// Perform a diagnostic query
    Query {
        /// Name to resolve
        name: String,
        /// Optional record type (A, AAAA, TXT, etc.)
        #[arg(short = 't', long)]
        record_type: Option<String>,
    },
    /// Manage micro-adblocker filtering
    Adblock {
        #[command(subcommand)]
        action: AdblockAction,
    },
    /// Manage resolver cache
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum CacheAction {
    /// Flush all entries from the DNS cache
    Flush,
    /// Dump the current DNS cache contents
    Dump,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DhcpCommand {
    /// View detailed pool utilization
    Pool,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum AdblockAction {
    /// Show current adblocker status and metrics
    Status,
    /// Enable the adblocker
    Enable,
    /// Disable the adblocker
    Disable {
        /// Duration to disable for (e.g. 15m, 2h, 1d)
        duration: Option<String>,
    },
    /// Reload blocklists from URLs
    Reload,
    /// Add a domain to the blocklist
    Block {
        /// Domain to block
        domain: String,
    },
    /// Add a domain to the allowlist
    Allow {
        /// Domain to allow
        domain: String,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum LeaseCommand {
    /// Forces a renew of a specific lease.
    Renew {
        /// Target device MAC
        mac: String,
        /// Trigger IPv6 renew instead of IPv4
        #[arg(short = '6', long)]
        v6: bool,
    },
    /// Forces a release of a specific lease.
    Release {
        /// Target device MAC
        mac: String,
        /// Trigger IPv6 release instead of IPv4
        #[arg(short = '6', long)]
        v6: bool,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum ConfigCommand {
    /// Update the daemon's API password (requires UDS connection).
    SetPassword {
        /// New password for remote access.
        password: String,
    },
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
    /// Perform a `SQLite` VACUUM operation
    Vacuum,
    /// Clear the transient system log database
    LogClean,
    /// Remove 'zombie' entries (dynamic devices with no IP nor hostname)
    Prune,
    /// Generate a diagnostic snapshot of the in-memory state as JSON
    Snapshot,
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
