use clap::{Parser, Subcommand};
use crate::commands::{
    AuthArgs, ConfigArgs, DbArgs, DevicesArgs, DhcpArgs, DnsArgs, FirewallArgs, HostArgs,
    PppoeArgs, RaArgs, ReloadArgs, ServiceArgs, StatusArgs, TrafficArgs, UserArgs, WatchArgs,
    WolArgs,
};

#[derive(Parser, Debug, Clone)]
#[command(
    name = "lanforge",
    version,
    about = "Lanforge Router & Network Orchestration CLI",
    long_about = "Modern, high-performance command-line management client for the Lanforge router daemon."
)]
#[allow(clippy::struct_excessive_bools)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Path to the Unix domain socket for local daemon control.
    #[arg(
        short,
        long,
        env = "LANFORGE_CONTROL_SOCKET",
        default_value = "/run/lanforge/control.sock",
        global = true
    )]
    pub socket: String,

    /// Remote URL of the Lanforge daemon (e.g. <https://192.168.1.1:8080>).
    #[cfg(feature = "remote")]
    #[arg(long, env = "LANFORGE_REMOTE_URL", global = true)]
    pub remote: Option<String>,

    /// Authentication token for remote connection.
    #[cfg(feature = "remote")]
    #[arg(long, env = "LANFORGE_TOKEN", global = true)]
    pub token: Option<String>,

    /// Output raw API JSON.
    #[arg(long, global = true)]
    pub json: bool,

    /// Disable ANSI colors.
    #[arg(long, env = "NO_COLOR", global = true)]
    pub no_color: bool,

    /// Replace Unicode box-drawing with ASCII equivalents.
    #[arg(long, global = true)]
    pub ascii: bool,

    /// Skip all interactive confirmation prompts.
    #[arg(short, long, global = true)]
    pub yes: bool,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Router health, resources, and general overview dashboard
    Status(StatusArgs),
    /// Manage daemon background services (start, stop, restart, list, show)
    Service(ServiceArgs),
    /// Stream live daemon events in real-time (devices, DHCP, DNS, firewall, `PPPoE`)
    #[command(alias = "events")]
    Watch(WatchArgs),
    /// Inspect and manage connected and discovered network devices (list, show, purge)
    #[command(alias = "device")]
    Devices(DevicesArgs),
    /// Manage static hosts, DHCP reservations, and local DNS overrides
    #[command(alias = "hosts")]
    Host(HostArgs),
    /// Send Wake-on-LAN magic packet to power on a networked device
    #[command(alias = "wake")]
    Wol(WolArgs),
    /// Trigger configuration reload across all running services in-place
    Reload(ReloadArgs),
    /// Manage `PPPoE` WAN session (status, reconnect, disconnect)
    Pppoe(PppoeArgs),
    /// Manage IPv6 Router Advertisement daemon (status, trigger, config, prefixes, RDNSS, DNSSL)
    Ra(RaArgs),
    /// Manage DNS resolver, cache, and adblock filter rules
    Dns(DnsArgs),
    /// Manage DHCP server (reconcile leases, release/renew client leases)
    Dhcp(DhcpArgs),
    /// Manage nftables firewall and NAT orchestrator (status, reload)
    Firewall(FirewallArgs),
    /// Manage network traffic shaping (`SQM` / `CAKE`), `NIC` hardware tuning, and live rates
    #[command(alias = "qos")]
    Traffic(TrafficArgs),
    /// Embedded database maintenance (vacuum, prune, clean)
    Db(DbArgs),
    /// Inspect, export, import, and validate system configuration
    Config(ConfigArgs),
    /// Manage router user accounts and roles (list, add, delete, passwd)
    #[command(alias = "users")]
    User(UserArgs),
    /// Manage API authentication tokens and access keys (list, generate, delete, renew)
    #[command(alias = "token", alias = "tokens")]
    Auth(AuthArgs),
}
