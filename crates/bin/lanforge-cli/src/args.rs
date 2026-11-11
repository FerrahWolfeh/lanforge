use crate::commands::{
    AuthArgs, ConfigArgs, DbArgs, DevicesArgs, DhcpArgs, DnsArgs, FirewallArgs, HostArgs,
    LoginArgs, PppoeArgs, RaArgs, ReloadArgs, ServiceArgs, SetupArgs, ShutdownArgs, StatusArgs,
    TrafficArgs, UserArgs, WatchArgs, WolArgs,
};
use clap::{Parser, Subcommand};
use std::env;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "lanforge",
    version = env!("LANFORGE_BUILD"),
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

    /// Disable ANSI colors (also when `NO_COLOR` is set to any non-empty value).
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Replace Unicode box-drawing with ASCII equivalents.
    #[arg(long, global = true)]
    pub ascii: bool,

    /// Skip all interactive confirmation prompts.
    #[arg(short, long, global = true)]
    pub yes: bool,
}

impl Cli {
    /// `--no-color`, or `NO_COLOR` set to any non-empty value (<https://no-color.org>): a clap
    /// `bool` env would refuse the usual `NO_COLOR=1` and stop every command.
    #[must_use]
    pub fn colors_off(&self) -> bool {
        self.no_color || env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty())
    }
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
    /// Embedded database maintenance (prune, clean)
    Db(DbArgs),
    /// Inspect, export, import, and validate system configuration
    Config(ConfigArgs),
    /// Manage router user accounts and roles (list, add, delete, passwd)
    #[command(alias = "users")]
    User(UserArgs),
    /// Manage API authentication tokens and access keys (list, generate, delete, renew)
    #[command(alias = "token", alias = "tokens")]
    Auth(AuthArgs),
    /// First-run router onboarding setup wizard and hardware topology inspection
    #[command(alias = "init", alias = "wizard")]
    Setup(SetupArgs),
    /// Gracefully shut down the Lanforge router daemon
    #[command(alias = "poweroff", alias = "halt")]
    Shutdown(ShutdownArgs),
    /// Save remote daemon credentials for CLI management
    Login(LoginArgs),
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::CommandFactory;

    /// Clap checks the whole command tree (unique short flags across globals and subcommands,
    /// valid groups); a clash only shows up when that subcommand runs in a debug build.
    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
