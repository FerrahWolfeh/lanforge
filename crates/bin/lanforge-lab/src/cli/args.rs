use std::net::SocketAddr;
use clap::{Args, Parser, Subcommand, ValueEnum};

/// Command-line arguments for Lanforge Lab Workbench.
#[derive(Parser, Debug)]
#[command(name = "lanforge-lab", version, about = "Interactive Lab Workbench & Automated Testbed for Lanforge")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Mode override: direct, netns, or interface.
    #[arg(long, default_value = "auto")]
    pub mode: ModeArg,

    /// DHCP server address (e.g. 127.0.0.1:1067 or 192.168.100.1:67).
    #[arg(long, default_value = "127.0.0.1:1067")]
    pub dhcp_server: SocketAddr,

    /// DNS server address (e.g. 127.0.0.1:1053 or 192.168.100.1:53).
    #[arg(long, default_value = "127.0.0.1:1053")]
    pub dns_server: SocketAddr,

    /// Target network interface name (optional).
    #[arg(short = 'i', long)]
    pub iface: Option<String>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeArg {
    Auto,
    Direct,
    Netns,
    Interface,
}

impl ModeArg {
    #[must_use]
    pub const fn requires_root(self) -> bool {
        matches!(self, Self::Netns)
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Launches the interactive visual Terminal UI (default when run in a TTY).
    Tui,

    /// Runs a single scenario headlessly (ideal for AI agents, CI/CD, and scripts).
    Run(RunArgs),

    /// Runs a high-throughput stress/benchmark test.
    Bench(BenchArgs),

    /// Runs the complete regression test suite across all subsystems.
    Suite(SuiteArgs),
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Scenario to run: dhcp, dns, ra, or discovery.
    #[arg(value_enum)]
    pub scenario: ScenarioArg,

    /// Domain name for DNS query.
    #[arg(long, default_value = "lanforge.lan")]
    pub domain: String,

    /// Client MAC address for DHCP (e.g. 02:11:22:33:44:55).
    #[arg(long)]
    pub mac: Option<String>,

    /// Client hostname for DHCP.
    #[arg(long)]
    pub hostname: Option<String>,

    /// 802.1Q VLAN ID for VLAN simulation (e.g. 10 or 100).
    #[arg(long, default_value = "100")]
    pub vlan_id: u16,

    /// Output results as JSON.
    #[arg(long)]
    pub json: bool,

    /// Asserts success and exits with code 1 if the scenario failed.
    #[arg(long)]
    pub assert_success: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScenarioArg {
    Dhcp,
    Dns,
    Ra,
    Discovery,
    Vlan,
}

impl ScenarioArg {
    #[must_use]
    pub const fn requires_root(self) -> bool {
        matches!(self, Self::Ra)
    }
}

#[derive(Args, Debug)]
pub struct BenchArgs {
    /// Benchmark scenario: dhcp-storm or dns-flood.
    #[arg(value_enum)]
    pub benchmark: BenchTypeArg,

    /// Target QPS for DNS flood (default: 1000).
    #[arg(long, default_value_t = 1000)]
    pub qps: usize,

    /// Number of clients for DHCP storm (default: 50).
    #[arg(long, default_value_t = 50)]
    pub clients: usize,

    /// Concurrency limit (default: 10).
    #[arg(long, default_value_t = 10)]
    pub concurrency: usize,

    /// Duration in seconds (default: 3).
    #[arg(long, default_value_t = 3)]
    pub duration: u64,

    /// Output results as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchTypeArg {
    DhcpStorm,
    DnsFlood,
}

#[derive(Args, Debug)]
pub struct SuiteArgs {
    /// Output results as JSON.
    #[arg(long)]
    pub json: bool,
}
