use clap::Parser;
#[cfg(feature = "debug-commands")]
use clap::Subcommand;
use std::net::Ipv4Addr;

#[cfg(feature = "debug-commands")]
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Start all enabled services with optional module filtering (debug only)
    Run {
        /// Run only a specific subsystem (e.g. ra, dhcpv4, dhcpv6, dns, slaac)
        #[arg(long)]
        only: Option<String>,
    },
}

#[derive(Parser, Debug)]
#[command(name = "lanforge", version, about, long_about = None)]
pub struct CliArgs {
    #[cfg(feature = "debug-commands")]
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Path to the TOML configuration file.
    #[arg(
        short,
        long,
        env = "LANFORGE_CONFIG",
        default_value = "/etc/lanforge/lanforge.toml"
    )]
    pub config: String,

    /// Path to the `SQLite` database (leases).
    #[arg(short = 'd', long, env = "LANFORGE_DB_PATH")]
    pub db_path: Option<String>,

    /// Database connection URL (e.g. `sqlite:///var/lib/lanforge/leases.db`).
    #[arg(long, env = "LANFORGE_DB_URL")]
    pub db_url: Option<String>,

    /// Path to the `SQLite` database for logs (history).
    #[arg(long, env = "LANFORGE_LOG_DB")]
    pub log_db: Option<String>,

    /// Log database connection URL (e.g. `sqlite:///tmp/lanforge_logs.db`).
    #[arg(long, env = "LANFORGE_LOG_DB_URL")]
    pub log_db_url: Option<String>,

    /// Path to an additional TOML/JSON file containing only static devices (debug).
    #[arg(long, env = "LANFORGE_DEVICES_FILE")]
    pub devices_file: Option<String>,

    // ── General Overrides ─────────────────────────────────────────────────
    /// Main LAN interface (e.g. end0, eth0).
    #[arg(short = 'i', long, env = "LANFORGE_IFACE_LAN")]
    pub iface_lan: Option<String>,

    /// Local IPv6 prefix for SLAAC tracking.
    #[arg(long, env = "LANFORGE_TARGET_PREFIX")]
    pub target_prefix: Option<String>,

    /// Debounce window in seconds for scans after network events.
    #[arg(long, env = "LANFORGE_DEBOUNCE_SECS")]
    pub debounce_secs: Option<u64>,

    /// Periodic scan interval (fallback) in minutes.
    #[arg(long, env = "LANFORGE_FALLBACK_MINS")]
    pub fallback_mins: Option<u64>,

    // ── Router Advertisements (RA) ────────────────────────────────────────
    /// Enable or disable the Router Advertisement service.
    #[arg(long, env = "LANFORGE_RA_ENABLED")]
    pub ra_enabled: Option<bool>,

    /// Sets the 'Managed Address Configuration' (M) flag in RA.
    #[arg(long, env = "LANFORGE_RA_MANAGED")]
    pub ra_managed: Option<bool>,

    /// Sets the 'Other Configuration' (O) flag in RA.
    #[arg(long, env = "LANFORGE_RA_OTHER")]
    pub ra_other_config: Option<bool>,

    /// Maximum interval between periodic RAs (seconds).
    #[arg(long, env = "LANFORGE_RA_MAX_INTERVAL")]
    pub ra_max_interval: Option<u64>,

    // ── DHCPv4 ────────────────────────────────────────────────────────────
    /// Enables the `DHCPv4` server.
    #[arg(long, env = "LANFORGE_DHCPV4_ENABLED")]
    pub dhcpv4_enabled: Option<bool>,

    /// First IP of the `DHCPv4` pool.
    #[arg(long, env = "LANFORGE_DHCPV4_START")]
    pub dhcpv4_range_start: Option<Ipv4Addr>,

    /// Last IP of the `DHCPv4` pool.
    #[arg(long, env = "LANFORGE_DHCPV4_END")]
    pub dhcpv4_range_end: Option<Ipv4Addr>,

    /// Default lease time (seconds).
    #[arg(long, env = "LANFORGE_DHCPV4_LEASE")]
    pub dhcpv4_lease_time: Option<u32>,

    /// UDP port for the `DHCPv4` server (default 67).
    #[arg(long, env = "LANFORGE_DHCPV4_PORT")]
    pub dhcpv4_port: Option<u16>,

    // ── DHCPv6 ────────────────────────────────────────────────────────────
    /// Enables the `DHCPv6` server.
    #[arg(long, env = "LANFORGE_DHCPV6_ENABLED")]
    pub dhcpv6_enabled: Option<bool>,

    /// UDP port for the `DHCPv6` server (default 547).
    #[arg(long, env = "LANFORGE_DHCPV6_PORT")]
    pub dhcpv6_port: Option<u16>,

    // ── DNS ───────────────────────────────────────────────────────────────
    /// Enables the authoritative/recursive DNS server.
    #[arg(long, env = "LANFORGE_DNS_ENABLED")]
    pub dns_enabled: Option<bool>,

    /// DNS listen address (e.g. 0.0.0.0:5353).
    #[arg(long, env = "LANFORGE_DNS_LISTEN")]
    pub dns_listen: Option<String>,

    /// Upstream resolver (e.g. 8.8.8.8:53).
    #[arg(short = 'u', long, env = "LANFORGE_DNS_UPSTREAM")]
    pub dns_upstream: Option<String>,

    /// DNS listen port (listen address port override).
    #[arg(short = 'p', long, env = "LANFORGE_DNS_PORT")]
    pub dns_port: Option<u16>,

    /// DNS-over-TLS listen address (e.g. 0.0.0.0:853).
    #[arg(long, env = "LANFORGE_DNS_DOT_LISTEN")]
    pub dns_dot_listen: Option<String>,

    /// Path to the TLS certificate for DNS-over-TLS.
    #[arg(long, env = "LANFORGE_DNS_TLS_CERT")]
    pub dns_tls_cert: Option<String>,

    /// Path to the TLS private key for DNS-over-TLS.
    #[arg(long, env = "LANFORGE_DNS_TLS_KEY")]
    pub dns_tls_key: Option<String>,

    /// Enable or disable the DNS adblocker.
    #[arg(long, env = "LANFORGE_DNS_ADBLOCK")]
    pub dns_adblock_enabled: Option<bool>,

    /// Default TTL for locally generated DNS records.
    #[arg(long, env = "LANFORGE_DNS_TTL")]
    pub dns_ttl: Option<u32>,

    /// Threshold in days to hide inactive devices from DNS.
    #[arg(long, env = "LANFORGE_DNS_LAST_SEEN")]
    pub dns_last_seen: Option<u32>,

    // ── API / Control ─────────────────────────────────────────────────────
    /// Path to the UDS control socket.
    #[arg(long, env = "LANFORGE_CONTROL_SOCKET")]
    pub control_socket: Option<String>,

    /// TCP port for the control API (optional for remote debug).
    #[arg(long, env = "LANFORGE_CONTROL_PORT")]
    pub control_port: Option<u16>,
    /// Listen address for the HTTP REST API (e.g. 0.0.0.0:8080).
    #[arg(long, env = "LANFORGE_HTTP_LISTEN")]
    pub http_listen: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_args_parsing() {
        // Just verify it doesn't panic on a simple case
        #[cfg(feature = "debug-commands")]
        {
            let args = CliArgs::try_parse_from(["lanforge", "run"]);
            assert!(args.is_ok());
            let args = args.unwrap();
            assert!(matches!(args.command, Some(Command::Run { .. })));
        }
        #[cfg(not(feature = "debug-commands"))]
        {
            let args = CliArgs::try_parse_from(["lanforge"]);
            assert!(args.is_ok());
        }
    }
}
