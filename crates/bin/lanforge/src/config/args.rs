use clap::Parser;

/// Command-line arguments for the Lanforge daemon.
#[derive(Parser, Debug)]
#[command(name = "lanforge", version, about, long_about = None)]
pub struct CliArgs {
    /// Path to the TOML configuration file.
    #[arg(
        short,
        long,
        env = "LANFORGE_CONFIG",
        default_value = "/etc/lanforge/lanforge.toml"
    )]
    pub config: String,

    /// Database connection URL (e.g. `postgres://lanforge:lanforge@localhost:5432/lanforge`).
    #[arg(long, env = "LANFORGE_DB_URL")]
    pub db_url: Option<String>,

    /// Log database connection URL or file path (e.g. `/tmp/lanforge-logs.jsonl`).
    #[arg(long, env = "LANFORGE_LOG_DB_URL")]
    pub log_db_url: Option<String>,

    /// Main LAN interface (e.g. eth0, enp3s0, br-lan).
    #[arg(short = 'i', long, env = "LANFORGE_IFACE_LAN")]
    pub iface_lan: Option<String>,

    /// Local IPv6 prefix for SLAAC tracking.
    #[arg(long, env = "LANFORGE_TARGET_PREFIX")]
    pub target_prefix: Option<String>,

    /// Debounce window in seconds for network event processing.
    #[arg(long, env = "LANFORGE_DEBOUNCE_SECS")]
    pub debounce_secs: Option<u64>,

    /// Listen address for the HTTP REST / `WebUI` API (e.g. 0.0.0.0:8088).
    #[arg(long, env = "LANFORGE_HTTP_LISTEN")]
    pub http_listen: Option<String>,

    /// Path to the UDS control socket.
    #[arg(long, env = "LANFORGE_CONTROL_SOCKET")]
    pub control_socket: Option<String>,

    /// Path to an additional TOML/JSON file containing static devices (debug).
    #[arg(long, env = "LANFORGE_DEVICES_FILE")]
    pub devices_file: Option<String>,
}
