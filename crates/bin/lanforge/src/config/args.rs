use clap::Parser;

/// Command-line arguments for the Lanforge daemon.
#[derive(Parser, Debug)]
#[command(name = "lanforge", version, about, long_about = None)]
pub struct CliArgs {
    /// Path to the TOML configuration file.
    #[arg(short, long, env = "LANFORGE_CONFIG", conflicts_with = "config_dir")]
    pub config: Option<String>,

    /// Path to the configuration directory (e.g. `/etc/lanforge`).
    #[arg(
        long = "config-dir",
        env = "LANFORGE_CONFIG_DIR",
        conflicts_with = "config"
    )]
    pub config_dir: Option<String>,

    /// Persistent configuration database path (e.g. `/var/lib/lanforge/config.redb`).
    #[arg(
        long = "config-db-path",
        alias = "db-path",
        alias = "db-url",
        env = "LANFORGE_CONFIG_DB_PATH"
    )]
    pub config_db_path: Option<String>,

    /// Volatile runtime database path (e.g. `/run/lanforge/runtime.redb` or `/tmp/lanforge/runtime.redb`).
    #[arg(
        long = "runtime-db-path",
        alias = "log-path",
        alias = "log-db-url",
        env = "LANFORGE_RUNTIME_DB_PATH"
    )]
    pub runtime_db_path: Option<String>,

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

    /// Skip first-run onboarding provisioning wizard and boot directly with configured services.
    #[arg(
        long = "auto-provision",
        alias = "skip-provisioning",
        env = "LANFORGE_AUTO_PROVISION"
    )]
    pub auto_provision: bool,

    /// Allow running without root (EUID 0) privileges (for capability-based or unprivileged sandboxes).
    #[arg(long, env = "LANFORGE_ALLOW_UNPRIVILEGED")]
    pub allow_unprivileged: bool,

    /// Quick start in ephemeral development/profiling mode (in-memory DB if unconfigured, auto-provision enabled).
    #[arg(long = "dev", env = "LANFORGE_DEV")]
    pub dev: bool,
}

impl CliArgs {
    /// Resolves the absolute path to the main TOML configuration file.
    #[must_use]
    pub fn resolved_config_path(&self) -> std::path::PathBuf {
        match (&self.config, &self.config_dir) {
            (Some(c), _) => std::path::PathBuf::from(c),
            (None, Some(d)) => std::path::Path::new(d).join("lanforge.toml"),
            (None, None) => std::path::PathBuf::from("/etc/lanforge/lanforge.toml"),
        }
    }

    /// Resolves the configuration directory (e.g. `/etc/lanforge`).
    #[must_use]
    pub fn resolved_config_dir(&self) -> std::path::PathBuf {
        match (&self.config_dir, &self.config) {
            (Some(d), _) => std::path::PathBuf::from(d),
            (None, Some(c)) => {
                let p = std::path::Path::new(c);
                p.parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .to_path_buf()
            }
            (None, None) => std::path::PathBuf::from("/etc/lanforge"),
        }
    }

    /// Probes if the resolved configuration directory is writable by attempting to create and remove a temp file.
    #[must_use]
    pub fn is_config_dir_writable(&self) -> bool {
        let dir = self.resolved_config_dir();
        if !dir.exists() && std::fs::create_dir_all(&dir).is_err() {
            return false;
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let probe_file = dir.join(format!(".lanforge_probe_{}_{}", std::process::id(), nonce));
        let Ok(file) = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe_file)
        else {
            return false;
        };
        drop(file);
        std::fs::remove_file(probe_file).is_ok()
    }
}
