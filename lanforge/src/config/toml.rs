use serde::{Deserialize, Serialize};
use std::net::Ipv6Addr;
use std::path::Path;
use tracing::{info, warn};

/// Root structure of the TOML file.
#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(default)]
pub struct TomlConfig {
    pub general: GeneralCfg,
    pub ra: RaCfg,
    pub dhcp: DhcpCfg,
    pub dns: DnsCfg,
    pub auth: AuthCfg,
    pub http: HttpCfg,
    #[serde(default)]
    pub devices: Vec<StaticDeviceCfg>,
}

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(default)]
pub struct DhcpCfg {
    pub v4: DhcpV4Cfg,
    pub v6: DhcpV6Cfg,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct DhcpV4Cfg {
    pub enabled: bool,
    pub range_start: String,
    pub range_end: String,
    pub lease_time: u64,
    pub router: String,
    pub dns: Vec<String>,
    pub subnet_mask: Option<String>,
    /// @deprecated use `[general].search_domains` instead. will be removed in the future.
    pub domain_name: Option<String>,
}

impl Default for DhcpV4Cfg {
    fn default() -> Self {
        Self {
            enabled: false,
            range_start: "192.168.0.100".into(),
            range_end: "192.168.0.254".into(),
            lease_time: 86400,
            router: "192.168.0.1".into(),
            dns: vec!["192.168.0.1".into()],
            subnet_mask: None,
            domain_name: None,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct DhcpV6Cfg {
    pub enabled: bool,
    pub lease_time: u32,
    pub range_start: Option<String>,
    pub range_end: Option<String>,
    #[serde(default)]
    pub pools: Vec<DhcpV6PoolCfg>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct DhcpV6PoolCfg {
    pub range_start: Option<String>,
    pub range_end: Option<String>,
    pub address: Option<String>,
}

impl Default for DhcpV6Cfg {
    fn default() -> Self {
        Self {
            enabled: false,
            lease_time: 86400,
            range_start: None,
            range_end: None,
            pools: Vec::new(),
        }
    }
}

/// General system configuration.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct GeneralCfg {
    /// LAN interface where the daemon listens.
    pub iface_lan: String,
    /// @deprecated Path to the `SQLite` database file (leases). Use `db_url` instead.
    pub leases_db: String,
    /// Database connection URL (e.g. `sqlite:///var/lib/lanforge/leases.db` or `postgresql://user:pass@host/db`).
    pub db_url: Option<String>,
    /// "Target" IPv6 prefix to identify local devices (SLAAC).
    pub target_prefix: String,
    /// Wait time before processing network events.
    pub debounce_secs: u64,
    /// Fallback scan interval.
    pub fallback_mins: u64,
    /// Socket path for the CLI.
    pub control_socket: String,
    /// HTTP REST API listen address (e.g. "0.0.0.0:8080").
    pub http_listen: Option<String>,
    /// Global list of search domains.
    pub search_domains: Option<Vec<String>>,
    /// @deprecated Path to the `SQLite` log database file. Use `log_db_url` instead.
    pub log_db: String,
    /// Log database connection URL.
    pub log_db_url: Option<String>,
}

impl GeneralCfg {
    /// Returns the resolved database URL, prioritizing `db_url` over `leases_db`.
    pub fn get_db_url(&self) -> String {
        self.db_url
            .as_ref()
            .map_or_else(|| format!("sqlite://{}", self.leases_db), Clone::clone)
    }

    /// Returns the resolved log database URL, prioritizing `log_db_url` over `log_db`.
    pub fn get_log_db_url(&self) -> String {
        self.log_db_url.as_ref().map_or_else(
            || {
                if self.log_db == ":memory:" {
                    "sqlite::memory:?cache=shared".to_string()
                } else {
                    format!("sqlite://{}", self.log_db)
                }
            },
            Clone::clone,
        )
    }
}

impl Default for GeneralCfg {
    fn default() -> Self {
        Self {
            iface_lan: "end0".into(),
            leases_db: "/var/lib/lanforge/leases.db".into(),
            db_url: None,
            target_prefix: "fd97:f00d:cafe:3731".into(),
            debounce_secs: 2,
            fallback_mins: 60,
            control_socket: "/run/lanforge/control.sock".into(),
            http_listen: None,
            search_domains: None,
            log_db: ":memory:".into(),
            log_db_url: None,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct RaCfg {
    pub enabled: bool,
    pub managed: bool,
    pub other_config: bool,
    pub max_interval: u64,
    pub router_lifetime: Option<u64>,
    pub mtu: Option<u32>,
    #[serde(default)]
    pub prefix: Vec<RaPrefixCfg>,
    #[serde(default)]
    pub rdnss: Vec<RaRdnssCfg>,
}

impl Default for RaCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            managed: true,
            other_config: true,
            max_interval: 100,
            router_lifetime: None,
            mtu: None,
            prefix: Vec::new(),
            rdnss: Vec::new(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct RaPrefixCfg {
    pub source: String,
    pub address: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct RaRdnssCfg {
    pub servers: Vec<Ipv6Addr>,
    pub lifetime: Option<u64>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct DnsCfg {
    pub enabled: bool,
    /// Address and port where the DNS server listens (e.g. "0.0.0.0:5300")
    pub listen: String,
    /// Upstream resolver for non-LAN queries, typically Unbound (e.g. "127.0.0.1:5335")
    pub upstream: Option<String>,
    /// @deprecated use `[general].search_domains` instead. will be removed in the future.
    pub search_domain: String,
    /// LAN responses TTL in seconds
    pub ttl: u32,
    /// Whether the micro-adblocker is enabled.
    #[serde(default)]
    pub adblock_enabled: bool,
    /// List of URLs to fetch blocklists from.
    #[serde(default)]
    pub adblock_urls: Vec<String>,
    /// Address and port for DNS-over-TLS (e.g. "0.0.0.0:853")
    pub dot_listen: Option<String>,
    /// How many days a device can be offline before its DNS entry is hidden.
    #[serde(default = "default_threshold_days")]
    pub last_seen_threshold_days: u32,
}

fn default_threshold_days() -> u32 {
    7
}

impl Default for DnsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:5300".into(),
            upstream: None,
            search_domain: "lan".into(),
            ttl: 60,
            adblock_enabled: false,
            adblock_urls: Vec::new(),
            dot_listen: None,
            last_seen_threshold_days: 7,
        }
    }
}

/// Static device — read from `[[devices]]` in the TOML.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct StaticDeviceCfg {
    pub mac: String,
    pub hostname: String,
    pub duid: Option<String>,
    pub v4_ip: Option<String>,
    pub v6_suffix: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(default)]
pub struct AuthCfg {
    pub password_hash: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(default)]
pub struct HttpCfg {
    pub listen: Option<String>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
}

/// Load and parse the TOML config file, or return defaults if missing.
pub fn load_toml(path: &str) -> TomlConfig {
    if !Path::new(path).exists() {
        if path != "/etc/lanforge/lanforge.toml" {
            // User explicitly specified a path that doesn't exist
            warn!("[config] Config file '{path}' not found, using defaults");
        }
        return TomlConfig::default();
    }

    match std::fs::read_to_string(path) {
        Ok(content) => match toml::from_str::<TomlConfig>(&content) {
            Ok(cfg) => {
                info!("[config] Loaded config from '{path}'");
                info!(
                    "[config]   {} static device(s), RA {}",
                    cfg.devices.len(),
                    if cfg.ra.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
                cfg
            }
            Err(e) => {
                warn!("[config] Failed to parse '{path}': {e} — using defaults");
                TomlConfig::default()
            }
        },
        Err(e) => {
            warn!("[config] Failed to read '{path}': {e} — using defaults");
            TomlConfig::default()
        }
    }
}

/// Load only the devices section from a TOML file for debugging.
pub fn load_devices_only(path: &str) -> Vec<StaticDeviceCfg> {
    if !Path::new(path).exists() {
        warn!("[config] Devices file '{path}' not found");
        return Vec::new();
    }

    match std::fs::read_to_string(path) {
        Ok(content) => {
            // Try as a direct list of devices first (common in quick debug)
            #[derive(Deserialize)]
            struct DeviceList {
                devices: Vec<StaticDeviceCfg>,
            }
            if let Ok(list) = toml::from_str::<DeviceList>(&content) {
                return list.devices;
            }
            // If it fails, try as a full TomlConfig and get only the devices field
            match toml::from_str::<TomlConfig>(&content) {
                Ok(cfg) => cfg.devices,
                Err(e) => {
                    warn!("[config] Failed to parse devices from '{path}': {e}");
                    Vec::new()
                }
            }
        }
        Err(e) => {
            warn!("[config] Failed to read devices file '{path}': {e}");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let default_cfg = TomlConfig::default();
        assert_eq!(default_cfg.general.iface_lan, "end0");
        assert!(!default_cfg.ra.enabled);
        assert_eq!(default_cfg.dns.listen, "0.0.0.0:5300");
    }

    #[test]
    fn test_parse_empty_toml() {
        let content = "";
        let cfg: TomlConfig = toml::from_str(content).unwrap_or_default();
        assert_eq!(cfg.general.iface_lan, "end0"); // should fallback to default values
    }
}
