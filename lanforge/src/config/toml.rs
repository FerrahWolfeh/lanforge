use lanforge_network::dhcp::{v4::config::Dhcpv4Config, v6::config::Dhcpv6Config};
use serde::{Deserialize, Serialize};

use std::path::Path;
use tracing::{info, warn};

/// Root structure of the TOML file.
#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(default)]
pub struct TomlConfig {
    pub general: GeneralCfg,
    pub ra: lanforge_network::ra::RaServiceConfig,
    pub dhcp: DhcpCfg,
    pub dns: lanforge_dns::DnsConfig,
    pub auth: AuthCfg,
    pub http: HttpCfg,
    pub tftp: TftpCfg,
    #[serde(default)]
    pub devices: Vec<StaticDeviceCfg>,
}

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(default)]
pub struct DhcpCfg {
    pub v4: Dhcpv4Config,
    pub v6: Dhcpv6Config,
}

// DhcpV4Cfg and DhcpV6Cfg have been replaced by lanforge_network equivalents

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
    /// Path to the directory containing boot files (PXE/HTTP boot).
    pub boot_dir: Option<String>,
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
            boot_dir: None,
            search_domains: None,
            log_db: ":memory:".into(),
            log_db_url: None,
        }
    }
}

// RaCfg has been replaced by lanforge_network::ra::RaServiceConfig

// DnsCfg has been replaced by lanforge_dns::DnsConfig

/// Static device — read from `[[devices]]` in the TOML.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct StaticDeviceCfg {
    pub mac: String,
    pub hostname: String,
    pub duid: Option<String>,
    pub v4_ip: Option<String>,
    pub v6_suffix: Option<String>,
    pub boot_file: Option<String>,
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

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct TftpCfg {
    pub enabled: bool,
    pub listen: String,
    pub root_dir: Option<String>,
}

impl Default for TftpCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:69".into(),
            root_dir: None,
        }
    }
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
        assert_eq!(default_cfg.dns.listen.to_string(), "0.0.0.0:53");
    }

    #[test]
    fn test_parse_empty_toml() {
        let content = "";
        let cfg: TomlConfig = toml::from_str(content).unwrap_or_default();
        assert_eq!(cfg.general.iface_lan, "end0"); // should fallback to default values
    }
}
