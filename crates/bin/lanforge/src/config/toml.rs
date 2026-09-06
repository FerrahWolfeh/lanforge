use lanforge_db::config::DatabaseConfig;
#[cfg(feature = "dhcp")]
use lanforge_dhcp::v4::config::Dhcpv4Config;
#[cfg(feature = "dhcp")]
use lanforge_dhcp::v6::config::Dhcpv6Config;
#[cfg(feature = "discovery")]
use lanforge_discovery::{mdns::MdnsConfig, ndp::config::MonitorConfig};
#[cfg(feature = "dns")]
use lanforge_dns::config::DnsConfig;
#[cfg(feature = "http")]
use lanforge_http::config::HttpConfig;
#[cfg(feature = "pppoe")]
use lanforge_pppoe::config::PppoeConfig;
#[cfg(feature = "ra")]
use lanforge_ra::RaServiceConfig;
#[cfg(feature = "tftp")]
use lanforge_tftp::config::TftpConfig;
#[cfg(feature = "uds")]
use lanforge_uds::config::ApiConfig;
use serde::{Deserialize, Serialize};

use std::path::Path;
use tracing::{info, warn};

/// Root structure of the TOML file.
#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(default)]
pub struct TomlConfig {
    pub system: SystemCfg,
    pub database: DatabaseConfig,
    #[cfg(feature = "ra")]
    pub ra: RaServiceConfig,
    #[cfg(feature = "dhcp")]
    pub dhcp: DhcpCfg,
    #[cfg(feature = "dns")]
    pub dns: DnsConfig,
    #[cfg(feature = "discovery")]
    pub monitor: MonitorConfig,
    #[cfg(feature = "discovery")]
    pub mdns: MdnsConfig,
    #[cfg(feature = "uds")]
    pub api: ApiConfig,
    #[cfg(feature = "http")]
    pub http: HttpConfig,
    #[cfg(feature = "tftp")]
    pub tftp: TftpConfig,
    #[cfg(feature = "pppoe")]
    pub pppoe: PppoeConfig,
    #[serde(default)]
    pub devices: Vec<StaticDeviceCfg>,
}

#[cfg(feature = "dhcp")]
#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(default)]
pub struct DhcpCfg {
    pub v4: Dhcpv4Config,
    pub v6: Dhcpv6Config,
}

/// System-wide global configuration.
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct SystemCfg {
    /// LAN interface where the daemon listens.
    pub iface: String,
    /// "Target" IPv6 prefix to identify local devices (SLAAC).
    pub target_prefix: String,
    /// Wait time before processing network events.
    pub debounce_secs: u64,
    /// Global list of search domains.
    pub search_domains: Vec<String>,
    /// Global TLS certificate path (inherited by DNS/HTTP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
    /// Global TLS private key path (inherited by DNS/HTTP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
}

impl Default for SystemCfg {
    fn default() -> Self {
        Self {
            iface: String::new(),
            target_prefix: String::new(),
            debounce_secs: 2,
            search_domains: Vec::new(),
            tls_cert: None,
            tls_key: None,
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
    pub boot_file: Option<String>,
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

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            warn!("[config] Failed to read '{path}': {e} — using defaults");
            return TomlConfig::default();
        }
    };

    // Try parsing the whole thing first (fast path)
    match toml::from_str::<TomlConfig>(&content) {
        Ok(cfg) => {
            let ra_status = {
                #[cfg(feature = "ra")]
                {
                    if cfg.ra.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                }
                #[cfg(not(feature = "ra"))]
                {
                    "disabled"
                }
            };
            info!(
                "Config: Loaded from '{path}' (devices: {}, RA: {ra_status})",
                cfg.devices.len()
            );
            return cfg;
        }
        Err(e) => {
            warn!("Config: Failed to parse '{path}' as a whole: {e}");
            warn!("Config: Attempting to recover valid sections individually...");
        }
    }

    // Slow path: parse as a generic value and extract known sections
    let value: toml::Value = match toml::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            warn!("[config] Critical syntax error in '{path}': {e} — using absolute defaults");
            return TomlConfig::default();
        }
    };

    let cfg = TomlConfig {
        system: load_section(&value, "system"),
        database: load_section(&value, "database"),
        #[cfg(feature = "ra")]
        ra: load_section(&value, "ra"),
        #[cfg(feature = "dhcp")]
        dhcp: load_section(&value, "dhcp"),
        #[cfg(feature = "dns")]
        dns: load_section(&value, "dns"),
        #[cfg(feature = "discovery")]
        monitor: load_section(&value, "monitor"),
        #[cfg(feature = "discovery")]
        mdns: load_section(&value, "mdns"),
        #[cfg(feature = "uds")]
        api: load_section(&value, "api"),
        #[cfg(feature = "http")]
        http: load_section(&value, "http"),
        #[cfg(feature = "tftp")]
        tftp: load_section(&value, "tftp"),
        #[cfg(feature = "pppoe")]
        pppoe: load_section(&value, "pppoe"),
        devices: load_section(&value, "devices"),
    };

    info!("[config] Partial config recovery complete");
    cfg
}

/// Load only the devices section from a TOML file for debugging.
pub fn load_devices_only(path: &str) -> Vec<StaticDeviceCfg> {
    if !Path::new(path).exists() {
        warn!("[config] Devices file '{path}' not found");
        return Vec::new();
    }

    match std::fs::read_to_string(path) {
        Ok(content) => {
            #[derive(Deserialize)]
            struct DeviceList {
                devices: Vec<StaticDeviceCfg>,
            }
            if let Ok(list) = toml::from_str::<DeviceList>(&content) {
                return list.devices;
            }
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

// Helper for section-by-section loading
fn load_section<T: serde::de::DeserializeOwned + Default>(v: &toml::Value, key: &str) -> T {
    v.get(key).map_or_else(T::default, |sec_val| {
        T::deserialize(sec_val.clone()).unwrap_or_else(|e| {
            warn!("[config]   - [FAIL] Section [{key}]: {e} (using defaults for this section)");
            T::default()
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let default_cfg = TomlConfig::default();
        assert_eq!(default_cfg.system.iface, "");
        #[cfg(feature = "ra")]
        assert!(!default_cfg.ra.enabled);
        #[cfg(feature = "dns")]
        assert_eq!(default_cfg.dns.listen.to_string(), "0.0.0.0:53");
    }

    #[test]
    fn test_parse_empty_toml() {
        let content = "";
        let cfg: TomlConfig = toml::from_str(content).unwrap_or_default();
        assert_eq!(cfg.system.iface, ""); // should fallback to default values
    }

    #[test]
    fn test_partial_recovery_logic() {
        let content = r#"
[system]
iface = "eth42"

[ra]
source = "broken" # Invalid variant
"#;
        let value: toml::Value = toml::from_str(content).unwrap();

        // Helper for section-by-section loading (copy-pasted from load_toml for testing)

        let system: SystemCfg = load_section(&value, "system");
        #[cfg(feature = "ra")]
        let ra: RaServiceConfig = load_section(&value, "ra");

        assert_eq!(system.iface, "eth42");
        #[cfg(feature = "ra")]
        assert!(!ra.enabled); // Should be default
    }

    #[test]
    fn test_contrib_example_config_parses_cleanly() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../contrib/lanforge.toml");
        let content = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read contrib/lanforge.toml at {path}: {e}"));
        let cfg: TomlConfig = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse contrib/lanforge.toml: {e}"));

        assert_eq!(cfg.system.iface, "end0");
        assert_eq!(cfg.system.target_prefix, "fd97:f00d:cafe:3731");
        #[cfg(feature = "http")]
        assert_eq!(cfg.http.listen.port(), 8088);
        assert!(!cfg.database.url.contains("sqlite"));
        assert_eq!(cfg.devices.len(), 1);
    }

    #[test]
    fn test_docs_example_config_parses_cleanly() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../docs/config/lanforge.example.toml"
        );
        let content = std::fs::read_to_string(path).unwrap_or_else(|e| {
            panic!("Failed to read docs/config/lanforge.example.toml at {path}: {e}")
        });
        let cfg: TomlConfig = toml::from_str(&content)
            .unwrap_or_else(|e| panic!("Failed to parse docs/config/lanforge.example.toml: {e}"));

        assert_eq!(cfg.system.iface, "end0");
        #[cfg(feature = "http")]
        assert_eq!(cfg.http.listen.port(), 8088);
        assert!(!cfg.database.url.contains("sqlite"));
        assert_eq!(cfg.devices.len(), 1);
    }

    fn load_section<T: serde::de::DeserializeOwned + Default>(v: &toml::Value, key: &str) -> T {
        v.get(key).map_or_else(T::default, |sec_val| {
            T::deserialize(sec_val.clone()).unwrap_or_default()
        })
    }
}
