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
#[cfg(feature = "ra")]
use lanforge_ra::RaServiceConfig;
#[cfg(feature = "tftp")]
use lanforge_tftp::config::TftpConfig;
#[cfg(feature = "pppoe")]
use lanforge_pppoe::config::PppoeConfig;
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

// DhcpV4Cfg and DhcpV6Cfg have been replaced by lanforge_network equivalents

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
            iface: "end0".into(),
            target_prefix: "fd97:f00d:cafe:3731".into(),
            debounce_secs: 2,
            search_domains: Vec::new(),
            tls_cert: None,
            tls_key: None,
        }
    }
}

// GeneralCfg was removed in favor of SystemCfg and DatabaseConfig

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

// AuthCfg, HttpCfg, and TftpCfg are now handled by their respective crate configs or merged into api/tftp

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
            info!("[config] Loaded config from '{path}'");
            info!(
                "[config]   {} static device(s), RA {}",
                cfg.devices.len(),
                {
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
                }
            );
            return cfg;
        }
        Err(e) => {
            warn!("[config] Failed to parse '{path}' as a whole: {e}");
            warn!("[config] Attempting to recover valid sections individually...");
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

// Helper for section-by-section loading
fn load_section<T: serde::de::DeserializeOwned + Default>(v: &toml::Value, key: &str) -> T {
    v.get(key).map_or_else(T::default, |sec_val| {
        match T::deserialize(sec_val.clone()) {
            Ok(s) => s,
            Err(e) => {
                warn!("[config]   - [FAIL] Section [{key}]: {e} (using defaults for this section)");
                T::default()
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let default_cfg = TomlConfig::default();
        assert_eq!(default_cfg.system.iface, "end0");
        #[cfg(feature = "ra")]
        assert!(!default_cfg.ra.enabled);
        #[cfg(feature = "dns")]
        assert_eq!(default_cfg.dns.listen.to_string(), "0.0.0.0:53");
    }

    #[test]
    fn test_parse_empty_toml() {
        let content = "";
        let cfg: TomlConfig = toml::from_str(content).unwrap_or_default();
        assert_eq!(cfg.system.iface, "end0"); // should fallback to default values
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

    fn load_section<T: serde::de::DeserializeOwned + Default>(v: &toml::Value, key: &str) -> T {
        v.get(key).map_or_else(T::default, |sec_val| {
            T::deserialize(sec_val.clone()).unwrap_or_default()
        })
    }
}
