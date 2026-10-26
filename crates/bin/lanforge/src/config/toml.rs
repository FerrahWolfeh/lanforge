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
    #[cfg(feature = "nft")]
    pub firewall: lanforge_nft::FirewallConfig,
    #[cfg(feature = "traffic")]
    pub traffic: lanforge_traffic::TrafficConfig,
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
    /// Whether to skip first-run onboarding setup and boot directly with configured services.
    #[serde(default, alias = "skip_provisioning", alias = "provisioned")]
    pub auto_provision: bool,
    /// Allow running without root (EUID 0) privileges.
    #[serde(default)]
    pub allow_unprivileged: bool,
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
            auto_provision: false,
            allow_unprivileged: false,
        }
    }
}

/// Load and parse the TOML config file, or return defaults if missing.
#[allow(clippy::too_many_lines)]
impl From<&lanforge_api::config_file::ConfigFile> for TomlConfig {
    fn from(fc: &lanforge_api::config_file::ConfigFile) -> Self {
        let export = lanforge_api::api::SystemConfigExport::from(fc);
        let mut cfg = Self {
            system: SystemCfg {
                iface: fc.system.iface.clone(),
                target_prefix: fc.system.ula_prefix.clone().unwrap_or_default(),
                debounce_secs: fc.system.debounce_secs.unwrap_or(2),
                search_domains: fc.system.search_domains.clone(),
                tls_cert: fc.system.tls_cert.clone(),
                tls_key: fc.system.tls_key.clone(),
                auto_provision: fc.system.auto_provision,
                allow_unprivileged: fc.system.allow_unprivileged,
            },
            database: DatabaseConfig {
                config_path: fc.database.config_path.clone(),
                runtime_path: fc.database.runtime_path.clone(),
                flush_interval: fc.database.flush_interval.0,
                max_connections: 10,
                min_connections: 2,
            },
            ..Self::default()
        };

        #[cfg(feature = "http")]
        {
            cfg.http.enabled = fc.http.enabled;
            if let Ok(listen) = fc.http.listen.parse() {
                cfg.http.listen = listen;
            }
            cfg.http.https_enabled = fc.http.https_enabled;
            cfg.http.allow_plaintext_http = fc.http.allow_plaintext_http;
            cfg.http.doh_enabled = fc.http.doh_enabled;
        }

        #[cfg(feature = "uds")]
        {
            cfg.api.enabled = fc.api.enabled;
            cfg.api.socket_path.clone_from(&fc.api.socket_path);
        }

        #[cfg(feature = "discovery")]
        {
            cfg.monitor.enabled = fc.monitor.enabled;
            cfg.monitor.scan_pacing_ms = fc.monitor.scan_pacing_ms;
            cfg.monitor.stale_timeout_secs = fc.monitor.stale_timeout_secs;
            cfg.monitor.ifaces.clone_from(&fc.monitor.interfaces);

            cfg.mdns.enabled = fc.mdns.enabled;
            cfg.mdns.probe_interval = fc.mdns.probe_interval.0;
        }

        #[cfg(feature = "tftp")]
        {
            cfg.tftp.enabled = fc.tftp.enabled;
            if let Ok(l) = fc.tftp.listen.parse() {
                cfg.tftp.listen = l;
            }
            cfg.tftp.root_dir = std::path::PathBuf::from(&fc.tftp.root_dir);
        }

        #[cfg(feature = "dhcp")]
        {
            cfg.dhcp.v4.enabled = fc.dhcp.v4.enabled;
            cfg.dhcp.v4.lease_time = fc
                .dhcp
                .v4
                .lease
                .map_or(86400, |d| u32::try_from(d.0).unwrap_or(u32::MAX));
            if let Some(r) = fc.dhcp.v4.router {
                cfg.dhcp.v4.router = r;
                cfg.dhcp.v4.server_id = r;
            }
            if let Some(m) = fc.dhcp.v4.subnet_mask {
                cfg.dhcp.v4.subnet_mask = m;
            }
            if !fc.dhcp.v4.dns.is_empty() {
                cfg.dhcp.v4.dns.clone_from(&fc.dhcp.v4.dns);
            }
            cfg.dhcp.v4.search_domains = if fc.dhcp.v4.search_domains.is_empty() {
                fc.system.search_domains.clone()
            } else {
                fc.dhcp.v4.search_domains.clone()
            };
            if let Some(pools) = export.dhcp_v4_pools {
                cfg.dhcp.v4.pools = pools;
            }

            cfg.dhcp.v6.enabled = fc.dhcp.v6.enabled;
            cfg.dhcp.v6.lease_time = fc
                .dhcp
                .v6
                .lease
                .map_or(86400, |d| u32::try_from(d.0).unwrap_or(u32::MAX));
            cfg.dhcp.v6.dns_servers.clone_from(&fc.dhcp.v6.dns);
            cfg.dhcp.v6.search_domains = if fc.dhcp.v6.search_domains.is_empty() {
                fc.system.search_domains.clone()
            } else {
                fc.dhcp.v6.search_domains.clone()
            };
            if let Some(pools) = export.dhcp_v6_pools {
                cfg.dhcp.v6.pools = pools;
            }
        }

        #[cfg(feature = "ra")]
        {
            cfg.ra.enabled = fc.ra.enabled;
            cfg.ra.managed = Some(fc.ra.managed);
            cfg.ra.other_config = Some(fc.ra.other_config);
            if let Some(mi) = fc.ra.max_interval {
                cfg.ra.max_interval = mi.0;
            }
            if let Some(lt) = fc.ra.lifetime {
                cfg.ra.lifetime = Some(lt.0);
            }
            if let Some(mtu) = fc.ra.mtu {
                cfg.ra.mtu = Some(u32::from(mtu));
            }
            if let Some(prefixes) = export.ra_prefixes {
                cfg.ra.prefixes = prefixes;
            }
            if let Some(rdnss) = export.ra_rdnss {
                cfg.ra.rdnss = rdnss;
            }
            if let Some(dnssl) = export.ra_dnssl {
                cfg.ra.dnssl = dnssl;
            }
        }

        #[cfg(feature = "dns")]
        {
            cfg.dns.enabled = fc.dns.enabled;
            if let Some(ref l) = fc.dns.listen
                && let Ok(listen) = l.parse()
            {
                cfg.dns.listen = listen;
            }
            cfg.dns.adblock_enabled = fc.adblock.enabled;
        }

        #[cfg(feature = "pppoe")]
        {
            cfg.pppoe.enabled = fc.pppoe.enabled;
            if let Some(ref w) = fc.pppoe.wan_iface {
                cfg.pppoe.wan_iface.clone_from(w);
            }
            if let Some(ref u) = fc.pppoe.username {
                cfg.pppoe.username.clone_from(u);
            }
            if let Some(ref p) = fc.pppoe.password {
                cfg.pppoe.password.clone_from(p);
            }
            if let Some(ref s) = fc.pppoe.service_name {
                cfg.pppoe.service_name = Some(s.clone());
            }
            if let Some(m) = fc.pppoe.mru {
                cfg.pppoe.mru = m;
            }
        }

        #[cfg(feature = "nft")]
        if let Some(fw) = export.firewall_config {
            cfg.firewall = *fw;
        }

        #[cfg(feature = "traffic")]
        if let Some(tr) = export.traffic_config {
            cfg.traffic = *tr;
        }

        cfg
    }
}

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

    match lanforge_api::config_file::ConfigFile::parse(&content) {
        Ok(file_cfg) => {
            info!("Config: Loaded from '{path}' using named-section schema");
            TomlConfig::from(&file_cfg)
        }
        Err(e) => {
            warn!("[config] Invalid configuration '{path}': {e}; using defaults");
            TomlConfig::default()
        }
    }
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
        assert_eq!(default_cfg.dns.listen.to_string(), "[::]:53");
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
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../contrib/lanforge.toml"
        );
        let content = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read contrib/lanforge.toml at {path}: {e}"));
        let cfg = load_toml(path);

        assert_eq!(cfg.system.iface, "end0");
        assert_eq!(cfg.system.target_prefix, "");
        #[cfg(feature = "http")]
        assert_eq!(cfg.http.listen.port(), 8088);
        assert!(!cfg.database.config_path.contains("sqlite"));

        let file_cfg = lanforge_api::config_file::ConfigFile::parse(&content)
            .unwrap_or_else(|e| panic!("ConfigFile::parse failed on contrib/lanforge.toml: {e}"));
        assert_eq!(file_cfg.system.iface, "end0");
        assert!(file_cfg.system.ula_prefix.is_none());
        assert!(file_cfg.ra.prefixes.is_empty());
        assert!(file_cfg.dhcp.v4.pools.contains_key("lan"));
        assert!(file_cfg.hosts.contains_key("nas"));
    }

    /// A `[dhcp.v6]` section without `iface` must leave it empty so `to_dhcpv6_config` inherits
    /// `system.iface` (it used to default to "end0" and serve the wrong interface).
    #[cfg(feature = "dhcp")]
    #[test]
    fn test_dhcpv6_iface_defaults_to_empty_for_inheritance() {
        let cfg: TomlConfig =
            toml::from_str("[system]\niface = \"lan0\"\n\n[dhcp.v6]\nenabled = true\n")
                .expect("minimal config parses");
        assert_eq!(cfg.dhcp.v6.iface, "");
        assert_eq!(cfg.dhcp.v4.iface, "");
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
        assert!(!cfg.database.config_path.contains("sqlite"));
    }

    fn load_section<T: serde::de::DeserializeOwned + Default>(v: &toml::Value, key: &str) -> T {
        v.get(key).map_or_else(T::default, |sec_val| {
            T::deserialize(sec_val.clone()).unwrap_or_default()
        })
    }
}
