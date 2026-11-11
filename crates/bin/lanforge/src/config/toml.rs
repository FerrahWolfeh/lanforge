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
#[cfg(feature = "tftp")]
use lanforge_tftp::config::TftpConfig;
#[cfg(feature = "tftp")]
use lanforge_types::network::dhcp::TftpOptions;
#[cfg(feature = "ra")]
use lanforge_types::network::ra::RaServerConfig;
#[cfg(feature = "uds")]
use lanforge_uds::config::ApiConfig;
#[cfg(test)]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use std::fs;
use std::path::Path;
#[cfg(feature = "tftp")]
use std::path::PathBuf;
use tracing::{info, warn};

#[cfg(feature = "dhcp")]
use lanforge_api::config_file::DhcpSettings;
#[cfg(feature = "dns")]
use lanforge_api::config_file::{AdblockSettings, DnsSettings};
use lanforge_api::config_file::{ConfigFile, Section};
use lanforge_types::device::StaticHost;
#[cfg(feature = "dns")]
use lanforge_types::network::dns::adblock::AdblockPolicy;

/// Root structure of the TOML file.
#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(default)]
pub struct TomlConfig {
    pub system: SystemCfg,
    pub database: DatabaseConfig,
    #[cfg(feature = "ra")]
    pub ra: RaServerConfig,
    #[cfg(feature = "dhcp")]
    pub dhcp: DhcpCfg,
    #[cfg(feature = "dns")]
    pub dns: DnsConfig,
    /// `[dns]` as the settings the daemon runs (its only source).
    #[cfg(feature = "dns")]
    #[serde(skip)]
    pub dns_settings: DnsSettings,
    /// `[adblock]` as the settings the daemon runs (its only source).
    #[cfg(feature = "dns")]
    #[serde(skip)]
    pub adblock: AdblockSettings,
    /// The text of the global rules file `[adblock] rules` names.
    #[cfg(feature = "dns")]
    #[serde(skip)]
    pub adblock_rules: String,
    /// The adblock groups and `bypass`, with the groups' rules files read.
    #[cfg(feature = "dns")]
    #[serde(skip)]
    pub adblock_policy: AdblockPolicy,
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
    /// Problems found while loading the file (set-aside sections), shown to the admin.
    #[serde(skip)]
    pub config_issues: Vec<String>,
    /// `[hosts]`, when the file was read and the section not set aside. `None` leaves the
    /// device table's static hosts as they are: an unread `[hosts]` is not an empty one.
    #[serde(skip)]
    pub static_hosts: Option<Vec<StaticHost>>,
    /// `[dhcp]` was in the file but set aside (unreadable): what runs are defaults, which must
    /// never be written over it.
    #[serde(skip)]
    pub dhcp_set_aside: bool,
}

#[cfg(feature = "dhcp")]
#[derive(Deserialize, Serialize, Debug, Default, Clone)]
#[serde(default)]
pub struct DhcpCfg {
    pub v4: Dhcpv4Config,
    pub v6: Dhcpv6Config,
    /// `[dhcp]` + `[tftp]` as the options and pools the daemon runs (their only source).
    #[serde(skip)]
    pub settings: DhcpSettings,
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
impl From<&ConfigFile> for TomlConfig {
    fn from(fc: &ConfigFile) -> Self {
        #[allow(unused_mut, reason = "only the compiled-in sections below fill it")]
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
        apply_tftp_options(&mut cfg.tftp, &fc.tftp.to_options());

        #[cfg(feature = "dhcp")]
        {
            // Entries the file gets wrong are left out (reported by `load_toml`).
            let settings = fc.dhcp_settings().0;
            let (v4, v6) = (&settings.options.v4, &settings.options.v6);
            cfg.dhcp.v4.enabled = v4.enabled;
            cfg.dhcp.v4.lease_time = v4.lease_time;
            if let Some(r) = v4.router {
                cfg.dhcp.v4.router = r;
                cfg.dhcp.v4.server_id = r;
            }
            if let Some(m) = v4.subnet_mask {
                cfg.dhcp.v4.subnet_mask = m;
            }
            if !v4.dns_servers.is_empty() {
                cfg.dhcp.v4.dns.clone_from(&v4.dns_servers);
            }
            cfg.dhcp.v4.search_domains = if v4.search_domains.is_empty() {
                fc.system.search_domains.clone()
            } else {
                v4.search_domains.clone()
            };
            cfg.dhcp.v4.pools.clone_from(&settings.v4_pools);

            cfg.dhcp.v6.enabled = v6.enabled;
            cfg.dhcp.v6.lease_time = v6.lease_time;
            cfg.dhcp.v6.dns_servers.clone_from(&v6.dns_servers);
            cfg.dhcp.v6.search_domains = if v6.search_domains.is_empty() {
                fc.system.search_domains.clone()
            } else {
                v6.search_domains.clone()
            };
            cfg.dhcp.v6.pools.clone_from(&settings.v6_pools);
            cfg.dhcp.settings = settings;
        }

        // Entries the file gets wrong are left out (reported by `load_toml`).
        #[cfg(feature = "ra")]
        {
            cfg.ra = fc.ra.to_config().0;
        }

        #[cfg(feature = "dns")]
        {
            // Entries the file gets wrong are left out (reported by `load_toml`).
            let dns = fc.dns.to_config().0;
            cfg.dns.enabled = dns.enabled;
            if let Some(ref listen) = dns.listen {
                cfg.dns.listen = listen.clone();
            }
            // Upstreams, mode, rewrites and reverse resolvers reach the service through the
            // context (`dns_settings`), never through `DnsConfig`: its upstream list feeds the
            // DHCPv6 DNS fallback and must stay as it was.
            cfg.dns_settings = dns;
            let adblock = fc.adblock.to_config().0;
            cfg.dns.adblock_enabled = adblock.config.enabled;
            cfg.adblock = adblock;
        }

        #[cfg(feature = "pppoe")]
        {
            cfg.pppoe = fc.pppoe.checked().0;
        }

        // Entries the file gets wrong are left out (reported by `load_toml`).
        #[cfg(feature = "nft")]
        {
            cfg.firewall = fc.firewall.to_config().0;
        }

        #[cfg(feature = "traffic")]
        {
            cfg.traffic = fc.traffic.clone();
        }

        cfg
    }
}

/// Sets the TFTP service's start-up config from `[tftp]` (the same values the DHCP options carry).
#[cfg(feature = "tftp")]
pub fn apply_tftp_options(cfg: &mut TftpConfig, tftp: &TftpOptions) {
    cfg.enabled = tftp.enabled;
    if let Ok(l) = tftp.listen_addr.parse() {
        cfg.listen = l;
    }
    cfg.root_dir = PathBuf::from(&tftp.root_dir);
    cfg.block_size = tftp.block_size;
    cfg.timeout = tftp.timeout;
    cfg.max_retries = tftp.max_retries;
}

use lanforge_api::config_file::set_aside_messages;
pub use lanforge_api::config_file::{log_issues, set_aside_issues};

pub fn load_toml(path: &str) -> TomlConfig {
    if !Path::new(path).exists() {
        if path != "/etc/lanforge/lanforge.toml" {
            // User explicitly specified a path that doesn't exist
            warn!("[config] Config file '{path}' not found, using defaults");
        }
        return TomlConfig::default();
    }

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            warn!("[config] Failed to read '{path}': {e} — using defaults");
            return TomlConfig::default();
        }
    };

    match ConfigFile::parse_lenient(&content) {
        Ok((file_cfg, set_aside)) => {
            info!("Config: Loaded from '{path}' using named-section schema");
            // Logged once by the bootstrap, after the start-up configs are derived.
            let mut cfg = TomlConfig::from(&file_cfg);
            cfg.config_issues = set_aside_messages(&set_aside);
            cfg.dhcp_set_aside = set_aside.iter().any(|(sec, _)| *sec == Section::Dhcp);
            #[cfg(feature = "nft")]
            cfg.config_issues.extend(file_cfg.firewall.to_config().1);
            #[cfg(feature = "dhcp")]
            cfg.config_issues.extend(file_cfg.dhcp.to_config().1);
            #[cfg(feature = "ra")]
            cfg.config_issues.extend(file_cfg.ra.to_config().1);
            #[cfg(feature = "pppoe")]
            cfg.config_issues.extend(file_cfg.pppoe.checked().1);
            #[cfg(feature = "dns")]
            {
                cfg.config_issues.extend(file_cfg.dns.to_config().1);
                cfg.config_issues.extend(file_cfg.adblock.to_config().1);
                let (rules, issues) = cfg.adblock.load_rules(Path::new(path));
                cfg.adblock_rules = rules.unwrap_or_default();
                cfg.config_issues.extend(issues);
                let (policy, issues) = cfg
                    .adblock
                    .policy(Some(Path::new(path)), &AdblockPolicy::default());
                cfg.adblock_policy = policy;
                cfg.config_issues.extend(issues);
            }
            if !set_aside.iter().any(|(sec, _)| *sec == Section::Hosts) {
                let (hosts, issues) = file_cfg.static_hosts();
                cfg.config_issues.extend(issues);
                cfg.static_hosts = Some(hosts);
            }
            cfg
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
    use std::env;
    use std::process::Command;
    #[cfg(feature = "pppoe")]
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let default_cfg = TomlConfig::default();
        assert_eq!(default_cfg.system.iface, "");
        #[cfg(feature = "ra")]
        assert_eq!(default_cfg.ra, RaServerConfig::default());
        #[cfg(feature = "dns")]
        assert_eq!(default_cfg.dns.listen.to_string(), "[::]:53");
    }

    /// Child half of `missing_file_ignores_foreign_db_env`: runs only in the subprocess that
    /// test spawns with the environment set (tests share one process, and `set_var` is unsafe).
    #[test]
    #[ignore = "spawned by missing_file_ignores_foreign_db_env"]
    fn missing_file_db_paths_child() {
        let cfg = load_toml("/nonexistent/lanforge-test/lanforge.toml");
        assert_eq!(cfg.database.config_path, "/var/lib/lanforge/config.redb");
        assert_eq!(cfg.database.runtime_path, "/run/lanforge/runtime.redb");
    }

    /// Without a config file the daemon runs on defaults; another app's `DATABASE_URL` (or a
    /// stray legacy variable) must not become lanforge's database: a SQL URL there booted the
    /// daemon into recovery mode, and `--dev` did not switch such a path to memory.
    #[test]
    fn missing_file_ignores_foreign_db_env() {
        let out = Command::new(env::current_exe().expect("test binary path"))
            .args([
                "--exact",
                "config::toml::tests::missing_file_db_paths_child",
            ])
            .args(["--ignored", "--test-threads=1"])
            .env("DATABASE_URL", "postgres://other-app/db")
            .env("LANFORGE_DB_PATH", "/tmp/legacy-config.redb")
            .env("LANFORGE_LOG_DB_URL", "/tmp/legacy-runtime.redb")
            .env_remove("LANFORGE_CONFIG_DB_PATH")
            .env_remove("LANFORGE_RUNTIME_DB_PATH")
            .output()
            .expect("spawn the test binary");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "child failed:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// At boot a hand-edited `[pppoe]` value the client cannot run on (MRU 0) is reported and
    /// replaced by the default; the other keys still apply.
    #[cfg(feature = "pppoe")]
    #[test]
    fn boot_replaces_pppoe_values_the_client_cannot_run_on() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("lanforge.toml");
        fs::write(&path, "[pppoe]\nusername = \"u\"\nmru = 0\n").expect("write config");
        let cfg = load_toml(path.to_str().expect("utf-8 path"));
        assert_eq!(cfg.pppoe.username, "u");
        assert_eq!(cfg.pppoe.mru, PppoeConfig::default().mru);
        assert!(
            cfg.config_issues
                .iter()
                .any(|i| i.starts_with("[pppoe] mru = 0")),
            "{:?}",
            cfg.config_issues
        );
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
        let ra: RaServerConfig = load_section(&value, "ra");

        assert_eq!(system.iface, "eth42");
        #[cfg(feature = "ra")]
        assert_eq!(ra, RaServerConfig::default()); // Should be default
    }

    #[test]
    fn test_contrib_example_config_parses_cleanly() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../contrib/lanforge.toml"
        );
        let content = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("Failed to read contrib/lanforge.toml at {path}: {e}"));
        let cfg = load_toml(path);

        assert_eq!(cfg.system.iface, "end0");
        assert_eq!(cfg.system.target_prefix, "");
        #[cfg(feature = "http")]
        assert_eq!(cfg.http.listen.port(), 8088);
        assert!(!cfg.database.config_path.contains("sqlite"));

        let file_cfg = ConfigFile::parse(&content)
            .unwrap_or_else(|e| panic!("ConfigFile::parse failed on contrib/lanforge.toml: {e}"));
        assert_eq!(file_cfg.system.iface, "end0");
        assert!(file_cfg.system.ula_prefix.is_none());
        assert_eq!(file_cfg.ra.prefixes, Vec::new());
        assert!(file_cfg.dhcp.v4.pools.iter().any(|(name, _)| name == "lan"));
        assert!(file_cfg.hosts.iter().any(|(name, _)| name == "nas"));
        #[cfg(feature = "dns")]
        {
            assert_eq!(file_cfg.adblock.to_config().1, Vec::<String>::new());
            assert_eq!(cfg.adblock.lists, ["oisd"]);
            assert!(cfg.adblock_rules.contains("||telemetry.microsoft.com^"));
        }
        assert_eq!(cfg.config_issues, Vec::<String>::new());
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

    /// Prefix deprecation (D-16) is on by default, with or without an `[ra]` section.
    #[cfg(feature = "ra")]
    #[test]
    fn test_ra_deprecate_on_renumber_defaults_on() {
        let without: TomlConfig = toml::from_str("[system]\niface = \"lan0\"\n").expect("parses");
        assert!(without.ra.deprecate_on_renumber);
        let with: TomlConfig =
            toml::from_str("[system]\niface = \"lan0\"\n\n[ra]\nenabled = true\n").expect("parses");
        assert!(with.ra.deprecate_on_renumber);
    }

    /// An unreadable `[hosts]` is set aside as "not read", not as "no hosts": applying an
    /// empty list would make every static host a discovered device.
    #[test]
    fn a_broken_hosts_section_is_not_an_empty_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lanforge.toml");
        fs::write(&path, "[hosts.archie]\nmac = 7\n").unwrap();
        let cfg = load_toml(path.to_str().unwrap());
        assert_eq!(cfg.static_hosts, None);
        assert!(
            cfg.config_issues[0].starts_with("[hosts]"),
            "{:?}",
            cfg.config_issues
        );

        fs::write(&path, "[hosts.archie]\nmac = \"bc:fc:e7:8a:a9:73\"\n").unwrap();
        assert_eq!(
            load_toml(path.to_str().unwrap())
                .static_hosts
                .map(|h| h.len()),
            Some(1)
        );
        assert_eq!(
            TomlConfig::default().static_hosts,
            None,
            "no file: not read"
        );
    }

    /// A config file in `docs/config/` as the daemon reads it: the strict file form takes every
    /// section (nothing set aside) and no value in it is an issue.
    fn docs_config(name: &str) -> ConfigFile {
        let path = format!("{}/../../../docs/config/{name}", env!("CARGO_MANIFEST_DIR"));
        let content =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("docs/config/{name}: {e}"));
        let file =
            ConfigFile::parse(&content).unwrap_or_else(|e| panic!("docs/config/{name}: {e}"));
        let mut issues = Vec::new();
        issues.extend(file.firewall.to_config().1);
        issues.extend(file.dhcp.to_config().1);
        issues.extend(file.ra.to_config().1);
        issues.extend(file.pppoe.checked().1);
        issues.extend(file.dns.to_config().1);
        issues.extend(file.static_hosts().1);
        issues.extend(file.adblock.to_config().1);
        assert_eq!(issues, Vec::<String>::new(), "docs/config/{name}");
        file
    }

    /// Every snippet in `docs/config/` is valid on its own (they are copied into a config).
    #[test]
    fn test_docs_config_snippets_parse_cleanly() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../docs/config");
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| {
                let path = e.ok()?.path();
                let toml = path
                    .extension()
                    .is_some_and(|x| x.eq_ignore_ascii_case("toml"));
                toml.then(|| path.file_name()?.to_str().map(String::from))?
            })
            .collect();
        names.sort();
        assert!(names.len() > 1, "{names:?}");
        for name in names {
            docs_config(&name);
        }
    }

    /// The reference config: every section, as the daemon loads it.
    #[test]
    fn test_docs_example_config_parses_cleanly() {
        let file = docs_config("lanforge.example.toml");
        let (adblock, _) = file.adblock.to_config();
        assert_eq!(adblock.groups.len(), 2);
        assert_eq!(adblock.bypass.len(), 1);

        // As the daemon loads it.
        let cfg = TomlConfig::from(&file);
        assert_eq!(cfg.system.iface, "end0");
        #[cfg(feature = "http")]
        assert_eq!(cfg.http.listen.port(), 8088);
    }

    fn load_section<T: DeserializeOwned + Default>(v: &toml::Value, key: &str) -> T {
        v.get(key).map_or_else(T::default, |sec_val| {
            T::deserialize(sec_val.clone()).unwrap_or_default()
        })
    }
}
