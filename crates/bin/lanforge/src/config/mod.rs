//! lanforge configuration — Unified management of CLI, TOML, and Environment.
//!
//! The configuration system uses three layers in order of precedence:
//! 1. **Default**: Fixed values in code (fail-safe).
//! 2. **TOML**: Main source located at `/etc/lanforge/lanforge.toml`.
//! 3. **CLI/Env**: Manual overrides passed via command line or `LANFORGE_*` variables.
//!
//! ## Configuration Flow
//!
//! ```text
//!    [ CliArgs ]       [ TomlConfig ]      [ Default ]
//!         │                  │                  │
//!         ▼                  ▼                  ▼
//!    ┌──────────────────────────────────────────────┐
//!    │            Merge (Config::load())            │
//!    └──────────────────┬───────────────────────────┘
//!                       │
//!         ┌─────────────┼─────────────┐
//!         │             │             │
//!         ▼             ▼             ▼
//!    [ RaConfig ] [ DhcpConfig ] [ DnsConfig ] ...
//!         │             │             │
//!    (Services started with specialized config)
//! ```

pub mod args;
pub mod toml;

pub use args::CliArgs;
use lanforge_db::config::DatabaseConfig;
use lanforge_dhcp::v4::config::Dhcpv4Config;
use lanforge_dhcp::v6::config::Dhcpv6Config;
use lanforge_discovery::{mdns::MdnsConfig, ndp::config::MonitorConfig};
use lanforge_dns::config::DnsConfig;
use lanforge_http::config::HttpConfig;
use lanforge_ra::ra::{DnsslConfig, PrefixConfig, PrefixSource, RaConfig, RaServiceConfig};
use lanforge_tftp::config::TftpConfig;
use lanforge_types::device::Ipv6AddrOrSuffix;
use lanforge_types::network::dns::adblock::BlockingMode;
use lanforge_types::network::dns::upstream::UpstreamEntry;
use lanforge_types::system::SystemStatus;
use lanforge_uds::config::ApiConfig;
pub use toml::{StaticDeviceCfg, load_devices_only, load_toml};

use clap::Parser;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::config::toml::SystemCfg;

// ---------------------------------------------------------------------------
// Config unificada (resultado do merge TOML + CLI overrides)
// ---------------------------------------------------------------------------

/// Consolidated and final system configuration.
///
/// Created via `Config::load()`, this struct contains all parameters
/// needed to initialize the lanforge subsystems.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    pub system: SystemCfg,
    pub database: DatabaseConfig,

    // RA
    pub ra_enabled: bool,
    pub ra_toml: RaServiceConfig,

    // DHCPv4
    pub dhcpv4_enabled: bool,
    pub dhcpv4_toml: Dhcpv4Config,

    // DHCPv6
    pub dhcpv6_enabled: bool,
    pub dhcpv6_toml: Dhcpv6Config,

    // DNS
    pub dns_enabled: bool,
    pub dns_toml: DnsConfig,
    pub search_domains: Vec<String>,

    // Monitor & mDNS
    pub monitor_toml: MonitorConfig,
    pub mdns_toml: MdnsConfig,

    // API, HTTP & TFTP
    pub api_toml: ApiConfig,
    pub http_toml: HttpConfig,
    pub tftp_toml: TftpConfig,

    // static devices
    pub devices: Vec<StaticDeviceCfg>,
    pub devices_file: Option<String>,

    pub config_path: String,
}

impl Config {
    /// Load config: parse CLI args, read TOML, merge with CLI overrides.
    #[must_use]
    pub fn load() -> Self {
        let cli = CliArgs::parse();

        let mut toml_cfg = load_toml(&cli.config);
        Self::load_modular_configs(&cli.config, &mut toml_cfg);

        let search_domains = Self::resolve_search_domains(&toml_cfg);

        Self::apply_cli_overrides(toml_cfg, &cli, search_domains)
    }

    fn load_modular_configs(config_path: &str, toml_cfg: &mut toml::TomlConfig) {
        let config_dir = Path::new(config_path)
            .parent()
            .unwrap_or_else(|| Path::new("/etc/lanforge"));

        let service_files = [
            ("database.toml", "database"),
            ("ra.toml", "ra"),
            ("dhcp.toml", "dhcp"),
            ("dns.toml", "dns"),
            ("monitor.toml", "monitor"),
            ("mdns.toml", "mdns"),
            ("api.toml", "api"),
            ("http.toml", "http"),
            ("tftp.toml", "tftp"),
        ];

        for (filename, _) in service_files {
            let path = config_dir.join(filename);
            if path.exists() {
                let extra = load_toml(path.to_str().unwrap());
                match filename {
                    "database.toml" => toml_cfg.database = extra.database,
                    "ra.toml" => toml_cfg.ra = extra.ra,
                    "dhcp.toml" => toml_cfg.dhcp = extra.dhcp,
                    "dns.toml" => toml_cfg.dns = extra.dns,
                    "monitor.toml" => toml_cfg.monitor = extra.monitor,
                    "mdns.toml" => toml_cfg.mdns = extra.mdns,
                    "api.toml" => toml_cfg.api = extra.api,
                    "http.toml" => toml_cfg.http = extra.http,
                    "tftp.toml" => toml_cfg.tftp = extra.tftp,
                    _ => {}
                }
            }
        }
    }

    fn resolve_search_domains(toml_cfg: &toml::TomlConfig) -> Vec<String> {
        let mut domains = Vec::new();
        for dom in &toml_cfg.system.search_domains {
            if !domains.contains(dom) {
                domains.push(dom.clone());
            }
        }
        for dom in &toml_cfg.dns.search_domains {
            if !domains.contains(dom) {
                domains.push(dom.clone());
            }
        }
        if let Some(ref d) = toml_cfg.dhcp.v4.domain_name
            && !domains.contains(d)
        {
            domains.push(d.clone());
        }
        if domains.is_empty() {
            domains.push("lan".to_string());
        }
        domains
    }

    fn apply_cli_overrides(
        toml_cfg: toml::TomlConfig,
        cli: &CliArgs,
        search_domains: Vec<String>,
    ) -> Self {
        Self {
            system: {
                let mut s = toml_cfg.system;
                if let Some(ref iface) = cli.iface_lan {
                    s.iface.clone_from(iface);
                }
                s
            },
            database: {
                let mut db = toml_cfg.database;
                if let Some(ref url) = cli.db_url {
                    db.url.clone_from(url);
                }
                db
            },
            ra_enabled: cli.ra_enabled.unwrap_or(toml_cfg.ra.enabled),
            ra_toml: Self::merge_ra_overrides(toml_cfg.ra, cli),
            dhcpv4_enabled: cli.dhcpv4_enabled.unwrap_or(toml_cfg.dhcp.v4.enabled),
            dhcpv4_toml: Self::merge_dhcpv4_overrides(toml_cfg.dhcp.v4, cli),
            dhcpv6_enabled: cli.dhcpv6_enabled.unwrap_or(toml_cfg.dhcp.v6.enabled),
            dhcpv6_toml: toml_cfg.dhcp.v6,
            dns_enabled: cli.dns_enabled.unwrap_or(toml_cfg.dns.enabled),
            dns_toml: Self::merge_dns_overrides(toml_cfg.dns, cli),
            search_domains,
            monitor_toml: toml_cfg.monitor,
            mdns_toml: toml_cfg.mdns,
            api_toml: toml_cfg.api,
            http_toml: toml_cfg.http,
            tftp_toml: toml_cfg.tftp,
            devices: toml_cfg.devices,
            devices_file: cli.devices_file.clone(),
            config_path: cli.config.clone(),
        }
    }

    /// Returns the path to the dedicated API password hash file.
    #[must_use]
    pub fn get_password_hash_path(&self) -> PathBuf {
        Path::new(&self.config_path)
            .parent()
            .unwrap_or_else(|| Path::new("/etc/lanforge"))
            .join("api_password.hash")
    }

    /// Builds an `RaConfig` from the merged configuration.
    #[must_use]
    pub fn to_ra_config(&self) -> RaConfig {
        let mut cfg = self.ra_toml.to_ra_config(self.system.iface.clone());

        // Intelligent Defaults for RA flags:
        // If managed/other are not explicitly configured, derive from DHCPv6 presence
        let has_v6_pools = !self.dhcpv6_toml.pools.is_empty();

        cfg.managed = self.ra_toml.managed.unwrap_or(has_v6_pools);
        cfg.other_config = self.ra_toml.other_config.unwrap_or(has_v6_pools);

        // Ensure at least one prefix exists if none configured
        if cfg.prefixes.is_empty() {
            cfg.prefixes.push(PrefixConfig::gua_dynamic());
        }

        // Add default search domains if none in RA config
        if cfg.dnssl.is_empty() && !self.search_domains.is_empty() {
            cfg.dnssl.push(DnsslConfig {
                domains: self.search_domains.clone(),
                lifetime: None,
            });
        }

        cfg
    }

    /// Builds a `Dhcpv4Config` from the merged configuration.
    #[must_use]
    pub fn to_dhcpv4_config(&self) -> Dhcpv4Config {
        let mut cfg = self.dhcpv4_toml.clone();

        // Injected fields
        cfg.enabled = self.dhcpv4_enabled;
        cfg.iface.clone_from(&self.system.iface);
        cfg.server_id = cfg.router; // Use router IP as server ID by default

        // Option 15 & 119
        if cfg.domain_name.is_none() {
            cfg.domain_name = self.search_domains.first().cloned();
        }
        cfg.search_domains.clone_from(&self.search_domains);

        cfg
    }

    /// Builds a `Dhcpv6Config` from the merged configuration.
    #[must_use]
    pub fn to_dhcpv6_config(&self) -> Dhcpv6Config {
        let mut cfg = self.dhcpv6_toml.clone();

        // Injected fields
        cfg.enabled = self.dhcpv6_enabled;
        cfg.iface.clone_from(&self.system.iface);

        // Prefix detection
        if let Some(p) = self.ra_toml.prefixes.iter().find(|p| {
            p.source == PrefixSource::AutoGua
                || p.source == PrefixSource::Static
                || p.source == PrefixSource::Ula
        }) {
            if let Some(addr) = p.resolved_address() {
                cfg.ula_prefix = Some(addr);
            }
            cfg.ula_prefix_len = p.prefix_len;
        } else {
            cfg.ula_prefix_len = 64;
        }

        // DNS Servers
        if cfg.dns_servers.is_empty() {
            cfg.dns_servers = self.dns_toml.upstreams.first().map_or_else(
                || {
                    cfg.ula_prefix
                        .map(|ip| {
                            let mut octets = ip.octets();
                            if octets[8..16].iter().all(|&b| b == 0) {
                                octets[15] = 1;
                            }
                            vec![std::net::Ipv6Addr::from(octets)]
                        })
                        .unwrap_or_default()
                },
                |u| match u.target.addr {
                    SocketAddr::V6(v6) => vec![*v6.ip()],
                    SocketAddr::V4(_) => vec![],
                },
            );
        }

        if cfg.search_domains.is_empty() {
            cfg.search_domains.clone_from(&self.search_domains);
        }

        cfg
    }

    /// Builds a `DnsConfig` from the merged configuration.
    #[must_use]
    pub fn to_dns_config(&self) -> DnsConfig {
        let mut cfg = self.dns_toml.clone();

        // Overrides
        cfg.enabled = self.dns_enabled;

        // TLS Inheritance
        if cfg.tls_cert.is_none() {
            cfg.tls_cert.clone_from(&self.system.tls_cert);
        }
        if cfg.tls_key.is_none() {
            cfg.tls_key.clone_from(&self.system.tls_key);
        }

        // Search labels
        cfg.multi_search_labels = self
            .search_domains
            .iter()
            .map(|d| d.split('.').map(|s| s.as_bytes().to_vec()).collect())
            .collect();

        // Prefix detection (if not explicitly set in DNS config)
        if cfg.ula_prefix.is_none() {
            cfg.ula_prefix = self
                .ra_toml
                .prefixes
                .iter()
                .find_map(PrefixConfig::resolved_address);
        }

        cfg
    }

    /// Builds an `ApiConfig` for the control service.
    #[must_use]
    pub fn to_api_config(&self) -> ApiConfig {
        self.api_toml.clone()
    }

    /// Builds an `HttpConfig` for the HTTP service.
    #[must_use]
    pub fn to_http_config(&self) -> HttpConfig {
        let mut cfg = self.http_toml.clone();

        // Resolve password hash from dedicated file, falling back to TOML
        cfg.auth_password_hash = std::fs::read_to_string(self.get_password_hash_path())
            .map(|s| s.trim().to_string())
            .ok()
            .or_else(|| self.http_toml.auth_password_hash.clone());

        // Inherit TLS from system if not set in HTTP
        if cfg.tls_cert.is_none() {
            cfg.tls_cert.clone_from(&self.system.tls_cert);
        }
        if cfg.tls_key.is_none() {
            cfg.tls_key.clone_from(&self.system.tls_key);
        }

        if cfg.boot_dir.is_none() {
            cfg.boot_dir = Some(self.tftp_toml.root_dir.to_string_lossy().to_string());
        }

        cfg
    }

    /// Builds a `SystemStatus` snapshot from the current configuration.
    #[must_use]
    pub fn to_system_status(&self) -> SystemStatus {
        SystemStatus {
            db_path: if self.database.url.starts_with("sqlite://") {
                self.database
                    .url
                    .strip_prefix("sqlite://")
                    .unwrap_or(&self.database.url)
                    .to_string()
            } else {
                self.database.url.clone()
            },
            log_db_path: if self.database.log_url.starts_with("sqlite://") {
                self.database
                    .log_url
                    .strip_prefix("sqlite://")
                    .unwrap_or(&self.database.log_url)
                    .to_string()
            } else {
                self.database.log_url.clone()
            },
            lan_iface: self.system.iface.clone(),
            ula_prefix: if self.system.target_prefix.starts_with("fe80") {
                None
            } else {
                self.system
                    .target_prefix
                    .parse::<std::net::Ipv6Addr>()
                    .ok()
                    .map(lanforge_types::network::Ipv6Prefix::from_addr)
            },
            ra_enabled: self.ra_enabled,
            dhcp_v4_enabled: self.dhcpv4_enabled,
            dhcp_v4_range_size: self
                .dhcpv4_toml
                .pools
                .iter()
                .map(|p| {
                    let start = u32::from(p.range_start);
                    let end = u32::from(p.range_end);
                    end.saturating_sub(start).saturating_add(1)
                })
                .sum(),
            dhcp_v6_enabled: self.dhcpv6_enabled,
            dhcp_v6_pool_size: self
                .dhcpv6_toml
                .pools
                .iter()
                .map(|p| match (&p.range_start, &p.range_end) {
                    (Some(Ipv6AddrOrSuffix::Full(s)), Some(Ipv6AddrOrSuffix::Full(e))) => {
                        let start = u128::from_be_bytes(s.octets());
                        let end = u128::from_be_bytes(e.octets());
                        u64::try_from(end.saturating_sub(start).saturating_add(1)).ok()
                    }
                    _ => None,
                })
                .sum(),
            dns_enabled: self.dns_enabled,
            dns_upstream: self.dns_toml.upstreams.first().map(|u| u.target.clone()),
            dns_port: self.dns_toml.listen.port(),
            boot_dir: Some(self.tftp_toml.root_dir.to_string_lossy().to_string()),
            http_enabled: self.http_toml.enabled,
        }
    }

    const fn merge_ra_overrides(mut r: RaServiceConfig, cli: &CliArgs) -> RaServiceConfig {
        if let Some(managed) = cli.ra_managed {
            r.managed = Some(managed);
        }
        if let Some(other) = cli.ra_other_config {
            r.other_config = Some(other);
        }
        if let Some(max_interval) = cli.ra_max_interval {
            r.max_interval = max_interval;
        }
        r
    }

    const fn merge_dhcpv4_overrides(mut d: Dhcpv4Config, cli: &CliArgs) -> Dhcpv4Config {
        if let Some(start) = cli.dhcpv4_range_start {
            d.range_start = Some(start);
        }
        if let Some(end) = cli.dhcpv4_range_end {
            d.range_end = Some(end);
        }
        if let Some(lt) = cli.dhcpv4_lease_time {
            d.lease_time = lt;
        }
        d
    }

    fn merge_dns_overrides(mut d: DnsConfig, cli: &CliArgs) -> DnsConfig {
        if let Some(listen) = &cli.dns_listen
            && let Ok(addr) = listen.parse()
        {
            d.listen = addr;
        }
        if let Some(upstream) = &cli.dns_upstream
            && let Ok(target) = upstream.parse()
        {
            d.upstreams = vec![UpstreamEntry { target }];
        }
        if let Some(port) = cli.dns_port {
            d.listen.set_port(port);
        }
        if let Some(dot_listen) = &cli.dns_dot_listen
            && let Ok(addr) = dot_listen.parse()
        {
            d.dot_listen = Some(addr);
        }
        if let Some(cert) = &cli.dns_tls_cert {
            d.tls_cert = Some(cert.clone());
        }
        if let Some(key) = &cli.dns_tls_key {
            d.tls_key = Some(key.clone());
        }
        #[cfg(feature = "adblock")]
        if let Some(adblock) = cli.dns_adblock_enabled {
            d.adblock_enabled = adblock;
        }
        if let Some(mode_str) = &cli.dns_blocking_mode
            && let Ok(mode) = mode_str.parse::<BlockingMode>()
        {
            d.blocking_mode = mode;
        }
        if let Some(ttl) = cli.dns_ttl {
            d.ttl = ttl;
        }
        if let Some(threshold) = cli.dns_last_seen {
            d.last_seen_threshold_days = threshold;
        }
        d
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            system: SystemCfg::default(),
            database: DatabaseConfig::default(),
            ra_enabled: true,
            ra_toml: RaServiceConfig::default(),
            dhcpv4_enabled: true,
            dhcpv4_toml: Dhcpv4Config::default(),
            dhcpv6_enabled: true,
            dhcpv6_toml: Dhcpv6Config::default(),
            dns_enabled: true,
            dns_toml: DnsConfig::default(),
            search_domains: vec!["lan".to_string()],
            monitor_toml: MonitorConfig::default(),
            mdns_toml: MdnsConfig::default(),
            api_toml: ApiConfig::default(),
            http_toml: HttpConfig::default(),
            tftp_toml: TftpConfig::default(),
            devices: Vec::new(),
            devices_file: None,
            config_path: "/etc/lanforge/lanforge.toml".to_string(),
        }
    }
}
