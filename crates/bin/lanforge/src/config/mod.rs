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
use lanforge_ra::{RaConfig, RaServiceConfig};
#[cfg(feature = "tftp")]
use lanforge_tftp::config::TftpConfig;
use lanforge_types::device::Ipv6AddrOrSuffix;
#[cfg(feature = "dns")]
use lanforge_types::network::dns::adblock::BlockingMode;
#[cfg(feature = "dns")]
use lanforge_types::network::dns::upstream::UpstreamEntry;
#[cfg(feature = "ra")]
use lanforge_types::network::ra::{DnsslConfig, PrefixSource, RAPrefix};
use lanforge_types::system::SystemStatus;
#[cfg(feature = "uds")]
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
    #[cfg(feature = "ra")]
    pub ra_enabled: bool,
    #[cfg(feature = "ra")]
    pub ra_toml: RaServiceConfig,

    // DHCPv4
    #[cfg(feature = "dhcp")]
    pub dhcpv4_enabled: bool,
    #[cfg(feature = "dhcp")]
    pub dhcpv4_toml: Dhcpv4Config,

    // DHCPv6
    #[cfg(feature = "dhcp")]
    pub dhcpv6_enabled: bool,
    #[cfg(feature = "dhcp")]
    pub dhcpv6_toml: Dhcpv6Config,

    // DNS
    #[cfg(feature = "dns")]
    pub dns_enabled: bool,
    #[cfg(feature = "dns")]
    pub dns_toml: DnsConfig,
    pub search_domains: Vec<String>,

    // Monitor & mDNS
    #[cfg(feature = "discovery")]
    pub monitor_toml: MonitorConfig,
    #[cfg(feature = "discovery")]
    pub mdns_toml: MdnsConfig,

    // API, HTTP, TFTP & PPPoE
    #[cfg(feature = "uds")]
    pub api_toml: ApiConfig,
    #[cfg(feature = "http")]
    pub http_toml: HttpConfig,
    #[cfg(feature = "tftp")]
    pub tftp_toml: TftpConfig,
    #[cfg(feature = "pppoe")]
    pub pppoe_enabled: bool,
    #[cfg(feature = "pppoe")]
    pub pppoe_toml: lanforge_pppoe::config::PppoeConfig,

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

        let mut service_files = vec![("database.toml", "database")];
        #[cfg(feature = "ra")]
        service_files.push(("ra.toml", "ra"));
        #[cfg(feature = "dhcp")]
        service_files.push(("dhcp.toml", "dhcp"));
        #[cfg(feature = "dns")]
        service_files.push(("dns.toml", "dns"));
        #[cfg(feature = "discovery")]
        service_files.push(("monitor.toml", "monitor"));
        #[cfg(feature = "discovery")]
        service_files.push(("mdns.toml", "mdns"));
        #[cfg(feature = "uds")]
        service_files.push(("api.toml", "api"));
        #[cfg(feature = "http")]
        service_files.push(("http.toml", "http"));
        #[cfg(feature = "tftp")]
        service_files.push(("tftp.toml", "tftp"));
        #[cfg(feature = "pppoe")]
        service_files.push(("pppoe.toml", "pppoe"));

        for (filename, _) in service_files {
            let path = config_dir.join(filename);
            if path.exists() {
                let extra = load_toml(path.to_str().unwrap());
                match filename {
                    "database.toml" => toml_cfg.database = extra.database,
                    #[cfg(feature = "ra")]
                    "ra.toml" => toml_cfg.ra = extra.ra,
                    #[cfg(feature = "dhcp")]
                    "dhcp.toml" => toml_cfg.dhcp = extra.dhcp,
                    #[cfg(feature = "dns")]
                    "dns.toml" => toml_cfg.dns = extra.dns,
                    #[cfg(feature = "discovery")]
                    "monitor.toml" => toml_cfg.monitor = extra.monitor,
                    #[cfg(feature = "discovery")]
                    "mdns.toml" => toml_cfg.mdns = extra.mdns,
                    #[cfg(feature = "uds")]
                    "api.toml" => toml_cfg.api = extra.api,
                    #[cfg(feature = "http")]
                    "http.toml" => toml_cfg.http = extra.http,
                    #[cfg(feature = "tftp")]
                    "tftp.toml" => toml_cfg.tftp = extra.tftp,
                    #[cfg(feature = "pppoe")]
                    "pppoe.toml" => toml_cfg.pppoe = extra.pppoe,
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
        #[cfg(feature = "dns")]
        for dom in &toml_cfg.dns.search_domains {
            if !domains.contains(dom) {
                domains.push(dom.clone());
            }
        }
        #[cfg(feature = "dhcp")]
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
            #[cfg(feature = "ra")]
            ra_enabled: cli.ra_enabled.unwrap_or(toml_cfg.ra.enabled),
            #[cfg(feature = "ra")]
            ra_toml: Self::merge_ra_overrides(toml_cfg.ra, cli),
            #[cfg(feature = "dhcp")]
            dhcpv4_enabled: cli.dhcpv4_enabled.unwrap_or(toml_cfg.dhcp.v4.enabled),
            #[cfg(feature = "dhcp")]
            dhcpv4_toml: Self::merge_dhcpv4_overrides(toml_cfg.dhcp.v4, cli),
            #[cfg(feature = "dhcp")]
            dhcpv6_enabled: cli.dhcpv6_enabled.unwrap_or(toml_cfg.dhcp.v6.enabled),
            #[cfg(feature = "dhcp")]
            dhcpv6_toml: toml_cfg.dhcp.v6,
            #[cfg(feature = "dns")]
            dns_enabled: cli.dns_enabled.unwrap_or(toml_cfg.dns.enabled),
            #[cfg(feature = "dns")]
            dns_toml: Self::merge_dns_overrides(toml_cfg.dns, cli),
            search_domains,
            #[cfg(feature = "discovery")]
            monitor_toml: toml_cfg.monitor,
            #[cfg(feature = "discovery")]
            mdns_toml: toml_cfg.mdns,
            #[cfg(feature = "uds")]
            api_toml: toml_cfg.api,
            #[cfg(feature = "http")]
            http_toml: toml_cfg.http,
            #[cfg(feature = "tftp")]
            tftp_toml: toml_cfg.tftp,
            #[cfg(feature = "pppoe")]
            pppoe_enabled: toml_cfg.pppoe.enabled,
            #[cfg(feature = "pppoe")]
            pppoe_toml: toml_cfg.pppoe,
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
    #[cfg(feature = "ra")]
    #[must_use]
    pub fn to_ra_config(&self) -> RaConfig {
        let mut cfg = self.ra_toml.to_ra_config(self.system.iface.clone());

        // Intelligent Defaults for RA flags:
        // If managed/other are not explicitly configured, derive from DHCPv6 presence
        let has_v6_pools = {
            #[cfg(feature = "dhcp")]
            {
                !self.dhcpv6_toml.pools.is_empty()
            }
            #[cfg(not(feature = "dhcp"))]
            {
                false
            }
        };

        cfg.managed = self.ra_toml.managed.unwrap_or(has_v6_pools);
        cfg.other_config = self.ra_toml.other_config.unwrap_or(has_v6_pools);

        // Ensure at least one prefix exists if none configured
        if cfg.prefixes.is_empty() {
            cfg.prefixes.push(RAPrefix::gua_dynamic());
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
    #[cfg(feature = "dhcp")]
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
    #[cfg(feature = "dhcp")]
    #[must_use]
    pub fn to_dhcpv6_config(&self) -> Dhcpv6Config {
        let mut cfg = self.dhcpv6_toml.clone();

        // Injected fields
        cfg.enabled = self.dhcpv6_enabled;
        cfg.iface.clone_from(&self.system.iface);

        // Prefix detection
        let mut prefix_detected = None;
        #[cfg(feature = "ra")]
        {
            if let Some(p) = self.ra_toml.prefixes.iter().find(|p| {
                p.source == PrefixSource::AutoGua
                    || p.source == PrefixSource::Static
                    || p.source == PrefixSource::Ula
            }) {
                prefix_detected = Some((p.resolved_address(), p.prefix_len));
            }
        }
        if let Some((addr, len)) = prefix_detected {
            cfg.ula_prefix = addr;
            cfg.ula_prefix_len = len;
        } else {
            cfg.ula_prefix_len = 64;
        }

        // DNS Servers
        if cfg.dns_servers.is_empty() {
            cfg.dns_servers = {
                #[cfg(feature = "dns")]
                let dns_upstream = self.dns_toml.upstreams.first().map(|u| u.target.clone());
                #[cfg(not(feature = "dns"))]
                let dns_upstream = None;

                dns_upstream.map_or_else(
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
                    |u| match u.addr {
                        SocketAddr::V6(v6) => vec![*v6.ip()],
                        SocketAddr::V4(_) => vec![],
                    },
                )
            };
        }

        if cfg.search_domains.is_empty() {
            cfg.search_domains.clone_from(&self.search_domains);
        }

        cfg
    }

    /// Builds a `DnsConfig` from the merged configuration.
    #[cfg(feature = "dns")]
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
            #[cfg(feature = "ra")]
            {
                cfg.ula_prefix = self
                    .ra_toml
                    .prefixes
                    .iter()
                    .find_map(RAPrefix::resolved_address);
            }
        }

        cfg
    }

    /// Builds an `ApiConfig` for the control service.
    #[cfg(feature = "uds")]
    #[must_use]
    pub fn to_api_config(&self) -> ApiConfig {
        self.api_toml.clone()
    }

    /// Builds an `HttpConfig` for the HTTP service.
    #[cfg(feature = "http")]
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
            #[cfg(feature = "tftp")]
            {
                cfg.boot_dir = Some(self.tftp_toml.root_dir.to_string_lossy().to_string());
            }
            #[cfg(not(feature = "tftp"))]
            {
                cfg.boot_dir = Some("/var/lib/tftpboot".to_string());
            }
        }

        cfg
    }

    /// Builds a `SystemStatus` snapshot from the current configuration.
    #[allow(clippy::too_many_lines)]
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
                sanitize_db_url(&self.database.url)
            },
            log_db_path: if self.database.log_url.starts_with("sqlite://") {
                self.database
                    .log_url
                    .strip_prefix("sqlite://")
                    .unwrap_or(&self.database.log_url)
                    .to_string()
            } else {
                sanitize_db_url(&self.database.log_url)
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
            ra_enabled: {
                #[cfg(feature = "ra")]
                {
                    self.ra_enabled
                }
                #[cfg(not(feature = "ra"))]
                {
                    false
                }
            },
            dhcp_v4_enabled: {
                #[cfg(feature = "dhcp")]
                {
                    self.dhcpv4_enabled
                }
                #[cfg(not(feature = "dhcp"))]
                {
                    false
                }
            },
            dhcp_v4_range_size: {
                #[cfg(feature = "dhcp")]
                {
                    self.dhcpv4_toml
                        .pools
                        .iter()
                        .map(|p| {
                            let start = u32::from(p.range_start);
                            let end = u32::from(p.range_end);
                            end.saturating_sub(start).saturating_add(1)
                        })
                        .sum()
                }
                #[cfg(not(feature = "dhcp"))]
                {
                    0
                }
            },
            dhcp_v6_enabled: {
                #[cfg(feature = "dhcp")]
                {
                    self.dhcpv6_enabled
                }
                #[cfg(not(feature = "dhcp"))]
                {
                    false
                }
            },
            dhcp_v6_pool_size: {
                #[cfg(feature = "dhcp")]
                {
                    self.dhcpv6_toml
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
                        .sum()
                }
                #[cfg(not(feature = "dhcp"))]
                {
                    0
                }
            },
            dns_enabled: {
                #[cfg(feature = "dns")]
                {
                    self.dns_enabled
                }
                #[cfg(not(feature = "dns"))]
                {
                    false
                }
            },
            dns_upstream: {
                #[cfg(feature = "dns")]
                {
                    self.dns_toml.upstreams.first().map(|u| u.target.clone())
                }
                #[cfg(not(feature = "dns"))]
                {
                    None
                }
            },
            dns_port: {
                #[cfg(feature = "dns")]
                {
                    self.dns_toml.listen.port()
                }
                #[cfg(not(feature = "dns"))]
                {
                    53
                }
            },
            boot_dir: {
                #[cfg(feature = "tftp")]
                {
                    Some(self.tftp_toml.root_dir.to_string_lossy().to_string())
                }
                #[cfg(not(feature = "tftp"))]
                {
                    None
                }
            },
            http_enabled: {
                #[cfg(feature = "http")]
                {
                    self.http_toml.enabled
                }
                #[cfg(not(feature = "http"))]
                {
                    false
                }
            },
            pppoe_enabled: {
                #[cfg(feature = "pppoe")]
                {
                    self.pppoe_toml.enabled
                }
                #[cfg(not(feature = "pppoe"))]
                {
                    false
                }
            },
        }
    }

    #[cfg(feature = "ra")]
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

    #[cfg(feature = "dhcp")]
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

    #[cfg(feature = "dns")]
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
            #[cfg(feature = "ra")]
            ra_enabled: true,
            #[cfg(feature = "ra")]
            ra_toml: RaServiceConfig::default(),
            #[cfg(feature = "dhcp")]
            dhcpv4_enabled: true,
            #[cfg(feature = "dhcp")]
            dhcpv4_toml: Dhcpv4Config::default(),
            #[cfg(feature = "dhcp")]
            dhcpv6_enabled: true,
            #[cfg(feature = "dhcp")]
            dhcpv6_toml: Dhcpv6Config::default(),
            #[cfg(feature = "dns")]
            dns_enabled: true,
            #[cfg(feature = "dns")]
            dns_toml: DnsConfig::default(),
            search_domains: vec!["lan".to_string()],
            #[cfg(feature = "discovery")]
            monitor_toml: MonitorConfig::default(),
            #[cfg(feature = "discovery")]
            mdns_toml: MdnsConfig::default(),
            #[cfg(feature = "uds")]
            api_toml: ApiConfig::default(),
            #[cfg(feature = "http")]
            http_toml: HttpConfig::default(),
            #[cfg(feature = "tftp")]
            tftp_toml: TftpConfig::default(),
            #[cfg(feature = "pppoe")]
            pppoe_enabled: false,
            #[cfg(feature = "pppoe")]
            pppoe_toml: lanforge_pppoe::config::PppoeConfig::default(),
            devices: Vec::new(),
            devices_file: None,
            config_path: "/etc/lanforge/lanforge.toml".to_string(),
        }
    }
}

/// Masks credentials in a database URL (e.g., `postgres://user:password@host/db` -> `postgres://user:****@host/db`)
#[must_use]
pub fn sanitize_db_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };

    // Split the rest into host-part and path-part (if any / exists)
    let (host_part, path_part) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));

    if let Some((auth, host)) = host_part.split_once('@') {
        let masked_auth = if let Some((user, _pass)) = auth.split_once(':') {
            format!("{user}:****")
        } else {
            auth.to_string()
        };
        if path_part.is_empty() {
            format!("{scheme}://{masked_auth}@{host}")
        } else {
            format!("{scheme}://{masked_auth}@{host}/{path_part}")
        }
    } else {
        url.to_string()
    }
}
