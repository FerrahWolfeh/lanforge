//! Lanforge configuration — Unified management of CLI, TOML, and Environment.
//!
//! The configuration system uses a clean layered pipeline:
//! 1. **Default**: Router-first fail-safe baseline values.
//! 2. **Auto-Detect**: Hardware-aware LAN interface detection & RFC 4193 ULA generation.
//! 3. **TOML**: Declarative files located at `/etc/lanforge/lanforge.toml` and modular configs.
//! 4. **CLI/Env**: Operational overrides passed via command line or environment variables.

pub mod args;
pub mod auto_detect;
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
#[cfg(feature = "ra")]
use lanforge_types::network::ra::{DnsslConfig, PrefixSource, RAPrefix};
use lanforge_types::system::SystemStatus;
#[cfg(feature = "uds")]
use lanforge_uds::config::ApiConfig;
pub use toml::load_toml;

use clap::Parser;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::config::toml::SystemCfg;

/// Consolidated and final system configuration.
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

    pub config_path: String,
}

impl Config {
    /// Load config: parse CLI args, read TOML, run auto-detection, and apply CLI overrides.
    #[must_use]
    pub fn load() -> Self {
        let cli = CliArgs::parse();

        let mut toml_cfg = load_toml(&cli.config);
        Self::load_modular_configs(&cli.config, &mut toml_cfg);

        // 1. Resolve LAN interface with hardware-aware auto-detection
        let wan_iface = {
            #[cfg(feature = "pppoe")]
            {
                Some(toml_cfg.pppoe.wan_iface.as_str())
            }
            #[cfg(not(feature = "pppoe"))]
            {
                None
            }
        };

        let configured_iface = cli
            .iface_lan
            .as_deref()
            .or(Some(toml_cfg.system.iface.as_str()));
        toml_cfg.system.iface = auto_detect::detect_lan_interface(configured_iface, wan_iface);

        // 2. Resolve IPv6 SLAAC target prefix with RFC 4193 ULA generator
        if toml_cfg.system.target_prefix.is_empty()
            || toml_cfg.system.target_prefix == "fd97:f00d:cafe:3731"
        {
            if let Some(ref cli_prefix) = cli.target_prefix {
                toml_cfg.system.target_prefix.clone_from(cli_prefix);
            } else {
                toml_cfg.system.target_prefix =
                    auto_detect::generate_rfc4193_ula().to_addr().to_string();
            }
        }

        // 3. Resolve DHCP defaults if pools are unconfigured
        #[cfg(feature = "dhcp")]
        {
            let dhcp_defaults = auto_detect::derive_dhcp_defaults(&toml_cfg.system.iface);
            if toml_cfg.dhcp.v4.pools.is_empty() && toml_cfg.dhcp.v4.range_start.is_none() {
                toml_cfg.dhcp.v4.router = dhcp_defaults.router;
                toml_cfg.dhcp.v4.server_id = dhcp_defaults.router;
                toml_cfg.dhcp.v4.subnet_mask = dhcp_defaults.subnet_mask;
                toml_cfg.dhcp.v4.dns = vec![dhcp_defaults.router];
            }
        }

        let search_domains = Self::resolve_search_domains(&toml_cfg);

        Self::apply_cli_overrides(toml_cfg, &cli, search_domains)
    }

    fn load_modular_configs(config_path: &str, toml_cfg: &mut toml::TomlConfig) {
        let config_dir = Path::new(config_path)
            .parent()
            .unwrap_or_else(|| Path::new("/etc/lanforge"));

        macro_rules! try_load_section {
            ($file:expr, $field:expr, $typ:ty) => {
                let path = config_dir.join($file);
                if path.exists() {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        if let Ok(sec) = ::toml::from_str::<$typ>(&content) {
                            $field = sec;
                        } else {
                            tracing::warn!(
                                "[config] Failed to parse modular config '{}'",
                                path.display()
                            );
                        }
                    }
                }
            };
        }

        try_load_section!("database.toml", toml_cfg.database, DatabaseConfig);
        #[cfg(feature = "ra")]
        try_load_section!("ra.toml", toml_cfg.ra, RaServiceConfig);
        #[cfg(feature = "dhcp")]
        try_load_section!("dhcp.toml", toml_cfg.dhcp, toml::DhcpCfg);
        #[cfg(feature = "dns")]
        try_load_section!("dns.toml", toml_cfg.dns, DnsConfig);
        #[cfg(feature = "discovery")]
        try_load_section!("monitor.toml", toml_cfg.monitor, MonitorConfig);
        #[cfg(feature = "discovery")]
        try_load_section!("mdns.toml", toml_cfg.mdns, MdnsConfig);
        #[cfg(feature = "uds")]
        try_load_section!("api.toml", toml_cfg.api, ApiConfig);
        #[cfg(feature = "http")]
        try_load_section!("http.toml", toml_cfg.http, HttpConfig);
        #[cfg(feature = "tftp")]
        try_load_section!("tftp.toml", toml_cfg.tftp, TftpConfig);
        #[cfg(feature = "pppoe")]
        try_load_section!("pppoe.toml", toml_cfg.pppoe, lanforge_pppoe::config::PppoeConfig);
    }

    fn resolve_search_domains(toml_cfg: &toml::TomlConfig) -> Vec<String> {
        let mut domains = Vec::with_capacity(4);
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
                if let Some(ref target_prefix) = cli.target_prefix {
                    s.target_prefix.clone_from(target_prefix);
                }
                if let Some(debounce) = cli.debounce_secs {
                    s.debounce_secs = debounce;
                }
                s
            },
            database: {
                let mut db = toml_cfg.database;
                if let Some(ref url) = cli.db_url {
                    db.url.clone_from(url);
                }
                if let Some(ref log_url) = cli.log_db_url {
                    db.log_url.clone_from(log_url);
                }
                db
            },
            #[cfg(feature = "ra")]
            ra_enabled: toml_cfg.ra.enabled,
            #[cfg(feature = "ra")]
            ra_toml: toml_cfg.ra,
            #[cfg(feature = "dhcp")]
            dhcpv4_enabled: toml_cfg.dhcp.v4.enabled,
            #[cfg(feature = "dhcp")]
            dhcpv4_toml: toml_cfg.dhcp.v4,
            #[cfg(feature = "dhcp")]
            dhcpv6_enabled: toml_cfg.dhcp.v6.enabled,
            #[cfg(feature = "dhcp")]
            dhcpv6_toml: toml_cfg.dhcp.v6,
            #[cfg(feature = "dns")]
            dns_enabled: toml_cfg.dns.enabled,
            #[cfg(feature = "dns")]
            dns_toml: toml_cfg.dns,
            search_domains,
            #[cfg(feature = "discovery")]
            monitor_toml: toml_cfg.monitor,
            #[cfg(feature = "discovery")]
            mdns_toml: toml_cfg.mdns,
            #[cfg(feature = "uds")]
            api_toml: {
                let mut api = toml_cfg.api;
                if let Some(ref socket) = cli.control_socket {
                    api.socket_path.clone_from(socket);
                }
                api
            },
            #[cfg(feature = "http")]
            http_toml: {
                let mut http = toml_cfg.http;
                if let Some(ref listen_str) = cli.http_listen
                    && let Ok(addr) = listen_str.parse()
                {
                    http.listen = addr;
                }
                http
            },
            #[cfg(feature = "tftp")]
            tftp_toml: toml_cfg.tftp,
            #[cfg(feature = "pppoe")]
            pppoe_enabled: toml_cfg.pppoe.enabled,
            #[cfg(feature = "pppoe")]
            pppoe_toml: toml_cfg.pppoe,
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

        cfg.enabled = self.dhcpv4_enabled;
        if cfg.iface.is_empty() {
            cfg.iface.clone_from(&self.system.iface);
        }
        cfg.server_id = cfg.router;

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

        cfg.enabled = self.dhcpv6_enabled;
        if cfg.iface.is_empty() {
            cfg.iface.clone_from(&self.system.iface);
        }

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

        cfg.enabled = self.dns_enabled;

        if cfg.tls_cert.is_none() {
            cfg.tls_cert.clone_from(&self.system.tls_cert);
        }
        if cfg.tls_key.is_none() {
            cfg.tls_key.clone_from(&self.system.tls_key);
        }

        cfg.multi_search_labels = self
            .search_domains
            .iter()
            .map(|d| d.split('.').map(|s| s.as_bytes().to_vec()).collect())
            .collect();

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

        cfg.auth_password_hash = std::fs::read_to_string(self.get_password_hash_path())
            .map(|s| s.trim().to_string())
            .ok()
            .or_else(|| self.http_toml.auth_password_hash.clone());

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
            db_path: sanitize_db_url(&self.database.url),
            log_db_path: sanitize_db_url(&self.database.log_url),
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
            config_path: "/etc/lanforge/lanforge.toml".to_string(),
        }
    }
}

pub use lanforge_db::sanitize_db_url;
