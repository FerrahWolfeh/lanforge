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
#[cfg(feature = "debug-commands")]
pub use args::Command;
use lanforge_api::config::ApiConfig;
use lanforge_dns::DnsConfig;
use lanforge_network::dhcp::v4::config::Dhcpv4Config;
use lanforge_network::dhcp::v6::config::Dhcpv6Config;
use lanforge_network::ra::{DnsslConfig, PrefixConfig, PrefixSource, RaConfig};
pub use toml::{StaticDeviceCfg, load_devices_only, load_toml};

use clap::Parser;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

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
    // general
    #[cfg(feature = "debug-commands")]
    pub command: Command,
    pub iface_lan: String,
    pub leases_db: String,
    pub db_url: String,
    pub fallback_mins: u64,
    pub control_socket: String,
    pub log_db: String,
    pub log_db_url: String,
    pub boot_dir: Option<String>,

    // RA
    pub ra_enabled: bool,
    pub ra_toml: lanforge_network::ra::RaServiceConfig,

    // DHCPv4
    pub dhcpv4_enabled: bool,
    pub dhcpv4_toml: Dhcpv4Config,

    // DHCPv6
    pub dhcpv6_enabled: bool,
    pub dhcpv6_toml: Dhcpv6Config,

    // DNS
    pub dns_enabled: bool,
    pub dns_toml: lanforge_dns::DnsConfig,
    pub search_domains: Vec<String>,

    // static devices
    pub devices: Vec<StaticDeviceCfg>,
    pub devices_file: Option<String>,

    pub dhcpv4_port: u16,
    pub dhcpv6_port: u16,
    pub dns_port: Option<u16>,
    pub api_port: Option<u16>,
    pub http_listen: Option<String>,
    pub auth_toml: toml::AuthCfg,
    pub http_toml: toml::HttpCfg,
    pub tftp_toml: toml::TftpCfg,
    pub config_path: String,
}

impl Config {
    /// Load config: parse CLI args, read TOML, merge with CLI overrides.
    pub fn load() -> Self {
        let cli = CliArgs::parse();

        // toml::load_toml instead of local if we were explicit, but we imported `load_toml`
        let toml_cfg = load_toml(&cli.config);

        let search_domains = {
            let mut domains = Vec::new();
            // 1. Unified search_domains from [general]
            if let Some(ref d) = toml_cfg.general.search_domains {
                for dom in d {
                    if !domains.contains(dom) {
                        domains.push(dom.clone());
                    }
                }
            }
            // 2. Legacy search_domain from [dns] (if not default "lan")
            if toml_cfg.dns.search_domain != "lan" && !domains.contains(&toml_cfg.dns.search_domain)
            {
                domains.push(toml_cfg.dns.search_domain.clone());
            }
            // 3. Legacy domain_name from [dhcp.v4]
            if let Some(ref d) = toml_cfg.dhcp.v4.domain_name
                && !domains.contains(d)
            {
                domains.push(d.clone());
            }
            // 4. Default "lan" if completely empty
            if domains.is_empty() {
                domains.push("lan".to_string());
            }
            domains
        };

        Self {
            #[cfg(feature = "debug-commands")]
            command: cli.command.unwrap_or(Command::Run { only: None }),
            iface_lan: cli
                .iface_lan
                .unwrap_or_else(|| toml_cfg.general.iface_lan.clone()),
            leases_db: cli
                .db_path
                .unwrap_or_else(|| toml_cfg.general.leases_db.clone()),
            db_url: if let Some(url) = cli.db_url {
                url
            } else {
                toml_cfg.general.get_db_url()
            },
            fallback_mins: cli.fallback_mins.unwrap_or(toml_cfg.general.fallback_mins),
            control_socket: cli
                .control_socket
                .unwrap_or_else(|| toml_cfg.general.control_socket.clone()),
            log_db: cli
                .log_db
                .unwrap_or_else(|| toml_cfg.general.log_db.clone()),
            log_db_url: if let Some(url) = cli.log_db_url {
                url
            } else {
                toml_cfg.general.get_log_db_url()
            },
            boot_dir: toml_cfg.general.boot_dir.clone(),

            ra_enabled: cli.ra_enabled.unwrap_or(toml_cfg.ra.enabled),
            ra_toml: {
                let mut r = toml_cfg.ra;
                if let Some(managed) = cli.ra_managed {
                    r.managed = managed;
                }
                if let Some(other) = cli.ra_other_config {
                    r.other_config = other;
                }
                if let Some(max_interval) = cli.ra_max_interval {
                    r.max_interval = max_interval;
                }
                r
            },

            dhcpv4_enabled: cli.dhcpv4_enabled.unwrap_or(toml_cfg.dhcp.v4.enabled),
            dhcpv4_toml: {
                let mut d = toml_cfg.dhcp.v4;
                if let Some(start) = cli.dhcpv4_range_start {
                    d.range_start = start;
                }
                if let Some(end) = cli.dhcpv4_range_end {
                    d.range_end = end;
                }
                if let Some(lt) = cli.dhcpv4_lease_time {
                    d.lease_time = lt;
                }
                d
            },

            dhcpv6_enabled: cli.dhcpv6_enabled.unwrap_or(toml_cfg.dhcp.v6.enabled),
            dhcpv6_toml: toml_cfg.dhcp.v6,

            dns_enabled: cli.dns_enabled.unwrap_or(toml_cfg.dns.enabled),
            dns_toml: {
                let mut d = toml_cfg.dns;
                if let Some(listen) = cli.dns_listen
                    && let Ok(addr) = listen.parse()
                {
                    d.listen = addr;
                }
                if let Some(upstream) = cli.dns_upstream
                    && let Ok(target) = upstream.parse()
                {
                    d.upstream = Some(target);
                }
                d
            },
            search_domains,

            devices: toml_cfg.devices,
            devices_file: cli.devices_file,

            dhcpv4_port: cli.dhcpv4_port.unwrap_or(67),
            dhcpv6_port: cli.dhcpv6_port.unwrap_or(547),
            dns_port: cli.dns_port,
            api_port: cli.control_port,
            http_listen: cli
                .http_listen
                .or(toml_cfg.general.http_listen)
                .or(toml_cfg.http.listen.clone()),
            auth_toml: toml_cfg.auth,
            http_toml: toml_cfg.http,
            tftp_toml: toml_cfg.tftp,
            config_path: cli.config,
        }
    }

    /// Returns the path to the dedicated API password hash file.
    pub fn get_password_hash_path(&self) -> PathBuf {
        Path::new(&self.config_path)
            .parent()
            .unwrap_or_else(|| Path::new("/etc/lanforge"))
            .join("api_password.hash")
    }

    /// Builds an `RaConfig` from the merged configuration.
    pub fn to_ra_config(&self) -> RaConfig {
        let mut cfg = self.ra_toml.to_ra_config(self.iface_lan.clone());

        // Overrides
        cfg.managed = self.ra_toml.managed; // Should be handled by to_ra_config but for safety

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
    pub fn to_dhcpv4_config(&self) -> Dhcpv4Config {
        let mut cfg = self.dhcpv4_toml.clone();

        // Injected fields
        cfg.enabled = self.dhcpv4_enabled;
        cfg.iface = self.iface_lan.clone();
        cfg.server_id = cfg.router; // Use router IP as server ID by default
        cfg.port = self.dhcpv4_port;

        // Option 15 & 119
        if cfg.domain_name.is_none() {
            cfg.domain_name = self.search_domains.first().cloned();
        }
        cfg.search_domains = self.search_domains.clone();

        cfg
    }

    /// Builds a `Dhcpv6Config` from the merged configuration.
    pub fn to_dhcpv6_config(&self) -> Dhcpv6Config {
        let mut cfg = self.dhcpv6_toml.clone();

        // Injected fields
        cfg.enabled = self.dhcpv6_enabled;
        cfg.iface = self.iface_lan.clone();
        cfg.port = self.dhcpv6_port;

        // Prefix detection
        if let Some(p) = self.ra_toml.prefixes.iter().find(|p| {
            p.source == PrefixSource::AutoGua || matches!(p.source, PrefixSource::Static(_))
        }) {
            if let PrefixSource::Static(addr) = p.source {
                cfg.ula_prefix = Some(addr);
            }
            cfg.ula_prefix_len = p.prefix_len;
        } else {
            cfg.ula_prefix_len = 64;
        }

        // DNS Servers
        if cfg.dns_servers.is_empty() {
            cfg.dns_servers = self.dns_toml.upstream.as_ref().map_or_else(
                || cfg.ula_prefix.map(|ip| vec![ip]).unwrap_or_default(),
                |target| match target.addr {
                    SocketAddr::V6(v6) => vec![*v6.ip()],
                    SocketAddr::V4(_) => vec![],
                },
            );
        }

        if cfg.search_domains.is_empty() {
            cfg.search_domains = self.search_domains.clone();
        }

        cfg
    }

    /// Builds a `DnsConfig` from the merged configuration.
    pub fn to_dns_config(&self) -> DnsConfig {
        let mut cfg = self.dns_toml.clone();

        // Overrides
        cfg.enabled = self.dns_enabled;
        if let Some(p) = self.dns_port {
            cfg.listen.set_port(p);
        }

        // Search labels
        cfg.multi_search_labels = self
            .search_domains
            .iter()
            .map(|d| d.split('.').map(|s| s.as_bytes().to_vec()).collect())
            .collect();

        // Prefix detection (if not explicitly set in DNS config)
        if cfg.ula_prefix.is_none() {
            cfg.ula_prefix = self.ra_toml.prefixes.iter().find_map(|p| {
                if let PrefixSource::Static(addr) = p.source {
                    Some(addr)
                } else {
                    None
                }
            });
        }

        cfg
    }

    /// Builds an `ApiConfig` for the control service.
    pub fn to_api_config(&self) -> ApiConfig {
        // Resolve password hash from dedicated file, falling back to TOML
        let auth_password_hash = std::fs::read_to_string(self.get_password_hash_path())
            .map(|s| s.trim().to_string())
            .ok()
            .or_else(|| self.auth_toml.password_hash.clone());

        ApiConfig {
            socket_path: self.control_socket.clone(),
            lan_iface: self.iface_lan.clone(),
            ra_enabled: self.ra_enabled,
            ula_prefix: self.ra_toml.prefixes.iter().find_map(|p| {
                if let PrefixSource::Static(addr) = p.source {
                    Some(addr.to_string())
                } else {
                    None
                }
            }),
            dhcp_v4_enabled: self.dhcpv4_enabled,
            dhcp_v6_enabled: self.dhcpv6_enabled,
            dns_enabled: self.dns_enabled,
            dns_upstream: self.dns_toml.upstream.as_ref().map(|u| u.clone().into()),
            db_path: self.leases_db.clone(),
            db_url: self.db_url.clone(),
            log_db_path: self.log_db.clone(),
            log_db_url: self.log_db_url.clone(),
            tcp_port: self.api_port,
            http_listen: self.http_listen.clone(),
            dot_listen: self.dns_toml.dot_listen.map(|addr| addr.to_string()),
            dhcp_v4_range_size: {
                let v4 = self.to_dhcpv4_config();
                u32::from(v4.range_end) - u32::from(v4.range_start) + 1
            },
            dhcp_v6_pool_size: {
                let v6 = self.to_dhcpv6_config();
                let mut total = 0;
                let mut finite = true;
                for p in &v6.pools {
                    if let (Some(start), Some(end)) = (&p.range_start, &p.range_end) {
                        // Very rough approximation for IPv6 range size
                        let s = start.as_u128(None);
                        let e = end.as_u128(None);
                        total += u64::try_from(e - s + 1).unwrap_or(u64::MAX);
                    } else {
                        finite = false;
                        break;
                    }
                }
                if finite { Some(total) } else { None }
            },
            auth_password_hash,
            tls_cert: self.http_toml.tls_cert.clone(),
            tls_key: self.http_toml.tls_key.clone(),
            boot_dir: self.http_listen.as_ref().and_then(|_| {
                self.tftp_toml
                    .root_dir
                    .clone()
                    .or_else(|| self.boot_dir.clone())
            }),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            #[cfg(feature = "debug-commands")]
            command: args::Command::Run { only: None },
            iface_lan: "lo".to_string(),
            leases_db: "lanforge.db".to_string(),
            db_url: "sqlite://lanforge.db".to_string(),
            fallback_mins: 60,
            control_socket: "/run/lanforge/control.sock".to_string(),
            log_db: "/run/lanforge/log.db".to_string(),
            log_db_url: "sqlite://:memory:".to_string(),
            boot_dir: None,
            ra_enabled: true,
            ra_toml: lanforge_network::ra::RaServiceConfig::default(),
            dhcpv4_enabled: true,
            dhcpv4_toml: lanforge_network::dhcp::v4::config::Dhcpv4Config::default(),
            dhcpv6_enabled: true,
            dhcpv6_toml: lanforge_network::dhcp::v6::config::Dhcpv6Config::default(),
            dns_enabled: true,
            dns_toml: lanforge_dns::DnsConfig::default(),
            search_domains: vec!["lan".to_string()],
            devices: Vec::new(),
            devices_file: None,
            dhcpv4_port: 67,
            dhcpv6_port: 547,
            dns_port: Some(5300),
            api_port: None,
            http_listen: None,
            auth_toml: toml::AuthCfg::default(),
            http_toml: toml::HttpCfg::default(),
            tftp_toml: toml::TftpCfg::default(),
            config_path: "/etc/lanforge/lanforge.toml".to_string(),
        }
    }
}
