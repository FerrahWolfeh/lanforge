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
use lanforge_core::device::Ipv6AddrOrSuffix;
use lanforge_dns::DnsConfig;
use lanforge_network::dhcp::v4::config::Dhcpv4Config;
use lanforge_network::dhcp::v6::config::{Dhcpv6Config, Dhcpv6PoolConfig};
use lanforge_network::ra::{DnsslConfig, PrefixConfig, PrefixSource, RaConfig, RdnssConfig};
pub use toml::{
    DhcpV4Cfg, DhcpV6Cfg, DnsCfg, RaCfg, StaticDeviceCfg, load_devices_only, load_toml,
};

use clap::Parser;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::warn;

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
    pub ra_toml: RaCfg,

    // DHCPv4
    pub dhcpv4_enabled: bool,
    pub dhcpv4_toml: DhcpV4Cfg,

    // DHCPv6
    pub dhcpv6_enabled: bool,
    pub dhcpv6_toml: DhcpV6Cfg,

    // DNS
    pub dns_enabled: bool,
    pub dns_toml: DnsCfg,
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
                domains.push(toml_cfg.dns.search_domain.clone());
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
            ra_toml: RaCfg {
                managed: cli.ra_managed.unwrap_or(toml_cfg.ra.managed),
                other_config: cli.ra_other_config.unwrap_or(toml_cfg.ra.other_config),
                max_interval: cli.ra_max_interval.unwrap_or(toml_cfg.ra.max_interval),
                ..toml_cfg.ra
            },

            dhcpv4_enabled: cli.dhcpv4_enabled.unwrap_or(toml_cfg.dhcp.v4.enabled),
            dhcpv4_toml: DhcpV4Cfg {
                range_start: cli
                    .dhcpv4_range_start
                    .unwrap_or(toml_cfg.dhcp.v4.range_start),
                range_end: cli.dhcpv4_range_end.unwrap_or(toml_cfg.dhcp.v4.range_end),
                lease_time: cli
                    .dhcpv4_lease_time
                    .map_or(toml_cfg.dhcp.v4.lease_time, u64::from),
                ..toml_cfg.dhcp.v4
            },

            dhcpv6_enabled: cli.dhcpv6_enabled.unwrap_or(toml_cfg.dhcp.v6.enabled),
            dhcpv6_toml: toml_cfg.dhcp.v6,

            dns_enabled: cli.dns_enabled.unwrap_or(toml_cfg.dns.enabled),
            dns_toml: DnsCfg {
                listen: cli.dns_listen.unwrap_or(toml_cfg.dns.listen),
                upstream: cli.dns_upstream.or(toml_cfg.dns.upstream),
                ..toml_cfg.dns
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

    /// Parses a CIDR string (e.g., "`fd00::/48`") into an `Ipv6Addr` and a prefix length.
    fn parse_cidr(s: &str) -> Option<(Ipv6Addr, u8)> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.is_empty() {
            return None;
        }
        let addr = parts[0].parse().ok()?;
        let len = if parts.len() > 1 {
            parts[1].parse().ok()?
        } else {
            64
        };
        Some((addr, len))
    }

    /// Builds an `RaConfig` from the merged configuration.
    pub fn to_ra_config(&self) -> RaConfig {
        let mut prefixes = Vec::new();

        for p in &self.ra_toml.prefix {
            match p.source.as_str() {
                "ula" => {
                    if let Some(ref addr_str) = p.address
                        && let Some((addr, len)) = Self::parse_cidr(addr_str)
                    {
                        prefixes.push(PrefixConfig {
                            source: PrefixSource::Static(addr),
                            prefix_len: len,
                            ..PrefixConfig::ula(&addr.to_string())
                        });
                    }
                }
                "auto_gua" => {
                    prefixes.push(PrefixConfig::gua_dynamic());
                }
                other => {
                    warn!("[config] Unknown RA prefix source: '{other}', ignoring");
                }
            }
        }

        // If no prefixes configured, default to auto_gua
        if prefixes.is_empty() {
            prefixes.push(PrefixConfig::gua_dynamic());
        }

        let rdnss: Vec<RdnssConfig> = self
            .ra_toml
            .rdnss
            .iter()
            .filter(|r| !r.servers.is_empty())
            .map(|r| {
                r.lifetime.map_or_else(
                    || RdnssConfig::new(r.servers.clone()),
                    |lt| {
                        RdnssConfig::with_lifetime(
                            r.servers.clone(),
                            u32::try_from(lt).unwrap_or(u32::MAX),
                        )
                    },
                )
            })
            .collect();

        RaConfig {
            iface: self.iface_lan.clone(),
            managed: self.ra_toml.managed,
            other_config: self.ra_toml.other_config,
            max_interval: Duration::from_secs(self.ra_toml.max_interval),
            router_lifetime: self.ra_toml.router_lifetime.map(Duration::from_secs),
            mtu: self.ra_toml.mtu,
            prefixes,
            rdnss,
            dnssl: vec![DnsslConfig {
                domains: self.search_domains.clone(),
                lifetime: None,
            }],
            ..Default::default()
        }
    }

    /// Builds a `Dhcpv4Config` from the merged configuration.
    pub fn to_dhcpv4_config(&self) -> Dhcpv4Config {
        let parse_ip = |s: &str, default: Ipv4Addr| -> Ipv4Addr {
            s.parse().unwrap_or_else(|_| {
                warn!("[config] Invalid IPv4 '{s}', using {default}");
                default
            })
        };

        let server_id = parse_ip(&self.dhcpv4_toml.router, Ipv4Addr::new(192, 168, 0, 1));

        Dhcpv4Config {
            iface: self.iface_lan.clone(),
            server_id,
            range_start: parse_ip(
                &self.dhcpv4_toml.range_start,
                Ipv4Addr::new(192, 168, 0, 100),
            ),
            range_end: parse_ip(&self.dhcpv4_toml.range_end, Ipv4Addr::new(192, 168, 0, 254)),
            lease_time: u32::try_from(self.dhcpv4_toml.lease_time).unwrap_or(u32::MAX),
            router: server_id,
            dns: self
                .dhcpv4_toml
                .dns
                .iter()
                .map(|s| parse_ip(s, Ipv4Addr::new(192, 168, 0, 1)))
                .collect(),
            subnet_mask: self
                .dhcpv4_toml
                .subnet_mask
                .as_deref()
                .map_or(Ipv4Addr::new(255, 255, 255, 0), |s| {
                    parse_ip(s, Ipv4Addr::new(255, 255, 255, 0))
                }),
            domain_name: self.search_domains.first().cloned(),
            search_domains: self.search_domains.clone(),
            port: self.dhcpv4_port,
            tftp_server: self.dhcpv4_toml.tftp_server.clone(),
            boot_file: self.dhcpv4_toml.boot_file.clone(),
        }
    }

    /// Builds a `Dhcpv6Config` from the merged configuration.
    pub fn to_dhcpv6_config(&self) -> Dhcpv6Config {
        let mut ula_prefix = None;

        let ula_prefix_len = if let Some(p) = self.ra_toml.prefix.iter().find(|p| p.source == "ula")
            && let Some(addr_str) = &p.address
            && let Some((addr, len)) = Self::parse_cidr(addr_str)
        {
            ula_prefix = Some(addr);
            len
        } else {
            64
        };

        let mut pools = Vec::new();

        // 1. Legacy support: if range_start/end are present in TOML, convert them to a pool
        if let (Some(start_s), Some(end_s)) =
            (&self.dhcpv6_toml.range_start, &self.dhcpv6_toml.range_end)
            && let (Some(start), Some(end)) = (
                Ipv6AddrOrSuffix::parse(start_s),
                Ipv6AddrOrSuffix::parse(end_s),
            )
        {
            pools.push(Dhcpv6PoolConfig {
                range_start: Some(start),
                range_end: Some(end),
                address: None,
            });
        }

        // 2. New multi-pool support
        for p in &self.dhcpv6_toml.pools {
            if let Some(addr_str) = &p.address {
                if p.range_start.is_some() || p.range_end.is_some() {
                    warn!(
                        "[config] DHCPv6 pool has both 'address' (CIDR) and 'range_start/end'. Prioritizing CIDR."
                    );
                }
                pools.push(Dhcpv6PoolConfig {
                    range_start: None,
                    range_end: None,
                    address: Some(addr_str.clone()),
                });
            } else if let (Some(start_s), Some(end_s)) = (&p.range_start, &p.range_end) {
                if let (Some(start), Some(end)) = (
                    Ipv6AddrOrSuffix::parse(start_s),
                    Ipv6AddrOrSuffix::parse(end_s),
                ) {
                    pools.push(Dhcpv6PoolConfig {
                        range_start: Some(start),
                        range_end: Some(end),
                        address: None,
                    });
                }
            } else {
                warn!(
                    "[config] DHCPv6 pool missing both 'address' (CIDR) and 'range_start/end', ignoring."
                );
            }
        }

        Dhcpv6Config {
            enabled: self.dhcpv6_enabled,
            iface: self.iface_lan.clone(),
            lease_time: self.dhcpv6_toml.lease_time,
            ula_prefix,
            ula_prefix_len,
            port: self.dhcpv6_port,
            pools,
            dns_servers: self
                .dns_toml
                .upstream
                .as_deref()
                .and_then(|s| s.parse::<SocketAddr>().ok())
                .map_or_else(
                    || {
                        // If no upstream, we might want to suggest ourselves if we have a ULA
                        ula_prefix.map(|ip| vec![ip]).unwrap_or_default()
                    },
                    |sa| match sa {
                        SocketAddr::V6(v6) => vec![*v6.ip()],

                        SocketAddr::V4(_) => vec![],
                    },
                ),
            search_domains: self.search_domains.clone(),
            boot_file: self.dhcpv6_toml.boot_file.clone(),
        }
    }

    /// Builds a `DnsConfig` from the merged configuration.
    pub fn to_dns_config(&self) -> DnsConfig {
        let parse_addr = |s: &str, default: &str| -> SocketAddr {
            s.parse().unwrap_or_else(|_| {
                warn!("[config] Invalid DNS address '{s}', using {default}");
                default.parse().unwrap()
            })
        };

        let ula_prefix = self.ra_toml.prefix.iter().find_map(|p| {
            if p.source == "ula" {
                p.address
                    .as_deref()
                    .and_then(Self::parse_cidr)
                    .map(|(addr, _)| addr)
            } else {
                None
            }
        });

        let multi_search_labels: Vec<Vec<Vec<u8>>> = self
            .search_domains
            .iter()
            .map(|d| d.split('.').map(|s| s.as_bytes().to_vec()).collect())
            .collect();

        DnsConfig {
            enabled: self.dns_enabled,
            listen: {
                let mut addr = parse_addr(&self.dns_toml.listen, "0.0.0.0:5300");
                if let Some(p) = self.dns_port {
                    addr.set_port(p);
                }
                addr
            },
            dot_listen: self.dns_toml.dot_listen.as_deref().map(|s| parse_addr(s, "0.0.0.0:853")),
            tls_cert: self.dns_toml.tls_cert.clone(),
            tls_key: self.dns_toml.tls_key.clone(),
            upstream: self
                .dns_toml
                .upstream
                .as_deref()
                .map(|s| {
                    if let Some(stripped) = s.strip_prefix("tls://") {
                        // tls://dns.google:853 OR tls://8.8.8.8:853
                        let (hostname, addr_str) = if let Some(pos) = stripped.find(':') {
                             let (h, _p) = stripped.split_at(pos);
                             (Some(h.to_string()), stripped)
                        } else {
                             (Some(stripped.to_string()), stripped) // This might be wrong if no port, but parse_addr handles default
                        };

                        let addr = parse_addr(addr_str, "8.8.8.8:853");
                        lanforge_dns::config::UpstreamTarget {
                            addr,
                            protocol: lanforge_dns::config::UpstreamProtocol::Tls,
                            hostname,
                        }
                    } else {
                        let addr_str = s.strip_prefix("udp://").unwrap_or(s);
                        lanforge_dns::config::UpstreamTarget {
                            addr: parse_addr(addr_str, "1.1.1.1:53"),
                            protocol: lanforge_dns::config::UpstreamProtocol::Udp,
                            hostname: None,
                        }
                    }
                }),
            search_domain: self.dns_toml.search_domain.clone(),
            ula_prefix,
            gua_prefix: None,
            ttl: self.dns_toml.ttl,
            multi_search_labels,
            #[cfg(feature = "adblock")]
            adblock_enabled: self.dns_toml.adblock_enabled,
            #[cfg(feature = "adblock")]
            adblock_urls: self.dns_toml.adblock_urls.clone(),
            last_seen_threshold_days: self.dns_toml.last_seen_threshold_days,
        }
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
            ula_prefix: self.ra_toml.prefix.iter().find_map(|p| {
                if p.source == "ula" {
                    p.address.clone()
                } else {
                    None
                }
            }),
            dhcp_v4_enabled: self.dhcpv4_enabled,
            dhcp_v6_enabled: self.dhcpv6_enabled,
            dns_enabled: self.dns_enabled,
            dns_upstream: self.dns_toml.upstream.clone(),
            db_path: self.leases_db.clone(),
            db_url: self.db_url.clone(),
            log_db_path: self.log_db.clone(),
            log_db_url: self.log_db_url.clone(),
            tcp_port: self.api_port,
            http_listen: self.http_listen.clone(),
            dot_listen: self.dns_toml.dot_listen.clone(),
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
                self.tftp_toml.root_dir.clone().or_else(|| self.boot_dir.clone())
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
            ra_toml: RaCfg::default(),
            dhcpv4_enabled: true,
            dhcpv4_toml: DhcpV4Cfg::default(),
            dhcpv6_enabled: true,
            dhcpv6_toml: DhcpV6Cfg::default(),
            dns_enabled: true,
            dns_toml: DnsCfg::default(),
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
