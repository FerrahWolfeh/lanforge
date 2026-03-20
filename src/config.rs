//! Configuração do lanforge — CLI + TOML + env.
//!
//! Três camadas em ordem crescente de precedência:
//! 1. Valores default hardcoded
//! 2. Arquivo TOML (`--config` ou LANFORGE_CONFIG, default `/etc/lanforge/lanforge.toml`)
//! 3. Variáveis de ambiente LANFORGE_* (via clap `env`)
//!
//! O TOML é a fonte primária de configuração. CLI/env overridam valores individuais.

use clap::Parser;
use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// CLI (clap) — entrypoint de parsing
// ---------------------------------------------------------------------------

/// lanforge — daemon unificado de controle de rede IPv4/IPv6.
#[derive(Parser, Debug)]
#[command(name = "lanforge", version, about, long_about = None)]
pub struct CliArgs {
    /// Path to TOML config file
    #[arg(
        long,
        env = "LANFORGE_CONFIG",
        default_value = "/etc/lanforge/lanforge.toml"
    )]
    pub config: String,

    // ── Overrides (prevalecem sobre TOML) ─────────────────────────────────
    /// Override: LAN interface
    #[arg(long, env = "LANFORGE_IFACE_LAN")]
    pub iface_lan: Option<String>,

    /// Override: output hosts file path
    #[arg(long, env = "LANFORGE_HOSTS_FILE")]
    pub hosts_file: Option<String>,

    /// Override: DNS process name for SIGHUP
    #[arg(long, env = "LANFORGE_DNS_PROCESS")]
    pub dns_process: Option<String>,

    /// Override: target prefix for SLAAC tracking
    #[arg(long, env = "LANFORGE_TARGET_PREFIX")]
    pub target_prefix: Option<String>,

    /// Override: debounce window in seconds
    #[arg(long, env = "LANFORGE_DEBOUNCE_SECS")]
    pub debounce_secs: Option<u64>,

    /// Override: fallback scan interval in minutes
    #[arg(long, env = "LANFORGE_FALLBACK_MINS")]
    pub fallback_mins: Option<u64>,

    /// Override: enable RA service
    #[arg(long, env = "LANFORGE_RA_ENABLED")]
    pub ra_enabled: Option<bool>,
}

// ---------------------------------------------------------------------------
// TOML structures (serde)
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug, Default)]
#[serde(default)]
pub struct TomlConfig {
    pub general: GeneralCfg,
    pub ra: RaCfg,
    pub dhcp: DhcpCfg,
    pub dns: DnsCfg,
    #[serde(default)]
    pub devices: Vec<StaticDeviceCfg>,
}

#[derive(Deserialize, Debug, Default)]
#[serde(default)]
pub struct DhcpCfg {
    pub v4: DhcpV4Cfg,
    pub v6: DhcpV6Cfg,
}

#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct DhcpV4Cfg {
    pub enabled: bool,
    pub range_start: String,
    pub range_end: String,
    pub lease_time: u64,
    pub router: String,
    pub dns: Vec<String>,
    pub subnet_mask: Option<String>,
    pub domain_name: Option<String>,
}

impl Default for DhcpV4Cfg {
    fn default() -> Self {
        DhcpV4Cfg {
            enabled: false,
            range_start: "192.168.0.100".into(),
            range_end: "192.168.0.254".into(),
            lease_time: 86400,
            router: "192.168.0.1".into(),
            dns: vec!["192.168.0.1".into()],
            subnet_mask: None,
            domain_name: None,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct DhcpV6Cfg {
    pub enabled: bool,
    pub lease_time: u32,
    pub range_start: Option<String>,
    pub range_end: Option<String>,
}

impl Default for DhcpV6Cfg {
    fn default() -> Self {
        DhcpV6Cfg {
            enabled: false,
            lease_time: 86400,
            range_start: None,
            range_end: None,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct GeneralCfg {
    pub iface_lan: String,
    pub iface_wan: String,
    pub hosts_file: String,
    pub leases_db: String,
    pub dns_reload_cmd: String,
    pub target_prefix: String,
    pub debounce_secs: u64,
    pub fallback_mins: u64,
}

impl Default for GeneralCfg {
    fn default() -> Self {
        GeneralCfg {
            iface_lan: "end0".into(),
            iface_wan: "ppp0".into(),
            hosts_file: "/mnt/ram/dnsmasq/ipv6_slaac_hosts".into(),
            leases_db: "/var/lib/lanforge/leases.db".into(),
            dns_reload_cmd: "pkill -HUP pihole-FTL".into(),
            target_prefix: "fd97:f00d:cafe:3731".into(),
            debounce_secs: 2,
            fallback_mins: 5,
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct RaCfg {
    pub enabled: bool,
    pub managed: bool,
    pub other_config: bool,
    pub max_interval: u64,
    pub router_lifetime: Option<u64>,
    pub mtu: Option<u32>,
    #[serde(default)]
    pub prefix: Vec<RaPrefixCfg>,
    #[serde(default)]
    pub rdnss: Vec<RaRdnssCfg>,
}

impl Default for RaCfg {
    fn default() -> Self {
        RaCfg {
            enabled: false,
            managed: true,
            other_config: true,
            max_interval: 100,
            router_lifetime: None,
            mtu: None,
            prefix: Vec::new(),
            rdnss: Vec::new(),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct RaPrefixCfg {
    pub source: String,
    pub address: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct RaRdnssCfg {
    pub servers: Vec<Ipv6Addr>,
    pub lifetime: Option<u64>,
}

#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct DnsCfg {
    pub enabled: bool,
    /// Endereço e porta onde o servidor DNS escuta (ex: "0.0.0.0:5300")
    pub listen: String,
    /// Resolver upstream para queries não-LAN, normalmente o Unbound (ex: "127.0.0.1:5335")
    pub upstream: String,
    /// Sufixo de domínio local — "lan" faz "archie.lan" resolver para o device "archie"
    pub search_domain: String,
    /// TTL das respostas LAN em segundos
    pub ttl: u32,
}

impl Default for DnsCfg {
    fn default() -> Self {
        DnsCfg {
            enabled: false,
            listen: "0.0.0.0:5300".into(),
            upstream: "127.0.0.1:5335".into(),
            search_domain: "lan".into(),
            ttl: 60,
        }
    }
}

/// Dispositivo estático — lido de `[[devices]]` no TOML.
#[derive(Deserialize, Debug, Clone)]
pub struct StaticDeviceCfg {
    pub mac: String,
    pub hostname: String,
    pub v4_ip: Option<String>,
    pub v6_suffix: Option<String>,
}

// ---------------------------------------------------------------------------
// Config unificada (resultado do merge TOML + CLI overrides)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Config {
    // general
    pub iface_lan: String,
    pub hosts_file: String,
    pub dns_process: String,
    pub target_prefix: String,
    pub leases_db: String,
    pub debounce_secs: u64,
    pub fallback_mins: u64,

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

    // static devices
    pub devices: Vec<StaticDeviceCfg>,
}

impl Config {
    /// Load config: parse CLI args, read TOML, merge with CLI overrides.
    pub fn load() -> anyhow::Result<Self> {
        let cli = CliArgs::parse();

        let toml_cfg = load_toml(&cli.config);

        Ok(Config {
            iface_lan: cli.iface_lan.unwrap_or(toml_cfg.general.iface_lan),
            hosts_file: cli.hosts_file.unwrap_or(toml_cfg.general.hosts_file),
            dns_process: cli.dns_process.unwrap_or_else(|| {
                // Extract process name from dns_reload_cmd e.g. "pkill -HUP pihole-FTL" → "pihole-FTL"
                toml_cfg
                    .general
                    .dns_reload_cmd
                    .split_whitespace()
                    .last()
                    .unwrap_or("pihole-FTL")
                    .to_string()
            }),
            target_prefix: cli.target_prefix.unwrap_or(toml_cfg.general.target_prefix),
            leases_db: toml_cfg.general.leases_db,
            debounce_secs: cli.debounce_secs.unwrap_or(toml_cfg.general.debounce_secs),
            fallback_mins: cli.fallback_mins.unwrap_or(toml_cfg.general.fallback_mins),

            ra_enabled: cli.ra_enabled.unwrap_or(toml_cfg.ra.enabled),
            ra_toml: toml_cfg.ra,

            dhcpv4_enabled: toml_cfg.dhcp.v4.enabled,
            dhcpv4_toml: toml_cfg.dhcp.v4,

            dhcpv6_enabled: toml_cfg.dhcp.v6.enabled,
            dhcpv6_toml: toml_cfg.dhcp.v6,

            dns_enabled: toml_cfg.dns.enabled,
            dns_toml: toml_cfg.dns,

            devices: toml_cfg.devices,
        })
    }

    /// Builds an `RaConfig` from the merged configuration.
    pub fn to_ra_config(&self) -> crate::ra::RaConfig {
        use crate::ra::*;

        let mut prefixes = Vec::new();

        for p in &self.ra_toml.prefix {
            match p.source.as_str() {
                "ula" => {
                    if let Some(ref addr) = p.address {
                        prefixes.push(PrefixConfig::ula(addr));
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
            .map(|r| match r.lifetime {
                Some(lt) => RdnssConfig::with_lifetime(r.servers.clone(), lt as u32),
                None => RdnssConfig::new(r.servers.clone()),
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
            ..Default::default()
        }
    }

    /// Builds a `Dhcpv4Config` from the merged configuration.
    pub fn to_dhcpv4_config(&self) -> crate::dhcp::v4::config::Dhcpv4Config {
        use crate::dhcp::v4::config::Dhcpv4Config;

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
            lease_time: self.dhcpv4_toml.lease_time as u32,
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
                .map(|s| parse_ip(s, Ipv4Addr::new(255, 255, 255, 0)))
                .unwrap_or(Ipv4Addr::new(255, 255, 255, 0)),
            domain_name: self.dhcpv4_toml.domain_name.clone(),
        }
    }

    /// Builds a `Dhcpv6Config` from the merged configuration.
    pub fn to_dhcpv6_config(&self) -> crate::dhcp::v6::config::Dhcpv6Config {
        let ula_prefix = self.ra_toml.prefix.iter().find_map(|p| {
            if p.source == "ula" {
                p.address.as_deref().and_then(|a| a.parse().ok())
            } else {
                None
            }
        });

        let parse_ipv6 = |s: &Option<String>| -> Option<Ipv6Addr> {
            s.as_deref().and_then(|ip_str| ip_str.parse().ok())
        };

        crate::dhcp::v6::config::Dhcpv6Config {
            enabled: self.dhcpv6_enabled,
            iface: self.iface_lan.clone(),
            lease_time: self.dhcpv6_toml.lease_time,
            ula_prefix,
            // Certifique-se de que sua config interna do v6 suporte esses campos!
            range_start: parse_ipv6(&self.dhcpv6_toml.range_start),
            range_end: parse_ipv6(&self.dhcpv6_toml.range_end),
        }
    }

    /// Builds a `DnsConfig` from the merged configuration.
    pub fn to_dns_config(&self) -> crate::dns::DnsConfig {
        let parse_addr = |s: &str, default: &str| -> std::net::SocketAddr {
            s.parse().unwrap_or_else(|_| {
                warn!("[config] Endereço DNS inválido '{s}', usando {default}");
                default.parse().unwrap()
            })
        };

        crate::dns::DnsConfig {
            enabled: self.dns_enabled,
            listen: parse_addr(&self.dns_toml.listen, "0.0.0.0:5300"),
            upstream: parse_addr(&self.dns_toml.upstream, "127.0.0.1:5335"),
            search_domain: self.dns_toml.search_domain.clone(),
            ttl: self.dns_toml.ttl,
        }
    }
}

/// Load and parse the TOML config file, or return defaults if missing.
fn load_toml(path: &str) -> TomlConfig {
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
