//! Configuração do lanforge — Gerenciamento unificado de CLI, TOML e Environment.
//!
//! O sistema de configuração utiliza três camadas em ordem de precedência:
//! 1. **Default**: Valores fixos no código (fail-safe).
//! 2. **TOML**: Fonte principal localizada em `/etc/lanforge/lanforge.toml`.
//! 3. **CLI/Env**: Overrides manuais passados via linha de comando ou variáveis `LANFORGE_*`.
//!
//! ## Fluxo de Configuração
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
//!    (Serviços iniciados com config especializada)
//! ```

pub mod args;
pub mod toml;

pub use args::{CliArgs, Command, DbCommand, HostCommand, LeaseCommand};
pub use toml::{DhcpV4Cfg, DhcpV6Cfg, DnsCfg, RaCfg, StaticDeviceCfg, load_toml};

use clap::Parser;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tracing::warn;

// ---------------------------------------------------------------------------
// Config unificada (resultado do merge TOML + CLI overrides)
// ---------------------------------------------------------------------------

/// Configuração consolidada e final do sistema.
///
/// Criada através de `Config::load()`, esta struct contém todos os parâmetros
/// necessários para inicializar os subsistemas do lanforge.
#[derive(Debug)]
pub struct Config {
    // general
    pub command: Command,
    pub iface_lan: String,
    pub target_prefix: String,
    pub leases_db: String,
    pub debounce_secs: u64,
    pub fallback_mins: u64,
    pub control_socket: String,

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
    pub fn load() -> Self {
        let cli = CliArgs::parse();

        // toml::load_toml instead of local if we were explicit, but we imported `load_toml`
        let toml_cfg = load_toml(&cli.config);

        Self {
            command: cli.command.unwrap_or(Command::Run { only: None }),
            iface_lan: cli.iface_lan.unwrap_or(toml_cfg.general.iface_lan),
            target_prefix: cli.target_prefix.unwrap_or(toml_cfg.general.target_prefix),
            leases_db: toml_cfg.general.leases_db,
            debounce_secs: cli.debounce_secs.unwrap_or(toml_cfg.general.debounce_secs),
            fallback_mins: cli.fallback_mins.unwrap_or(toml_cfg.general.fallback_mins),
            control_socket: cli
                .control_socket
                .unwrap_or(toml_cfg.general.control_socket),

            ra_enabled: cli.ra_enabled.unwrap_or(toml_cfg.ra.enabled),
            ra_toml: toml_cfg.ra,

            dhcpv4_enabled: toml_cfg.dhcp.v4.enabled,
            dhcpv4_toml: toml_cfg.dhcp.v4,

            dhcpv6_enabled: toml_cfg.dhcp.v6.enabled,
            dhcpv6_toml: toml_cfg.dhcp.v6,

            dns_enabled: toml_cfg.dns.enabled,
            dns_toml: toml_cfg.dns,

            devices: toml_cfg.devices,
        }
    }

    /// Builds an `RaConfig` from the merged configuration.
    pub fn to_ra_config(&self) -> crate::ra::RaConfig {
        use crate::ra::{PrefixConfig, RaConfig, RdnssConfig};

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
            upstream: self
                .dns_toml
                .upstream
                .as_deref()
                .map(|s| parse_addr(s, "127.0.0.1:5335")),
            search_domain: self.dns_toml.search_domain.clone(),
            ttl: self.dns_toml.ttl,
        }
    }
}
