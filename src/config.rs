//! Configuração do lanforge — CLI + env + arquivo TOML.
//!
//! Três camadas em ordem crescente de precedência:
//! 1. Valores default hardcoded no código
//! 2. Arquivo TOML (futuro — carregado se --config é passado)
//! 3. Variáveis de ambiente (via clap `env`)
//!
//! Campos de RA configuráveis via LANFORGE_RA_* env vars.

use clap::Parser;
use std::net::Ipv6Addr;
use std::time::Duration;

/// lanforge — daemon unificado de controle de rede IPv4/IPv6.
///
/// All options can also be supplied via the matching environment variable.
#[derive(Parser, Debug)]
#[command(name = "lanforge", version, about, long_about = None)]
pub struct Config {
    // ── SLAAC tracker (legado, mantido para compatibilidade) ──────────────

    /// dnsmasq leases file
    #[arg(
        long,
        env = "LANFORGE_LEASES_FILE",
        default_value = "/mnt/ram/dnsmasq/dnsmasq.leases"
    )]
    pub leases_file: String,

    /// Output hosts file written for dnsmasq
    #[arg(
        long,
        env = "LANFORGE_OUTPUT_FILE",
        default_value = "/mnt/ram/dnsmasq/ipv6_slaac_hosts"
    )]
    pub output_file: String,

    /// IPv6 prefix to watch (only neighbours matching this prefix are recorded)
    #[arg(
        long,
        env = "LANFORGE_TARGET_PREFIX",
        default_value = "fd97:f00d:cafe:3731"
    )]
    pub target_prefix: String,

    /// dnsmasq static-host config file (parsed for dhcp-host entries)
    #[arg(
        long,
        env = "LANFORGE_DNSMASQ_CONFIG",
        default_value = "/etc/dnsmasq-dhcp.conf"
    )]
    pub dnsmasq_config: String,

    /// Name of the DNS process to send SIGHUP to after updating the hosts file
    #[arg(long, env = "LANFORGE_DNS_PROCESS", default_value = "pihole-FTL")]
    pub dns_process: String,

    /// Debounce window in seconds: coalesces rapid NDP events into a single scan
    #[arg(long, env = "LANFORGE_DEBOUNCE_SECS", default_value_t = 2)]
    pub debounce_secs: u64,

    /// Interval in minutes for a periodic fallback full scan (guards against missed events)
    #[arg(long, env = "LANFORGE_FALLBACK_MINS", default_value_t = 5)]
    pub fallback_mins: u64,

    // ── Router Advertisement service ─────────────────────────────────────

    /// Enable the RA service (replaces radvd)
    #[arg(long, env = "LANFORGE_RA_ENABLED", default_value_t = false)]
    pub ra_enabled: bool,

    /// LAN interface for RA (ex: "end0")
    #[arg(long, env = "LANFORGE_RA_IFACE", default_value = "end0")]
    pub ra_iface: String,

    /// M flag: clients use DHCPv6 for managed addresses
    #[arg(long, env = "LANFORGE_RA_MANAGED", default_value_t = true)]
    pub ra_managed: bool,

    /// O flag: clients use DHCPv6 for other config (DNS, etc.)
    #[arg(long, env = "LANFORGE_RA_OTHER_CONFIG", default_value_t = true)]
    pub ra_other_config: bool,

    /// MaxRtrAdvInterval in seconds (RFC 4861 §6.2.1: 4–1800)
    #[arg(long, env = "LANFORGE_RA_MAX_INTERVAL", default_value_t = 100)]
    pub ra_max_interval: u64,

    /// Router lifetime in seconds (0 = not default gateway; None → 3 × max_interval)
    #[arg(long, env = "LANFORGE_RA_ROUTER_LIFETIME")]
    pub ra_router_lifetime: Option<u64>,

    /// MTU to announce (relevant for PPPoE = 1492)
    #[arg(long, env = "LANFORGE_RA_MTU")]
    pub ra_mtu: Option<u32>,

    /// ULA prefix to announce (ex: "fd97:f00d:cafe:3731::")
    #[arg(long, env = "LANFORGE_RA_ULA_PREFIX")]
    pub ra_ula_prefix: Option<String>,

    /// Announce auto-detected GUA prefix from the interface
    #[arg(long, env = "LANFORGE_RA_AUTO_GUA", default_value_t = true)]
    pub ra_auto_gua: bool,

    /// DNS servers for RDNSS option (comma-separated IPv6 addresses)
    #[arg(long, env = "LANFORGE_RA_RDNSS", value_delimiter = ',')]
    pub ra_rdnss: Vec<Ipv6Addr>,
}

impl Config {
    /// Builds an `RaConfig` from the CLI/env configuration.
    pub fn to_ra_config(&self) -> crate::ra::RaConfig {
        use crate::ra::*;

        let mut prefixes = Vec::new();

        if let Some(ref ula) = self.ra_ula_prefix {
            prefixes.push(PrefixConfig::ula(ula));
        }

        if self.ra_auto_gua {
            prefixes.push(PrefixConfig::gua_dynamic());
        }

        let rdnss = if self.ra_rdnss.is_empty() {
            Vec::new()
        } else {
            vec![RdnssConfig::new(self.ra_rdnss.clone())]
        };

        RaConfig {
            iface: self.ra_iface.clone(),
            managed: self.ra_managed,
            other_config: self.ra_other_config,
            max_interval: Duration::from_secs(self.ra_max_interval),
            router_lifetime: self.ra_router_lifetime.map(Duration::from_secs),
            mtu: self.ra_mtu,
            prefixes,
            rdnss,
            ..Default::default()
        }
    }
}
