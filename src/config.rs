//! Configuração do lanforge — CLI + env + arquivo TOML.
//!
//! Três camadas em ordem crescente de precedência:
//! 1. Valores default hardcoded no código
//! 2. Arquivo TOML (futuro — Fase 1+)
//! 3. Variáveis de ambiente (via clap `env`)
//!
//! Atualmente mantém apenas a configuração do tracker SLAAC original (CLI/env).
//! Nas fases seguintes, será expandido com suporte a TOML e config completa.

use clap::Parser;

/// lanforge — daemon unificado de controle de rede IPv4/IPv6.
///
/// All options can also be supplied via the matching environment variable.
#[derive(Parser, Debug)]
#[command(name = "lanforge", version, about, long_about = None)]
pub struct Config {
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
}
