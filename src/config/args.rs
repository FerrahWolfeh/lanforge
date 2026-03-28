use clap::{Parser, Subcommand};

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Start all enabled services (default behavior)
    Run {
        /// Run only a specific subsystem (e.g. ra, dhcpv4, dhcpv6, dns, slaac)
        #[arg(long)]
        only: Option<String>,
    },
    /// List known devices
    Devices {
        #[arg(short, long)]
        verbose: bool,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        format: Option<String>,
    },
    /// Live view reativo via socket (sem polling)
    Watch,
    /// Service health and general status
    Status,
    /// `EventBus` interno em tempo real
    Log {
        #[arg(long)]
        follow: bool,
    },
    /// Gerenciamento de leases (renew/release)
    Lease {
        #[command(subcommand)]
        action: LeaseCommand,
    },
    /// Dispara ciclo NDP imediato com feedback
    Scan,
    /// Gerenciamento de devices customizados
    Host {
        #[command(subcommand)]
        action: HostCommand,
    },
    /// Send reload signal to running daemon (recarrega config estática do TOML)
    Reload,
    /// Gerenciamento de persistência
    Db {
        #[command(subcommand)]
        action: DbCommand,
    },
    /// Encerramento gracioso com flush imediato
    Shutdown,
    /// Forcefully purge a device from memory and database by its MAC
    Purge {
        /// MAC address of the device to purge
        mac: String,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum LeaseCommand {
    Renew { mac: String },
    Release { mac: String },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum HostCommand {
    Add {
        /// Prefix MAC with this argument, or run interactively
        mac: Option<String>,
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        v4: Option<String>,
        #[arg(long)]
        v6_suffix: Option<String>,
    },
    Set {
        mac: String,
        field: String,
        value: String,
    },
    List,
    Remove {
        mac: String,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DbCommand {
    Vacuum,
}

#[derive(Parser, Debug)]
#[command(name = "lanforge", version, about, long_about = None)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Caminho para o arquivo de configuração TOML.
    #[arg(
        short,
        long,
        env = "LANFORGE_CONFIG",
        default_value = "/etc/lanforge/lanforge.toml"
    )]
    pub config: String,

    /// Caminho para o banco de dados SQLite (leases).
    #[arg(short = 'd', long, env = "LANFORGE_DB_PATH")]
    pub db_path: Option<String>,

    /// Caminho para o banco de dados SQLite de logs (history).
    #[arg(
        long,
        env = "LANFORGE_LOG_DB",
        default_value = "/tmp/lanforge_logs.db"
    )]
    pub log_db: String,

    /// Caminho para um arquivo TOML/JSON adicional contendo apenas devices estáticos (debug).

    #[arg(long, env = "LANFORGE_DEVICES_FILE")]
    pub devices_file: Option<String>,

    // ── Overrides Gerais ──────────────────────────────────────────────────
    /// Interface LAN principal (ex: end0, eth0).
    #[arg(short = 'i', long, env = "LANFORGE_IFACE_LAN")]
    pub iface_lan: Option<String>,

    /// Prefixo IPv6 local para rastreamento SLAAC.
    #[arg(long, env = "LANFORGE_TARGET_PREFIX")]
    pub target_prefix: Option<String>,

    /// Janela de debounce em segundos para scans após eventos de rede.
    #[arg(long, env = "LANFORGE_DEBOUNCE_SECS")]
    pub debounce_secs: Option<u64>,

    /// Intervalo de scan periódico (fallback) em minutos.
    #[arg(long, env = "LANFORGE_FALLBACK_MINS")]
    pub fallback_mins: Option<u64>,

    // ── Router Advertisements (RA) ────────────────────────────────────────
    /// Habilita ou desabilita o serviço de Router Advertisements.
    #[arg(long, env = "LANFORGE_RA_ENABLED")]
    pub ra_enabled: Option<bool>,

    /// Define o flag 'Managed Address Configuration' (M) no RA.
    #[arg(long, env = "LANFORGE_RA_MANAGED")]
    pub ra_managed: Option<bool>,

    /// Define o flag 'Other Configuration' (O) no RA.
    #[arg(long, env = "LANFORGE_RA_OTHER")]
    pub ra_other_config: Option<bool>,

    /// Intervalo máximo entre RAs periódicos (segundos).
    #[arg(long, env = "LANFORGE_RA_MAX_INTERVAL")]
    pub ra_max_interval: Option<u64>,

    // ── DHCPv4 ────────────────────────────────────────────────────────────
    /// Habilita o servidor DHCPv4.
    #[arg(long, env = "LANFORGE_DHCPV4_ENABLED")]
    pub dhcpv4_enabled: Option<bool>,

    /// Primeiro IP do pool DHCPv4.
    #[arg(long, env = "LANFORGE_DHCPV4_START")]
    pub dhcpv4_range_start: Option<String>,

    /// Último IP do pool DHCPv4.
    #[arg(long, env = "LANFORGE_DHCPV4_END")]
    pub dhcpv4_range_end: Option<String>,

    /// Tempo de lease padrão (segundos).
    #[arg(long, env = "LANFORGE_DHCPV4_LEASE")]
    pub dhcpv4_lease_time: Option<u32>,

    /// Porta UDP do servidor DHCPv4 (default 67).
    #[arg(long, env = "LANFORGE_DHCPV4_PORT")]
    pub dhcpv4_port: Option<u16>,

    // ── DHCPv6 ────────────────────────────────────────────────────────────
    /// Habilita o servidor DHCPv6.
    #[arg(long, env = "LANFORGE_DHCPV6_ENABLED")]
    pub dhcpv6_enabled: Option<bool>,

    /// Porta UDP do servidor DHCPv6 (default 547).
    #[arg(long, env = "LANFORGE_DHCPV6_PORT")]
    pub dhcpv6_port: Option<u16>,

    // ── DNS ───────────────────────────────────────────────────────────────
    /// Habilita o servidor DNS autoritativo/recursivo.
    #[arg(long, env = "LANFORGE_DNS_ENABLED")]
    pub dns_enabled: Option<bool>,

    /// Endereço de escuta DNS (ex: 0.0.0.0:5353).
    #[arg(long, env = "LANFORGE_DNS_LISTEN")]
    pub dns_listen: Option<String>,

    /// Resolver upstream (ex: 8.8.8.8:53).
    #[arg(short = 'u', long, env = "LANFORGE_DNS_UPSTREAM")]
    pub dns_upstream: Option<String>,

    /// Porta de escuta DNS (override de porta no listen).
    #[arg(short = 'p', long, env = "LANFORGE_DNS_PORT")]
    pub dns_port: Option<u16>,

    // ── API / Control ─────────────────────────────────────────────────────
    /// Caminho para o socket de controle UDS.
    #[arg(long, env = "LANFORGE_CONTROL_SOCKET")]
    pub control_socket: Option<String>,

    /// Porta TCP para a API de controle (opcional para debug remoto).
    #[arg(long, env = "LANFORGE_CONTROL_PORT")]
    pub control_port: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_args_parsing() {
        // Just verify it doesn't panic on a simple case
        let args = CliArgs::try_parse_from(["lanforge", "status"]);
        assert!(args.is_ok());
        let args = args.unwrap();
        assert_eq!(args.command, Some(Command::Status));
    }
}
