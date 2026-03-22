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
    /// EventBus interno em tempo real
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
        long,
        env = "LANFORGE_CONFIG",
        default_value = "/etc/lanforge/lanforge.toml"
    )]
    pub config: String,

    // ── Overrides (prevalecem sobre TOML) ─────────────────────────────────
    /// Interface LAN principal (ex: end0, eth0).
    #[arg(long, env = "LANFORGE_IFACE_LAN")]
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

    /// Habilita ou desabilita o serviço de Router Advertisements.
    #[arg(long, env = "LANFORGE_RA_ENABLED")]
    pub ra_enabled: Option<bool>,

    /// Caminho para o socket de controle UDS.
    #[arg(long, env = "LANFORGE_CONTROL_SOCKET")]
    pub control_socket: Option<String>,
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
