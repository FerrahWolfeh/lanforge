use serde::Deserialize;
use std::net::Ipv6Addr;
use std::path::Path;
use tracing::{info, warn};

/// Estrutura raiz do arquivo TOML.
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
        Self {
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
        Self {
            enabled: false,
            lease_time: 86400,
            range_start: None,
            range_end: None,
        }
    }
}

/// Configurações gerais do sistema.
#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct GeneralCfg {
    /// Interface LAN onde o daemon escuta.
    pub iface_lan: String,
    /// Caminho para o arquivo de banco de dados `SQLite`.
    pub leases_db: String,
    /// Prefixo IPv6 "alvo" para identificar dispositivos locais (SLAAC).
    pub target_prefix: String,
    /// Tempo de espera antes de processar eventos de rede.
    pub debounce_secs: u64,
    /// Intervalo do scan de fallback.
    pub fallback_mins: u64,
    /// Caminho do socket para a CLI.
    pub control_socket: String,
}

impl Default for GeneralCfg {
    fn default() -> Self {
        Self {
            iface_lan: "end0".into(),
            leases_db: "/var/lib/lanforge/leases.db".into(),
            target_prefix: "fd97:f00d:cafe:3731".into(),
            debounce_secs: 2,
            fallback_mins: 5,
            control_socket: "/run/lanforge/control.sock".into(),
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
        Self {
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
    pub upstream: Option<String>,
    /// Sufixo de domínio local — "lan" faz "archie.lan" resolver para o device "archie"
    pub search_domain: String,
    /// TTL das respostas LAN em segundos
    pub ttl: u32,
}

impl Default for DnsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:5300".into(),
            upstream: None,
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

/// Load and parse the TOML config file, or return defaults if missing.
pub fn load_toml(path: &str) -> TomlConfig {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let default_cfg = TomlConfig::default();
        assert_eq!(default_cfg.general.iface_lan, "end0");
        assert!(!default_cfg.ra.enabled);
        assert_eq!(default_cfg.dns.listen, "0.0.0.0:5300");
    }

    #[test]
    fn test_parse_empty_toml() {
        let content = "";
        let cfg: TomlConfig = toml::from_str(content).unwrap_or_default();
        assert_eq!(cfg.general.iface_lan, "end0"); // should fallback to default values
    }
}
