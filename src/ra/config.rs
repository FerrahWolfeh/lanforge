//! Tipos de configuração do serviço de Router Advertisement.
//!
//! Todos os parâmetros seguem os limites definidos nas RFCs:
//! - RFC 4861 §6.2.1 — intervalos e lifetimes
//! - RFC 4191 §2.1   — prioridade do roteador
//! - RFC 8106         — RDNSS e DNSSL

use anyhow::{Result, anyhow};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Constantes RFC 4861 §6.2.1
// ---------------------------------------------------------------------------

/// Razão padrão MinRtrAdvInterval / MaxRtrAdvInterval (§6.2.1).
pub(crate) const DEFAULT_MIN_MAX_RATIO: f64 = 1.0 / 3.0;

/// RouterLifetime padrão = 3 × MaxRtrAdvInterval.
pub(crate) const DEFAULT_ROUTER_LIFETIME_MULTIPLIER: u64 = 3;

/// Prefixo default valid lifetime: 30 dias (§6.3.1).
pub const DEFAULT_VALID_LIFETIME_SECS: u32 = 30 * 24 * 3600;

/// Prefixo default preferred lifetime: 7 dias (§6.3.1).
pub const DEFAULT_PREFERRED_LIFETIME_SECS: u32 = 7 * 24 * 3600;

/// Valor de lifetime "infinito" nos campos de prefixo (0xFFFF_FFFF).
pub const LIFETIME_INFINITY: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// Tipos de configuração
// ---------------------------------------------------------------------------

/// Prioridade do roteador padrão (RFC 4191 §2.1).
/// Influencia qual roteador é preferido quando há múltiplos na rede.
#[derive(Debug, Clone, Copy, Default)]
#[allow(dead_code)]
pub enum RouterPriority {
    Low,
    #[default]
    Medium,
    High,
}

impl RouterPriority {
    /// Bits de prioridade no byte de flags do RA (bits 3–4).
    pub fn bits(self) -> u8 {
        match self {
            RouterPriority::Low => 0b0001_1000,
            RouterPriority::Medium => 0b0000_0000,
            RouterPriority::High => 0b0000_1000,
        }
    }
}

/// Lifetime de um prefixo — finito em segundos ou infinito.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum PrefixLifetime {
    Secs(u32),
    Infinity,
}

impl PrefixLifetime {
    pub fn as_u32(self) -> u32 {
        match self {
            PrefixLifetime::Secs(s) => s,
            PrefixLifetime::Infinity => LIFETIME_INFINITY,
        }
    }
}

/// Origem do endereço IPv6 para a opção Prefix Information.
#[derive(Debug, Clone)]
pub enum PrefixSource {
    /// Prefixo estático — endereço explícito (ex: ULA fixo).
    Static(std::net::Ipv6Addr),
    /// Detecta automaticamente o GUA (2000::/3) atribuído à interface.
    /// Equivalente ao `prefix ::/64` do radvd com resolução dinâmica.
    /// Se não houver GUA atribuído, a opção é omitida silenciosamente.
    AutoGua,
}

/// Configuração de um prefixo IPv6 a ser anunciado (opção tipo 3, RFC 4861 §4.6.2).
#[derive(Debug, Clone)]
pub struct PrefixConfig {
    pub source: PrefixSource,
    /// Comprimento do prefixo em bits. Para SLAAC deve ser 64.
    pub prefix_len: u8,
    /// L=1 (on-link): clientes podem se comunicar diretamente neste prefixo.
    pub on_link: bool,
    /// A=1 (autonomous): habilita SLAAC — clientes formam endereço com EUI-64/privacidade.
    pub autonomous: bool,
    /// R=1 (RFC 3775): endereço do roteador; relevante apenas para Mobile IPv6.
    pub router_addr: bool,
    pub valid_lifetime: PrefixLifetime,
    pub preferred_lifetime: PrefixLifetime,
}

impl PrefixConfig {
    /// Prefixo ULA com defaults recomendados (valid=24h, preferred=4h).
    pub fn ula(prefix: &str) -> Self {
        PrefixConfig {
            source: PrefixSource::Static(prefix.parse().expect("endereço ULA inválido")),
            prefix_len: 64,
            on_link: true,
            autonomous: true,
            router_addr: true,
            valid_lifetime: PrefixLifetime::Secs(86400),
            preferred_lifetime: PrefixLifetime::Secs(14400),
        }
    }

    /// Prefixo GUA detectado dinamicamente da interface.
    pub fn gua_dynamic() -> Self {
        PrefixConfig {
            source: PrefixSource::AutoGua,
            prefix_len: 64,
            on_link: true,
            autonomous: true,
            router_addr: true,
            valid_lifetime: PrefixLifetime::Secs(DEFAULT_VALID_LIFETIME_SECS),
            preferred_lifetime: PrefixLifetime::Secs(DEFAULT_PREFERRED_LIFETIME_SECS),
        }
    }

    /// Prefixo estático com controle total dos parâmetros.
    #[allow(dead_code)]
    pub fn static_full(
        prefix: std::net::Ipv6Addr,
        on_link: bool,
        autonomous: bool,
        valid: u32,
        preferred: u32,
    ) -> Self {
        PrefixConfig {
            source: PrefixSource::Static(prefix),
            prefix_len: 64,
            on_link,
            autonomous,
            router_addr: true,
            valid_lifetime: PrefixLifetime::Secs(valid),
            preferred_lifetime: PrefixLifetime::Secs(preferred),
        }
    }
}

/// Servidores DNS via RDNSS (RFC 8106 §3.1, opção tipo 25).
/// Essencial para clientes que ignoram DHCPv6 (Android, muitos IoT).
#[derive(Debug, Clone)]
pub struct RdnssConfig {
    pub servers: Vec<std::net::Ipv6Addr>,
    /// None → 2 × MaxRtrAdvInterval (RFC 8106 §5.1: mínimo recomendado para
    /// sobreviver a RAs perdidos; na prática usar >= 6 × MaxRtrAdvInterval).
    pub lifetime: Option<Duration>,
}

impl RdnssConfig {
    pub fn new(servers: Vec<std::net::Ipv6Addr>) -> Self {
        RdnssConfig {
            servers,
            lifetime: None,
        }
    }
    pub fn with_lifetime(servers: Vec<std::net::Ipv6Addr>, secs: u32) -> Self {
        RdnssConfig {
            servers,
            lifetime: Some(Duration::from_secs(secs as u64)),
        }
    }
}

/// Sufixos de busca DNS via DNSSL (RFC 8106 §3.2, opção tipo 31).
#[derive(Debug, Clone)]
pub struct DnsslConfig {
    pub domains: Vec<String>,
    /// None → mesma política do RDNSS (2 × MaxRtrAdvInterval).
    pub lifetime: Option<Duration>,
}

/// Configuração completa do serviço de RA para uma interface.
#[derive(Debug, Clone)]
pub struct RaConfig {
    /// Interface de rede (ex: "end0").
    pub iface: String,

    /// M=1: clientes devem usar DHCPv6 para endereço gerenciado (RFC 4861 §4.2).
    pub managed: bool,
    /// O=1: clientes buscam DNS e outras opções via DHCPv6 (RFC 4861 §4.2).
    pub other_config: bool,

    /// Hop limit sugerido para tráfego unicast dos clientes (0 = não especificado).
    pub hop_limit: u8,
    /// Prioridade do roteador padrão (RFC 4191).
    pub priority: RouterPriority,

    /// MaxRtrAdvInterval: RFC 4861 §6.2.1 — entre 4s e 1800s; default: 200s.
    pub max_interval: Duration,
    /// MinRtrAdvInterval: None → 0.33 × max_interval, mínimo 3s.
    /// RFC 4861: entre 3s e 0.75 × MaxRtrAdvInterval.
    pub min_interval: Option<Duration>,

    /// RouterLifetime: None → 3 × MaxRtrAdvInterval.
    /// 0 → este roteador não é default gateway (clientes não o usam para fora da LAN).
    /// RFC 4861: deve ser 0 ou em [MaxRtrAdvInterval, 9000s].
    pub router_lifetime: Option<Duration>,

    /// MTU a anunciar (opção tipo 5, RFC 4861 §4.6.4).
    /// Relevante quando a WAN tem MTU < 1500 (ex: PPPoE = 1492 bytes).
    pub mtu: Option<u32>,

    /// Prefixos IPv6 a anunciar (opção tipo 3).
    pub prefixes: Vec<PrefixConfig>,
    /// Servidores DNS via RDNSS (opção tipo 25).
    pub rdnss: Vec<RdnssConfig>,
    /// Sufixos de busca DNS via DNSSL (opção tipo 31).
    pub dnssl: Vec<DnsslConfig>,
}

impl Default for RaConfig {
    fn default() -> Self {
        RaConfig {
            iface: "end0".into(),
            managed: false,
            other_config: false,
            hop_limit: 64,
            priority: RouterPriority::Medium,
            max_interval: Duration::from_secs(200),
            min_interval: None,
            router_lifetime: None,
            mtu: None,
            prefixes: Vec::new(),
            rdnss: Vec::new(),
            dnssl: Vec::new(),
        }
    }
}

impl RaConfig {
    /// Calcula MinRtrAdvInterval efetivo respeitando os limites da RFC 4861 §6.2.1.
    pub fn effective_min_interval(&self) -> Duration {
        self.min_interval.unwrap_or_else(|| {
            let secs = (self.max_interval.as_secs_f64() * DEFAULT_MIN_MAX_RATIO).max(3.0) as u64;
            Duration::from_secs(secs)
        })
    }

    /// Calcula RouterLifetime efetivo.
    pub fn effective_router_lifetime(&self) -> Duration {
        self.router_lifetime.unwrap_or_else(|| {
            Duration::from_secs(self.max_interval.as_secs() * DEFAULT_ROUTER_LIFETIME_MULTIPLIER)
        })
    }

    /// Valida todas as restrições das RFCs antes de iniciar o serviço.
    pub fn validate(&self) -> Result<()> {
        let max = self.max_interval.as_secs();
        if !(4..=1800).contains(&max) {
            return Err(anyhow!(
                "max_interval={max}s fora de [4, 1800] (RFC 4861 §6.2.1)"
            ));
        }

        let min = self.effective_min_interval().as_secs();
        if min < 3 {
            return Err(anyhow!("min_interval={min}s < 3s mínimo (RFC 4861 §6.2.1)"));
        }
        if min > (max as f64 * 0.75) as u64 {
            return Err(anyhow!(
                "min_interval={min}s > 0.75 * max_interval={max}s (RFC 4861 §6.2.1)"
            ));
        }

        let rl = self.effective_router_lifetime().as_secs();
        if rl != 0 && (rl < max || rl > 9000) {
            return Err(anyhow!(
                "router_lifetime={rl}s deve ser 0 ou em [max_interval={max}s, 9000s] (RFC 4861 §4.2)"
            ));
        }

        if let Some(mtu) = self.mtu
            && mtu < 1280
        {
            return Err(anyhow!("mtu={mtu} < 1280 (mínimo IPv6, RFC 8200 §5)"));
        }

        Ok(())
    }
}
