//! Configuration types for the Router Advertisement (RA) service.
//!
//! All parameters follow the limits defined in the following RFCs:
//! - RFC 4861 §6.2.1 — Intervals and lifetimes
//! - RFC 4191 §2.1   — Router priority
//! - RFC 8106         — RDNSS and DNSSL

use crate::error::{NetworkError, Result};
use std::time::Duration;

// ---------------------------------------------------------------------------
// RFC 4861 §6.2.1 Constants
// ---------------------------------------------------------------------------

/// Default ratio of `MinRtrAdvInterval` / `MaxRtrAdvInterval` (§6.2.1).
pub const DEFAULT_MIN_MAX_RATIO: f64 = 1.0 / 3.0;

/// Default `RouterLifetime` multiplier = 3 × `MaxRtrAdvInterval`.
pub const DEFAULT_ROUTER_LIFETIME_MULTIPLIER: u64 = 3;

/// Default prefix valid lifetime: 30 days (§6.3.1).
pub const DEFAULT_VALID_LIFETIME_SECS: u32 = 30 * 24 * 3600;

/// Default prefix preferred lifetime: 7 days (§6.3.1).
pub const DEFAULT_PREFERRED_LIFETIME_SECS: u32 = 7 * 24 * 3600;

/// "Infinite" lifetime value for prefix fields (`0xFFFF_FFFF`).
pub const LIFETIME_INFINITY: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// Configuration Types
// ---------------------------------------------------------------------------

/// Default router priority (RFC 4191 §2.1).
/// Influences which router is preferred when multiple are present on the network.
#[derive(Debug, Clone, Copy, Default)]
pub enum RouterPriority {
    Low,
    #[default]
    Medium,
    High,
}

impl RouterPriority {
    /// Priority bits in the RA flags byte (bits 3–4).
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::Low => 0b0001_1000,
            Self::Medium => 0b0000_0000,
            Self::High => 0b0000_1000,
        }
    }
}

/// Lifetime for a prefix — finite in seconds or infinite.
#[derive(Debug, Clone, Copy)]
pub enum PrefixLifetime {
    Secs(u32),
    Infinity,
}

impl PrefixLifetime {
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Secs(s) => s,
            Self::Infinity => LIFETIME_INFINITY,
        }
    }
}

/// Source of the IPv6 address for the Prefix Information option.
#[derive(Debug, Clone)]
pub enum PrefixSource {
    /// Static prefix — explicit address (e.g., a fixed ULA).
    Static(std::net::Ipv6Addr),
    /// Automatically detects the GUA (`2000::/3`) assigned to the interface.
    /// Equivalent to `prefix ::/64` in radvd with dynamic resolution.
    /// If no GUA is assigned, the option is silently omitted.
    AutoGua,
}

/// Configuration for an IPv6 prefix to be advertised (Option type 3, RFC 4861 §4.6.2).
#[derive(Debug, Clone)]
pub struct PrefixConfig {
    pub source: PrefixSource,
    /// Prefix length in bits. For SLAAC, this must be 64.
    pub prefix_len: u8,
    /// L=1 (on-link): clients can communicate directly within this prefix.
    pub on_link: bool,
    /// A=1 (autonomous): enables SLAAC — clients form addresses via EUI-64 or privacy extensions.
    pub autonomous: bool,
    /// R=1 (RFC 3775): router address; only relevant for Mobile IPv6.
    pub router_addr: bool,
    pub valid_lifetime: PrefixLifetime,
    pub preferred_lifetime: PrefixLifetime,
}

impl PrefixConfig {
    /// ULA prefix with recommended defaults (valid=24h, preferred=4h).
    #[must_use]
    pub fn ula(prefix: &str) -> Self {
        Self {
            source: PrefixSource::Static(prefix.parse().expect("Invalid ULA address")),
            prefix_len: 64,
            on_link: true,
            autonomous: true,
            router_addr: true,
            valid_lifetime: PrefixLifetime::Secs(86400),
            preferred_lifetime: PrefixLifetime::Secs(14400),
        }
    }

    /// GUA prefix detected dynamically from the interface.
    #[must_use]
    pub const fn gua_dynamic() -> Self {
        Self {
            source: PrefixSource::AutoGua,
            prefix_len: 64,
            on_link: true,
            autonomous: true,
            router_addr: true,
            valid_lifetime: PrefixLifetime::Secs(DEFAULT_VALID_LIFETIME_SECS),
            preferred_lifetime: PrefixLifetime::Secs(DEFAULT_PREFERRED_LIFETIME_SECS),
        }
    }
}

/// DNS Servers via RDNSS (RFC 8106 §3.1, option type 25).
/// Essential for clients that ignore `DHCPv6` (e.g., Android, many `IoT` devices).
#[derive(Debug, Clone)]
pub struct RdnssConfig {
    pub servers: Vec<std::net::Ipv6Addr>,
    /// None → 2 × `MaxRtrAdvInterval` (RFC 8106 §5.1: recommended minimum to
    /// survive lost RAs; in practice, use >= 6 × `MaxRtrAdvInterval`).
    pub lifetime: Option<Duration>,
}

impl RdnssConfig {
    #[must_use]
    pub const fn new(servers: Vec<std::net::Ipv6Addr>) -> Self {
        Self {
            servers,
            lifetime: None,
        }
    }

    #[must_use]
    pub const fn with_lifetime(servers: Vec<std::net::Ipv6Addr>, secs: u32) -> Self {
        Self {
            servers,
            lifetime: Some(Duration::from_secs(secs as u64)),
        }
    }
}

/// DNS Search Lists via DNSSL (RFC 8106 §3.2, option type 31).
#[derive(Debug, Clone)]
pub struct DnsslConfig {
    pub domains: Vec<String>,
    /// None → same policy as RDNSS (2 × `MaxRtrAdvInterval`).
    pub lifetime: Option<Duration>,
}

/// Full RA service configuration for an interface.
#[derive(Debug, Clone)]
pub struct RaConfig {
    /// Network interface name (e.g., "eth0").
    pub iface: String,

    /// M=1: Clients should use `DHCPv6` for managed address configuration (RFC 4861 §4.2).
    pub managed: bool,
    /// O=1: Clients seek DNS and other options via stateless `DHCPv6` (RFC 4861 §4.2).
    pub other_config: bool,

    /// Suggested hop limit for clients' unicast traffic (0 = unspecified).
    pub hop_limit: u8,
    /// Default router priority (RFC 4191).
    pub priority: RouterPriority,

    /// `MaxRtrAdvInterval`: RFC 4861 §6.2.1 — between 4s and 1800s; default: 200s.
    pub max_interval: Duration,
    /// `MinRtrAdvInterval`: None → 0.33 × `max_interval`, minimum 3s.
    /// RFC 4861: between 3s and 0.75 × `MaxRtrAdvInterval`.
    pub min_interval: Option<Duration>,

    /// `RouterLifetime`: None → 3 × `MaxRtrAdvInterval`.
    /// 0 → This router is not a default gateway (clients won't use it for external routing).
    /// RFC 4861: must be 0 or in the range [`MaxRtrAdvInterval`, 9000s].
    pub router_lifetime: Option<Duration>,

    /// MTU to announce (Option type 5, RFC 4861 §4.6.4).
    /// Relevant when the WAN bandwidth has an MTU < 1500 (e.g., `PPPoE` = 1492 bytes).
    pub mtu: Option<u32>,

    /// IPv6 prefixes to advertise (Option type 3).
    pub prefixes: Vec<PrefixConfig>,
    /// DNS servers via RDNSS (Option type 25).
    pub rdnss: Vec<RdnssConfig>,
    /// DNS search lists via DNSSL (Option type 31).
    pub dnssl: Vec<DnsslConfig>,
}

impl Default for RaConfig {
    fn default() -> Self {
        Self {
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
    /// Calculates effective `MinRtrAdvInterval` respecting the limits of RFC 4861 §6.2.1.
    #[must_use]
    pub fn effective_min_interval(&self) -> Duration {
        self.min_interval.unwrap_or_else(|| {
            let float_secs = self.max_interval.as_secs_f64() * DEFAULT_MIN_MAX_RATIO;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let secs = float_secs.max(3.0).floor() as u64;
            Duration::from_secs(secs)
        })
    }

    /// Calculates effective `RouterLifetime`.
    #[must_use]
    pub fn effective_router_lifetime(&self) -> Duration {
        self.router_lifetime.unwrap_or_else(|| {
            Duration::from_secs(self.max_interval.as_secs() * DEFAULT_ROUTER_LIFETIME_MULTIPLIER)
        })
    }

    /// Validates all RFC constraints before starting the service.
    ///
    /// # Example
    /// ```
    /// use lanforge_network::ra::RaConfig;
    /// use std::time::Duration;
    ///
    /// let mut cfg = RaConfig::default();
    /// cfg.max_interval = Duration::from_secs(3); // Too low (RFC minimum is 4s)
    /// assert!(cfg.validate().is_err());
    /// ```
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    pub fn validate(&self) -> Result<()> {
        let max = self.max_interval.as_secs();
        if !(4..=1800).contains(&max) {
            return Err(NetworkError::Config(format!(
                "max_interval={max}s out of range [4, 1800] (RFC 4861 §6.2.1)"
            )));
        }

        let min = self.effective_min_interval().as_secs();
        if min < 3 {
            return Err(NetworkError::Config(format!(
                "min_interval={min}s < 3s minimum (RFC 4861 §6.2.1)"
            )));
        }

        let max_float = max as f64;
        let limit = (max_float * 0.75).floor() as u64;
        if min > limit {
            return Err(NetworkError::Config(format!(
                "min_interval={min}s > 0.75 * max_interval={max}s (RFC 4861 §6.2.1)"
            )));
        }

        let rl = self.effective_router_lifetime().as_secs();
        if rl != 0 && (rl < max || rl > 9000) {
            return Err(NetworkError::Config(format!(
                "router_lifetime={rl}s must be 0 or in range [max_interval={max}s, 9000s] (RFC 4861 §4.2)"
            )));
        }

        if let Some(mtu) = self.mtu
            && mtu < 1280
        {
            return Err(NetworkError::Config(format!(
                "mtu={mtu} < 1280 (IPv6 minimum, RFC 8200 §5)"
            )));
        }

        Ok(())
    }
}
