//! Configuration types for the Router Advertisement (RA) service.
//!
//! All parameters follow the limits defined in the following RFCs:
//! - RFC 4861 §6.2.1 — Intervals and lifetimes
//! - RFC 4191 §2.1   — Router priority
//! - RFC 8106         — RDNSS and DNSSL

use crate::error::NetworkError;
use lanforge_macros::ServiceConfig;
use serde::{Deserialize, Serialize};
use std::{net::Ipv6Addr, str::FromStr, time::Duration};

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
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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
///
/// Maps to the `ValidLifetime` and `PreferredLifetime` fields
/// in the Prefix Information Option (RFC 4861 §4.6.2).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "String", into = "String")]
pub enum PrefixLifetime {
    /// Finite lifetime in seconds.
    Secs(u32),
    /// Infinite lifetime (`0xFFFF_FFFF`).
    Infinity,
}

impl FromStr for PrefixLifetime {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("infinity") || s.eq_ignore_ascii_case("infinite") {
            Ok(Self::Infinity)
        } else if let Ok(secs) = s.parse::<u32>() {
            Ok(Self::Secs(secs))
        } else {
            // Try parsing as duration string (e.g. "24h")
            let dur = parse_duration(s)?;
            Ok(Self::Secs(
                u32::try_from(dur.as_secs()).map_err(|_| "Duration too long".to_string())?,
            ))
        }
    }
}

impl From<PrefixLifetime> for String {
    fn from(lt: PrefixLifetime) -> Self {
        match lt {
            PrefixLifetime::Infinity => "infinity".to_string(),
            PrefixLifetime::Secs(s) => s.to_string(),
        }
    }
}

impl TryFrom<String> for PrefixLifetime {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

fn parse_duration(s: &str) -> Result<Duration, String> {
    if s.is_empty() {
        return Err("Empty duration".to_string());
    }

    let (num_part, unit_part) = s.split_at(s.find(|c: char| !c.is_numeric()).unwrap_or(s.len()));
    let num: u64 = num_part
        .parse()
        .map_err(|_| format!("Invalid number in duration '{s}'"))?;

    match unit_part.to_lowercase().as_str() {
        "s" | "" => Ok(Duration::from_secs(num)),
        "m" => Ok(Duration::from_secs(num * 60)),
        "h" => Ok(Duration::from_secs(num * 3600)),
        "d" => Ok(Duration::from_secs(num * 86400)),
        "w" => Ok(Duration::from_secs(num * 86400 * 7)),
        _ => Err(format!("Unknown duration unit '{unit_part}'")),
    }
}

impl Default for PrefixLifetime {
    fn default() -> Self {
        Self::Secs(0)
    }
}

impl PrefixLifetime {
    /// Converts to the raw `u32` value used in the RA packet.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Secs(s) => s,
            Self::Infinity => LIFETIME_INFINITY,
        }
    }
}

/// Source of the IPv6 address for the Prefix Information option.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrefixSource {
    /// Static prefix — explicit address (e.g., a fixed ULA).
    Static,
    /// Alias for Static, often used for ULAs.
    Ula,
    /// Automatically detects the GUA (`2000::/3`) assigned to the interface.
    /// Equivalent to `prefix ::/64` in radvd with dynamic resolution.
    /// If no GUA is assigned, the option is silently omitted.
    #[default]
    AutoGua,
}

/// Configuration for an IPv6 prefix to be advertised in RA packets.
///
/// Generates a **Prefix Information Option** (type 3, RFC 4861 §4.6.2).
///
/// # Key Flags
///
/// | Flag | Field | Effect |
/// | :--- | :--- | :--- |
/// | L | `on_link` | Clients treat addresses in this prefix as on-link neighbors |
/// | A | `autonomous` | Enables SLAAC — clients autoconfigure addresses via EUI-64 |
/// | R | `router_addr` | This address is the router's own address (Mobile IPv6, RFC 3775) |
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct PrefixConfig {
    pub source: PrefixSource,
    /// IPv6 address or prefix (e.g., "`fd00::/64`").
    /// Required when source is "static" or "ula".
    pub address: Option<String>,
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
            source: PrefixSource::Ula,
            address: Some(prefix.to_string()),
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
            address: None,
            prefix_len: 64,
            on_link: true,
            autonomous: true,
            router_addr: true,
            valid_lifetime: PrefixLifetime::Secs(DEFAULT_VALID_LIFETIME_SECS),
            preferred_lifetime: PrefixLifetime::Secs(DEFAULT_PREFERRED_LIFETIME_SECS),
        }
    }

    /// Resolves the IPv6 address from the `address` field, handling CIDR notation.
    #[must_use]
    pub fn resolved_address(&self) -> Option<Ipv6Addr> {
        self.address.as_ref().and_then(|s| {
            let addr_part = s.split('/').next()?;
            addr_part.parse().ok()
        })
    }
}

/// DNS Servers via RDNSS (RFC 8106 §3.1, option type 25).
/// Essential for clients that ignore `DHCPv6` (e.g., Android, many `IoT` devices).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct RdnssConfig {
    pub servers: Vec<Ipv6Addr>,
    /// None → 2 × `MaxRtrAdvInterval` (RFC 8106 §5.1: recommended minimum to
    /// survive lost RAs; in practice, use >= 6 × `MaxRtrAdvInterval`).
    pub lifetime: Option<Duration>,
}

impl RdnssConfig {
    #[must_use]
    pub const fn new(servers: Vec<Ipv6Addr>) -> Self {
        Self {
            servers,
            lifetime: None,
        }
    }

    #[must_use]
    pub const fn with_lifetime(servers: Vec<Ipv6Addr>, secs: u32) -> Self {
        Self {
            servers,
            lifetime: Some(Duration::from_secs(secs as u64)),
        }
    }
}

/// DNS Search Lists via DNSSL (RFC 8106 §3.2, option type 31).
///
/// Provides domain search suffixes to clients without requiring `DHCPv6`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct DnsslConfig {
    /// Domain names (e.g., `["lan", "home.arpa"]`).
    pub domains: Vec<String>,
    /// None → same policy as RDNSS (2 × `MaxRtrAdvInterval`).
    pub lifetime: Option<Duration>,
}

/// Full RA service configuration for an interface.
///
/// Maps directly to RA packet fields and options per RFC 4861 and RFC 8106.
#[derive(Debug, Clone, Serialize, Deserialize, ServiceConfig)]
#[config(key = "ra")]
#[serde(default)]
pub struct RaConfig {
    /// Network interface name (e.g., `"eth0"`).
    pub iface: String,

    /// M=1: Managed flag — clients should use `DHCPv6` for address assignment (RFC 4861 §4.2).
    pub managed: bool,
    /// O=1: Other config flag — clients should use `DHCPv6` for DNS/options only (RFC 4861 §4.2).
    pub other_config: bool,

    /// Suggested hop limit for clients' unicast traffic (0 = unspecified).
    pub hop_limit: u8,
    /// Default router priority (RFC 4191) — Low, Medium, or High.
    pub priority: RouterPriority,

    /// `MaxRtrAdvInterval`: RFC 4861 §6.2.1 — between 4s and 1800s; default: 200s.
    pub max_interval: Duration,
    /// `MinRtrAdvInterval`: None → 0.33 × `max_interval`, minimum 3s.
    /// RFC 4861: between 3s and 0.75 × `MaxRtrAdvInterval`.
    pub min_interval: Option<Duration>,

    /// `RouterLifetime`: None → 3 × `MaxRtrAdvInterval`.
    /// 0 → This router is not a default gateway.
    /// RFC 4861: must be 0 or in the range [`MaxRtrAdvInterval`, 9000s].
    pub lifetime: Option<Duration>,

    /// `ReachableTime`: RFC 4861 §4.2 — 0 = unspecified.
    pub reachable_time: u32,
    /// `RetransTimer`: RFC 4861 §4.2 — 0 = unspecified.
    pub retrans_timer: u32,

    /// MTU to announce (Option type 5, RFC 4861 §4.6.4).
    /// Relevant when WAN bandwidth has an MTU < 1500 (e.g., `PPPoE` = 1492 bytes).
    pub mtu: Option<u32>,

    /// IPv6 prefixes to advertise (Option type 3 — Prefix Information).
    pub prefixes: Vec<PrefixConfig>,
    /// DNS servers via RDNSS (Option type 25).
    pub rdnss: Vec<RdnssConfig>,
    /// DNS search lists via DNSSL (Option type 31).
    pub dnssl: Vec<DnsslConfig>,
}

/// Simplified RA configuration used in the TOML file.
#[derive(Debug, Clone, Serialize, Deserialize, ServiceConfig, Default)]
#[config(key = "ra")]
#[serde(default)]
pub struct RaServiceConfig {
    pub enabled: bool,
    pub managed: Option<bool>,
    pub other_config: Option<bool>,
    pub hop_limit: Option<u8>,
    pub max_interval: u64,
    pub lifetime: Option<u64>,
    pub reachable_time: Option<u32>,
    pub retrans_timer: Option<u32>,
    pub mtu: Option<u32>,
    #[serde(rename = "prefix")]
    pub prefixes: Vec<PrefixConfig>,
    #[serde(rename = "rdnss")]
    pub rdnss: Vec<RdnssConfig>,
    #[serde(rename = "dnssl")]
    pub dnssl: Vec<DnsslConfig>,
}

impl RaServiceConfig {
    pub fn to_ra_config(&self, iface: String) -> RaConfig {
        RaConfig {
            iface,
            managed: self.managed.unwrap_or(false),
            other_config: self.other_config.unwrap_or(false),
            hop_limit: self.hop_limit.unwrap_or(64),
            priority: RouterPriority::Medium,
            max_interval: Duration::from_secs(self.max_interval),
            min_interval: None,
            lifetime: self.lifetime.map(Duration::from_secs),
            reachable_time: self.reachable_time.unwrap_or(0),
            retrans_timer: self.retrans_timer.unwrap_or(0),
            mtu: self.mtu,
            prefixes: self.prefixes.clone(),
            rdnss: self.rdnss.clone(),
            dnssl: self.dnssl.clone(),
        }
    }
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
            lifetime: None,
            reachable_time: 0,
            retrans_timer: 0,
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
        self.lifetime.unwrap_or_else(|| {
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
    pub fn validate(&self) -> Result<(), NetworkError> {
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
                "lifetime={rl}s must be 0 or in range [max_interval={max}s, 9000s] (RFC 4861 §4.2)"
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
