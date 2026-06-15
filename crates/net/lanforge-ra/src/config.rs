//! Configuration types for the Router Advertisement (RA) service.
//!
//! All parameters follow the limits defined in the following RFCs:
//! - RFC 4861 §6.2.1 — Intervals and lifetimes
//! - RFC 4191 §2.1   — Router priority
//! - RFC 8106         — RDNSS and DNSSL

use crate::error::NetworkError;
use lanforge_macros::ServiceConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig};
use serde::{Deserialize, Serialize};
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
    pub prefixes: Vec<RAPrefix>,
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
    pub prefixes: Vec<RAPrefix>,
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
    /// use lanforge_ra::config::RaConfig;
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
