//! IPv6 Router Advertisements (RA) types.
//!
//! This module provides configuration structures and helpers for configuring IPv6 Router
//! Advertisements, which are transmitted as part of the Neighbor Discovery Protocol (NDP)
//! under RFC 4861.
//!
//! # Concepts
//!
//! ## Neighbor Discovery Protocol (NDP) & SLAAC
//! In IPv6 networks, routers broadcast Router Advertisement (RA) messages to configure and
//! coordinate network parameters for hosts on the local link. RAs facilitate:
//! - **SLAAC (Stateless Address Autoconfiguration - RFC 4862):** Allows hosts to dynamically configure
//!   their own IPv6 addresses using the advertised prefix(es). This is controlled by the Autonomous (A)
//!   flag in the Prefix Information option.
//!   A prefix length of exactly `/64` is required for SLAAC.
//! - **On-Link Determination:** Controlled by the On-Link (L) flag. If set, hosts assume that any address
//!   matching the prefix is directly reachable on the local link without traversing a router.
//! - **DNS Configuration (RFC 8106):** Allows the router to advertise DNS server addresses (via RDNSS)
//!   and DNS search domains (via DNSSL) directly within RAs, avoiding the need for `DHCPv6` in simple networks.
//!
//! ## Prefix Lifetimes
//! Every advertised prefix is associated with two lifetimes (RFC 4861 §4.6.2):
//! 1. **Valid Lifetime:** The length of time (in seconds or infinite) that the prefix is valid for on-link
//!    determination.
//! 2. **Preferred Lifetime:** The length of time (in seconds or infinite) that addresses generated from
//!    the prefix via SLAAC remain preferred. After expiration, the address becomes deprecated; it can
//!    continue to be used for active connections but must not be used for new outgoing connections.
//!    The preferred lifetime must not exceed the valid lifetime.
//!
//! # Lifetime Durations
//! The [`PrefixLifetime`] enum represents prefix lifetimes. It supports parsing from convenient,
//! human-readable string formats (e.g. `"infinity"`, `"infinite"`, `"30d"`, `"12h"`, `"15m"`, `"30s"`).

use serde::{Deserialize, Serialize};
use std::{net::Ipv6Addr, str::FromStr, time::Duration};

// ---------------------------------------------------------------------------
// RFC 4861 §6.2.1 and §10 Constants
// ---------------------------------------------------------------------------

/// Maximum interval between the initial RAs during startup (§6.2.6).
/// Ensures newly connected clients don't wait for the full `MaxRtrAdvInterval`.
pub const MAX_INITIAL_RTR_ADVERT_INTERVAL: Duration = Duration::from_secs(16);

/// Number of initial RAs sent with a reduced interval (§6.2.6).
pub const MAX_INITIAL_RTR_ADVERTISEMENTS: u8 = 3;

/// Minimum delay between consecutive multicast RAs (§6.2.4).
/// Protects against RA storms when multiple clients solicit simultaneously.
pub const MIN_DELAY_BETWEEN_RAS: Duration = Duration::from_secs(3);

/// Maximum random delay before responding to an RS (§6.2.6), in ms.
pub const MAX_RA_DELAY_TIME_MS: u64 = 500;

/// The default Valid Lifetime (30 days in seconds) for a Prefix Information Option (RFC 4861 §4.6.2).
pub const DEFAULT_VALID_LIFETIME_SECS: u32 = 30 * 24 * 3600;
/// The default Preferred Lifetime (7 days in seconds) for a Prefix Information Option (RFC 4861 §4.6.2).
pub const DEFAULT_PREFERRED_LIFETIME_SECS: u32 = 7 * 24 * 3600;
/// Special value representing an infinite lifetime (all bits set: `0xFFFF_FFFF`).
pub const LIFETIME_INFINITY: u32 = u32::MAX;

/// `ICMPv6` Type for Router Solicitation.
pub const ICMPV6_TYPE_RS: u8 = 133;
/// `ICMPv6` Type for Router Advertisement.
pub const ICMPV6_TYPE_RA: u8 = 134;
/// `ICMPv6` Type for Neighbor Solicitation.
pub const ICMPV6_TYPE_NS: u8 = 135;
/// `ICMPv6` Type for Neighbor Advertisement.
pub const ICMPV6_TYPE_NA: u8 = 136;

/// Lifetime for a prefix — finite in seconds or infinite.
///
/// Maps to the `ValidLifetime` and `PreferredLifetime` fields
/// in the Prefix Information Option (RFC 4861 §4.6.2).
///
/// # Parsing human-readable durations
/// This type can be parsed from strings using [`FromStr`]. It supports:
/// - Case-insensitive `"infinity"` or `"infinite"`
/// - Integer strings representing raw seconds (e.g., `"86400"`)
/// - Standard duration suffix units:
///   - `s` (seconds, e.g. `"30s"`)
///   - `m` (minutes, e.g. `"15m"`)
///   - `h` (hours, e.g. `"12h"`)
///   - `d` (days, e.g. `"7d"`)
///   - `w` (weeks, e.g. `"4w"`)
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
#[serde(into = "String")]
pub enum PrefixLifetime {
    /// Finite lifetime in seconds.
    Secs(u32),
    /// Infinite lifetime (`0xFFFF_FFFF`).
    Infinity,
}

impl<'de> Deserialize<'de> for PrefixLifetime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct LifetimeVisitor;

        impl serde::de::Visitor<'_> for LifetimeVisitor {
            type Value = PrefixLifetime;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an integer number of seconds, or a duration string like '86400', '1d', or 'infinity'")
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let Ok(val) = u64::try_from(v) else {
                    return Err(E::custom("lifetime cannot be negative"));
                };
                self.visit_u64(val)
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v >= u64::from(u32::MAX) {
                    Ok(PrefixLifetime::Infinity)
                } else {
                    let secs = u32::try_from(v).unwrap_or(u32::MAX);
                    Ok(PrefixLifetime::Secs(secs))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                PrefixLifetime::from_str(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(LifetimeVisitor)
    }
}

impl FromStr for PrefixLifetime {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("infinity") || s.eq_ignore_ascii_case("infinite") {
            Ok(Self::Infinity)
        } else if let Ok(secs) = s.parse::<u32>() {
            Ok(Self::Secs(secs))
        } else {
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
    /// Returns the lifetime value as a `u32` in seconds.
    ///
    /// If the lifetime is infinite, returns [`LIFETIME_INFINITY`] (`0xFFFF_FFFF`).
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Secs(s) => s,
            Self::Infinity => LIFETIME_INFINITY,
        }
    }
}

/// Source of the IPv6 address for the Prefix Information option.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PrefixSource {
    /// A statically configured subnet prefix.
    Static,
    /// Unique Local Address (ULA) prefix (RFC 4193).
    /// Typically randomized local prefixes (e.g. `fd00::/8`).
    Ula,
    /// Automatically generated or discovered Global Unicast Address (GUA) prefix (RFC 4291).
    #[default]
    AutoGua,
}

/// Configuration for an IPv6 prefix to be advertised in RA packets.
///
/// This specifies the options that the router places in its Router Advertisements to guide hosts
/// in configuring their local addresses, determining routing table prefixes, and validating local links.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(default)]
pub struct RAPrefix {
    /// Source category/mode of this prefix.
    pub source: PrefixSource,
    /// The IPv6 address prefix string (e.g. `"2001:db8::"`).
    ///
    /// If `None`, the address may be dynamically discovered (e.g. for [`PrefixSource::AutoGua`]).
    pub address: Option<String>,
    /// Prefix length in bits (commonly `64` for SLAAC address auto-configuration).
    pub prefix_len: u8,
    /// The On-Link (L) flag.
    ///
    /// When set to `true`, hosts assume that any address matching this prefix is directly reachable
    /// on the local link without transmitting packets via a default router.
    pub on_link: bool,
    /// The Autonomous Address-Configuration (A) flag.
    ///
    /// When set to `true`, hosts can use SLAAC (RFC 4862) to configure their own address based on this
    /// prefix and their interface identifier.
    pub autonomous: bool,
    /// The Router Address (R) flag.
    ///
    /// When set to `true`, indicates that the prefix field contains a complete IP address of the advertising
    /// router interface (under RFC 6275 Mobile IPv6).
    pub router_addr: bool,
    /// Time period in seconds that the prefix remains valid for on-link determination.
    pub valid_lifetime: PrefixLifetime,
    /// Time period in seconds that addresses generated via SLAAC remain preferred.
    ///
    /// Must not be larger than `valid_lifetime`.
    pub preferred_lifetime: PrefixLifetime,
}

impl Default for RAPrefix {
    fn default() -> Self {
        Self::gua_dynamic()
    }
}

impl RAPrefix {
    /// Constructs a standard Unique Local Address (ULA) prefix configuration.
    ///
    /// Generates a ULA prefix configuration with typical default lifetimes
    /// (valid for 24 hours, preferred for 4 hours) with standard flags enabled.
    #[must_use]
    pub fn ula(prefix: &str) -> Self {
        let trimmed = prefix.trim();
        let (clean_addr, prefix_len) = if let Some((addr, len_str)) = trimmed.split_once('/') {
            let len = len_str.parse::<u8>().unwrap_or(64);
            (addr.to_string(), len)
        } else {
            (trimmed.to_string(), 64)
        };
        Self {
            source: PrefixSource::Ula,
            address: Some(clean_addr),
            prefix_len,
            on_link: true,
            autonomous: true,
            router_addr: true,
            valid_lifetime: PrefixLifetime::Secs(86400),
            preferred_lifetime: PrefixLifetime::Secs(14400),
        }
    }

    /// Constructs a dynamically determined Global Unicast Address (GUA) prefix configuration.
    ///
    /// Generates a configuration that dynamically resolves the prefix, utilizing standard default RFC
    /// lifetimes (valid for 30 days, preferred for 7 days) and basic SLAAC/on-link flags.
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

    /// Resolves the IPv6 address from the prefix string, removing any subnet masks if present.
    #[must_use]
    pub fn resolved_address(&self) -> Option<Ipv6Addr> {
        self.address.as_ref().and_then(|s| {
            let addr_part = s.split('/').next()?;
            addr_part.parse().ok()
        })
    }
}

/// Recursive DNS Server (RDNSS) option configuration.
///
/// As defined in RFC 8106, the `RDNSS` option enables IPv6 routers to advertise a list of
/// one or more recursive DNS server IPv6 addresses directly inside Router Advertisement messages.
/// This allows IPv6 hosts to discover local DNS servers without requiring `DHCPv6`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
#[serde(default)]
pub struct RdnssConfig {
    /// IPv6 addresses of the recursive DNS servers.
    pub servers: Vec<Ipv6Addr>,
    /// Lifetime of the recursive DNS server addresses.
    ///
    /// If `None`, hosts will typically derive a default lifetime value.
    pub lifetime: Option<u32>,
}

impl RdnssConfig {
    /// Creates a new RDNSS configuration with the specified list of server addresses.
    #[must_use]
    pub const fn new(servers: Vec<Ipv6Addr>) -> Self {
        Self {
            servers,
            lifetime: None,
        }
    }

    /// Creates a new RDNSS configuration with the specified server addresses and a custom lifetime.
    #[must_use]
    pub const fn with_lifetime(servers: Vec<Ipv6Addr>, secs: u32) -> Self {
        Self {
            servers,
            lifetime: Some(secs),
        }
    }
}

/// DNS Search List (DNSSL) option configuration.
///
/// As defined in RFC 8106, the DNSSL option enables IPv6 routers to advertise a list of
/// DNS suffix search domains to IPv6 hosts. Hosts append these domains to short, single-label
/// hostnames when executing DNS name resolution queries.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
#[serde(default)]
pub struct DnsslConfig {
    /// DNS suffix search domains (e.g. `["lan", "home.arpa"]`).
    pub domains: Vec<String>,
    /// Lifetime of the DNS search list domains.
    ///
    /// If `None`, hosts will typically derive a default lifetime value.
    pub lifetime: Option<u32>,
}

/// Default router priority (RFC 4191 §2.1).
/// Influences which router is preferred when multiple are present on the network.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
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

/// Full runtime configuration for the Router Advertisement service.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RaServerConfig {
    /// Whether the RA service is enabled.
    pub enabled: bool,
    /// Interface name (e.g. "eth0").
    pub iface: Option<String>,
    /// Managed address configuration flag (M): `DHCPv6` is available for address configuration.
    pub managed: bool,
    /// Other stateful configuration flag (O): `DHCPv6` is available for other configuration (DNS, NTP).
    pub other_config: bool,

    /// Default hop limit suggested to LAN hosts.
    pub hop_limit: u8,
    /// Router priority preference (RFC 4191).
    pub priority: RouterPriority,
    /// Max interval between periodic unsolicited Router Advertisements (RFC 4861 §6.2.1), in seconds.
    pub max_interval_secs: u64,
    /// Min interval between periodic unsolicited Router Advertisements (RFC 4861 §6.2.1), in seconds.
    pub min_interval_secs: Option<u64>,
    /// Router lifetime (seconds) indicating lifetime as a default router.
    pub lifetime_secs: Option<u64>,
    /// Reachable time in milliseconds (0 = unspecified).
    pub reachable_time_ms: u32,
    /// Retransmission timer in milliseconds (0 = unspecified).
    pub retrans_timer_ms: u32,
    /// Link MTU option (RFC 4861 §4.6.4).
    pub mtu: Option<u32>,
    /// IPv6 prefixes to advertise.
    pub prefixes: Vec<RAPrefix>,
    /// Recursive DNS server addresses (RFC 8106).
    pub rdnss: Vec<RdnssConfig>,
    /// DNS search list suffixes (RFC 8106).
    pub dnssl: Vec<DnsslConfig>,
}

impl Default for RaServerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            iface: None,
            managed: false,
            other_config: false,
            hop_limit: 64,
            priority: RouterPriority::Medium,
            max_interval_secs: 200,
            min_interval_secs: None,
            lifetime_secs: None,
            reachable_time_ms: 0,
            retrans_timer_ms: 0,
            mtu: None,
            prefixes: Vec::new(),
            rdnss: Vec::new(),
            dnssl: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_lifetime_deserialization_from_number_and_string() {
        // Deserialization from JSON integer (seconds)
        let lt_int: PrefixLifetime = serde_json::from_str("86400").unwrap();
        assert_eq!(lt_int, PrefixLifetime::Secs(86400));

        // Deserialization from JSON string
        let lt_str: PrefixLifetime = serde_json::from_str("\"86400\"").unwrap();
        assert_eq!(lt_str, PrefixLifetime::Secs(86400));

        let lt_duration: PrefixLifetime = serde_json::from_str("\"30d\"").unwrap();
        assert_eq!(lt_duration, PrefixLifetime::Secs(30 * 86400));

        let lt_inf: PrefixLifetime = serde_json::from_str("\"infinity\"").unwrap();
        assert_eq!(lt_inf, PrefixLifetime::Infinity);
    }

    #[test]
    fn test_ra_prefix_ula_strips_cidr() {
        let pref1 = RAPrefix::ula("fd97:f00d:cafe:3731::/64");
        assert_eq!(pref1.address.as_deref(), Some("fd97:f00d:cafe:3731::"));
        assert_eq!(pref1.prefix_len, 64);

        let pref2 = RAPrefix::ula("fd00:1234::");
        assert_eq!(pref2.address.as_deref(), Some("fd00:1234::"));
        assert_eq!(pref2.prefix_len, 64);
    }
}

