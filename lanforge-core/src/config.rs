//! Modular configuration system for Lanforge services.
//!
//! Each service defines its own configuration structure that can be
//! automatically mapped to a section in the main TOML file.

use serde::{Deserialize, Serialize};

/// Trait implemented by service-specific configuration structures.
///
/// This trait allows the main daemon to automatically identify which
/// TOML section belongs to which service and handle deserialization.
pub trait ServiceConfig: Serialize + for<'de> Deserialize<'de> + Default + Clone {
    /// The top-level key in the TOML file for this configuration.
    /// Example: "dns", "dhcp.v4", etc.
    const KEY: &'static str;

    /// Optional: Merge this configuration with another one (e.g., from CLI).
    /// By default, it just replaces the current value.
    fn merge(&mut self, other: Self) {
        *self = other;
    }
}

/// Represents a DNS rewrite rule (domain -> IP/Hostname).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct RewriteRule {
    pub domain: String,
    pub answer: String,
}

impl RewriteRule {
    #[must_use]
    pub fn parse_answer(&self) -> RewriteAnswer {
        self.answer.parse::<std::net::Ipv4Addr>().map_or_else(
            |_| {
                self.answer.parse::<std::net::Ipv6Addr>().map_or_else(
                    |_| {
                        if self.answer.contains('.') {
                            RewriteAnswer::Cname(self.answer.clone())
                        } else {
                            RewriteAnswer::Device(self.answer.clone())
                        }
                    },
                    RewriteAnswer::Aaaa,
                )
            },
            RewriteAnswer::A,
        )
    }
}

/// Parsed DNS rewrite answer.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum RewriteAnswer {
    A(std::net::Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
    Cname(String),
    Device(String),
}

/// DNS blocking modes.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BlockingMode {
    #[default]
    NxDomain,
    NullIp,
    CustomIp,
    Refused,
}

impl std::str::FromStr for BlockingMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "nxdomain" => Ok(Self::NxDomain),
            "null_ip" | "nullip" => Ok(Self::NullIp),
            "custom_ip" | "customip" => Ok(Self::CustomIp),
            "refused" => Ok(Self::Refused),
            _ => Err(format!("Invalid blocking mode: {s}")),
        }
    }
}

impl std::fmt::Display for BlockingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NxDomain => write!(f, "nxdomain"),
            Self::NullIp => write!(f, "null_ip"),
            Self::CustomIp => write!(f, "custom_ip"),
            Self::Refused => write!(f, "refused"),
        }
    }
}

/// Adblock configuration as stored in DB.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq, Hash)]
pub struct AdblockDbConfig {
    pub enabled: bool,
    pub blocking_mode: BlockingMode,
    pub blocking_ip_v4: Option<std::net::Ipv4Addr>,
    pub blocking_ip_v6: Option<std::net::Ipv6Addr>,
    pub refresh_hours: u32,
    pub refresh_at_night: bool,
}

/// Types of adblock URLs.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdblockUrlKind {
    #[default]
    Blocklist,
    Allowlist,
}

impl std::str::FromStr for AdblockUrlKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "blocklist" => Ok(Self::Blocklist),
            "allowlist" => Ok(Self::Allowlist),
            _ => Err(format!("Invalid adblock URL kind: {s}")),
        }
    }
}

impl std::fmt::Display for AdblockUrlKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blocklist => write!(f, "blocklist"),
            Self::Allowlist => write!(f, "allowlist"),
        }
    }
}
