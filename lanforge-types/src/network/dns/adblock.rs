use crate::network::DnsRecordType;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Represents a DNS rewrite rule (domain -> IP/Hostname).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct RewriteRule {
    pub id: Option<i64>,
    pub domain: String,
    pub rtype: DnsRecordType,
    pub answer: String,
}

impl RewriteRule {
    #[must_use]
    pub fn parse_answer(&self) -> RewriteAnswer {
        self.answer.parse::<Ipv4Addr>().map_or_else(
            |_| {
                self.answer.parse::<Ipv6Addr>().map_or_else(
                    |_| {
                        self.answer.strip_prefix("dev:").map_or_else(
                            || {
                                if self.answer.contains('.') {
                                    RewriteAnswer::Cname(self.answer.clone())
                                } else {
                                    RewriteAnswer::Device(self.answer.clone())
                                }
                            },
                            |dev_name| RewriteAnswer::Device(dev_name.to_string()),
                        )
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
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Device(String),
}

/// DNS blocking modes.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default, Hash)]
#[serde(rename_all = "snake_case")]
pub enum BlockingMode {
    /// Return NXDOMAIN (default).
    #[default]
    NxDomain,
    /// Return 0.0.0.0 (A) and :: (AAAA).
    NullIp,
    /// Return a custom user-specified IP address.
    CustomIp,
    /// Return REFUSED.
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
    pub blocking_ip_v4: Option<Ipv4Addr>,
    pub blocking_ip_v6: Option<Ipv6Addr>,
    pub refresh_hours: u32,
    pub refresh_at_night: bool,
}

/// Adblock source URL kind.
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
