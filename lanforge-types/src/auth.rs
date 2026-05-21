use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

/// Granular capability / security scope for API authentication tokens.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ApiScope {
    Admin,
    Monitoring,
    UpstreamWrite,
    DnsQuery,
    DeviceWrite,
    ConfigWrite,
}

impl std::fmt::Display for ApiScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Admin => "admin",
            Self::Monitoring => "monitoring",
            Self::UpstreamWrite => "upstream_write",
            Self::DnsQuery => "dns_query",
            Self::DeviceWrite => "device_write",
            Self::ConfigWrite => "config_write",
        };
        write!(f, "{s}")
    }
}

impl std::str::FromStr for ApiScope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "admin" => Ok(Self::Admin),
            "monitoring" => Ok(Self::Monitoring),
            "upstream_write" => Ok(Self::UpstreamWrite),
            "dns_query" => Ok(Self::DnsQuery),
            "device_write" => Ok(Self::DeviceWrite),
            "config_write" => Ok(Self::ConfigWrite),
            other => Err(format!("Unknown API scope: {other}")),
        }
    }
}

/// A lean, stack-allocated vector of API scopes.
pub type ApiScopes = SmallVec<[ApiScope; 8]>;
