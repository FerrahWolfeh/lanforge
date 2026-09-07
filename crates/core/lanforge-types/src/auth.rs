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

/// Security role assigned to a database user account.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    Admin,
    Operator,
    Viewer,
}

impl UserRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Viewer => "viewer",
        }
    }
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for UserRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "admin" => Ok(Self::Admin),
            "operator" => Ok(Self::Operator),
            "viewer" | "read_only" | "readonly" => Ok(Self::Viewer),
            other => Err(format!("Unknown user role: {other}")),
        }
    }
}

/// Public user profile representation excluding sensitive fields like password hashes.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct UserInfo {
    pub id: i64,
    pub username: String,
    pub role: UserRole,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_login: Option<i64>,
}
