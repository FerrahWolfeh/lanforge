use crate::network::{Ipv6Prefix, dns::upstream::UpstreamTarget};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::borrow::Cow;

/// Global system status and runtime configuration snapshot.
///
/// This struct contains information about the system that is not
/// strictly part of a single service's configuration, but is needed
/// for reporting, metrics, and global status commands.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct SystemStatus {
    /// Filesystem path to the primary device database.
    pub db_path: String,
    /// Filesystem path to the query/event log database.
    pub log_db_path: String,
    /// Name of the primary LAN interface (e.g., "eth0").
    pub lan_iface: String,
    /// Current ULA prefix if active.
    pub ula_prefix: Option<Ipv6Prefix>,

    // Service readiness/enabled flags
    pub ra_enabled: bool,
    pub dhcp_v4_enabled: bool,
    pub dhcp_v4_range_size: u32,
    pub dhcp_v6_enabled: bool,
    pub dhcp_v6_pool_size: Option<u64>,
    pub dns_enabled: bool,
    pub dns_upstream: Option<UpstreamTarget>,
    pub dns_port: u16,
    pub boot_dir: Option<String>,
    pub http_enabled: bool,
}

/// Flat enum representing all sub-systems, protocols, and database backends.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Cap {
    Dns,
    UpstreamUdpTcp,
    UpstreamDoT,
    UpstreamDoQ,
    UpstreamDoH,
    DohDownstream,
    DhcpV4,
    DhcpV6,
    Ra,
    NdpDiscovery,
    MdnsProbe,
    Uds,
    Http,
    Zstd,
    Sqlite,
    Postgresql,
}

/// Server capabilities representing compiled feature flags and runtime enabled features.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ServerCapabilities {
    pub compiled: SmallVec<[Cap; 32]>,
    pub enabled: SmallVec<[Cap; 32]>,
}

/// Represents the operating state of a decoupled service.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    #[default]
    #[serde(rename = "offline")]
    Offline,
    #[serde(rename = "starting")]
    Starting,
    #[serde(rename = "online")]
    Online,
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "inactive")]
    Inactive,
    #[serde(rename = "degraded")]
    Degraded,
    #[serde(rename = "error")]
    Error,
}

impl ServiceState {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Starting => "starting",
            Self::Online => "online",
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Degraded => "degraded",
            Self::Error => "failed",
        }
    }
}

impl AsRef<str> for ServiceState {
    fn as_ref(&self) -> &str {
        match self {
            Self::Offline => "offline",
            Self::Starting => "starting",
            Self::Online => "online",
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Degraded => "degraded",
            Self::Error => "failed",
        }
    }
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

pub mod vec_as_map {
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeMap};
    use std::borrow::Cow;

    /// Serializes a slice of key-value tuples as a JSON map.
    ///
    /// # Errors
    /// Returns an error if map serialization fails.
    pub fn serialize<S>(
        stats: &[(Cow<'static, str>, String)],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(stats.len()))?;
        for (k, v) in stats {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }

    /// Deserializes a JSON map into a vector of key-value tuples.
    ///
    /// # Errors
    /// Returns an error if map deserialization fails.
    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Vec<(Cow<'static, str>, String)>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let map: std::collections::HashMap<String, String> =
            Deserialize::deserialize(deserializer)?;
        Ok(map.into_iter().map(|(k, v)| (Cow::Owned(k), v)).collect())
    }
}

/// Banner representing the status and metrics of a decoupled service.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ServiceBanner {
    pub id: String,
    pub name: String,
    pub state: ServiceState,
    pub uptime_secs: u64,
    #[serde(with = "vec_as_map")]
    pub stats: Vec<(Cow<'static, str>, String)>,
}

/// Actions that can be performed on a service.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunResult {
    Shutdown,
    ConfigChanged,
}
