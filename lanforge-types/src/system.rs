use serde::{Deserialize, Serialize};

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
    pub ula_prefix: Option<String>,

    // Service readiness/enabled flags
    pub ra_enabled: bool,
    pub dhcp_v4_enabled: bool,
    pub dhcp_v4_range_size: u32,
    pub dhcp_v6_enabled: bool,
    pub dhcp_v6_pool_size: Option<u64>,
    pub dns_enabled: bool,
    pub dns_upstream: Option<String>,
    pub boot_dir: Option<String>,
    pub http_enabled: bool,
}

use std::collections::HashMap;

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
    LldpProbe,
    Uds,
    Http,
    Zstd,
    Sqlite,
    Postgresql,
}

/// Server capabilities representing compiled feature flags and runtime enabled features.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ServerCapabilities {
    pub compiled: smallvec::SmallVec<[Cap; 32]>,
    pub enabled: smallvec::SmallVec<[Cap; 32]>,
}

/// Banner representing the status and metrics of a decoupled service.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ServiceBanner {
    pub name: String,
    pub state: String,
    pub uptime_secs: u64,
    pub stats: HashMap<String, String>,
}
