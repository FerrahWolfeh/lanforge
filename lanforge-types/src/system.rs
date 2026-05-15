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
