use serde::{Deserialize, Serialize};
use super::common::{Capabilities, ServerCapabilities, ServiceBanner};

/// Interface information.
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct Interfaces {
    /// Lan interface name (e.g., "eth0").
    pub lan: String,
}

/// Full system status information.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Seconds since the daemon started.
    pub uptime_secs: u64,
    /// Current daemon version.
    pub version: String,
    /// Detailed status of each sub-service.
    pub services: ServicesStatus,
    /// Underlying database statistics.
    pub db: DbStatus,
    /// Local network interface and prefix status.
    pub network: NetworkStatus,
    /// Usage of system resources (CPU, Memory).
    pub resources: ResourcesStatus,
    /// General device counting statistics.
    pub devices: DevicesStats,
    /// Daemon capabilities.
    pub capabilities: Capabilities,
    /// Decoupled server capabilities (compiled vs enabled).
    pub server_caps: ServerCapabilities,
    /// Decoupled service banners.
    pub service_banners: Vec<ServiceBanner>,
}

/// Response containing all decoupled service banners.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceBannersResponse {
    pub banners: Vec<ServiceBanner>,
}

/// Aggregated status for all major daemon services.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServicesStatus {
    // --- Core Services ---
    /// Database worker status.
    pub db_worker: ServiceStatusInfo,
    /// mDNS prober status.
    pub mdns_prober: ServiceStatusInfo,
    /// Interface monitoring service.
    pub iface_monitor: ServiceStatusInfo,
    /// NDP Monitor (neighbor discovery and address tracking).
    pub ndp_monitor: ServiceNdp,
    /// Control API (Unix Domain Socket).
    pub control_api: ServiceStatusInfo,
    /// Optional HTTP REST API.
    pub http_api: Option<ServiceStatusInfo>,

    // --- Protocol Services ---
    /// Router Advertisement service (NDP).
    pub ra: ServiceRa,
    /// `DHCPv4` server.
    pub dhcp_v4: ServiceDhcpV4,
    /// `DHCPv6` server.
    pub dhcp_v6: ServiceDhcpV6,
    /// Authoritative/Caching `DNS` server.
    pub dns: ServiceDns,
}

/// Status of the Router Advertisement (RA) service.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceRa {
    /// Current state (e.g., "online", "offline").
    pub state: String,
    /// Seconds since the RA service started.
    pub uptime_secs: u64,
    /// Current Global Unicast Address (GUA) prefix being announced.
    pub gua: Option<String>,
    /// Unique Local Address (ULA) prefix being announced, if any.
    pub ula: Option<String>,
}

/// Status of the `DHCPv4` service.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceDhcpV4 {
    /// Current state (e.g., "online", "offline").
    pub state: String,
    /// Seconds since the `DHCPv4` service started.
    pub uptime_secs: u64,
    /// Number of active leases currently assigned.
    pub leases_active: usize,
    /// Number of available addresses in the pool.
    pub pool_free: usize,
}

/// Status of the `DHCPv6` service.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceDhcpV6 {
    /// Current state (e.g., "online", "offline").
    pub state: String,
    /// Seconds since the `DHCPv6` service started.
    pub uptime_secs: u64,
    /// Number of active leases currently assigned.
    pub leases_active: usize,
    /// Number of available addresses in the pool.
    pub pool_free: usize,
    /// Current Global Unicast Address (GUA) prefix being managed.
    pub gua: Option<String>,
    /// Unique Local Address (ULA) prefix being managed, if any.
    pub ula: Option<String>,
}

/// Status of the DNS service.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceDns {
    /// Current state (e.g., "online", "offline").
    pub state: String,
    /// Seconds since the DNS service started.
    pub uptime_secs: u64,
    /// Configured upstream resolver.
    pub upstream: Option<String>,
}

/// Generic status information for auxiliary services.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ServiceStatusInfo {
    /// Current state (e.g., "online", "ativo").
    pub state: String,
}

/// Status of the NDP Monitor service.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceNdp {
    /// Current state (e.g., "online", "offline").
    pub state: String,
    /// Seconds since the scanner service started.
    pub uptime_secs: u64,
    /// Total number of unique IPv6 addresses being tracked via neighbor discovery.
    pub addrs_tracked: usize,
    /// Seconds since the last full scan was performed.
    pub last_scan_secs_ago: u64,
}

/// Statistics and path information for the `SQLite` database.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DbStatus {
    /// Filesystem path to the database file.
    pub path: String,
    /// Current database file size in bytes.
    pub size_bytes: u64,
    /// Seconds since the last data flush to disk.
    pub last_flush_secs_ago: u64,
}

/// Statistics about daemon resource consumption.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ResourcesStatus {
    /// Resident Set Size (RSS) in bytes.
    pub memory_rss_bytes: u64,
    /// Virtual Memory Size (VMS) in bytes.
    pub memory_vms_bytes: u64,
}

/// Information about the host's current network configuration.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct NetworkStatus {
    /// Primary LAN interface being managed (e.g., "eth0").
    pub lan_iface: String,
    /// Primary IPv4 address of the LAN interface.
    pub lan_ipv4: Option<String>,
    /// Primary IPv4 address with CIDR (e.g., "192.168.1.1/24").
    pub lan_ipv4_cidr: Option<String>,
    /// Primary IPv6 address of the LAN interface.
    pub lan_ipv6: Option<String>,
    /// Primary GUA prefix.
    pub gua: Option<String>,
    /// Primary ULA prefix.
    pub ula: Option<String>,
}

/// Device classification statistics.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DevicesStats {
    /// Combined total of all devices in database.
    pub total: usize,
    /// Devices seen in the last 5 minutes.
    pub online: usize,
    /// Devices configured via `lanforge.toml`.
    pub static_toml: usize,
    /// Devices configured/updated via CLI control.
    pub managed_cli: usize,
    /// Purely dynamic devices (no manual config).
    pub dynamic: usize,
}

use crate::api::devices::HostConfigEntry;
use crate::api::dns::{AllowlistEntry, DnsUpstreamConfig};
use lanforge_types::network::dns::{AdblockUrlEntry, adblock::{AdblockDbConfig, RewriteRule}};

/// Unified system configuration export aggregating all persistent database tables.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct SystemConfigExport {
    pub hosts: Vec<HostConfigEntry>,
    pub dns_rewrites: Vec<RewriteRule>,
    pub dns_upstreams: Vec<DnsUpstreamConfig>,
    pub dns_adblock_config: AdblockDbConfig,
    pub dns_adblock_urls: Vec<AdblockUrlEntry>,
    pub dns_allowlist: Vec<AllowlistEntry>,
}

