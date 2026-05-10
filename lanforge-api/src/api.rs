use lanforge_core::types::{DnsRecordEntry, LeaseTarget, UpstreamHealthSnapshot};
use lanforge_core::{bus::TimedEvent, context::state::State};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported response encodings.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    /// JSON line-based (standard).
    Json,
    /// Bincode binary (length-prefixed).
    Bincode,
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json => write!(f, "json"),
            Self::Bincode => write!(f, "bincode"),
        }
    }
}

/// Supported compression algorithms.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Compression {
    /// No compression.
    None,
    /// Zstd compression.
    Zstd,
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Zstd => write!(f, "zstd"),
        }
    }
}

/// Daemon capabilities payload.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Capabilities {
    /// List of supported response encodings.
    pub encodings: Vec<Encoding>,
    /// List of supported compression algorithms.
    pub compression: Vec<Compression>,
}

/// Represents a command sent from a client to the Lanforge daemon.
///
/// Commands are serialized to JSON with a `command` tag and `snake_case` fields.
///
/// # Example
///
/// ```rust
/// use lanforge_api::api::{Command, CommandAction};
///
/// let cmd = Command::new(CommandAction::Devices { filter: Some("arch".into()), vendor: None, method: None, format: None });
/// let json = serde_json::to_string(&cmd).unwrap();
/// assert!(json.contains(r#""command":"devices""#));
/// ```
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash)]
pub struct Command {
    /// Override response encoding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<Encoding>,
    /// Request response compression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression: Option<Compression>,
    /// The actual command to execute.
    #[serde(flatten)]
    pub action: CommandAction,
}

impl Command {
    /// Helper to create a command with default transport options.
    #[must_use]
    pub const fn new(action: CommandAction) -> Self {
        Self {
            encoding: None,
            compression: None,
            action,
        }
    }

    /// Pre-defined Status command.
    pub const STATUS: Self = Self {
        encoding: None,
        compression: None,
        action: CommandAction::Status,
    };
}

use lanforge_macros::CommandDispatch;

/// The actual action variants for a Command.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq, Hash, CommandDispatch)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum CommandAction {
    /// Retrieve general system status (uptime, versions, service states).
    #[dispatch(handler = "handle_status", readonly)]
    Status,
    /// List all managed devices with optional filtering.
    #[dispatch(handler = "handle_devices", args(filter, vendor, method), readonly)]
    Devices {
        /// Filter by hostname, MAC, or IP address.
        filter: Option<String>,
        /// Filter by specific vendor name (OUI).
        vendor: Option<String>,
        /// Filter by specific learning method.
        method: Option<String>,
        /// Output format (reserved for future use).
        format: Option<String>,
    },
    /// Request the daemon to reload its configuration from disk.
    #[dispatch(handler = "handle_reload")]
    Reload,
    /// Enter 'watch' mode to stream live state changes.
    #[dispatch(handler = "handle_watch", readonly)]
    Watch,
    /// Stream or fetch logs/events.
    #[dispatch(handler = "handle_log", args(follow, n), readonly)]
    Log {
        /// If true, keep the connection open and stream new events.
        follow: bool,
        /// Number of historical entries to fetch.
        n: Option<usize>,
    },
    /// Force an immediate network scan.
    #[dispatch(handler = "handle_scan")]
    Scan,
    /// Gracefully shut down the daemon.
    #[dispatch(handler = "handle_shutdown")]
    Shutdown,
    /// Add or update a static host configuration via CLI.
    #[dispatch(handler = "handle_host_add", args(mac, hostname, v4, v6_suffix))]
    HostAdd {
        /// Target device MAC address.
        mac: Option<String>,
        /// Desired hostname.
        hostname: Option<String>,
        /// Static IPv4 address.
        v4: Option<String>,
        /// IPv6 interface ID or Full address.
        v6_suffix: Option<String>,
    },
    /// Set a specific field for a host configuration.
    #[dispatch(handler = "handle_host_set", args(mac, field, value))]
    HostSet {
        /// Target device MAC address.
        mac: String,
        /// Field name (e.g., "hostname", "v4", "`v6_suffix`").
        field: String,
        /// New value for the field.
        value: String,
    },
    /// Remove a host configuration by MAC.
    #[dispatch(handler = "handle_host_remove", args(mac))]
    HostRemove {
        /// Target device MAC address.
        mac: String,
    },
    /// List all manually configured hosts.
    #[dispatch(handler = "handle_hosts", readonly)]
    HostList,
    /// Force a DHCP 'forcerenew' for a specific device.
    #[dispatch(handler = "handle_lease_renew", args(mac, target))]
    LeaseRenew {
        /// Target device MAC address.
        mac: String,
        /// Optional specific lease target (V4, V6, or `V6Prefix` with IAID).
        target: Option<LeaseTarget>,
    },
    /// Manually release a DHCP lease.
    #[dispatch(handler = "handle_lease_release", args(mac, target))]
    LeaseRelease {
        /// Target device MAC address.
        mac: String,
        /// Optional specific lease target (V4, V6, or `V6Prefix` with IAID).
        target: Option<LeaseTarget>,
    },
    /// Fetch DHCP pool utilization.
    #[dispatch(handler = "handle_dhcp_pools")]
    DhcpPools,
    /// Perform a VACUUM operation on the underlying `SQLite` database.
    #[dispatch(handler = "handle_db_vacuum")]
    DbVacuum,
    /// Clear all transient system logs.
    #[dispatch(handler = "handle_db_log_clean")]
    DbLogClean,
    /// Remove 'zombie' entries from the database (dynamic devices with no IPs/Hostname).
    #[dispatch(handler = "handle_db_prune")]
    DbPrune,
    /// Forcefully purge a device from memory and database by its MAC.
    #[dispatch(handler = "handle_purge", args(mac))]
    Purge {
        /// Target device MAC address.
        mac: String,
    },
    /// Send a Wake-on-LAN magic packet to a target (MAC or Name).
    #[dispatch(handler = "handle_wol", args(target))]
    Wol {
        /// Target device MAC or Hostname.
        target: String,
    },
    /// Retrieve detailed aggregated information about a device.
    #[dispatch(handler = "handle_whois", args(target), readonly)]
    Whois {
        /// Target MAC, IP, or Hostname.
        target: String,
    },
    /// Retrieve DNS resolver statistics.
    #[dispatch(handler = "handle_dns_stats")]
    DnsStats,
    /// Retrieve DNS upstream status and health.
    #[dispatch(handler = "handle_dns_upstreams")]
    DnsUpstreams,
    /// Perform a diagnostic DNS query.
    #[dispatch(handler = "handle_dns_query", args(name, record_type))]
    DnsQuery {
        /// Name to resolve.
        name: String,
        /// Optional record type (A, AAAA, TXT, etc.).
        record_type: Option<String>,
    },
    /// Flush the DNS cache.
    #[dispatch(handler = "handle_dns_cache_flush")]
    DnsCacheFlush,
    /// Dump the DNS cache contents.
    #[dispatch(handler = "handle_dns_cache_dump")]
    DnsCacheDump,
    /// Enable or disable the DNS adblocker.
    #[dispatch(handler = "handle_dns_adblock_set", args(enabled, duration_secs))]
    DnsAdblockSet {
        /// Whether to enable or disable the adblocker.
        #[serde(default)]
        enabled: bool,
        /// Optional duration in seconds for temporary disabling.
        duration_secs: Option<u64>,
    },
    /// Force a reload of the adblock blocklists.
    #[dispatch(handler = "handle_dns_adblock_reload")]
    DnsAdblockReload,
    /// Retrieve recent DNS query logs.
    #[dispatch(handler = "handle_dns_query_log", args(limit, client), readonly)]
    DnsQueryLog {
        /// Maximum number of entries to retrieve.
        limit: Option<usize>,
        /// Filter by client IP address.
        client: Option<String>,
    },
    /// Dump the full system context (for debugging).
    #[dispatch(handler = "handle_context_dump", args(only_devices, only_orphans))]
    ContextDump {
        #[serde(default)]
        only_devices: bool,
        #[serde(default)]
        only_orphans: bool,
    },
    /// Factory reset the database and in-memory state.
    #[dispatch(handler = "handle_db_reset")]
    DbReset,
    /// List active DHCP leases.
    #[dispatch(handler = "handle_leases", args(count), readonly)]
    Leases {
        #[serde(default)]
        count: bool,
    },
    /// Get network topology.
    #[dispatch(handler = "handle_topology", readonly)]
    Topology,
    /// Update the daemon's API password (requires UDS connection).
    #[dispatch(handler = "handle_config_set_password", args(password))]
    ConfigSetPassword {
        /// New plaintext password to hash and store.
        password: String,
    },
}

/// Represents a response sent from the daemon to a client.
///
/// This enum is untagged, meaning its variant is determined by the JSON structure.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    /// Detailed system status.
    Status(Box<StatusResponse>),
    /// List of managed devices.
    Devices(DevicesResponse),
    /// List of manually configured hosts.
    Hosts(HostsResponse),
    /// Generic error message.
    Error {
        /// Human-readable error description.
        error: String,
    },
    /// Generic success indicator.
    Success(SimpleSuccess),
    /// A live event from the internal bus (for 'watch' or 'log' commands).
    Event(TimedEvent),
    /// Response for a Whois query.
    Whois(Box<WhoisResponse>),
    /// Response for DNS statistics.
    DnsStats(DnsStatsResponse),
    /// Response for DNS upstreams status.
    DnsUpstreams(DnsUpstreamsResponse),
    /// Response for a DNS diagnostic query.
    DnsQuery(DnsQueryResponse),
    /// Response for DNS query logs.
    DnsQueryLog(DnsQueryLogResponse),
    /// Response for DHCP pool utilization.
    DhcpPools(DhcpPoolsResponse),
    /// Response for DNS cache dump.
    DnsCache(DnsCacheResponse),
    /// Response for a full context dump.
    ContextDump(Box<State>),
    /// List of active DHCP leases.
    Leases(LeasesResponse),
    /// Hierarchical physical topology.
    Topology(TopologyResponse),
}

/// A simple success result containing a message.
#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleSuccess {
    /// Informational message about the operation.
    pub message: String,
}

/// Interface information.
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct Interfaces {
    /// Lan interface name (e.g., "eth0").
    pub lan: String,
}

/// A response containing a list of devices and metadata.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DevicesResponse {
    /// The list of device entries.
    pub devices: Vec<DeviceEntry>,
    /// Statistical metadata about the scan results.
    pub meta: DevicesMeta,
}

/// A response containing a list of manually configured hosts.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostsResponse {
    /// The list of host configurations.
    pub hosts: Vec<HostConfigEntry>,
}

/// A response containing active DHCP leases.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LeasesResponse {
    /// List of lease entries.
    pub leases: Vec<LeaseEntry>,
}

/// A single active DHCP lease entry.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LeaseEntry {
    /// MAC address of the leased device.
    pub mac: String,
    /// Hostname of the device.
    pub hostname: String,
    /// Assigned IP address or prefix.
    pub address: String,
    /// Type of lease (v4, v6, prefix).
    pub kind: LeaseKind,
    /// Expiration timestamp in ISO 8601.
    pub expires: String,
    /// Remaining lifetime in seconds.
    pub remaining_secs: i64,
}

/// Supported DHCP lease types.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum LeaseKind {
    /// Standard `DHCPv4` lease.
    V4,
    /// `DHCPv6` `IA_NA` address lease.
    V6,
    /// `DHCPv6` `IA_PD` prefix delegation lease.
    V6Prefix,
}

/// A response containing the discovered physical topology.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TopologyResponse {
    /// The list of devices with known topology connections.
    pub entries: Vec<TopologyEntry>,
}

/// A topology connection representing a link between a device and its parent.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TopologyEntry {
    /// MAC address of the device.
    pub mac: String,
    /// Hostname of the device.
    pub hostname: String,
    /// Parent MAC address, if known.
    pub parent_mac: Option<String>,
    /// Port on the parent device, if known.
    pub port: Option<String>,
    /// Local interface index connecting to this topology tree.
    pub local_ifindex: u32,
    /// Last seen timestamp of this topology link.
    pub last_updated: String,
}

/// A single entry in the host configuration list.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HostConfigEntry {
    /// MAC address identifying the device.
    pub mac: String,
    /// Manually configured hostname.
    pub hostname: String,
    /// Fixed IPv4 address, if set.
    pub v4_fixed: Option<String>,
    /// IPv6 Interface ID (suffix) or Full address.
    pub v6_suffix: Option<String>,
    /// Source of the configuration (e.g., "Toml", "Cli").
    pub origin: String,
}

/// A single device discovered on the network.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DeviceEntry {
    /// Device MAC address.
    pub mac: String,
    /// Hostname, either broadcast by the device or manually set.
    pub hostname: String,
    /// Source of identification (e.g., "Dynamic", "Toml", "Cli").
    pub origin: String,
    /// Current online/offline status.
    pub online: bool,
    /// Last seen timestamp in ISO 8601.
    pub last_seen: String,
    /// Hex-encoded DUID for `DHCPv6`, if available.
    pub duid: Option<String>,
    /// Human-readable primary `IPv4` display.
    pub display_v4: String,
    /// Human-readable primary `IPv6` display.
    pub display_v6: String,
    /// Active `DHCPv4` lease information.
    pub v4: Option<LeaseInfo>,
    /// List of all `IPv4` addresses seen for this device.
    pub seen_v4: Vec<String>,
    /// Active `DHCPv6` lease information.
    pub v6: Option<LeaseInfo>,
    /// List of IPv6 addresses (SLAAC, GUA, etc.) tracked for this device.
    pub ipv6_addrs: Vec<Ipv6Entry>,
    pub learning_method: String,
    /// Discovered category (e.g., "printer", "media").
    pub class: String,
}

/// A single IPv6 address entry with its type category.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ipv6Entry {
    /// Full IPv6 address.
    pub addr: String,
    /// Category of the address (e.g., "SLAAC", "ULA", "GUA", "Link-Local").
    pub kind: String,
}

/// Details about a DHCP lease.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LeaseInfo {
    /// Assigned IP address.
    pub ip: String,
    /// Expiration timestamp in ISO 8601, or "Static".
    pub expires: String,
    /// Whether this is a static reservation.
    pub reserved: bool,
}

/// Statistical metadata for a devices list response.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DevicesMeta {
    /// Total number of devices in the database.
    pub total: usize,
    /// Number of devices currently considered online.
    pub online: usize,
    /// Seconds since the last full network scan.
    pub last_scan_secs_ago: u64,
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

/// Detailed aggregated information for a single device.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WhoisResponse {
    /// Current device state.
    pub entry: DeviceEntry,
    /// Historical lease assignments.
    pub history: Vec<lanforge_db::engine::LeaseHistoryEntry>,
}

/// A snapshot of DNS resolver statistics.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsStatsResponse {
    /// Total requests received.
    pub total_requests: u64,
    /// Number of cache hits.
    pub cache_hits: u64,
    /// Number of cache misses.
    pub cache_misses: u64,
    /// Number of upstream errors encountered.
    pub upstream_errors: u64,
    /// Number of authoritative queries resolved locally.
    pub auth_queries: u64,
    /// Number of recursive queries forwarded.
    pub recursions: u64,
    /// Number of queries blocked by the adblocker.
    pub blocked_queries: u64,
}

/// A response containing status for all configured DNS upstreams.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsUpstreamsResponse {
    pub upstreams: Vec<UpstreamHealthSnapshot>,
}

/// Results of a DNS diagnostic query.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsQueryResponse {
    /// The resolved records.
    pub records: Vec<DnsRecordEntry>,
    /// Query latency in milliseconds.
    pub latency_ms: u64,
    /// Whether the result was authoritative.
    pub authoritative: bool,
}

/// Detailed DHCP pool utilization.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DhcpPoolsResponse {
    pub v4_pools: Vec<DhcpPoolEntry>,
    pub v6_pools: Vec<DhcpPoolEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DhcpPoolEntry {
    pub subnet: String,
    pub total: u32,
    pub used: u32,
    pub available: u32,
    pub utilization_percent: f32,
}

/// DNS cache dump entry.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsCacheResponse {
    pub entries: Vec<DnsCacheEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DnsCacheEntry {
    pub name: String,
    pub kind: String,
    pub data: String,
    pub expires_in_secs: u64,
}

/// A response containing recent DNS query logs.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsQueryLogResponse {
    pub entries: Vec<lanforge_core::types::network::QueryLogEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_serialization() {
        let cmd = Command::new(CommandAction::Status);
        let json = serde_json::to_string(&cmd).unwrap();
        assert_eq!(json, r#"{"command":"status"}"#);

        let cmd = Command::new(CommandAction::Devices {
            filter: Some("arch".to_string()),
            vendor: None,
            method: None,
            format: None,
        });
        let json = serde_json::to_string(&cmd).unwrap();
        assert_eq!(
            json,
            r#"{"command":"devices","filter":"arch","vendor":null,"method":null,"format":null}"#
        );
    }
}
