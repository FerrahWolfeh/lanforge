use std::net::{Ipv4Addr, Ipv6Addr};

use super::common::{
    Capabilities, HttpDataResponse, HttpWrappedResponse, ServerCapabilities, ServiceBanner,
};
use lanforge_types::network::dhcp::{Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::network::firewall::{
    FirewallCommitResponse, FirewallConfig, FirewallStatus, FirewallValidationReport,
};
use lanforge_types::network::pppoe::PppoeConfig;
use lanforge_types::network::ra::{DnsslConfig, RAPrefix, RdnssConfig};
use lanforge_types::network::traffic::TrafficConfig;
use lanforge_types::system::ServiceState;
use serde::{Deserialize, Serialize};

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
    pub state: ServiceState,
    /// Seconds since the RA service started.
    pub uptime_secs: u64,
    /// Current Global Unicast Address (GUA) prefix being announced.
    pub gua: Option<Ipv6Addr>,
    /// Unique Local Address (ULA) prefix being announced, if any.
    pub ula: Option<Ipv6Addr>,
}

/// Status of the `DHCPv4` service.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceDhcpV4 {
    /// Current state (e.g., "online", "offline").
    pub state: ServiceState,
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
    pub state: ServiceState,
    /// Seconds since the `DHCPv6` service started.
    pub uptime_secs: u64,
    /// Number of active leases currently assigned.
    pub leases_active: usize,
    /// Number of available addresses in the pool.
    pub pool_free: usize,
    /// Current Global Unicast Address (GUA) prefix being managed.
    pub gua: Option<Ipv6Addr>,
    /// Unique Local Address (ULA) prefix being managed, if any.
    pub ula: Option<Ipv6Addr>,
}

/// Status of the DNS service.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceDns {
    /// Current state (e.g., "online", "offline").
    pub state: ServiceState,
    /// Seconds since the DNS service started.
    pub uptime_secs: u64,
    /// Configured upstream resolver.
    pub upstream: Option<String>,
    /// Configured port.
    pub port: u16,
    /// DoT service status.
    pub dot: Option<ServiceDot>,
    /// DoH service status.
    pub doh: Option<ServiceDoh>,
    /// DoQ service status.
    pub doq: Option<ServiceDoq>,
    /// Cache size in bytes.
    pub cache_size: u64,
    /// Number of cached entries.
    pub cache_entries: u16,
}

/// Status of the DNS DoT subservice
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceDot {
    /// Current state (e.g., "online", "offline").
    pub state: ServiceState,
    /// Seconds since the DNS service started.
    pub uptime_secs: u64,
    /// Configured upstream resolver.
    pub upstream: Option<String>,
    /// Configured port.
    pub port: u16,
}

/// Status of the DNS DoH subservice
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceDoh {
    /// Current state (e.g., "online", "offline").
    pub state: ServiceState,
    /// Seconds since the DNS service started.
    pub uptime_secs: u64,
    /// Configured port.
    pub port: u16,
}

/// Status of the DNS DoQ subservice
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceDoq {
    /// Current state (e.g., "online", "offline").
    pub state: ServiceState,
    /// Seconds since the DNS service started.
    pub uptime_secs: u64,
    /// Configured port.
    pub port: u16,
}

/// Generic status information for auxiliary services.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ServiceStatusInfo {
    /// Current state (e.g., "online", "ativo").
    pub state: ServiceState,
}

/// Status of the NDP Monitor service.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ServiceNdp {
    /// Current state (e.g., "online", "offline").
    pub state: ServiceState,
    /// Seconds since the scanner service started.
    pub uptime_secs: u64,
    /// Total number of unique IPv6 addresses being tracked via neighbor discovery.
    pub addrs_tracked: usize,
}

/// Statistics and path information for the persistent database.
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
    pub lan_ipv4: Option<Ipv4Addr>,
    /// Primary IPv4 address with CIDR (e.g., "192.168.1.1/24").
    pub lan_ipv4_cidr: Option<u8>,
    /// Primary IPv6 address of the LAN interface.
    pub lan_ipv6: Option<Ipv6Addr>,
    /// Primary GUA prefix.
    pub gua: Option<Ipv6Addr>,
    /// Primary ULA prefix.
    pub ula: Option<Ipv6Addr>,
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
use lanforge_types::network::dns::{
    AdblockUrlEntry,
    adblock::{AdblockDbConfig, AdblockRuleEntry, RewriteRule},
};

use lanforge_types::auth::ApiScopes;
use lanforge_types::network::DnsReverseResolver;
use lanforge_types::network::dhcp::DhcpOptionsConfig;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportedApiToken {
    pub token: String,
    pub name: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
    pub scopes: ApiScopes,
    pub expires_at: Option<i64>,
}

/// Unified system configuration export aggregating all persistent database tables.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SystemConfigExport {
    pub hosts: Vec<HostConfigEntry>,
    pub dns_rewrites: Vec<RewriteRule>,
    pub dns_upstreams: Vec<DnsUpstreamConfig>,
    pub dns_adblock_config: AdblockDbConfig,
    pub dns_adblock_urls: Vec<AdblockUrlEntry>,
    pub dns_allowlist: Vec<AllowlistEntry>,
    #[serde(default)]
    pub dns_adblock_rules: Option<Vec<AdblockRuleEntry>>,
    pub api_tokens: Option<Vec<ExportedApiToken>>,
    pub dhcp_v4_pools: Option<Vec<Dhcpv4Pool>>,
    pub dhcp_v6_pools: Option<Vec<Dhcpv6Pool>>,
    pub ra_prefixes: Option<Vec<RAPrefix>>,
    pub ra_rdnss: Option<Vec<RdnssConfig>>,
    pub ra_dnssl: Option<Vec<DnsslConfig>>,
    pub pppoe_config: Option<Box<PppoeConfig>>,
    #[serde(default)]
    pub dhcp_options: Option<Box<DhcpOptionsConfig>>,
    #[serde(default)]
    pub dns_reverse_resolvers: Option<Vec<DnsReverseResolver>>,
    #[serde(default)]
    pub firewall_config: Option<Box<FirewallConfig>>,
    #[serde(default)]
    pub traffic_config: Option<Box<TrafficConfig>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_iface: Option<String>,
    #[serde(default)]
    pub overwrite: bool,
}

impl HttpWrappedResponse for PppoeConfig {
    type Wrapper = HttpDataResponse<PppoeConfig>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for StatusResponse {
    type Wrapper = HttpDataResponse<StatusResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for ServiceBannersResponse {
    type Wrapper = HttpDataResponse<ServiceBannersResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for SystemConfigExport {
    type Wrapper = HttpDataResponse<SystemConfigExport>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ImportSection {
    Hosts,
    DnsRewrites,
    DnsUpstreams,
    DnsAdblockConfig,
    DnsAdblockUrls,
    DnsAllowlist,
    DnsAdblockRules,
    ApiTokens,
    DhcpV4Pools,
    DhcpV6Pools,
    RaPrefixes,
    RaRdnss,
    RaDnssl,
    PppoeConfig,
    DhcpOptions,
    DnsReverseResolvers,
    FirewallConfig,
    TrafficConfig,
}

impl ImportSection {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Hosts => "hosts",
            Self::DnsRewrites => "dns_rewrites",
            Self::DnsUpstreams => "dns_upstreams",
            Self::DnsAdblockConfig => "dns_adblock_config",
            Self::DnsAdblockUrls => "dns_adblock_urls",
            Self::DnsAllowlist => "dns_allowlist",
            Self::DnsAdblockRules => "dns_adblock_rules",
            Self::ApiTokens => "api_tokens",
            Self::DhcpV4Pools => "dhcp_v4_pools",
            Self::DhcpV6Pools => "dhcp_v6_pools",
            Self::RaPrefixes => "ra_prefixes",
            Self::RaRdnss => "ra_rdnss",
            Self::RaDnssl => "ra_dnssl",
            Self::PppoeConfig => "pppoe_config",
            Self::DhcpOptions => "dhcp_options",
            Self::DnsReverseResolvers => "dns_reverse_resolvers",
            Self::FirewallConfig => "firewall_config",
            Self::TrafficConfig => "traffic_config",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ImportResult {
    pub section: ImportSection,
    pub success: bool,
    pub count: usize,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SystemConfigImportResponse {
    pub results: Vec<ImportResult>,
    pub total_success: bool,
}

impl HttpWrappedResponse for SystemConfigImportResponse {
    type Wrapper = HttpDataResponse<SystemConfigImportResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for lanforge_types::system::PppoeStatusResponse {
    type Wrapper = HttpDataResponse<lanforge_types::system::PppoeStatusResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for lanforge_types::system::RaStatusResponse {
    type Wrapper = HttpDataResponse<lanforge_types::system::RaStatusResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for lanforge_types::network::ra::RaServerConfig {
    type Wrapper = HttpDataResponse<lanforge_types::network::ra::RaServerConfig>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

pub use lanforge_types::system::{
    NetworkInterfaceInfo, SetupPayload, SetupPppoeNftables, SetupRaConfig, SetupResponse,
    SetupStatusResponse, SetupWanConfig,
};

impl HttpWrappedResponse for SetupStatusResponse {
    type Wrapper = HttpDataResponse<SetupStatusResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for SetupResponse {
    type Wrapper = HttpDataResponse<SetupResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

use lanforge_types::system::StorageMode;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DbEngineSwitchRequest {
    #[serde(alias = "engine")]
    pub mode: StorageMode,
    #[serde(default, alias = "url")]
    pub path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DbEngineSwitchResponse {
    pub success: bool,
    #[serde(alias = "engine")]
    pub mode: StorageMode,
    pub message: String,
}

impl HttpWrappedResponse for DbEngineSwitchResponse {
    type Wrapper = HttpDataResponse<DbEngineSwitchResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for FirewallConfig {
    type Wrapper = HttpDataResponse<FirewallConfig>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for FirewallStatus {
    type Wrapper = HttpDataResponse<FirewallStatus>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for FirewallValidationReport {
    type Wrapper = HttpDataResponse<FirewallValidationReport>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for FirewallCommitResponse {
    type Wrapper = HttpDataResponse<FirewallCommitResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for lanforge_types::network::TrafficConfig {
    type Wrapper = HttpDataResponse<lanforge_types::network::TrafficConfig>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for lanforge_types::system::TrafficStatusResponse {
    type Wrapper = HttpDataResponse<lanforge_types::system::TrafficStatusResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for lanforge_types::network::traffic::TrafficTelemetryResponse {
    type Wrapper = HttpDataResponse<lanforge_types::network::traffic::TrafficTelemetryResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}
