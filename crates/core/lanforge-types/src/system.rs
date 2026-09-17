use crate::identifiers::MacAddr;
use crate::network::{
    FirewallMode, Ipv6Prefix,
    dns::upstream::UpstreamTarget,
    ra::{DnsslConfig, RAPrefix, RdnssConfig, RouterPriority},
};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};


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
    pub pppoe_enabled: bool,
}

/// The operational storage mode of the persistence layer.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum StorageMode {
    #[default]
    #[serde(alias = "file", alias = "persistent", alias = "redb", alias = "disk")]
    Persistent,
    #[serde(alias = "memory", alias = "none", alias = "mock", alias = "in_memory")]
    InMemory,
}

impl StorageMode {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Persistent => "persistent",
            Self::InMemory => "in_memory",
        }
    }

    #[must_use]
    pub const fn is_in_memory(&self) -> bool {
        matches!(self, Self::InMemory)
    }
}

impl std::fmt::Display for StorageMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
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
    #[serde(alias = "redb")]
    Storage,
    Pppoe,
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

/// Status of the `PPPoE` session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PppoeSessionState {
    #[default]
    Disconnected,
    Authenticating,
    Connected,
    Reconnecting,
}

/// Status response payload for `PPPoE`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PppoeStatusResponse {
    pub enabled: bool,
    pub dataplane: Option<crate::network::pppoe::PppoeDataplane>,
    pub state: PppoeSessionState,
    pub interface: Option<String>,
    pub wan_iface: Option<String>,
    pub local_ip: Option<Ipv4Addr>,
    pub peer_ip: Option<Ipv4Addr>,
    pub ac_mac: Option<MacAddr>,
    pub ac_name: Option<String>,
    pub session_id: Option<u16>,
    pub mru: Option<u16>,
    pub dns_servers: Vec<IpAddr>,
    pub uptime_secs: Option<u64>,
    pub reconnect_attempts: u32,
    pub last_error: Option<String>,
    pub auth: Option<crate::network::pppoe::AuthMethod>,
}

/// Status response payload for Network Traffic & SQM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TrafficStatusResponse {
    pub service_state: ServiceState,
    pub tuning_applied: bool,
    pub tuned_interfaces: Vec<String>,
    pub effective_cpu_mask: String,
    pub sqm_active: bool,
    pub wan_interface: Option<String>,
    pub ingress_device: Option<String>,
    pub download_mbps: u32,
    pub upload_mbps: u32,
    pub overhead: crate::network::traffic::SqmOverhead,
    pub diffserv: crate::network::traffic::SqmDiffserv,
    pub flow_offload_suppressed: bool,
}


/// Discovered network interface information for setup and topology display.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub mac: Option<MacAddr>,
    pub is_physical: bool,
    pub is_up: bool,
    pub carrier_up: bool,
    pub ips: Vec<String>,
    pub bus_type: String,
}

/// Setup status and environment discovery for the first-run onboarding wizard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStatusResponse {
    pub first_run: bool,
    pub is_provisioned: bool,
    pub detected_lan_iface: String,
    pub detected_gateway: Option<Ipv4Addr>,
    #[serde(default)]
    pub detected_subnet_mask: Option<Ipv4Addr>,
    pub detected_ula_prefix: String,
    pub interfaces: Vec<NetworkInterfaceInfo>,
}

const fn default_subnet_mask() -> Ipv4Addr {
    Ipv4Addr::new(255, 255, 255, 0)
}

const fn default_true() -> bool {
    true
}

/// Router Advertisement (IPv6 SLAAC) configuration for initial setup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct SetupRaConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub auto_gua: bool,
    #[serde(default = "default_true")]
    pub ula_enabled: bool,
    #[serde(default)]
    pub ula_prefix: Option<String>,
    #[serde(default = "default_true")]
    pub managed: bool,
    #[serde(default = "default_true")]
    pub other_config: bool,
}

impl Default for SetupRaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_gua: true,
            ula_enabled: true,
            ula_prefix: None,
            managed: true,
            other_config: true,
        }
    }
}

/// `PPPoE` firewall / nftables tuning options for initial setup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct SetupPppoeNftables {
    #[serde(default = "default_true")]
    pub mss_clamping: bool,
    #[serde(default)]
    pub flow_offload: bool,
    #[serde(default = "default_true")]
    pub masquerade: bool,
    #[serde(default = "default_true")]
    pub bypass_dns: bool,
    #[serde(default = "default_true")]
    pub bypass_vowifi: bool,
}

impl Default for SetupPppoeNftables {
    fn default() -> Self {
        Self {
            mss_clamping: true,
            flow_offload: false,
            masquerade: true,
            bypass_dns: true,
            bypass_vowifi: true,
        }
    }
}

/// WAN uplink configuration for initial setup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SetupWanConfig {
    Pppoe {
        interface: String,
        username: String,
        password: String,
        #[serde(default)]
        vlan_id: Option<u16>,
        #[serde(default)]
        mtu: Option<u16>,
        #[serde(default)]
        nftables: Option<SetupPppoeNftables>,
    },
    SystemGateway {
        gateway_ip: Ipv4Addr,
    },
}

/// Consolidated payload submitted by the initial setup wizard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupPayload {
    pub admin_username: String,
    pub admin_password: String,
    pub lan_iface: String,
    pub lan_ip: Ipv4Addr,
    #[serde(default = "default_subnet_mask")]
    pub subnet_mask: Ipv4Addr,
    pub domain_name: String,
    pub dhcp_enabled: bool,
    pub dhcp_pool_start: Ipv4Addr,
    pub dhcp_pool_end: Ipv4Addr,
    #[serde(default)]
    pub dhcp_router: Option<Ipv4Addr>,
    pub adblock_enabled: bool,
    #[serde(default)]
    pub upstream_dns: Vec<String>,
    #[serde(default)]
    pub ra: Option<SetupRaConfig>,
    pub wan: Option<SetupWanConfig>,
    #[serde(default)]
    pub firewall_mode: Option<FirewallMode>,
}

/// Response returned after successfully applying the initial setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupResponse {
    pub success: bool,
    pub token: String,
    pub username: String,
    pub message: String,
}

/// Status, metrics, and active configuration response payload for Router Advertisement (RA) server.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RaStatusResponse {
    /// Whether the RA service is running/enabled.
    pub enabled: bool,
    /// Network interface name (e.g. "eth0").
    pub interface: Option<String>,
    /// Link-local IPv6 address of the interface.
    pub link_local: Option<Ipv6Addr>,
    /// Current detected or active Global Unicast Address (GUA) prefix.
    pub active_gua_prefix: Option<Ipv6Addr>,
    /// Current detected or active Unique Local Address (ULA) prefix.
    pub active_ula_prefix: Option<Ipv6Addr>,
    /// Prefixes currently being advertised.
    pub prefixes: Vec<RAPrefix>,
    /// Recursive DNS servers currently being advertised (RFC 8106).
    pub rdnss: Vec<RdnssConfig>,
    /// DNS search lists currently being advertised (RFC 8106).
    pub dnssl: Vec<DnsslConfig>,
    /// Deprecated prefixes currently advertised with decremented lifetimes: (prefix, `remaining_valid_secs`).
    pub deprecated_prefixes: Vec<(Ipv6Addr, u32)>,

    // Packet counters
    /// Total multicast RAs sent to `ff02::1`.
    pub sent_multicast_ras: u64,

    /// Total unicast RAs sent directly to soliciting clients.
    pub sent_unicast_ras: u64,
    /// Total Router Solicitations (RS) received from hosts.
    pub received_solicitations: u64,
    /// Total Router Solicitations ignored/dropped due to RFC 4861 rate limits.
    pub ignored_solicitations: u64,

    // Timing & Activity
    /// Seconds elapsed since the last RA was sent.
    pub last_ra_sent_secs_ago: Option<u64>,
    /// Seconds elapsed since the last RS was received.
    pub last_rs_received_secs_ago: Option<u64>,
    /// Estimated seconds until next scheduled periodic RA.
    pub next_ra_in_secs: Option<u64>,

    // Operating flags & parameters
    /// Managed address configuration flag (M).
    pub managed: bool,
    /// Other configuration flag (O).
    pub other_config: bool,
    /// Suggested hop limit.
    pub hop_limit: u8,
    /// Router priority preference (RFC 4191).
    pub priority: RouterPriority,
    /// Max interval between periodic unsolicited Router Advertisements (seconds).
    pub max_interval_secs: u64,
    /// Effective min interval between periodic unsolicited Router Advertisements (seconds).
    pub min_interval_secs: u64,
    /// Router lifetime (seconds; 0 = not a default router).
    pub router_lifetime_secs: u64,
    /// Announced link MTU.
    pub mtu: Option<u32>,
    /// Service uptime in seconds.
    pub uptime_secs: Option<u64>,
}

