use lanforge_types::device::LeaseHistoryEntry;
use serde::{Deserialize, Serialize};

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

/// Detailed aggregated information for a single device.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WhoisResponse {
    /// Current device state.
    pub entry: DeviceEntry,
    /// Historical lease assignments.
    pub history: Vec<LeaseHistoryEntry>,
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
