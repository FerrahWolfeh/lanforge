use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::common::{HttpDataResponse, HttpPaginatedResponse, HttpWrappedResponse};
use lanforge_types::{
    device::{
        DeviceClass, DeviceStatus, IpClassification, Ipv6AddrOrSuffix, LearningMethod, Origin,
        TransientOrigin,
    },
    identifiers::{Duid, MacAddr},
    network::dhcp::empty_string_as_none,
};
use serde::{Deserialize, Deserializer, Serialize};

/// A response containing a list of devices and metadata.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DevicesResponse {
    /// The list of device entries.
    pub devices: Vec<DeviceEntry>,
    /// Statistical metadata about the scan results.
    pub meta: DevicesMeta,
}

/// Query parameters for listing devices with pagination and filtering.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct DeviceListQuery {
    pub filter: Option<String>,
    pub vendor: Option<String>,
    pub method: Option<String>,
    pub format: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// A response containing a list of manually configured hosts.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostsResponse {
    /// The list of host configurations.
    pub hosts: Vec<HostConfigEntry>,
}

const fn default_host_origin() -> Origin {
    Origin::Static
}

fn deserialize_string_or_empty<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    if !deserializer.is_human_readable() {
        return String::deserialize(deserializer);
    }
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(opt.map(|s| s.trim().to_string()).unwrap_or_default())
}

/// A single entry in the host configuration list.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HostConfigEntry {
    /// MAC address identifying the device.
    pub mac: MacAddr,
    /// Manually configured hostname.
    #[serde(default, deserialize_with = "deserialize_string_or_empty")]
    pub hostname: String,
    /// Fixed IPv4 address, if set.
    #[serde(default, alias = "v4", deserialize_with = "empty_string_as_none")]
    pub v4_fixed: Option<Ipv4Addr>,
    /// IPv6 Interface ID (suffix) or Full address.
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub v6_suffix: Option<Ipv6AddrOrSuffix>,
    /// Source of the configuration (e.g., "Toml", "Cli").
    #[serde(default = "default_host_origin")]
    pub origin: Origin,
    /// Whether DNS query logging is suppressed for this host.
    #[serde(default)]
    pub ignore_dns_log: bool,
    /// Specific domains or wildcards to suppress from DNS query logs for this host.
    #[serde(default)]
    pub ignored_log_domains: Vec<String>,
}

/// A single device discovered on the network.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct DeviceEntry {
    /// Device MAC address.
    pub mac: MacAddr,
    /// Source of identification (e.g., "Dynamic", "Toml", "Cli").
    pub origin: Origin,
    /// Current online/offline status.
    pub online: bool,
    /// Detailed reachability status (Online, Stale, Offline).
    pub status: DeviceStatus,
    /// Method by which the device was discovered.
    pub learning_method: LearningMethod,
    /// Discovered category (e.g., "printer", "media").
    pub class: DeviceClass,
    /// Whether DNS query logging is suppressed for this device.
    #[serde(default)]
    pub ignore_dns_log: bool,
    /// Inferred 802.1Q VLAN ID if observed on a VLAN subinterface (e.g., 100 for "lan0.100").
    #[serde(default)]
    pub vlan_id: Option<u16>,
    /// Last seen timestamp.
    pub last_seen: u64,
    /// Hostname, either broadcast by the device or manually set.
    pub hostname: String,
    /// Primary `IPv4` address, if assigned or discovered.
    pub primary_v4: Option<Ipv4Addr>,
    /// Primary `IPv6` address, if assigned or discovered.
    pub primary_v6: Option<Ipv6Addr>,
    /// Ingress network interface where the device was observed (e.g., "lan0.100").
    #[serde(default)]
    pub iface: Option<String>,
    /// Hex-encoded DUID for `DHCPv6`, if available.
    pub duid: Option<Duid>,
    /// Active `DHCPv4` lease information.
    pub v4: Option<Box<LeaseInfo>>,
    /// Active `DHCPv6` lease information.
    pub v6: Option<Box<LeaseInfo>>,
    /// List of IPv6 addresses (SLAAC, GUA, etc.) tracked for this device.
    pub ipv6_addrs: Vec<Ipv6Entry>,
    /// Specific domains or wildcards to suppress from DNS query logs for this device.
    #[serde(default)]
    pub ignored_log_domains: Vec<String>,
}

/// A single IPv6 address entry with its type category.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Ipv6Entry {
    /// Full IPv6 address.
    pub addr: Ipv6Addr,
    /// Category of the address (e.g., "SLAAC", "ULA", "GUA", "Link-Local").
    pub kind: IpClassification,
}

/// Details about a DHCP lease.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LeaseInfo {
    /// Assigned IP address.
    pub ip: IpAddr,
    /// Expiration timestamp - 0 means it will not expire (static).
    pub expires: u64,
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
}

/// Detailed aggregated information for a single device.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WhoisResponse {
    /// Current device state.
    pub entry: DeviceEntry,
}

/// A single entry in the transient hosts list.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransientHostEntry {
    /// Resolved IP address of the transient host.
    pub ip: IpAddr,
    /// Resolved hostname.
    pub hostname: String,
    /// Origin of this transient host.
    pub origin: TransientOrigin,
    /// When the host was resolved (secs since epoch).
    pub resolved_at: u64,
    /// When the host was last seen (secs since epoch).
    pub last_seen: u64,
}

impl Default for TransientHostEntry {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            hostname: String::new(),
            origin: TransientOrigin::default(),
            resolved_at: 0,
            last_seen: 0,
        }
    }
}

/// A response containing the list of transient hosts.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransientHostsResponse {
    /// The list of transient hosts.
    pub hosts: Vec<TransientHostEntry>,
}

impl HttpWrappedResponse for DevicesResponse {
    type Wrapper = HttpPaginatedResponse<Vec<DeviceEntry>, DevicesMeta>;

    fn wrap(self) -> Self::Wrapper {
        HttpPaginatedResponse {
            data: self.devices,
            meta: self.meta,
        }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        Self {
            devices: wrapper.data,
            meta: wrapper.meta,
        }
    }
}

impl HttpWrappedResponse for HostsResponse {
    type Wrapper = HttpDataResponse<HostsResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for WhoisResponse {
    type Wrapper = HttpDataResponse<WhoisResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

impl HttpWrappedResponse for TransientHostsResponse {
    type Wrapper = HttpDataResponse<TransientHostsResponse>;

    fn wrap(self) -> Self::Wrapper {
        HttpDataResponse { data: self }
    }

    fn unwrap(wrapper: Self::Wrapper) -> Self {
        wrapper.data
    }
}

/// A representation of multiple network interfaces correlated/grouped into one physical device.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GroupedDevice {
    pub hostname: String,
    pub duid: Option<Duid>,
    pub primary_mac: MacAddr,
    pub interfaces: Vec<DeviceEntry>,
}

#[must_use]
pub fn group_devices(devices: &[DeviceEntry]) -> Vec<GroupedDevice> {
    if devices.is_empty() {
        return Vec::new();
    }

    let n = devices.len();
    let mut parent: Vec<usize> = (0..n).collect();

    fn find(parent: &mut [usize], mut i: usize) -> usize {
        let mut root = i;
        while root != parent[root] {
            root = parent[root];
        }
        while i != root {
            let next = parent[i];
            parent[i] = root;
            i = next;
        }
        root
    }

    fn union(parent: &mut [usize], i: usize, j: usize) {
        let root_i = find(parent, i);
        let root_j = find(parent, j);
        if root_i != root_j {
            parent[root_i] = root_j;
        }
    }

    let mut duid_map: HashMap<&Duid, usize> = HashMap::with_capacity(n);
    let mut name_map: HashMap<String, usize> = HashMap::with_capacity(n);

    for (i, dev) in devices.iter().enumerate() {
        if let Some(ref duid) = dev.duid {
            if let Some(&prev_idx) = duid_map.get(duid) {
                union(&mut parent, i, prev_idx);
            } else {
                duid_map.insert(duid, i);
            }
        }

        if is_valid_hostname(&dev.hostname) {
            let lower = dev.hostname.to_ascii_lowercase();
            if let Some(&prev_idx) = name_map.get(&lower) {
                union(&mut parent, i, prev_idx);
            } else {
                name_map.insert(lower, i);
            }
        }
    }

    // Bucket devices by their root while preserving deterministic first-seen order
    let mut root_to_group: Vec<Option<Vec<DeviceEntry>>> = (0..n).map(|_| None).collect();
    let mut group_roots: Vec<usize> = Vec::with_capacity(n);

    for (i, dev) in devices.iter().enumerate() {
        let root = find(&mut parent, i);
        if let Some(ref mut group) = root_to_group[root] {
            group.push(dev.clone());
        } else {
            group_roots.push(root);
            root_to_group[root] = Some(vec![dev.clone()]);
        }
    }

    // Construct GroupedDevice list
    let mut correlated = Vec::with_capacity(group_roots.len());
    for root in group_roots {
        let mut interfaces = root_to_group[root].take().unwrap_or_default();
        // Sort interfaces inside the group
        sort_interfaces(&mut interfaces);

        let primary_mac = interfaces[0].mac;
        let duid = interfaces.iter().find_map(|d| d.duid.clone());

        // Find the best hostname
        let hostname = interfaces
            .iter()
            .find(|d| is_valid_hostname(&d.hostname))
            .map(|d| d.hostname.clone())
            .unwrap_or_else(|| {
                interfaces
                    .iter()
                    .find(|d| !d.hostname.is_empty())
                    .map(|d| d.hostname.clone())
                    .unwrap_or_else(|| "—".to_string())
            });

        correlated.push(GroupedDevice {
            hostname,
            duid,
            primary_mac,
            interfaces,
        });
    }

    correlated
}

fn is_valid_hostname(hostname: &str) -> bool {
    !hostname.is_empty() && hostname != "<unknown>" && !hostname.starts_with("host-")
}

pub fn sort_interfaces(interfaces: &mut [DeviceEntry]) {
    interfaces.sort_by(|a, b| {
        // Online first
        let a_online = a.status == DeviceStatus::Online;
        let b_online = b.status == DeviceStatus::Online;
        b_online
            .cmp(&a_online)
            .then(b.last_seen.cmp(&a.last_seen))
            .then(a.mac.cmp(&b.mac))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_devices() {
        let mac1 = MacAddr::parse("00:11:22:33:44:55").unwrap();
        let mac2 = MacAddr::parse("00:11:22:33:44:56").unwrap();
        let mac3 = MacAddr::parse("00:11:22:33:44:57").unwrap();

        let duid1 = Duid::new(vec![1, 2, 3]);

        let dev1 = DeviceEntry {
            mac: mac1,
            hostname: "my-laptop".to_string(),
            duid: Some(duid1.clone()),
            status: DeviceStatus::Online,
            last_seen: 100,
            ..Default::default()
        };

        let dev2 = DeviceEntry {
            mac: mac2,
            hostname: "".to_string(),
            duid: Some(duid1.clone()),
            status: DeviceStatus::Offline,
            last_seen: 50,
            ..Default::default()
        };

        let dev3 = DeviceEntry {
            mac: mac3,
            hostname: "my-laptop".to_string(),
            duid: None,
            status: DeviceStatus::Stale,
            last_seen: 200,
            ..Default::default()
        };

        let devices = vec![dev1, dev2, dev3];
        let groups = group_devices(&devices);

        assert_eq!(groups.len(), 1);
        let group = &groups[0];
        assert_eq!(group.hostname, "my-laptop");
        assert_eq!(group.duid, Some(duid1));
        assert_eq!(group.interfaces.len(), 3);

        // interfaces should be sorted: online first, then stale, then offline
        assert_eq!(group.interfaces[0].mac, mac1); // Online, last_seen = 100
        assert_eq!(group.interfaces[1].mac, mac3); // Stale, last_seen = 200
        assert_eq!(group.interfaces[2].mac, mac2); // Offline, last_seen = 50
    }

    #[test]
    fn test_no_group_on_fallback_hostname() {
        let mac1 = MacAddr::parse("00:11:22:33:44:55").unwrap();
        let mac2 = MacAddr::parse("00:11:22:33:44:56").unwrap();

        let dev1 = DeviceEntry {
            mac: mac1,
            hostname: "host-001122334455".to_string(),
            duid: None,
            ..Default::default()
        };

        let dev2 = DeviceEntry {
            mac: mac2,
            hostname: "host-001122334455".to_string(),
            duid: None,
            ..Default::default()
        };

        let devices = vec![dev1, dev2];
        let groups = group_devices(&devices);

        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn test_host_config_entry_deserialization_tolerance() {
        // Minimal JSON (only MAC, no origin, no hostname)
        let json_minimal = r#"{"mac":"00:11:22:33:44:55"}"#;
        let entry: HostConfigEntry = serde_json::from_str(json_minimal).unwrap();
        assert_eq!(entry.mac, MacAddr::parse("00:11:22:33:44:55").unwrap());
        assert_eq!(entry.hostname, "");
        assert_eq!(entry.origin, Origin::Static);
        assert_eq!(entry.v4_fixed, None);
        assert_eq!(entry.v6_suffix, None);
        assert!(!entry.ignore_dns_log);

        // JSON with nulls and empty strings
        let json_nulls = r#"{"mac":"aa:bb:cc:dd:ee:ff","hostname":null,"v4":"","v6_suffix":null}"#;
        let entry_nulls: HostConfigEntry = serde_json::from_str(json_nulls).unwrap();
        assert_eq!(
            entry_nulls.mac,
            MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap()
        );
        assert_eq!(entry_nulls.hostname, "");
        assert_eq!(entry_nulls.origin, Origin::Static);
        assert_eq!(entry_nulls.v4_fixed, None);
        assert_eq!(entry_nulls.v6_suffix, None);

        // JSON with v4 alias and whitespace hostname
        let json_alias = r#"{"mac":"aa:bb:cc:dd:ee:01","hostname":" my-pc ","v4":"192.168.1.50"}"#;
        let entry_alias: HostConfigEntry = serde_json::from_str(json_alias).unwrap();
        assert_eq!(entry_alias.hostname, "my-pc");
        assert_eq!(entry_alias.v4_fixed, Some("192.168.1.50".parse().unwrap()));
        assert_eq!(entry_alias.origin, Origin::Static);
    }
}
