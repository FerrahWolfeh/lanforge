use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::common::{HttpDataResponse, HttpPaginatedResponse, HttpWrappedResponse};
use lanforge_types::{
    device::{
        DeviceClass, DeviceStatus, IpClassification, Ipv6AddrOrSuffix, LearningMethod,
        LeaseHistoryEntry, Origin, TransientOrigin,
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
    /// Hostname, either broadcast by the device or manually set.
    pub hostname: String,
    /// Source of identification (e.g., "Dynamic", "Toml", "Cli").
    pub origin: Origin,
    /// Current online/offline status.
    pub online: bool,
    /// Detailed reachability status (Online, Stale, Offline).
    pub status: DeviceStatus,
    /// Last seen timestamp.
    pub last_seen: u64,
    /// Hex-encoded DUID for `DHCPv6`, if available.
    pub duid: Option<Duid>,
    /// Human-readable primary `IPv4` display.
    pub display_v4: String,
    /// Human-readable primary `IPv6` display.
    pub display_v6: String,
    /// Active `DHCPv4` lease information.
    pub v4: Option<LeaseInfo>,
    /// List of all `IPv4` addresses seen for this device.
    pub seen_v4: Vec<Ipv4Addr>,
    /// Active `DHCPv6` lease information.
    pub v6: Option<LeaseInfo>,
    /// List of IPv6 addresses (SLAAC, GUA, etc.) tracked for this device.
    pub ipv6_addrs: Vec<Ipv6Entry>,
    /// Method by which the device was discovered.
    pub learning_method: LearningMethod,
    /// Discovered category (e.g., "printer", "media").
    pub class: DeviceClass,
    /// Ingress network interface where the device was observed (e.g., "lan0.100").
    #[serde(default)]
    pub iface: Option<String>,
    /// Inferred 802.1Q VLAN ID if observed on a VLAN subinterface (e.g., 100 for "lan0.100").
    #[serde(default)]
    pub vlan_id: Option<u16>,
    /// Whether DNS query logging is suppressed for this device.
    #[serde(default)]
    pub ignore_dns_log: bool,
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
    /// Historical lease assignments.
    pub history: Vec<LeaseHistoryEntry>,
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
    let mut groups: Vec<Vec<DeviceEntry>> = devices.iter().cloned().map(|d| vec![d]).collect();

    // Iteratively merge groups
    let mut merged = true;
    while merged {
        merged = false;
        'outer: for i in 0..groups.len() {
            for j in (i + 1)..groups.len() {
                if should_merge(&groups[i], &groups[j]) {
                    let mut other = groups.remove(j);
                    groups[i].append(&mut other);
                    merged = true;
                    break 'outer;
                }
            }
        }
    }

    // Construct GroupedDevice list
    let mut correlated = Vec::new();
    for mut interfaces in groups {
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

fn should_merge(a: &[DeviceEntry], b: &[DeviceEntry]) -> bool {
    // Check DUID match
    for dev_a in a {
        if let Some(ref duid_a) = dev_a.duid {
            for dev_b in b {
                if let Some(ref duid_b) = dev_b.duid
                    && duid_a == duid_b
                {
                    return true;
                }
            }
        }
    }
    // Check Hostname match
    for dev_a in a {
        if is_valid_hostname(&dev_a.hostname) {
            for dev_b in b {
                if is_valid_hostname(&dev_b.hostname)
                    && dev_a.hostname.eq_ignore_ascii_case(&dev_b.hostname)
                {
                    return true;
                }
            }
        }
    }
    false
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
        assert_eq!(entry_nulls.mac, MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap());
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
