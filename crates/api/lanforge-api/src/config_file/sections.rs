use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::duration::HumanDuration;

const fn default_true() -> bool {
    true
}

const fn default_false() -> bool {
    false
}

fn default_database_config_path() -> String {
    "/var/lib/lanforge/config.redb".to_string()
}

fn default_database_runtime_path() -> String {
    "/run/lanforge/runtime.redb".to_string()
}

fn default_flush_interval() -> HumanDuration {
    HumanDuration(60)
}

fn default_api_socket_path() -> String {
    "/run/lanforge/control.sock".to_string()
}

fn default_http_listen() -> String {
    "[::]:8088".to_string()
}

fn default_monitor_scan_pacing_ms() -> u64 {
    10
}

fn default_monitor_stale_timeout_secs() -> u64 {
    3600
}

fn default_mdns_probe_interval() -> HumanDuration {
    HumanDuration(3600)
}

fn default_tftp_listen() -> String {
    "0.0.0.0:69".to_string()
}

fn default_tftp_root_dir() -> String {
    "/var/lib/lanforge/tftp".to_string()
}

const fn default_tftp_block_size() -> u16 {
    512
}

const fn default_tftp_timeout() -> u64 {
    5
}

const fn default_tftp_max_retries() -> u8 {
    3
}

fn default_policy_drop() -> String {
    "drop".to_string()
}

fn default_on_stop() -> String {
    "lockdown".to_string()
}

fn default_firewall_mode() -> String {
    "full".to_string()
}

fn default_table_name() -> String {
    "lanforge".to_string()
}

fn default_zone_external() -> String {
    "external".to_string()
}

/// A file without the key keeps the default matrix; `forwardings = []` means no routing.
pub(super) fn default_forwardings() -> Vec<ZoneForwardingFile> {
    [
        ("internal", "external"),
        ("trusted", "external"),
        ("trusted", "internal"),
        ("internal", "trusted"),
    ]
    .into_iter()
    .map(|(from, to)| ZoneForwardingFile {
        from: from.to_string(),
        to: to.to_string(),
    })
    .collect()
}

fn default_policy_accept() -> String {
    "accept".to_string()
}

fn default_proto_tcp() -> String {
    "tcp".to_string()
}

// ============================================================================
// Static Sections
// ============================================================================

/// Global system configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SystemFile {
    #[serde(default)]
    pub iface: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ula_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debounce_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
    #[serde(default = "default_false")]
    pub auto_provision: bool,
    #[serde(default = "default_false")]
    pub allow_unprivileged: bool,
}

/// Embedded database configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseFile {
    #[serde(default = "default_database_config_path")]
    pub config_path: String,
    #[serde(default = "default_database_runtime_path")]
    pub runtime_path: String,
    #[serde(default = "default_flush_interval")]
    pub flush_interval: HumanDuration,
}

impl Default for DatabaseFile {
    fn default() -> Self {
        Self {
            config_path: default_database_config_path(),
            runtime_path: default_database_runtime_path(),
            flush_interval: default_flush_interval(),
        }
    }
}

/// Control API (Unix Domain Socket) configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_api_socket_path")]
    pub socket_path: String,
}

impl Default for ApiFile {
    fn default() -> Self {
        Self {
            enabled: true,
            socket_path: default_api_socket_path(),
        }
    }
}

/// HTTP/Web Console server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_http_listen")]
    pub listen: String,
    #[serde(default = "default_false")]
    pub https_enabled: bool,
    #[serde(default = "default_true")]
    pub allow_plaintext_http: bool,
    #[serde(default = "default_false")]
    pub doh_enabled: bool,
}

impl Default for HttpFile {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: default_http_listen(),
            https_enabled: false,
            allow_plaintext_http: true,
            doh_enabled: false,
        }
    }
}

/// Network monitor and device discovery configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_monitor_scan_pacing_ms")]
    pub scan_pacing_ms: u64,
    #[serde(default = "default_monitor_stale_timeout_secs")]
    pub stale_timeout_secs: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
}

impl Default for MonitorFile {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_pacing_ms: default_monitor_scan_pacing_ms(),
            stale_timeout_secs: default_monitor_stale_timeout_secs(),
            interfaces: Vec::new(),
        }
    }
}

/// mDNS multicast discovery configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MdnsFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_mdns_probe_interval")]
    pub probe_interval: HumanDuration,
}

impl Default for MdnsFile {
    fn default() -> Self {
        Self {
            enabled: true,
            probe_interval: default_mdns_probe_interval(),
        }
    }
}

/// TFTP server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TftpFile {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_tftp_listen")]
    pub listen: String,
    #[serde(default = "default_tftp_root_dir")]
    pub root_dir: String,
    #[serde(default = "default_tftp_block_size")]
    pub block_size: u16,
    /// Seconds.
    #[serde(default = "default_tftp_timeout")]
    pub timeout: u64,
    #[serde(default = "default_tftp_max_retries")]
    pub max_retries: u8,
}

impl Default for TftpFile {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_tftp_listen(),
            root_dir: default_tftp_root_dir(),
            block_size: default_tftp_block_size(),
            timeout: default_tftp_timeout(),
            max_retries: default_tftp_max_retries(),
        }
    }
}

// ============================================================================
// Dynamic Sections
// ============================================================================

/// DHCP subsystem configuration.
///
/// The file form of the DHCP scope options and pools (`DhcpFile::from_config` / `to_config`):
/// pools keyed by name in file order, `range = "start-end"`, human leases. A pool field left
/// out inherits the scope value at lease time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DhcpFile {
    #[serde(default)]
    pub v4: Dhcpv4File,
    #[serde(default)]
    pub v6: Dhcpv6File,
}

/// DHCPv4 server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dhcpv4File {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<HumanDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet_mask: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search_domains: Vec<String>,
    /// Absent: the default public NTP servers. `ntp = []` advertises none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntp: Option<Vec<Ipv4Addr>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tftp_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_file: Option<String>,
    /// Raw options by code: `options = { "43" = "..." }`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
    /// In file order.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "named_tables")]
    pub pools: Vec<(String, Dhcpv4PoolFile)>,
}

impl Default for Dhcpv4File {
    fn default() -> Self {
        Self {
            enabled: true,
            lease: Some(HumanDuration(86400)),
            router: None,
            dns: Vec::new(),
            subnet_mask: None,
            domain_name: None,
            search_domains: Vec::new(),
            ntp: None,
            tftp_server: None,
            boot_file: None,
            options: BTreeMap::new(),
            pools: Vec::new(),
        }
    }
}

/// A named DHCPv4 dynamic address pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Dhcpv4PoolFile {
    pub range: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<HumanDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subnet_mask: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ntp: Vec<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tftp_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_file: Option<String>,
}

/// DHCPv6 server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dhcpv6File {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<HumanDuration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<Ipv6Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search_domains: Vec<String>,
    /// Absent: the default public NTP servers. `ntp = []` advertises none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntp: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_file: Option<String>,
    /// Raw options by code: `options = { "17" = "..." }`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, String>,
    /// In file order.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "named_tables")]
    pub pools: Vec<(String, Dhcpv6PoolFile)>,
}

impl Default for Dhcpv6File {
    fn default() -> Self {
        Self {
            enabled: true,
            lease: Some(HumanDuration(86400)),
            dns: Vec::new(),
            search_domains: Vec::new(),
            ntp: None,
            boot_file: None,
            options: BTreeMap::new(),
            pools: Vec::new(),
        }
    }
}

/// A named DHCPv6 dynamic address pool: a `range` (suffixes such as `"::100-::1fff"` follow the
/// LAN prefix, full addresses are fixed) and/or a static `address`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Dhcpv6PoolFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// IPv6 Router Advertisement (RFC 4861) configuration.
///
/// The file form of `RaServerConfig` (`RaFile::from_config` / `to_config`). What the daemon
/// derives when a key is left out (interface, default prefixes, the ULA from `[system]`,
/// RDNSS/DNSSL from DHCPv6 and the search domains) is applied in memory, never written here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RaFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Absent: the LAN interface (`[system] iface`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    #[serde(default = "default_true")]
    pub managed: bool,
    #[serde(default = "default_true")]
    pub other_config: bool,
    /// Absent: 64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hop_limit: Option<u8>,
    /// `low`, `medium` (absent) or `high`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_interval: Option<HumanDuration>,
    /// Absent: a third of `max_interval` (at least 3 s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_interval: Option<HumanDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<HumanDuration>,
    /// Milliseconds; absent: unspecified (0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachable_time: Option<u32>,
    /// Milliseconds; absent: unspecified (0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrans_timer: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(default = "default_true")]
    pub deprecate_on_renumber: bool,
    /// In file order: RA lists the prefixes as written.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "named_tables")]
    pub prefixes: Vec<(String, RaPrefixFile)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "named_tables")]
    pub rdnss: Vec<(String, RaRdnssFile)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "named_tables")]
    pub dnssl: Vec<(String, RaDnsslFile)>,
}

impl Default for RaFile {
    fn default() -> Self {
        Self {
            enabled: true,
            iface: None,
            managed: true,
            other_config: true,
            hop_limit: None,
            priority: None,
            // `None` = the daemon's built-in value (200 s, 3 × max_interval, no MTU option), the
            // same as a `[ra]` section without these keys.
            max_interval: None,
            min_interval: None,
            lifetime: None,
            reachable_time: None,
            retrans_timer: None,
            mtu: None,
            deprecate_on_renumber: true,
            prefixes: Vec::new(),
            rdnss: Vec::new(),
            dnssl: Vec::new(),
        }
    }
}

/// A prefix lifetime: a duration (`"30d"`, `"4h"`, seconds) or `"infinity"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct LifetimeFile(pub lanforge_types::network::ra::PrefixLifetime);

impl Serialize for LifetimeFile {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use lanforge_types::network::ra::PrefixLifetime;
        match self.0 {
            PrefixLifetime::Infinity => serializer.serialize_str("infinity"),
            PrefixLifetime::Secs(s) => HumanDuration(u64::from(s)).serialize(serializer),
        }
    }
}

/// A named RA IPv6 Prefix announcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RaPrefixFile {
    /// `static`, `ula`, `auto_ula` or `auto_gua`. Absent: `ula` for an `fc00::/7` prefix,
    /// `static` for another one, `auto_gua` without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// `"address/len"` (`/64` if left out).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Length of a prefix found at run time (no `prefix`); absent: 64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_len: Option<u8>,
    #[serde(default = "default_true")]
    pub on_link: bool,
    #[serde(default = "default_true")]
    pub autonomous: bool,
    #[serde(default = "default_true")]
    pub router_addr: bool,
    /// Absent: 1 day.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_lifetime: Option<LifetimeFile>,
    /// Absent: 4 hours.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_lifetime: Option<LifetimeFile>,
}

impl Default for RaPrefixFile {
    fn default() -> Self {
        Self {
            source: None,
            prefix: None,
            prefix_len: None,
            on_link: true,
            autonomous: true,
            router_addr: true,
            valid_lifetime: None,
            preferred_lifetime: None,
        }
    }
}

/// A named RDNSS IPv6 recursive DNS announcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RaRdnssFile {
    pub servers: Vec<Ipv6Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<HumanDuration>,
}

/// A named DNSSL IPv6 DNS search list announcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RaDnsslFile {
    pub domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<HumanDuration>,
}

/// Stateful Netlink/nftables firewall configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// `full`, `minimal` or `disabled`.
    #[serde(default = "default_firewall_mode")]
    pub mode: String,
    #[serde(default = "default_table_name")]
    pub table_name: String,
    #[serde(default = "default_true")]
    pub flow_offload: bool,
    #[serde(default = "default_true")]
    pub bypass_dns: bool,
    #[serde(default = "default_true")]
    pub bypass_vowifi: bool,
    #[serde(default = "default_policy_drop")]
    pub default_input_policy: String,
    #[serde(default = "default_policy_drop")]
    pub default_forward_policy: String,
    /// `lockdown` (default) keeps the WAN closed when the firewall stops; `remove` deletes the table.
    #[serde(default = "default_on_stop")]
    pub on_stop: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_rules_file: Option<String>,
    /// Always written, even empty: an absent key means the default zones. In file order: the
    /// ruleset is built zone by zone.
    #[serde(default = "default_firewall_zones", with = "named_tables")]
    pub zones: Vec<(String, FirewallZoneFile)>,
    /// Routed traffic allowed between zones. Always written, even empty: an absent key (`None`)
    /// means the default matrix, between the zones the file has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwardings: Option<Vec<ZoneForwardingFile>>,
    /// In file order. Keys are labels only (unique per file); the rule's comment is
    /// `description`.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "named_tables")]
    pub port_forwards: Vec<(String, PortForwardFile)>,
}

/// `[parent.<name>]` tables kept as an ordered list: a `BTreeMap` sorted them by name, and
/// `toml_edit` reads tables in document order, so the order written is the order read back.
pub(crate) mod named_tables {
    use std::fmt;
    use std::marker::PhantomData;

    use serde::de::{MapAccess, Visitor};
    use serde::ser::SerializeMap;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer, T: Serialize>(
        entries: &[(String, T)],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(entries.len()))?;
        for (name, value) in entries {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
        deserializer: D,
    ) -> Result<Vec<(String, T)>, D::Error> {
        struct Ordered<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for Ordered<T> {
            type Value = Vec<(String, T)>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a table of named tables")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some((name, value)) = map.next_entry::<String, T>()? {
                    out.push((name, value));
                }
                Ok(out)
            }
        }
        deserializer.deserialize_map(Ordered(PhantomData))
    }
}

/// Inter-zone routing permission (`from` zone may open connections to `to` zone).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneForwardingFile {
    pub from: String,
    pub to: String,
}

/// The zones a file gets when it has no `zones` key: without `internal`, the default-drop input
/// policy would cut the LAN off the router (DNS, DHCP, UI, SSH).
fn default_firewall_zones() -> Vec<(String, FirewallZoneFile)> {
    // Name order, as the former `BTreeMap` produced: a file without `zones` keeps its ruleset.
    let mut zones = vec![
        (
            "internal".to_string(),
            FirewallZoneFile {
                interfaces: Vec::new(),
                input: default_policy_accept(),
                forward: default_policy_accept(),
                masquerade: false,
                mtu_fix: false,
                open_ports: [
                    "22/tcp", "53/udp", "53/tcp", "67/udp", "8088/tcp", "9090/tcp",
                ]
                .into_iter()
                .map(|p| OpenPortFile::Short(p.to_string()))
                .collect(),
                allowed_subnets: Vec::new(),
            },
        ),
        (
            "external".to_string(),
            FirewallZoneFile {
                interfaces: vec!["ppp0".to_string(), "wan0".to_string()],
                input: default_policy_drop(),
                forward: default_policy_drop(),
                masquerade: true,
                mtu_fix: true,
                open_ports: Vec::new(),
                allowed_subnets: Vec::new(),
            },
        ),
        (
            "trusted".to_string(),
            FirewallZoneFile {
                interfaces: vec!["tailscale0".to_string(), "podman*".to_string()],
                input: default_policy_accept(),
                forward: default_policy_accept(),
                masquerade: false,
                mtu_fix: false,
                open_ports: Vec::new(),
                allowed_subnets: Vec::new(),
            },
        ),
    ];
    zones.sort_by(|a, b| a.0.cmp(&b.0));
    zones
}

impl Default for FirewallFile {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: default_firewall_mode(),
            table_name: default_table_name(),
            flow_offload: true,
            bypass_dns: true,
            bypass_vowifi: true,
            default_input_policy: default_policy_drop(),
            default_forward_policy: default_policy_drop(),
            on_stop: default_on_stop(),
            custom_rules_file: None,
            zones: default_firewall_zones(),
            forwardings: None,
            port_forwards: Vec::new(),
        }
    }
}

/// A port the router accepts in a zone: `"22/tcp"`, or `{ port = 22, proto = "tcp", comment =
/// "SSH" }` when it carries a comment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OpenPortFile {
    Short(String),
    Full {
        port: u16,
        #[serde(default = "default_proto_tcp")]
        proto: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        comment: Option<String>,
    },
}

/// A named firewall zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallZoneFile {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    /// A zone written without policies is closed (fail closed): an `external` zone missing
    /// `input` must not open the WAN.
    #[serde(default = "default_policy_drop")]
    pub input: String,
    #[serde(default = "default_policy_drop")]
    pub forward: String,
    #[serde(default = "default_false")]
    pub masquerade: bool,
    #[serde(default = "default_false")]
    pub mtu_fix: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_ports: Vec<OpenPortFile>,
    /// Never enforced by any lanforge release and no longer supported: still read, so a file
    /// that has it keeps its firewall, and reported as an issue; never written.
    #[serde(default, skip_serializing)]
    pub allowed_subnets: Vec<String>,
}

impl Default for FirewallZoneFile {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            input: default_policy_drop(),
            forward: default_policy_drop(),
            masquerade: false,
            mtu_fix: false,
            open_ports: Vec::new(),
            allowed_subnets: Vec::new(),
        }
    }
}

/// A named port forwarding rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortForwardFile {
    #[serde(default = "default_proto_tcp")]
    pub proto: String,
    /// Zone the traffic arrives from.
    #[serde(default = "default_zone_external")]
    pub zone: String,
    #[serde(default = "default_true")]
    pub hairpin: bool,
    pub port: u16,
    pub to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `"ipv4"` or `"ipv6"`: limits a `dev:` target to one family (default: both).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
}

/// A static host in `[hosts.<name>]` (`ConfigFile::static_hosts` / `set_static_hosts`): only
/// what a minimal router needs — the reservation and the boot file. The table name is the
/// hostname. DNS log settings and the device class are WebUI settings kept with the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HostFileEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// The hostname when it is not the table name (a repeated or empty one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v4: Option<Ipv4Addr>,
    /// A suffix (`"::501"`, follows the LAN prefix) or a full address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6_suffix: Option<String>,
    /// Older files: a full address (read as `v6_suffix`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6: Option<Ipv6Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_file: Option<String>,
    /// Older files: the DNS log switch, now a WebUI setting kept with the device. Read and
    /// ignored, never written.
    #[serde(default, skip_serializing)]
    pub dns: Option<bool>,
}
