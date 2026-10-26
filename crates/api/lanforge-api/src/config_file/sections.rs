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

fn default_blocking_mode() -> String {
    "nxdomain".to_string()
}

fn default_refresh_time() -> String {
    "03:00".to_string()
}

fn default_source_format() -> String {
    "auto".to_string()
}

fn default_blocklist_kind() -> String {
    "blocklist".to_string()
}

fn default_policy_drop() -> String {
    "drop".to_string()
}

fn default_on_stop() -> String {
    "lockdown".to_string()
}

fn default_policy_accept() -> String {
    "accept".to_string()
}

fn default_proto_tcp() -> String {
    "tcp".to_string()
}

fn default_cpu_mask() -> String {
    "auto".to_string()
}

fn default_rx_ring() -> String {
    "auto".to_string()
}

fn default_tx_ring() -> String {
    "auto".to_string()
}

// ============================================================================
// Static Sections
// ============================================================================

/// Global system configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl Default for SystemFile {
    fn default() -> Self {
        Self {
            iface: String::new(),
            ula_prefix: None,
            debounce_secs: Some(2),
            search_domains: Vec::new(),
            tls_cert: None,
            tls_key: None,
            auto_provision: false,
            allow_unprivileged: false,
        }
    }
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
}

impl Default for TftpFile {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_tftp_listen(),
            root_dir: default_tftp_root_dir(),
        }
    }
}

// ============================================================================
// Dynamic Sections
// ============================================================================

/// DHCP subsystem configuration.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_file: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pools: BTreeMap<String, Dhcpv4PoolFile>,
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
            boot_file: None,
            pools: BTreeMap::new(),
        }
    }
}

/// A named DHCPv4 dynamic address pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pools: BTreeMap<String, Dhcpv6PoolFile>,
}

impl Default for Dhcpv6File {
    fn default() -> Self {
        Self {
            enabled: true,
            lease: Some(HumanDuration(86400)),
            dns: Vec::new(),
            search_domains: Vec::new(),
            pools: BTreeMap::new(),
        }
    }
}

/// A named DHCPv6 dynamic address pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dhcpv6PoolFile {
    pub range: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<HumanDuration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<Ipv6Addr>,
}

/// IPv6 Router Advertisement (RFC 4861) configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RaFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub managed: bool,
    #[serde(default = "default_true")]
    pub other_config: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_interval: Option<HumanDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<HumanDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub prefixes: BTreeMap<String, RaPrefixFile>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rdnss: BTreeMap<String, RaRdnssFile>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dnssl: BTreeMap<String, RaDnsslFile>,
}

impl Default for RaFile {
    fn default() -> Self {
        Self {
            enabled: true,
            managed: true,
            other_config: true,
            max_interval: Some(HumanDuration(200)),
            lifetime: Some(HumanDuration(600)),
            mtu: Some(1500),
            prefixes: BTreeMap::new(),
            rdnss: BTreeMap::new(),
            dnssl: BTreeMap::new(),
        }
    }
}

/// A named RA IPv6 Prefix announcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RaPrefixFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default = "default_true")]
    pub on_link: bool,
    #[serde(default = "default_true")]
    pub autonomous: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_lifetime: Option<HumanDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_lifetime: Option<HumanDuration>,
}

impl Default for RaPrefixFile {
    fn default() -> Self {
        Self {
            source: None,
            prefix: None,
            on_link: true,
            autonomous: true,
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

/// DNS server, upstreams, and rewrite rules configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub upstreams: BTreeMap<String, DnsUpstreamFile>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rewrites: BTreeMap<String, DnsRewriteFile>,
}

impl Default for DnsFile {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: Some("[::]:53".to_string()),
            upstreams: BTreeMap::new(),
            rewrites: BTreeMap::new(),
        }
    }
}

/// A named group of DNS upstream endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsUpstreamFile {
    pub addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

/// A named DNS rewrite rule (domain mapping).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRewriteFile {
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtype: Option<String>,
}

/// DNS Adblock subsystem configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdblockFile {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default = "default_blocking_mode")]
    pub blocking_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_ip_v4: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_ip_v6: Option<Ipv6Addr>,
    #[serde(default = "default_refresh_time")]
    pub refresh_time: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sources: BTreeMap<String, AdblockSourceFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowlist: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rules: BTreeMap<String, AdblockRuleFile>,
}

impl Default for AdblockFile {
    fn default() -> Self {
        Self {
            enabled: false,
            blocking_mode: default_blocking_mode(),
            blocking_ip_v4: None,
            blocking_ip_v6: None,
            refresh_time: default_refresh_time(),
            sources: BTreeMap::new(),
            allowlist: Vec::new(),
            rules: BTreeMap::new(),
        }
    }
}

/// A named adblock list source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdblockSourceFile {
    pub url: String,
    #[serde(default = "default_source_format")]
    pub format: String,
    #[serde(default = "default_blocklist_kind")]
    pub kind: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// A named custom adblock rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdblockRuleFile {
    pub action: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Stateful Netlink/nftables firewall configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub zones: BTreeMap<String, FirewallZoneFile>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub port_forwards: BTreeMap<String, PortForwardFile>,
}

impl Default for FirewallFile {
    fn default() -> Self {
        let mut zones = BTreeMap::new();
        zones.insert(
            "internal".to_string(),
            FirewallZoneFile {
                interfaces: Vec::new(),
                input: default_policy_accept(),
                forward: default_policy_accept(),
                masquerade: false,
                mtu_fix: false,
                open_ports: vec![
                    "22/tcp".to_string(),
                    "53/udp".to_string(),
                    "53/tcp".to_string(),
                    "67/udp".to_string(),
                    "8088/tcp".to_string(),
                    "9090/tcp".to_string(),
                ],
                allowed_subnets: Vec::new(),
            },
        );
        zones.insert(
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
        );
        zones.insert(
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
        );

        Self {
            enabled: true,
            flow_offload: true,
            bypass_dns: true,
            bypass_vowifi: true,
            default_input_policy: default_policy_drop(),
            default_forward_policy: default_policy_drop(),
            on_stop: default_on_stop(),
            custom_rules_file: None,
            zones,
            port_forwards: BTreeMap::new(),
        }
    }
}

/// A named firewall zone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallZoneFile {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    #[serde(default = "default_policy_accept")]
    pub input: String,
    #[serde(default = "default_policy_accept")]
    pub forward: String,
    #[serde(default = "default_false")]
    pub masquerade: bool,
    #[serde(default = "default_false")]
    pub mtu_fix: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_ports: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_subnets: Vec<String>,
}

impl Default for FirewallZoneFile {
    fn default() -> Self {
        Self {
            interfaces: Vec::new(),
            input: default_policy_accept(),
            forward: default_policy_accept(),
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
    pub port: u16,
    pub to: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// PPPoE WAN client configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PppoeFile {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_iface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mru: Option<u16>,
}

/// Traffic shaping, SQM, and NIC tuning configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TrafficFile {
    #[serde(default)]
    pub tuning: NicTuningFile,
    #[serde(default)]
    pub sqm: SqmFile,
}

/// NIC hardware tuning settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NicTuningFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    #[serde(default = "default_cpu_mask")]
    pub cpu_mask: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rps_flow_entries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rps_flow_cnt: Option<u32>,
    #[serde(default = "default_rx_ring")]
    pub rx_ring: String,
    #[serde(default = "default_tx_ring")]
    pub tx_ring: String,
    #[serde(default = "default_true")]
    pub disable_eee: bool,
    #[serde(default = "default_true")]
    pub udp_gro_forwarding: bool,
}

impl Default for NicTuningFile {
    fn default() -> Self {
        Self {
            enabled: true,
            interfaces: Vec::new(),
            cpu_mask: default_cpu_mask(),
            rps_flow_entries: Some(32768),
            rps_flow_cnt: Some(4096),
            rx_ring: default_rx_ring(),
            tx_ring: default_tx_ring(),
            disable_eee: true,
            udp_gro_forwarding: true,
        }
    }
}

/// SQM (Smart Queue Management) settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SqmFile {
    #[serde(default = "default_false")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_mbps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_mbps: Option<u32>,
}

/// A static host or pinned client entry in `[hosts.<name>]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct HostFileEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v4: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6_suffix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6: Option<Ipv6Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<bool>,
}
