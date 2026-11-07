pub mod transaction;
pub mod validation;

pub use transaction::FirewallTransactionState;
pub use validation::validate_firewall_candidate;

use crate::identifiers::DeviceIdentifier;
use crate::network::pppoe::PppoeNftablesConfig;
use serde::de::{Deserializer, Error as DeError};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Traffic disposition policy for a zone or chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum FirewallPolicy {
    #[default]
    Drop = 0,
    Accept = 1,
    Reject = 2,
}

/// Transport layer 4 protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum L4Protocol {
    #[default]
    Tcp = 0,
    Udp = 1,
    Both = 2,
}

impl L4Protocol {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Both => "tcp/udp",
        }
    }
}

/// Authorized inbound port for host access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPortRule {
    pub comment: Option<String>,
    pub port: u16,
    pub protocol: L4Protocol,
}

/// Dynamic inbound port requested at runtime by internal services (HTTP `WebUI`, DNS, DHCP, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicPortRequest {
    pub service: String,
    pub zone: String,
    pub comment: Option<String>,
    pub port: u16,
    pub protocol: L4Protocol,
}

/// A logical firewall network zone (e.g., "internal", "external", "trusted", "guest").
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FirewallZone {
    pub name: String,
    pub interfaces: Vec<String>,
    pub open_ports: Vec<HostPortRule>,
    pub input_policy: FirewallPolicy,
    pub forward_policy: FirewallPolicy,
    pub masquerade: bool,
    pub mtu_fix: bool,
}

/// Inter-zone traffic forwarding permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneForwarding {
    pub from: String,
    pub to: String,
}

/// Port forwarding rule (DNAT on IPv4 or Pinhole forward on IPv6) with Hairpin NAT support.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortForwardRule {
    pub comment: Option<String>,
    pub src_zone: String,
    /// Where the traffic goes: an address, or a device (`dev:<name|mac>`) resolved to its
    /// current addresses whenever the ruleset compiles.
    pub internal_ip: ForwardTarget,
    pub external_port: u16,
    pub internal_port: u16,
    pub protocol: L4Protocol,
    pub enable_hairpin: bool,
    /// Limits a device target to one family; `None` forwards both. An address target is its
    /// own family.
    #[serde(default)]
    pub family: Option<ForwardFamily>,
}

impl PortForwardRule {
    /// Whether the rule forwards IPv4 and IPv6, given its target and `family`.
    #[must_use]
    pub const fn families(&self) -> (bool, bool) {
        match self.internal_ip {
            ForwardTarget::Ip(IpAddr::V4(_)) => (true, false),
            ForwardTarget::Ip(IpAddr::V6(_)) => (false, true),
            ForwardTarget::Device(_) => match self.family {
                None => (true, true),
                Some(ForwardFamily::Ipv4) => (true, false),
                Some(ForwardFamily::Ipv6) => (false, true),
            },
        }
    }
}

/// The target of a port forward: a fixed address or a device by name or MAC.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ForwardTarget {
    Ip(IpAddr),
    Device(DeviceIdentifier),
}

impl ForwardTarget {
    /// Follows a renamed device (see [`DeviceIdentifier::rename_device`]).
    pub fn rename_device(&mut self, old: &str, new: &DeviceIdentifier) -> bool {
        match self {
            Self::Device(id) => id.rename_device(old, new),
            Self::Ip(_) => false,
        }
    }

    /// The fixed address, if the target is one.
    #[must_use]
    pub const fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(*ip),
            Self::Device(_) => None,
        }
    }
}

impl From<IpAddr> for ForwardTarget {
    fn from(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }
}

impl From<Ipv4Addr> for ForwardTarget {
    fn from(ip: Ipv4Addr) -> Self {
        Self::Ip(ip.into())
    }
}

impl From<Ipv6Addr> for ForwardTarget {
    fn from(ip: Ipv6Addr) -> Self {
        Self::Ip(ip.into())
    }
}

impl FromStr for ForwardTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some(device) = s.strip_prefix("dev:") {
            return device.parse().map(Self::Device);
        }
        s.parse()
            .map(Self::Ip)
            .map_err(|_| format!("\"{s}\" is not an IP address or \"dev:<name|mac>\""))
    }
}

impl fmt::Display for ForwardTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Device(device) => write!(f, "dev:{device}"),
        }
    }
}

impl Serialize for ForwardTarget {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ForwardTarget {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(DeError::custom)
    }
}

/// The address family a device port forward is limited to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardFamily {
    Ipv4,
    Ipv6,
}

impl ForwardFamily {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

impl FromStr for ForwardFamily {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            other => Err(format!("\"{other}\" is not ipv4 or ipv6")),
        }
    }
}

/// Where a device port forward goes now: its predictable IPv4 and GUAs (see
/// `Device::forward_addresses`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ForwardAddrs {
    pub v4: Option<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
}

/// Operational mode of the Lanforge firewall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FirewallMode {
    /// Full stateful firewall with host protection, zone isolation, and NAT (replaces firewalld/ufw).
    #[default]
    Full,
    /// Minimal `PPPoE` routing helper (MSS clamping, flowtable offload, and masquerade only; policy accept, priority filter - 10).
    /// Coexists cleanly with firewalld or ufw.
    Minimal,
    /// Completely disabled (table is flushed and deleted).
    Disabled,
}

/// What stopping the firewall (admin `stop`, daemon shutdown) leaves in the kernel.
///
/// The OS keeps IP forwarding enabled when lanforge stops, so removing the table would forward
/// WAN traffic to the LAN unfiltered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FirewallStopAction {
    /// Replace the ruleset with a closed-WAN baseline: no port forwards, pinholes or WAN host
    /// rules; LAN keeps reaching the router and the internet.
    #[default]
    Lockdown,
    /// Delete the table, leaving the host to whatever other ruleset is loaded.
    Remove,
}

impl FirewallStopAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lockdown => "lockdown",
            Self::Remove => "remove",
        }
    }
}

/// Complete declarative firewall configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
#[serde(default)]
pub struct FirewallConfig {
    pub table_name: String,
    pub mode: FirewallMode,
    pub zones: Vec<FirewallZone>,
    pub forwardings: Vec<ZoneForwarding>,
    pub port_forwards: Vec<PortForwardRule>,
    pub custom_rules_file: Option<String>,
    pub enabled: bool,
    pub flow_offload: bool,
    pub bypass_dns: bool,
    pub bypass_vowifi: bool,
    pub default_input_policy: FirewallPolicy,
    pub default_forward_policy: FirewallPolicy,
    pub on_stop: FirewallStopAction,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            table_name: "lanforge".into(),
            mode: FirewallMode::Full,
            enabled: true,
            flow_offload: true,
            bypass_dns: true,
            bypass_vowifi: true,
            default_input_policy: FirewallPolicy::Drop,
            default_forward_policy: FirewallPolicy::Drop,
            on_stop: FirewallStopAction::Lockdown,
            custom_rules_file: None,
            zones: vec![
                FirewallZone {
                    name: "internal".into(),
                    interfaces: Vec::new(),
                    open_ports: vec![
                        HostPortRule {
                            port: 22,
                            protocol: L4Protocol::Tcp,
                            comment: Some("SSH host management".into()),
                        },
                        HostPortRule {
                            port: 53,
                            protocol: L4Protocol::Udp,
                            comment: Some("DNS server (UDP)".into()),
                        },
                        HostPortRule {
                            port: 53,
                            protocol: L4Protocol::Tcp,
                            comment: Some("DNS server (TCP)".into()),
                        },
                        HostPortRule {
                            port: 67,
                            protocol: L4Protocol::Udp,
                            comment: Some("DHCPv4 server".into()),
                        },
                        HostPortRule {
                            port: 8088,
                            protocol: L4Protocol::Tcp,
                            comment: Some("Web Console & REST API".into()),
                        },
                        HostPortRule {
                            port: 9090,
                            protocol: L4Protocol::Tcp,
                            comment: Some("Fedora Cockpit".into()),
                        },
                    ],
                    input_policy: FirewallPolicy::Accept,
                    forward_policy: FirewallPolicy::Accept,
                    masquerade: false,
                    mtu_fix: false,
                },
                FirewallZone {
                    name: "external".into(),
                    interfaces: Vec::new(),
                    open_ports: Vec::new(),
                    input_policy: FirewallPolicy::Drop,
                    forward_policy: FirewallPolicy::Drop,
                    masquerade: true,
                    mtu_fix: true,
                },
                FirewallZone {
                    name: "trusted".into(),
                    interfaces: vec!["tailscale0".into(), "podman*".into()],
                    open_ports: Vec::new(),
                    input_policy: FirewallPolicy::Accept,
                    forward_policy: FirewallPolicy::Accept,
                    masquerade: false,
                    mtu_fix: false,
                },
            ],
            forwardings: vec![
                ZoneForwarding {
                    from: "internal".into(),
                    to: "external".into(),
                },
                ZoneForwarding {
                    from: "trusted".into(),
                    to: "external".into(),
                },
                ZoneForwarding {
                    from: "trusted".into(),
                    to: "internal".into(),
                },
                ZoneForwarding {
                    from: "internal".into(),
                    to: "trusted".into(),
                },
            ],
            port_forwards: Vec::new(),
        }
    }
}

impl FirewallConfig {
    /// The firewall the daemon runs: this one (what the admin wrote) plus what other sections
    /// force on it. Never written back.
    /// - flowtable offload and the DNS/`VoWiFi` bypasses off when the `PPPoE` dataplane turns
    ///   them off, and offload off under SQM (CAKE must see every packet; a flowtable would
    ///   send forwarded traffic past it);
    /// - the LAN interface in the internal zone when no zone has it, `podman*` in `trusted`.
    #[must_use]
    pub fn effective(
        &self,
        pppoe: Option<&PppoeNftablesConfig>,
        sqm_enabled: bool,
        lan_iface: &str,
    ) -> Self {
        let mut fw = self.clone();
        if let Some(nft) = pppoe {
            fw.flow_offload &= nft.flow_offload;
            fw.bypass_dns &= nft.bypass_dns;
            fw.bypass_vowifi &= nft.bypass_vowifi;
        }
        if sqm_enabled {
            fw.flow_offload = false;
        }
        if !lan_iface.is_empty()
            && !fw
                .zones
                .iter()
                .any(|z| z.interfaces.iter().any(|i| i == lan_iface))
            && let Some(internal) = fw
                .zones
                .iter_mut()
                .find(|z| z.name == "internal" || z.name == "lan")
        {
            internal.interfaces.push(lan_iface.to_string());
        }
        if let Some(trusted) = fw.zones.iter_mut().find(|z| z.name == "trusted")
            && !trusted.interfaces.iter().any(|i| i == "podman*")
        {
            trusted.interfaces.push("podman*".into());
        }
        fw
    }
}

/// Operational status and statistics snapshot for RPC and telemetry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct FirewallStatus {
    pub mode: FirewallMode,
    pub table: String,
    pub active_wan: Option<String>,
    pub lan_ifaces: Vec<String>,
    pub last_applied_secs_ago: Option<u64>,
    pub open_ports_count: u32,
    pub rules_count: u32,
    pub enabled: bool,
    pub flow_offload_active: bool,
    #[serde(default)]
    pub flow_offload_suspended: bool,
    pub default_drop_active: bool,
}

/// Detailed pre-flight validation report for a proposed firewall transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallValidationReport {
    /// True if the candidate configuration has zero blocking errors and can be safely committed.
    pub valid: bool,
    /// Transaction ID generated when valid, used to commit or abort the transaction.
    pub tx_id: Option<String>,
    /// Human-readable diff summary showing what will change.
    pub diff_summary: Vec<String>,
    /// Warnings that do not prevent application (e.g. anti-lockout notes, performance tips).
    pub warnings: Vec<String>,
    /// Blocking errors that prevent application (e.g. port collisions, duplicate zones).
    pub errors: Vec<String>,
}

/// Request to commit a staged firewall transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallCommitRequest {
    /// The transaction ticket ID returned by the pre-flight validation.
    pub tx_id: String,
    /// Optional auto-rollback timeout in seconds.
    /// If specified (e.g. 20s), the candidate rules are applied, but will automatically
    /// roll back unless a confirmation heartbeat is received before the deadline.
    pub auto_rollback_secs: Option<u32>,
}

/// Result of committing a staged firewall transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallCommitResponse {
    pub success: bool,
    pub message: String,
    pub auto_rollback_active: bool,
    pub rollback_deadline_secs: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqm_turns_offload_off_and_lan_joins_internal() {
        let fw = FirewallConfig {
            flow_offload: true,
            ..FirewallConfig::default()
        };
        let out = fw.effective(None, true, "lan0");
        assert!(!out.flow_offload);
        let internal = out.zones.iter().find(|z| z.name == "internal").unwrap();
        assert_eq!(internal.interfaces, vec!["lan0".to_string()]);
        assert!(fw.flow_offload, "the configured firewall is left as it is");
    }

    #[test]
    fn without_sqm_the_admins_offload_stands() {
        let fw = FirewallConfig {
            flow_offload: true,
            ..FirewallConfig::default()
        };
        assert!(fw.effective(None, false, "lan0").flow_offload);
    }

    #[test]
    fn the_pppoe_dataplane_turns_offload_and_bypasses_off() {
        let nft = PppoeNftablesConfig {
            flow_offload: false,
            bypass_dns: false,
            ..PppoeNftablesConfig::default()
        };
        let out = FirewallConfig::default().effective(Some(&nft), false, "");
        assert!(!out.flow_offload);
        assert!(!out.bypass_dns);
        assert!(out.bypass_vowifi);
    }

    #[test]
    fn an_already_adjusted_firewall_is_unchanged() {
        let mut fw = FirewallConfig {
            flow_offload: false,
            ..FirewallConfig::default()
        };
        fw.zones[0].interfaces = vec!["lan0".into()];
        assert_eq!(fw.effective(None, true, "lan0"), fw);
    }
}
