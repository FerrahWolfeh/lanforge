pub mod transaction;
pub mod validation;

pub use transaction::FirewallTransactionState;
pub use validation::validate_firewall_candidate;

use crate::network::IpSubnet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallZone {
    pub name: String,
    pub interfaces: Vec<String>,
    pub open_ports: Vec<HostPortRule>,
    pub allowed_subnets: Vec<IpSubnet>,
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
    pub internal_ip: IpAddr,
    pub external_port: u16,
    pub internal_port: u16,
    pub protocol: L4Protocol,
    pub enable_hairpin: bool,
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
                    allowed_subnets: Vec::new(),
                    input_policy: FirewallPolicy::Accept,
                    forward_policy: FirewallPolicy::Accept,
                    masquerade: false,
                    mtu_fix: false,
                },
                FirewallZone {
                    name: "external".into(),
                    interfaces: Vec::new(),
                    open_ports: Vec::new(),
                    allowed_subnets: Vec::new(),
                    input_policy: FirewallPolicy::Drop,
                    forward_policy: FirewallPolicy::Drop,
                    masquerade: true,
                    mtu_fix: true,
                },
                FirewallZone {
                    name: "trusted".into(),
                    interfaces: vec!["tailscale0".into(), "podman*".into()],
                    open_ports: Vec::new(),
                    allowed_subnets: Vec::new(),
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
