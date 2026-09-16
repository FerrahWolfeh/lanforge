use crate::network::firewall::{DynamicPortRequest, L4Protocol};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FirewallAppliedSummary {
    pub table: String,
    pub wan_iface: Option<String>,
    pub rules_count: u32,
    pub flow_offload: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FirewallEvent {
    /// Dispatched by a service (e.g. HTTP, DNS, DHCP) to request opening an inbound port on a zone
    PortOpenRequested(Box<DynamicPortRequest>),
    /// Dispatched by a service to release an inbound port
    PortReleaseRequested {
        service: String,
        port: u16,
        protocol: L4Protocol,
    },
    /// Dispatched after an atomic ruleset batch commit to the kernel
    RulesetApplied(Box<FirewallAppliedSummary>),
    /// Dispatched when nftables execution fails
    ApplyFailed {
        error: String,
    },
    /// Dispatched when firewall rules are flushed
    RulesetFlushed,
    /// Dispatched when firewall configuration has changed and kernel ruleset should be recompiled and applied
    RulesetChanged,
}
