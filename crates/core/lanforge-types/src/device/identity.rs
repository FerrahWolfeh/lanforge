use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::device::core::{DeviceClass, Origin};
use crate::identifiers::{Duid, MacAddr};
use crate::network::Hostname;
use crate::utils::serde::{deserialize_time_opt, serialize_time_opt};

/// Cold administrative and identity metadata for a network device.
///
/// This metadata is read frequently by administration interfaces (`WebUI`, CLI)
/// but mutated rarely (e.g. during manual configuration or initial discovery).
/// Isolating it inside an `Arc` ensures that fast-path network events (such as
/// DHCP lease renewals, ARP activity, and NDP packets) do not clone strings or
/// vectors during state `CoW` mutations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub mac: MacAddr,
    pub hostname: Hostname,
    pub origin: Origin,
    pub class: DeviceClass,
    pub duid: Option<Duid>,
    pub dns_fallback: String,
    pub boot_file: Option<String>,
    pub iface: Option<String>,
    pub ignore_dns_log: bool,
    pub ignored_log_domains: Vec<String>,
    #[serde(
        default,
        serialize_with = "serialize_time_opt",
        deserialize_with = "deserialize_time_opt"
    )]
    pub managed_at: Option<SystemTime>,
}

impl DeviceIdentity {
    #[must_use]
    pub fn new(mac: MacAddr) -> Self {
        Self {
            mac,
            hostname: Hostname::default(),
            origin: Origin::Dynamic,
            class: DeviceClass::None,
            duid: None,
            dns_fallback: format!(
                "host-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5]
            ),
            boot_file: None,
            iface: None,
            ignore_dns_log: false,
            ignored_log_domains: Vec::new(),
            managed_at: None,
        }
    }

    /// Infers the 802.1Q VLAN ID if the interface name contains a dot (e.g. "lan0.100" -> 100).
    #[must_use]
    pub fn vlan_id(&self) -> Option<u16> {
        self.iface.as_deref().and_then(|name| {
            name.split('.').nth(1)?.parse().ok()
        })
    }

    #[must_use]
    pub const fn is_static(&self) -> bool {
        self.origin.is_static()
    }
}
