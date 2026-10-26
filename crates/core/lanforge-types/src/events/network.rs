use crate::{identifiers::MacAddr, network::Ipv6Prefix, update::LeaseTarget};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrefixChangeDetails {
    /// Interface whose addresses changed. Every interface emits this event (LAN, `ppp0`, ...):
    /// consumers must filter on the interface they serve, never assume it is "theirs".
    pub ifindex: u32,
    pub gua: Option<Ipv6Prefix>,
    pub ula: Option<Ipv6Prefix>,
    pub preferred: u32,
    pub valid: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetworkEvent {
    PrefixChanged(Box<PrefixChangeDetails>),
    InterfaceUpdated {
        ifindex: u32,
    },

    WolTriggered {
        mac: MacAddr,
        ip_hint: Option<Ipv4Addr>,
    },
    RsReceived {
        mac: MacAddr,
    },
    LeaseRenewRequested {
        mac: MacAddr,
        target: Option<LeaseTarget>,
    },
    LeaseReleaseRequested {
        mac: MacAddr,
        target: Option<LeaseTarget>,
    },
    RaTriggerRequested,
}
