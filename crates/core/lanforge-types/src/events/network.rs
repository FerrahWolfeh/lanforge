use crate::{identifiers::MacAddr, update::LeaseTarget};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrefixChangeDetails {
    pub gua: Option<Ipv6Addr>,
    pub ula: Option<Ipv6Addr>,
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

