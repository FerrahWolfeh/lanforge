use crate::identifiers::MacAddr;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NetworkEvent {
    PrefixChanged {
        gua: Option<Ipv6Addr>,
        ula: Option<Ipv6Addr>,
        preferred: u32,
        valid: u32,
    },
    InterfaceUpdated {
        ifindex: u32,
    },
    ScanRequested,
    NeighborScanRequested,
    SubnetScanStarted {
        subnet: String,
    },
    WolTriggered {
        mac: MacAddr,
        ip_hint: Option<Ipv4Addr>,
    },
    RsReceived {
        mac: MacAddr,
    },
}
