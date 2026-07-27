use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PppoeEvent {
    SessionUp {
        interface: String,
        ipv4: Option<Ipv4Addr>,
        ipv4_peer: Option<Ipv4Addr>,
        dns: Vec<IpAddr>,
        ipv6_link_local: bool,
    },
    SessionDown {
        reason: String,
    },
    Reconnecting {
        attempt: u32,
        next_retry_secs: u64,
    },
}
