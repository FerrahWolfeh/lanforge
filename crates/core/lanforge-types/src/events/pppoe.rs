use crate::identifiers::MacAddr;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PppoeSessionUp {
    pub interface: String,
    pub ac_mac: Option<MacAddr>,
    pub ac_name: Option<String>,
    pub session_id: u16,
    pub mru: u16,
    pub ipv4: Option<Ipv4Addr>,
    pub ipv4_peer: Option<Ipv4Addr>,
    pub dns: Vec<IpAddr>,
    pub ipv6_link_local: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PppoeEvent {
    SessionUp(Box<PppoeSessionUp>),
    SessionDown {
        reason: String,
    },
    Reconnecting {
        attempt: u32,
        next_retry_secs: u64,
    },
    AuthFailed {
        reason: String,
    },
    KeepaliveWarning {
        consecutive_failures: u32,
        max_failures: u32,
    },
    KeepaliveRestored,
}
