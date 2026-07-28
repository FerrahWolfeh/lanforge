use crate::identifiers::MacAddr;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PppoeEvent {
    SessionUp {
        interface: String,
        ac_mac: Option<MacAddr>,
        ac_name: Option<String>,
        session_id: u16,
        mru: u16,
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
    AuthFailed {
        reason: String,
    },
    KeepaliveWarning {
        consecutive_failures: u32,
        max_failures: u32,
    },
    KeepaliveRestored,
}

