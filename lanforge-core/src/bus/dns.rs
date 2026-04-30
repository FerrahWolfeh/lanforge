#[cfg(feature = "adblock")]
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DnsEvent {
    #[cfg(feature = "adblock")]
    AdblockToggle {
        enabled: bool,
        duration_secs: Option<u64>,
    },
    #[cfg(feature = "adblock")]
    AdblockReload,
    #[cfg(feature = "adblock")]
    QueryBlocked { src_addr: IpAddr, domain: String },
}
