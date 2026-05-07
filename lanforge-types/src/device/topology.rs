use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use crate::identifiers::MacAddr;
use crate::utils::serde::{deserialize_time, serialize_time};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TopologyInfo {
    pub parent_mac: Option<MacAddr>,
    pub port: Option<String>,
    pub local_ifindex: u32,
    #[serde(
        serialize_with = "serialize_time",
        deserialize_with = "deserialize_time"
    )]
    pub last_updated: SystemTime,
}
