use crate::network::Hostname;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Sourced origin of a transient host entry.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum TransientOrigin {
    Tailscale,
    Wireguard,
    #[default]
    LocalPtr,
}

/// Dynamic, non-persisted details of a transient host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransientHost {
    pub hostname: Hostname,
    pub origin: TransientOrigin,
    pub resolved_at: SystemTime,
    pub last_seen: SystemTime,
}

impl TransientHost {
    #[must_use]
    pub fn new(hostname: Hostname, origin: TransientOrigin) -> Self {
        let now = SystemTime::now();
        Self {
            hostname,
            origin,
            resolved_at: now,
            last_seen: now,
        }
    }
}
