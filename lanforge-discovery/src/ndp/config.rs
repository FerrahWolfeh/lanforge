//! Configuration for the neighbor monitor and network tuning.

use lanforge_macros::ServiceConfig;
use serde::{Deserialize, Serialize};

/// Configuration for the network monitor and internal tuning.
#[derive(Debug, Clone, Serialize, Deserialize, ServiceConfig)]
#[config(key = "monitor")]
#[serde(default)]
pub struct MonitorConfig {
    /// Whether the neighbor monitor is enabled.
    pub enabled: bool,
    /// Pacing between ARP/NDP probes during a subnet scan (milliseconds).
    pub scan_pacing_ms: u64,

    /// Interval for batching neighbor events before applying updates (milliseconds).
    pub batch_interval_ms: u64,

    /// Seconds after which a neighbor is considered stale if no activity is detected.
    pub stale_timeout_secs: u64,

    /// Whether active ping probing is enabled.
    pub ping_enabled: bool,
    /// Interval for periodic active ping sweeps (seconds).
    pub ping_interval_secs: u64,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            scan_pacing_ms: 10,
            batch_interval_ms: 100,
            stale_timeout_secs: 3600, // 1 hour
            ping_enabled: true,
            ping_interval_secs: 120, // 2 minutes
        }
    }
}
