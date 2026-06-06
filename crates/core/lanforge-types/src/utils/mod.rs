use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub mod network;
pub mod serde;

pub use network::{compute_eui64_ip, ip_matches_prefix, is_slaac_iid, mac_from_eui64_link_local};

/// Converts a `SystemTime` to a Unix timestamp (seconds since epoch).
#[must_use]
pub fn system_time_to_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Converts a Unix timestamp (seconds since epoch) to `SystemTime`.
#[must_use]
pub fn secs_to_system_time(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}
