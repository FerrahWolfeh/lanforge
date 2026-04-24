use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Converts a `SystemTime` to a Unix timestamp (seconds since epoch).
pub(crate) fn system_time_to_unix(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().cast_signed())
}

/// Converts a Unix timestamp (seconds since epoch) to `SystemTime`.
pub(crate) fn unix_to_system_time(unix: i64) -> SystemTime {
    if unix > 0 {
        UNIX_EPOCH + Duration::from_secs(unix.cast_unsigned())
    } else {
        UNIX_EPOCH
    }
}
