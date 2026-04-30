//! Device-specific mutation wrappers.

use std::time::Duration;

use crate::{
    bus::{LanforgeEvent, StorageEvent},
    context::LanforgeContext,
    identifiers::MacAddr,
};

impl LanforgeContext {
    /// Triggers the background garbage collection process.
    pub fn expire_stale(&self, interval: Duration) {
        let events = {
            let mut state = self.inner.state.write();
            state.expire_stale(interval)
        };

        if !events.is_empty() {
            let bus = self.bus();
            for event in events {
                let _ = bus.publish(event);
            }
            let _ = bus.publish(LanforgeEvent::Storage(StorageEvent::TableDirty));
        }
    }

    /// Attempts a Just-In-Time lookup for a hostname.
    /// If found, the device is promoted to the hot-path index.
    #[must_use]
    pub fn find_mac_by_hostname_jit(
        &self,
        hostname: &str,
        last_seen_threshold: Option<Duration>,
    ) -> Option<MacAddr> {
        self.write()
            .find_mac_by_hostname_jit(hostname, last_seen_threshold)
    }
}
