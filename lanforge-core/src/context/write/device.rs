//! Device-specific mutation wrappers.

#[cfg(test)]
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::context::LanforgeContext;
use crate::identifiers::MacAddr;
#[cfg(test)]
use crate::{
    device::{Device, Ipv6AddrOrSuffix},
    identifiers::Duid,
};

impl LanforgeContext {
    /// Triggers the background garbage collection process.
    pub fn expire_stale(&self, interval: Duration) {
        let events = {
            let mut state = self.inner.state.write();
            state.expire_stale(interval)
        };

        if !events.is_empty() {
            let bus = self.bus_ref();
            for event in events {
                let _ = bus.publish(event);
            }
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

    /// Adds a static device to the registry (test-only helper).
    #[cfg(test)]
    pub fn add_static_device(
        &self,
        mac: MacAddr,
        hostname: String,
        duid: Option<Duid>,
        v4_static: Option<Ipv4Addr>,
        v6_suffix: Option<Ipv6AddrOrSuffix>,
        boot_file: Option<String>,
    ) {
        use crate::context::state::{DeviceUpdate, FieldUpdate};
        use crate::device::Origin;

        let _ = self.apply(DeviceUpdate::CliHostUpdated {
            mac,
            update: crate::context::state::CliHostUpdate {
                hostname: FieldUpdate::from(Some(hostname)),
                duid: FieldUpdate::from(duid),
                v4_static: FieldUpdate::from(v4_static),
                v6_suffix: FieldUpdate::from(v6_suffix),
                origin: Origin::Cli,
                boot_file: FieldUpdate::from(boot_file),
            },
        });
    }

    /// Mutates a device directly (test-only helper).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutation closure is not executed, which would
    /// indicate a logical error in the state transition.
    #[cfg(test)]
    pub fn mutate_device<F, R>(&self, mac: MacAddr, f: F) -> R
    where
        F: FnOnce(&mut Device) -> R,
    {
        let mut res = None;
        self.write().mutate_device(mac, |dev| {
            res = Some(f(dev));
            None // No event emitted by this helper itself
        });
        res.expect("mutation failed")
    }

    /// Sets whether indexing is enabled (test-only helper).
    #[cfg(test)]
    pub fn set_indexing_enabled(&self, enabled: bool) {
        self.write().set_indexing_enabled(enabled);
    }

    /// Inserts a device directly (test-only helper).
    #[cfg(test)]
    pub fn insert_device(&self, mac: MacAddr, dev: Device) {
        self.write().insert_device(mac, dev);
    }
}
