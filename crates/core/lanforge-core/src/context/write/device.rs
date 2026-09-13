//! Device-specific mutation wrappers.

use crate::context::LanforgeContext;
use lanforge_types::identifiers::MacAddr;
use std::time::Duration;

#[cfg(test)]
use lanforge_types::device::Device;
#[cfg(test)]
use lanforge_types::device::Ipv6AddrOrSuffix;
#[cfg(test)]
use lanforge_types::device::Origin;
#[cfg(test)]
use lanforge_types::identifiers::Duid;
#[cfg(test)]
use lanforge_types::update::{CliHostUpdate, DeviceUpdate, FieldUpdate};
#[cfg(test)]
use std::net::Ipv4Addr;

impl LanforgeContext {
    /// Triggers the background garbage collection process.
    pub fn expire_stale(&self, interval: Duration) {
        let events = self.with_state_mut(|state| state.expire_stale(interval));
        self.inner.discovery.prune_stale(Duration::from_hours(2));

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
        let found_mac = {
            let state = self.read();
            let now = std::time::SystemTime::now();
            state.devices.iter().find_map(|(mac, dev)| {
                if let (Some(threshold), Ok(elapsed)) =
                    (last_seen_threshold, now.duration_since(dev.last_seen))
                    && elapsed > threshold
                {
                    return None;
                }

                if dev.hostname.name.eq_ignore_ascii_case(hostname)
                    || dev.dns_fallback.eq_ignore_ascii_case(hostname)
                {
                    Some(*mac)
                } else {
                    None
                }
            })
        };

        found_mac.inspect(|&mac| {
            self.with_state_mut(|state| state.promote_device_to_index(mac));
        })
    }

    /// Adds a static device to the registry (test-only helper).
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn add_static_device(
        &self,
        mac: MacAddr,
        hostname: String,
        duid: Option<Duid>,
        v4_static: Option<Ipv4Addr>,
        v6_suffix: Option<Ipv6AddrOrSuffix>,
        boot_file: Option<String>,
        origin: Origin,
    ) {
        let _ = self.apply(DeviceUpdate::CliHostUpdated {
            mac,
            update: Box::new(CliHostUpdate {
                hostname: FieldUpdate::from(Some(hostname)),
                duid: FieldUpdate::from(duid),
                v4_static: FieldUpdate::from(v4_static),
                v6_suffix: FieldUpdate::from(v6_suffix),
                origin,
                boot_file: FieldUpdate::from(boot_file),
                dns_fallback: FieldUpdate::NoChange,
                class: FieldUpdate::NoChange,
            }),
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
        self.with_state_mut(|state| {
            state.mutate_device(mac, |dev| {
                res = Some(f(dev));
                None // No event emitted by this helper itself
            });
        });
        res.expect("mutation failed")
    }

    /// Sets whether indexing is enabled (test-only helper).
    #[cfg(test)]
    pub fn set_indexing_enabled(&self, enabled: bool) {
        self.with_state_mut(|state| state.set_indexing_enabled(enabled));
    }

    /// Inserts a device directly (test-only helper).
    #[cfg(test)]
    pub fn insert_device(&self, mac: MacAddr, dev: Device) {
        self.with_state_mut(|state| state.insert_device(mac, dev));
    }
}
