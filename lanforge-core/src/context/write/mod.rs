//! Central mutation orchestration.

pub(crate) mod device;
pub(crate) mod network;
pub(crate) mod storage;

use crate::context::{
    LanforgeContext,
    state::{DeviceUpdate, State},
};
use parking_lot::RwLockWriteGuard;
use std::sync::atomic::Ordering;

impl LanforgeContext {
    /// Provides direct write access to the underlying device state.
    pub fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.inner.state.write()
    }
    /// Applies a state mutation to the context.
    #[must_use]
    pub fn apply(&self, update: DeviceUpdate) -> bool {
        // 1. Update Metrics
        self.update_metrics(&update);

        // 2. Fast-path for redundant activity updates (Debounce)
        let Some(update) = self.debounce_update(update) else {
            return true;
        };

        // 3. Apply to State
        let events = {
            let mut state = self.inner.state.write();
            state.apply_update(update)
        };

        if events.is_empty() {
            return false;
        }

        // 4. Publish Events
        let bus = self.bus();
        for event in events {
            let _ = bus.publish(event);
        }

        true
    }

    /// Internal helper to update discovery metrics based on incoming updates.
    fn update_metrics(&self, update: &DeviceUpdate) {
        match update {
            DeviceUpdate::ArpSeen { .. } => {
                self.inner
                    .event_counters
                    .arp_seen
                    .fetch_add(1, Ordering::Relaxed);
            }
            DeviceUpdate::NdpSeen { .. } => {
                self.inner
                    .event_counters
                    .ndp_seen
                    .fetch_add(1, Ordering::Relaxed);
            }
            DeviceUpdate::SlaacObserved { .. } => {
                self.inner
                    .event_counters
                    .slaac_observed
                    .fetch_add(1, Ordering::Relaxed);
            }
            DeviceUpdate::V4LeaseGranted { .. } => {
                self.inner
                    .event_counters
                    .dhcp_v4_leases
                    .fetch_add(1, Ordering::Relaxed);
            }
            DeviceUpdate::V6LeaseGranted { .. } => {
                self.inner
                    .event_counters
                    .dhcp_v6_leases
                    .fetch_add(1, Ordering::Relaxed);
            }
            DeviceUpdate::NeighborBatch { entries } => {
                for (_, ip, _) in entries {
                    match ip {
                        std::net::IpAddr::V4(_) => {
                            self.inner
                                .event_counters
                                .arp_seen
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        std::net::IpAddr::V6(_) => {
                            self.inner
                                .event_counters
                                .ndp_seen
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Internal helper to perform fast-path debounce checks.
    /// Returns `None` if the update was skipped, or `Some(update)` (possibly filtered) to proceed.
    fn debounce_update(&self, update: DeviceUpdate) -> Option<DeviceUpdate> {
        match update {
            DeviceUpdate::ArpSeen { mac, ip, is_active } => {
                let should_skip = {
                    let state = self.inner.state.read();
                    state.devices.get(&mac).is_some_and(|dev| {
                        let recently_seen = dev.last_seen.elapsed().unwrap_or_default()
                            < crate::device::Device::ACTIVITY_DEBOUNCE;
                        let has_ip = dev.seen_v4.iter().any(|(a, _)| *a == ip);
                        recently_seen && has_ip
                    })
                };
                if should_skip {
                    None
                } else {
                    Some(DeviceUpdate::ArpSeen { mac, ip, is_active })
                }
            }
            DeviceUpdate::NdpSeen { mac, ip, is_active } => {
                let should_skip = {
                    let state = self.inner.state.read();
                    state.devices.get(&mac).is_some_and(|dev| {
                        let recently_seen = dev.last_seen.elapsed().unwrap_or_default()
                            < crate::device::Device::ACTIVITY_DEBOUNCE;
                        let has_ip = dev.v6.iter().any(|s| s.ip() == Some(ip));
                        recently_seen && has_ip
                    })
                };
                if should_skip {
                    None
                } else {
                    Some(DeviceUpdate::NdpSeen { mac, ip, is_active })
                }
            }
            DeviceUpdate::NeighborBatch { entries } => {
                let filtered: Vec<_> = {
                    let state = self.inner.state.read();
                    entries
                        .into_iter()
                        .filter(|(mac, ip, _)| {
                            state.devices.get(mac).is_none_or(|dev| {
                                let recently_seen = dev.last_seen.elapsed().unwrap_or_default()
                                    < crate::device::Device::ACTIVITY_DEBOUNCE;
                                let has_ip = match ip {
                                    std::net::IpAddr::V4(v4) => {
                                        dev.seen_v4.iter().any(|(a, _)| a == v4)
                                    }
                                    std::net::IpAddr::V6(v6) => {
                                        dev.v6.iter().any(|s| s.ip() == Some(*v6))
                                    }
                                };
                                !(recently_seen && has_ip)
                            })
                        })
                        .collect()
                };

                if filtered.is_empty() {
                    None
                } else {
                    Some(DeviceUpdate::NeighborBatch { entries: filtered })
                }
            }
            _ => Some(update),
        }
    }
}
