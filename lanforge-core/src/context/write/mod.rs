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
    ///
    /// This is the central entry point for all state changes. It manages:
    /// 1. Metric counters for discovery rates
    /// 2. Write-locking the state
    /// 3. Executing the state mutation logic
    /// 4. Publishing resulting events to the bus
    ///
    /// Returns `true` if any change occurred, `false` otherwise.
    #[must_use]
    pub fn apply(&self, update: DeviceUpdate) -> bool {
        // 1. Update Metrics (Pre-apply based on intent)
        match &update {
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

        // 2. Apply to State
        let events = {
            let mut state = self.inner.state.write();
            state.apply_update(update)
        };

        if events.is_empty() {
            return false;
        }

        // 3. Publish Events
        let bus = self.bus();
        for event in events {
            let _ = bus.publish(event);
        }

        true
    }
}
