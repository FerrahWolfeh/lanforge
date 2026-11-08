//! Central mutation orchestration.

pub(crate) mod device;
pub(crate) mod storage;

use crate::context::LanforgeContext;
use crate::context::state::State;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::{
    device::{Device, IPv4State, IPv6State},
    events::EventVec,
    update::DeviceUpdate,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    sync::atomic::Ordering,
};

/// Names of the `hotpath` scopes of one kind of state write; empty without the feature.
pub(crate) struct WriteScope {
    #[cfg(feature = "hotpath")]
    wait: &'static str,
    #[cfg(feature = "hotpath")]
    hold: &'static str,
    #[cfg(feature = "hotpath")]
    clone: &'static str,
}

macro_rules! write_scope {
    ($prefix:literal) => {
        WriteScope {
            #[cfg(feature = "hotpath")]
            wait: concat!($prefix, ".writer_wait"),
            #[cfg(feature = "hotpath")]
            hold: concat!($prefix, ".writer_hold"),
            #[cfg(feature = "hotpath")]
            clone: concat!($prefix, ".state_clone"),
        }
    };
}

const SINGLE_SCOPE: WriteScope = write_scope!("core.single");
const BATCH_SCOPE: WriteScope = write_scope!("core.batch");
const MAINTENANCE_SCOPE: WriteScope = write_scope!("core.maintenance");

impl LanforgeContext {
    /// The one way the state changes: take the writer lock, edit a copy-on-write copy of the
    /// current state, publish it whole. Readers see the old or the new state, never a mix.
    /// Events are the caller's to publish, after the lock is released.
    #[cfg_attr(
        not(feature = "hotpath"),
        expect(
            unused_variables,
            reason = "the scope only names profiling measurements"
        )
    )]
    fn write_state<R>(&self, scope: &WriteScope, edit: impl FnOnce(&mut State) -> R) -> R {
        let _guard = {
            #[cfg(feature = "hotpath")]
            let _profile = hotpath::MeasurementGuardSync::new(scope.wait, false, false);
            self.inner.writer_mutex.lock()
        };
        #[cfg(feature = "hotpath")]
        let _hold = hotpath::MeasurementGuardSync::new(scope.hold, false, false);
        let current = self.inner.state.load_full();
        let mut next = {
            #[cfg(feature = "hotpath")]
            let _profile = hotpath::MeasurementGuardSync::new(scope.clone, false, false);
            (*current).clone()
        };
        let result = edit(&mut next);
        self.inner.state.store(Arc::new(next));
        result
    }

    /// Edits the state outside the update protocol (maintenance, expiry, tests).
    pub(crate) fn with_state_mut<R>(&self, edit: impl FnOnce(&mut State) -> R) -> R {
        self.write_state(&MAINTENANCE_SCOPE, edit)
    }
}

impl LanforgeContext {
    /// Applies a state mutation to the context.
    #[must_use]
    pub fn apply(&self, update: DeviceUpdate) -> bool {
        !self.apply_with_events(update).is_empty()
    }

    /// Applies a batch of state mutations in a single transaction (single `CoW` clone)
    /// and returns whether any state change occurred.
    pub fn apply_batch<I>(&self, updates: I) -> bool
    where
        I: IntoIterator<Item = DeviceUpdate>,
    {
        !self.apply_batch_with_events(updates).is_empty()
    }

    /// Applies a batch of state mutations in a single transaction (single `CoW` clone)
    /// and returns all events that were published to the bus.
    #[must_use]
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn apply_batch_with_events<I>(&self, updates: I) -> EventVec
    where
        I: IntoIterator<Item = DeviceUpdate>,
    {
        let mut filtered = smallvec::SmallVec::<[DeviceUpdate; 4]>::new();
        for update in updates {
            self.update_metrics(&update);
            if let Some(debounced) = self.debounce_update(update) {
                filtered.push(debounced);
            }
        }

        if filtered.is_empty() {
            return EventVec::new();
        }

        let events = self.write_state(&BATCH_SCOPE, |state| {
            let mut all_events = EventVec::new();
            for update in filtered {
                all_events.extend(state.apply_update(update, &self.inner.discovery));
            }
            all_events
        });

        if events.is_empty() {
            return EventVec::new();
        }

        let bus = self.bus_ref();
        for event in &events {
            let _ = bus.publish(event.clone());
        }

        events
    }

    /// Applies a state mutation and returns any events that were published to the bus.
    #[must_use]
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn apply_with_events(&self, update: DeviceUpdate) -> EventVec {
        // 1. Update Metrics
        self.update_metrics(&update);

        // 2. Fast-path for redundant activity updates (Debounce)
        let Some(update) = self.debounce_update(update) else {
            return EventVec::new();
        };

        // 3. Apply to State
        let events = self.write_state(&SINGLE_SCOPE, |state| {
            state.apply_update(update, &self.inner.discovery)
        });

        if events.is_empty() {
            return EventVec::new();
        }

        // 4. Publish Events
        let bus = self.bus_ref();
        for event in &events {
            let _ = bus.publish(event.clone());
        }

        events
    }

    /// Internal helper to update discovery metrics based on incoming updates.
    fn update_metrics(&self, update: &DeviceUpdate) {
        match update {
            DeviceUpdate::ArpSeen { .. } => {
                self.inner
                    .runtime
                    .event_counters
                    .arp_seen
                    .fetch_add(1, Ordering::Relaxed);
            }
            DeviceUpdate::NdpSeen { .. } => {
                self.inner
                    .runtime
                    .event_counters
                    .ndp_seen
                    .fetch_add(1, Ordering::Relaxed);
            }
            DeviceUpdate::SlaacObserved { .. } => {
                self.inner
                    .runtime
                    .event_counters
                    .slaac_observed
                    .fetch_add(1, Ordering::Relaxed);
            }
            DeviceUpdate::V4LeaseGranted { .. } => {
                self.inner
                    .runtime
                    .event_counters
                    .dhcp_v4_leases
                    .fetch_add(1, Ordering::Relaxed);
            }
            DeviceUpdate::V6LeaseGranted(_) => {
                self.inner
                    .runtime
                    .event_counters
                    .dhcp_v6_leases
                    .fetch_add(1, Ordering::Relaxed);
            }
            DeviceUpdate::NeighborBatch { entries } => {
                for (_, ip, _) in entries {
                    match ip {
                        IpAddr::V4(_) => {
                            self.inner
                                .runtime
                                .event_counters
                                .arp_seen
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        IpAddr::V6(_) => {
                            self.inner
                                .runtime
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
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn debounce_update(&self, update: DeviceUpdate) -> Option<DeviceUpdate> {
        let state = self.inner.state.load();
        match update {
            DeviceUpdate::ArpSeen { mac, ip, is_active }
                if should_debounce_arp(&state, mac, ip, is_active) =>
            {
                None
            }
            DeviceUpdate::NdpSeen { mac, ip, is_active }
                if should_debounce_ndp(&state, mac, ip, is_active) =>
            {
                None
            }
            DeviceUpdate::SlaacObserved {
                mac,
                addr,
                is_active,
            } if should_debounce_slaac(&state, mac, addr, is_active) => None,
            DeviceUpdate::NeighborBatch { mut entries } => {
                debounce_neighbor_entries(&state, &mut entries);
                if entries.is_empty() {
                    None
                } else {
                    Some(DeviceUpdate::NeighborBatch { entries })
                }
            }
            DeviceUpdate::DeviceInterfaceSeen { mac, ref iface }
                if state
                    .devices
                    .get(&mac)
                    .is_some_and(|dev| dev.iface.as_deref() == Some(iface.as_str())) =>
            {
                None
            }
            DeviceUpdate::ClassHint { mac, class }
                if state
                    .devices
                    .get(&mac)
                    .is_some_and(|dev| dev.class == class) =>
            {
                None
            }
            _ => Some(update),
        }
    }
}

#[inline]
fn is_recently_seen(dev: &Device) -> bool {
    dev.last_seen.elapsed().unwrap_or_default() < Device::ACTIVITY_DEBOUNCE
}

fn should_debounce_arp(state: &State, mac: MacAddr, ip: Ipv4Addr, is_active: bool) -> bool {
    state.devices.get(&mac).is_some_and(|dev| {
        if is_active {
            is_recently_seen(dev) && dev.v4.ip() == Some(ip)
        } else {
            !matches!(dev.v4, IPv4State::None)
        }
    })
}

fn should_debounce_ndp(state: &State, mac: MacAddr, ip: Ipv6Addr, is_active: bool) -> bool {
    state.devices.get(&mac).is_some_and(|dev| {
        let has_ip = dev.v6.iter().any(|s| match s {
            IPv6State::Static(s, _) => s.matches(ip),
            _ => s.ip() == Some(ip),
        });
        if is_active {
            is_recently_seen(dev) && has_ip
        } else {
            has_ip
        }
    })
}

fn should_debounce_slaac(state: &State, mac: MacAddr, addr: Ipv6Addr, is_active: bool) -> bool {
    state.devices.get(&mac).is_some_and(|dev| {
        let has_slaac = dev.v6.iter().any(|s| match s {
            IPv6State::Slaac(a, _) => *a == addr,
            IPv6State::Dynamic(l) => l.ip == addr,
            IPv6State::Static(suf, _) => suf.matches(addr),
            _ => false,
        });
        if is_active {
            is_recently_seen(dev) && has_slaac
        } else {
            has_slaac
        }
    })
}

fn debounce_neighbor_entries(state: &State, entries: &mut Vec<(MacAddr, IpAddr, bool)>) {
    entries.retain(|(mac, ip, is_active)| {
        let Some(dev) = state.devices.get(mac) else {
            return true;
        };
        match ip {
            IpAddr::V4(v4) => {
                if *is_active {
                    !(is_recently_seen(dev) && dev.v4.ip() == Some(*v4))
                } else {
                    matches!(dev.v4, IPv4State::None)
                }
            }
            IpAddr::V6(v6) => {
                let has_ip = dev.v6.iter().any(|s| match s {
                    IPv6State::Static(s, _) => s.matches(*v6),
                    _ => s.ip() == Some(*v6),
                });
                if *is_active {
                    !(is_recently_seen(dev) && has_ip)
                } else {
                    !has_ip
                }
            }
        }
    });
}
