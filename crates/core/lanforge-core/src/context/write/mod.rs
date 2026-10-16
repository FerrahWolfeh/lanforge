//! Central mutation orchestration.

pub(crate) mod device;
pub(crate) mod network;
pub(crate) mod storage;

use lanforge_types::{
    device::{Device, IPv6State},
    events::EventVec,
    update::DeviceUpdate,
};
use std::{net::IpAddr, sync::Arc, sync::atomic::Ordering};

use crate::context::LanforgeContext;

impl LanforgeContext {
    /// Applies a state mutation to the context.
    #[must_use]
    pub fn apply(&self, update: DeviceUpdate) -> bool {
        !self.apply_with_events(update).is_empty()
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
        let events = {
            let _guard = self.inner.writer_mutex.lock();
            let current = self.inner.state.load_full();
            let mut new_state = (*current).clone();
            let events = new_state.apply_update(update, &self.inner.discovery);
            self.inner.state.store(Arc::new(new_state));
            events
        };

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
            DeviceUpdate::V6LeaseGranted(_) => {
                self.inner
                    .event_counters
                    .dhcp_v6_leases
                    .fetch_add(1, Ordering::Relaxed);
            }
            DeviceUpdate::NeighborBatch { entries } => {
                for (_, ip, _) in entries {
                    match ip {
                        IpAddr::V4(_) => {
                            self.inner
                                .event_counters
                                .arp_seen
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        IpAddr::V6(_) => {
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
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn debounce_update(&self, update: DeviceUpdate) -> Option<DeviceUpdate> {
        let state = self.inner.state.load();
        match update {
            DeviceUpdate::ArpSeen {
                mac,
                ip,
                is_active,
            } if should_debounce_arp(&state, mac, ip, is_active) => None,
            DeviceUpdate::NdpSeen {
                mac,
                ip,
                is_active,
            } if should_debounce_ndp(&state, mac, ip, is_active) => None,
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

fn should_debounce_arp(
    state: &crate::context::state::State,
    mac: lanforge_types::identifiers::MacAddr,
    ip: std::net::Ipv4Addr,
    is_active: bool,
) -> bool {
    is_active
        && state.devices.get(&mac).is_some_and(|dev| {
            is_recently_seen(dev) && dev.seen_v4.iter().any(|(a, _)| *a == ip)
        })
}

fn should_debounce_ndp(
    state: &crate::context::state::State,
    mac: lanforge_types::identifiers::MacAddr,
    ip: std::net::Ipv6Addr,
    is_active: bool,
) -> bool {
    is_active
        && state.devices.get(&mac).is_some_and(|dev| {
            is_recently_seen(dev) && dev.v6.iter().any(|s| s.ip() == Some(ip))
        })
}

fn should_debounce_slaac(
    state: &crate::context::state::State,
    mac: lanforge_types::identifiers::MacAddr,
    addr: std::net::Ipv6Addr,
    is_active: bool,
) -> bool {
    is_active
        && state.devices.get(&mac).is_some_and(|dev| {
            is_recently_seen(dev)
                && dev.v6.iter().any(|s| match s {
                    IPv6State::Slaac(a, _) => *a == addr,
                    IPv6State::Dynamic(l) => l.ip == addr,
                    IPv6State::Static(suf, _) => suf.matches(addr),
                    _ => false,
                })
        })
}

fn debounce_neighbor_entries(
    state: &crate::context::state::State,
    entries: &mut Vec<(lanforge_types::identifiers::MacAddr, IpAddr, bool)>,
) {
    entries.retain(|(mac, ip, is_active)| {
        if !*is_active {
            return true;
        }
        state.devices.get(mac).is_none_or(|dev| {
            let has_ip = match *ip {
                IpAddr::V4(v4) => dev.seen_v4.iter().any(|(a, _)| *a == v4),
                IpAddr::V6(v6) => dev.v6.iter().any(|s| s.ip() == Some(v6)),
            };
            !(is_recently_seen(dev) && has_ip)
        })
    });
}
