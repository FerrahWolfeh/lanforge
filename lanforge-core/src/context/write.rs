//! Write & publish operations on the device state.
//!
//! This module implements all state mutation methods on [`LanforgeContext`](super::LanforgeContext).
//! These operations acquire a **write lock** on the state and are exclusive.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, atomic::Ordering},
    time::SystemTime,
};

use crate::{
    bus::{DeviceChange, LanforgeEvent},
    context::{
        LanforgeContext,
        utils::{device_change_of, mac_of},
    },
    device::{HostnameOrigin, Ipv6AddrOrSuffix, Origin},
    identifiers::{Duid, MacAddr},
    state::{DeviceUpdate, FieldUpdate, InterfaceState, LeaseTarget, State},
};

use parking_lot::RwLockWriteGuard;

impl LanforgeContext {
    /// Provides direct write access to the underlying device state.
    pub fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.inner.state.write()
    }

    /// Sets the system lifecycle to shutdown mode for this instance.
    pub fn terminate(&self) {
        self.inner.running.store(false, Ordering::SeqCst);
    }

    /// Sets the database readiness state.
    pub fn set_db_ready(&self, ready: bool) {
        self.inner.db_ready.store(ready, Ordering::SeqCst);
    }

    /// Sets the interface readiness state.
    pub fn set_if_ready(&self, ready: bool) {
        self.inner.if_ready.store(ready, Ordering::SeqCst);
    }

    /// Performs a write operation on the table and publishes events to the bus.
    #[must_use]
    pub fn apply(&self, update: &DeviceUpdate) -> bool {
        let mut state = self.inner.state.write();

        let mut opt_mac = mac_of(update);

        // Special case: IpOffline/IpDeleted don't have MAC in the update, but we can resolve it from state
        if opt_mac.is_none()
            && let DeviceUpdate::IpOffline { ip } | DeviceUpdate::IpDeleted { ip } = update
        {
            opt_mac = state.get_mac_by_ip(*ip);
        }

        let was_online = opt_mac
            .and_then(|mac| state.get_device(&mac))
            .map(|d| d.is_online());
        let is_new = opt_mac.is_some_and(|mac| state.get_device(&mac).is_none());
        let change = device_change_of(update);

        // Pre-capture prefix state for comparison
        let mut prev_prefix = None;
        if let DeviceUpdate::InterfaceIpsChanged { ifindex, .. } = update {
            let is_primary = self
                .inner
                .target_ifindex
                .is_none_or(|target| target == *ifindex);
            if is_primary {
                let ips = state.get_interface_ips(*ifindex);
                prev_prefix = Some((ips.gua, ips.ula));
            }
        }

        let changed_in_state = state.apply_update(update.clone());
        if !changed_in_state {
            return false;
        }

        // Increment metrics counters
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
            _ => {}
        }

        let events = Self::compute_events(
            update,
            &state,
            opt_mac,
            is_new,
            was_online,
            change,
            prev_prefix,
        );

        drop(state);

        for event in events {
            let _ = self.inner.bus.publish(event);
        }
        let _ = self.inner.bus.publish(LanforgeEvent::DeviceTableDirty);
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn compute_events(
        update: &DeviceUpdate,
        state: &State,
        mac: Option<MacAddr>,
        is_new: bool,
        was_online: Option<bool>,
        change: Option<DeviceChange>,
        prev_prefix: Option<(Option<Ipv6Addr>, Option<Ipv6Addr>)>,
    ) -> Vec<LanforgeEvent> {
        let mut events = Vec::new();

        if let Some(mac) = mac {
            let dev = state.get_device(&mac);
            let now_online = dev.as_ref().is_some_and(|d| d.is_online());
            let hostname = dev.as_ref().map(|d| d.hostname.name.clone());

            if is_new {
                events.push(LanforgeEvent::DeviceDiscovered {
                    mac,
                    hostname: hostname.clone(),
                });
            }

            if let Some(mut change) = change {
                if let DeviceChange::StatusChanged {
                    ref mut hostname, ..
                } = change
                {
                    *hostname = dev.as_ref().map(|d| d.hostname.name.clone());
                }

                events.push(LanforgeEvent::DeviceUpdated {
                    mac,
                    change,
                    hostname: hostname.clone(),
                });
            }

            if let Some(was) = was_online
                && was != now_online
            {
                events.push(LanforgeEvent::DeviceUpdated {
                    mac,
                    change: DeviceChange::StatusChanged {
                        online: now_online,
                        hostname: hostname.clone(),
                    },
                    hostname,
                });
            }

            if matches!(update, DeviceUpdate::HostRemoved { .. }) {
                events.push(LanforgeEvent::DevicePurged { mac });
            }
        }

        if let DeviceUpdate::InterfaceIpsChanged {
            ifindex,
            state: update_state,
        } = update
        {
            events.push(LanforgeEvent::InterfaceUpdated { ifindex: *ifindex });
            if let Some((prev_gua, prev_ula)) = prev_prefix
                && ((update_state.gua.is_some() && update_state.gua != prev_gua)
                    || (update_state.ula.is_some() && update_state.ula != prev_ula))
            {
                events.push(LanforgeEvent::PrefixChanged {
                    gua: update_state.gua,
                    ula: update_state.ula,
                    preferred: update_state.gua_preferred,
                    valid: update_state.gua_valid,
                });
            }
        }

        events
    }

    /// Allocates an IPv4 lease for a device.
    #[must_use]
    pub fn allocate_v4_lease(&self, mac: MacAddr, ip: Ipv4Addr, expires: SystemTime) -> bool {
        self.apply(&DeviceUpdate::V4LeaseGranted { mac, ip, expires })
    }

    /// Grants an IPv6 address lease via `DHCPv6`.
    #[must_use]
    pub fn grant_v6_lease(
        &self,
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        ip: Ipv6Addr,
        expires: SystemTime,
    ) -> bool {
        self.apply(&DeviceUpdate::V6LeaseGranted {
            mac,
            duid,
            iaid,
            ip,
            expires,
        })
    }

    /// Delegates an IPv6 prefix via `DHCPv6` Prefix Delegation.
    #[must_use]
    pub fn delegate_v6_prefix(
        &self,
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        prefix: Ipv6Addr,
        len: u8,
        expires: SystemTime,
    ) -> bool {
        self.apply(&DeviceUpdate::V6PrefixAssigned {
            mac,
            duid,
            iaid,
            prefix,
            len,
            expires,
        })
    }

    /// Associates a DUID with a MAC address.
    #[must_use]
    pub fn associate_duid(&self, mac: Option<MacAddr>, duid: Duid, iaid: u32) -> bool {
        self.apply(&DeviceUpdate::DuidAssociated { mac, duid, iaid })
    }

    /// Updates or hints a device hostname (e.g., via DHCP or mDNS).
    #[must_use]
    pub fn update_hostname(&self, mac: MacAddr, hostname: String, _source: HostnameOrigin) -> bool {
        self.apply(&DeviceUpdate::DhcpHostnameHint { mac, hostname })
    }

    /// Tracks a neighbor seen via NDP (IPv6).
    #[must_use]
    pub fn track_ndp_neighbor(&self, mac: MacAddr, ip: Ipv6Addr) -> bool {
        self.apply(&DeviceUpdate::NdpSeen { mac, ip })
    }

    /// Tracks a neighbor seen via ARP (IPv4).
    #[must_use]
    pub fn track_arp_neighbor(&self, mac: MacAddr, ip: Ipv4Addr) -> bool {
        self.apply(&DeviceUpdate::ArpSeen { mac, ip })
    }

    /// Observes a single SLAAC address for a device.
    #[must_use]
    pub fn observe_slaac(&self, mac: MacAddr, ip: Ipv6Addr) -> bool {
        self.apply(&DeviceUpdate::SlaacObserved { mac, addr: ip })
    }

    /// Signals a change in interface IP configuration.
    #[must_use]
    pub fn signal_interface_update(&self, ifindex: u32, state: InterfaceState) -> bool {
        self.apply(&DeviceUpdate::InterfaceIpsChanged { ifindex, state })
    }

    /// Signals a global IPv6 GUA change for an interface.
    #[must_use]
    pub fn signal_gua_change(
        &self,
        ifindex: u32,
        gua: Ipv6Addr,
        preferred: u32,
        valid: u32,
    ) -> bool {
        let state = InterfaceState {
            gua: Some(gua),
            gua_preferred: preferred,
            gua_valid: valid,
            ..Default::default()
        };
        self.apply(&DeviceUpdate::InterfaceIpsChanged { ifindex, state })
    }

    /// Explicitly removes a host from the system.
    #[must_use]
    pub fn remove_host(&self, mac: MacAddr) -> bool {
        self.apply(&DeviceUpdate::HostRemoved { mac })
    }

    /// Releases a `DHCPv4` lease associated with a MAC.
    #[must_use]
    pub fn release_v4_lease(&self, mac: MacAddr) -> bool {
        self.apply(&DeviceUpdate::LeaseReleased {
            mac,
            target: LeaseTarget::V4,
        })
    }

    /// Releases a `DHCPv6` address lease (`IA_NA`) for a MAC.
    #[must_use]
    pub fn release_v6_lease(&self, mac: MacAddr, iaid: u32) -> bool {
        self.apply(&DeviceUpdate::LeaseReleased {
            mac,
            target: LeaseTarget::V6 { iaid },
        })
    }

    /// Releases a `DHCPv6` prefix delegation (`IA_PD`) for a MAC.
    #[must_use]
    pub fn release_v6_prefix(&self, mac: MacAddr, iaid: u32) -> bool {
        self.apply(&DeviceUpdate::LeaseReleased {
            mac,
            target: LeaseTarget::V6Prefix { iaid },
        })
    }

    /// Deletes a specific neighbor IP.
    #[must_use]
    pub fn delete_ip(&self, ip: IpAddr) -> bool {
        self.apply(&DeviceUpdate::IpDeleted { ip })
    }

    /// Triggers the background garbage collection process.
    pub fn expire_stale(&self, interval: std::time::Duration) {
        let dead_leases = {
            let mut state = self.inner.state.write();
            state.expire_stale(interval)
        };

        if !dead_leases.is_empty() {
            for (mac, hostname, change) in dead_leases {
                let _ = self.inner.bus.publish(LanforgeEvent::DeviceUpdated {
                    mac,
                    hostname,
                    change,
                });
            }
            let _ = self.inner.bus.publish(LanforgeEvent::DeviceTableDirty);
        }
    }

    /// Adds or updates a static device reservation in the table.
    #[must_use]
    pub fn add_static_device(
        &self,
        mac: MacAddr,
        hostname: String,
        duid: Option<Duid>,
        v4_static: Option<Ipv4Addr>,
        v6_suffix: Option<Ipv6AddrOrSuffix>,
    ) -> bool {
        self.apply(&DeviceUpdate::CliHostUpdated {
            mac,
            hostname: FieldUpdate::Set(hostname),
            duid: duid.into(),
            v4_static: v4_static.into(),
            v6_suffix: v6_suffix.into(),
            origin: Origin::Cli,
        })
    }

    /// Explicitly triggers a rebuild of the high-performance DNS lookup indices.
    pub fn rebuild_dns_indices(&self) {
        let _ = self.apply(&DeviceUpdate::RebuildDnsIndices);
    }

    /// Sets the shared DNS statistics.
    pub fn set_dns_stats<T: std::any::Any + Send + Sync + 'static>(&self, stats: Arc<T>) {
        *self.inner.dns_stats.write() = Some(stats);
    }

    /// Completely resets the in-memory state.
    pub fn reset(&self) {
        let _ = self.apply(&DeviceUpdate::Reset);
        *self.inner.last_db_flush.write() = None;
    }
}
