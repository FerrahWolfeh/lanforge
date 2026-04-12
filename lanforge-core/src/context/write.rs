//! Write & publish operations on the device state.
//!
//! This module implements all state mutation methods on [`LanforgeContext`](super::LanforgeContext).
//! These operations acquire a **write lock** on the state and are exclusive.
//!
//! # Core Method: `apply`
//!
//! The primary entry point for all state changes. It:
//! 1. Acquires a write lock on the state
//! 2. Applies the [`DeviceUpdate`](crate::state::DeviceUpdate)
//! 3. Computes resulting [`LanforgeEvent`](crate::bus::LanforgeEvent)s
//! 4. Publishes events to the bus
//! 5. Marks the table as dirty (triggers DB flush)
//!
//! # Convenience Methods
//!
//! | Method                     | Purpose                          |
//! |----------------------------|----------------------------------|
//! | `allocate_v4_lease`        | Grant a `DHCPv4` lease             |
//! | `grant_v6_lease`           | Grant a `DHCPv6` (`IA_NA`) lease     |
//! | `delegate_v6_prefix`       | Delegate an `IPv6` prefix (`IA_PD`)  |
//! | `associate_duid`           | Link a `DUID` to a `MAC`             |
//! | `update_hostname`          | Set or hint a hostname           |
//! | `track_ndp_neighbor`       | Record an `NDP` observation        |
//! | `track_arp_neighbor`       | Record an ARP observation        |
//! | `observe_slaac`            | Record a SLAAC address           |
//! | `sync_slaac`               | Full SLAAC sync for a device     |
//! | `add_static_device`        | Add/update a static reservation  |
//! | `release_v4_lease`         | Release a `DHCPv4` lease           |
//! | `release_v6_lease`         | Release a `DHCPv6` lease           |
//! | `release_v6_prefix`        | Release a delegated prefix       |
//! | `remove_host`              | Explicitly remove a device       |
//! | `delete_ip`                | Remove a specific IP             |
//! | `expire_stale`             | Run garbage collection           |
//! | `rebuild_dns_indices`      | Rebuild DNS lookup caches        |
//!
//! # Lifecycle Control
//!
//! | Method           | Purpose                          |
//! |------------------|----------------------------------|
//! | `terminate`      | Set shutdown flag                |
//! | `set_db_ready`   | Mark database as initialized     |
//! | `set_if_ready`   | Mark interfaces as configured    |
//!
//! # Example
//!
//! ```rust
//! use lanforge_core::context::LanforgeContext;
//! use lanforge_core::state::State;
//! use lanforge_core::bus::EventBus;
//! use lanforge_core::identifiers::MacAddr;
//! use std::sync::Arc;
//! use std::time::{Duration, SystemTime};
//!
//! let bus = Arc::new(EventBus::new());
//! let ctx = LanforgeContext::new(bus, State::new(), None);
//!
//! let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
//! let ip = "192.168.1.10".parse().unwrap();
//! let expires = SystemTime::now() + Duration::from_secs(3600);
//!
//! ctx.allocate_v4_lease(mac, ip, expires);
//! ```

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
    state::{DeviceUpdate, FieldUpdate, InterfaceState, LeaseTarget},
};

impl LanforgeContext {
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
    ///
    /// This is the **primary entry point** for all system state mutations.
    ///
    /// # Flow
    ///
    /// 1. Resolves the MAC address from the update (or from IP index for IpOffline/IpDeleted)
    /// 2. Captures pre-update state (online status, prefix state)
    /// 3. Applies the update to the internal state
    /// 4. Computes resulting events (`DeviceDiscovered`, `DeviceUpdated`, `StatusChanged`)
    /// 5. Publishes all events to the bus
    /// 6. Publishes `DeviceTableDirty` to signal a DB flush is needed
    ///
    /// # Returns
    ///
    /// `true` if the state was actually changed, `false` if the update was a no-op
    /// (e.g., renewing an existing lease with the same parameters).
    ///
    /// # Example
    ///
    /// ```rust
    /// use lanforge_core::context::LanforgeContext;
    /// use lanforge_core::state::{DeviceUpdate, State};
    /// use lanforge_core::bus::EventBus;
    /// use lanforge_core::identifiers::MacAddr;
    /// use std::sync::Arc;
    /// use std::time::{Duration, SystemTime};
    ///
    /// let bus = Arc::new(EventBus::new());
    /// let ctx = LanforgeContext::new(bus, State::new(), None);
    ///
    /// let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    /// let update = DeviceUpdate::V4LeaseGranted {
    ///     mac,
    ///     ip: "192.168.1.10".parse().unwrap(),
    ///     expires: SystemTime::now() + Duration::from_secs(3600),
    /// };
    ///
    /// let changed = ctx.apply(&update);
    /// assert!(changed); // First time, should be true
    /// ```
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

        let mut events = Vec::new();
        if let Some(mac) = opt_mac {
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
                // If the update itself generated a StatusChanged (e.g., from IpOffline),
                // ensure it has the hostname.
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
            if let DeviceUpdate::HostRemoved { .. } = update {
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

        drop(state);

        for event in events {
            let _ = self.inner.bus.publish(event);
        }
        let _ = self.inner.bus.publish(LanforgeEvent::DeviceTableDirty);
        true
    }

    // -----------------------------------------------------------------------
    // Mutation Methods
    // -----------------------------------------------------------------------

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

    /// Performs a full synchronization of SLAAC addresses for a device.
    #[must_use]
    pub fn sync_slaac(&self, mac: MacAddr, addresses: Vec<Ipv6Addr>) -> bool {
        self.apply(&DeviceUpdate::SlaacSynced { mac, addresses })
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
    ///
    /// This method identifies expired leases and stale devices, removes them from
    /// the table, and publishes granular `DeviceUpdated` events for each change.
    ///
    /// # Garbage Collection Rules
    ///
    /// - `DHCPv4` leases past their expiry → removed, `LeaseExpired` event
    /// - `DHCPv6` `IA_NA` leases past their expiry → removed, `LeaseExpired` event
    /// - `DHCPv6` `IA_PD` prefixes past their expiry → removed, `LeaseExpired` event
    /// - Dynamic devices with no leases, no prefixes, and no activity for 7 days → removed
    /// - `NDP` cache entries older than 24 hours → purged
    /// - Orphaned `IPv6` leases past expiry → purged
    ///
    /// # Events Published
    ///
    /// For each expired lease: `DeviceUpdated { change: LeaseExpired { .. } }`
    /// For each removed device: `DeviceUpdated { change: HostRemoved }`
    /// If any changes: `DeviceTableDirty`
    ///
    /// # Alias
    ///
    /// This is an alias for `trigger_garbage_collection`.
    pub fn expire_stale(&self) {
        let dead_leases = {
            let mut state = self.inner.state.write();
            state.expire_stale()
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
        v4_static: Option<Ipv4Addr>,
        v6_suffix: Option<Ipv6AddrOrSuffix>,
    ) -> bool {
        self.apply(&DeviceUpdate::CliHostUpdated {
            mac,
            hostname: FieldUpdate::Set(hostname),
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
}
