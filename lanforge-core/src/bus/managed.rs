//! `ManagedTable` — A high-level wrapper connecting `DeviceTable` to the `EventBus`.
//!
//! This module automates the publication of events to the bus after every
//! successful state update.

use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::sync::Arc;

use super::{DeviceChange, EventBus, LanforgeEvent};
use crate::state::DeviceTable;
use crate::state::update::DeviceUpdate;

/// A thread-safe wrapper around `DeviceTable` that automatically publishes events
/// to the `EventBus` after each successful `update`.
///
/// This is the primary type that should be shared via `Arc<ManagedTable>`
/// among protocol tasks (DHCP, RA, etc.) to ensure state updates are
/// broadcasted across the system.
pub struct ManagedTable {
    inner: RwLock<DeviceTable>,
    bus: Arc<EventBus>,
}

impl ManagedTable {
    /// Creates a new managed table wrapping an empty device table.
    #[must_use]
    pub fn new(bus: Arc<EventBus>) -> Self {
        Self {
            inner: RwLock::new(DeviceTable::new()),
            bus,
        }
    }

    /// Creates a new managed table wrapping an existing device table.
    #[must_use]
    pub const fn from_table(bus: Arc<EventBus>, table: DeviceTable) -> Self {
        Self {
            inner: RwLock::new(table),
            bus,
        }
    }

    /// Applies a [`DeviceUpdate`] to the table and publishes corresponding events to the bus.
    ///
    /// Returns `true` if the state was actually modified.
    #[must_use]
    pub fn update(&self, update: DeviceUpdate) -> bool {
        let mut table = self.inner.write();

        let opt_mac = mac_of(&update);
        let is_new = opt_mac.is_some_and(|mac| table.get_device(&mac).is_none());

        let change = device_change_of(&update);
        let changed = table.apply_update(update);

        drop(table);

        if !changed {
            return false;
        }

        if let Some(mac) = opt_mac {
            if is_new {
                let _ = self.bus.publish(LanforgeEvent::DeviceDiscovered { mac });
            }

            if let Some(change) = change {
                let _ = self
                    .bus
                    .publish(LanforgeEvent::DeviceUpdated { mac, change });
            }
        }

        let _ = self.bus.publish(LanforgeEvent::DeviceTableDirty);
        true
    }

    /// Provides a read-only lock to the internal device table.
    pub fn read(&self) -> RwLockReadGuard<'_, DeviceTable> {
        self.inner.read()
    }

    /// Provides a direct write lock to the internal device table.
    ///
    /// # Warning
    /// Use this only for maintenance or background operations where event
    /// publication needs to be handled manually or skipped.
    pub fn write(&self) -> RwLockWriteGuard<'_, DeviceTable> {
        self.inner.write()
    }

    /// Returns a reference to the shared event bus.
    pub fn bus(&self) -> Arc<EventBus> {
        self.bus.clone()
    }
}

// ---------------------------------------------------------------------------
// Helpers internos
// ---------------------------------------------------------------------------

use crate::identifiers::MacAddr;

/// Extracts the MAC address from any variant of [`DeviceUpdate`], if present.
const fn mac_of(update: &DeviceUpdate) -> Option<MacAddr> {
    match update {
        DeviceUpdate::V6LeaseGranted { mac, .. }
        | DeviceUpdate::V6PrefixAssigned { mac, .. }
        | DeviceUpdate::DuidAssociated { mac, .. } => *mac,
        DeviceUpdate::V4LeaseGranted { mac, .. }
        | DeviceUpdate::SlaacObserved { mac, .. }
        | DeviceUpdate::NdpSeen { mac, .. }
        | DeviceUpdate::ArpSeen { mac, .. }
        | DeviceUpdate::DhcpHostnameHint { mac, .. }
        | DeviceUpdate::MdnsHostnameHint { mac, .. }
        | DeviceUpdate::CliHostUpdated { mac, .. }
        | DeviceUpdate::SlaacCleared { mac }
        | DeviceUpdate::HostRemoved { mac }
        | DeviceUpdate::LeaseReleased { mac } => Some(*mac),
        DeviceUpdate::IpDeleted { .. } | DeviceUpdate::RebuildDnsIndices => None,
    }
}

/// Converts a [`DeviceUpdate`] into its corresponding [`DeviceChange`] for the bus.
fn device_change_of(update: &DeviceUpdate) -> Option<DeviceChange> {
    match update {
        DeviceUpdate::V4LeaseGranted { ip, .. } => Some(DeviceChange::V4Assigned { ip: *ip }),
        DeviceUpdate::V6LeaseGranted { ip, iaid, .. } => Some(DeviceChange::V6Assigned {
            ip: *ip,
            iaid: *iaid,
        }),
        DeviceUpdate::V6PrefixAssigned {
            prefix, len, iaid, ..
        } => Some(DeviceChange::V6PrefixAssigned {
            prefix: *prefix,
            len: *len,
            iaid: *iaid,
        }),
        DeviceUpdate::SlaacObserved { addr, .. } => {
            Some(DeviceChange::SlaacObserved { addr: *addr })
        }
        DeviceUpdate::DhcpHostnameHint { hostname, .. }
        | DeviceUpdate::MdnsHostnameHint { hostname, .. } => Some(DeviceChange::HostnameChanged {
            hostname: hostname.clone(),
        }),
        DeviceUpdate::DuidAssociated { .. } => Some(DeviceChange::DuidAssociated),
        DeviceUpdate::NdpSeen { .. }
        | DeviceUpdate::ArpSeen { .. }
        | DeviceUpdate::SlaacCleared { .. }
        | DeviceUpdate::HostRemoved { .. }
        | DeviceUpdate::LeaseReleased { .. }
        | DeviceUpdate::IpDeleted { .. }
        | DeviceUpdate::RebuildDnsIndices => None,
        DeviceUpdate::CliHostUpdated {
            hostname,
            v4_static,
            v6_suffix,
            ..
        } => {
            if let Some(Some(hn)) = hostname {
                return Some(DeviceChange::HostnameChanged {
                    hostname: hn.clone(),
                });
            }
            if let Some(v4) = v4_static {
                return Some(DeviceChange::V4StaticChanged { ip: *v4 });
            }
            if let Some(v6) = v6_suffix {
                return Some(DeviceChange::V6SuffixChanged { suffix: v6.clone() });
            }
            None
        }
    }
}
