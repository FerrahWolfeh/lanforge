//! `GlobalContext` — Thread-safe singleton for system-wide state.
//!
//! This module provides a global access point for the [`ManagedTable`] and
//! [`EventBus`]. It is intended to reduce "constructor drilling" while
//! maintaining thread safety.

use crate::bus::{DeviceChange, EventBus, LanforgeEvent};
use crate::device::{Device, HostnameOrigin, Ipv6AddrOrSuffix};
use crate::identifiers::{Duid, MacAddr};
use crate::state::DeviceTable;
use crate::state::update::{DeviceUpdate, FieldUpdate, LeaseTarget};
use parking_lot::RwLock;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

#[derive(Clone)]
pub struct LanforgeContext {
    inner: Arc<LanforgeContextInner>,
}

struct LanforgeContextInner {
    bus: Arc<EventBus>,
    table: RwLock<crate::state::DeviceTable>,
    target_ifindex: Option<u32>,
    running: AtomicBool,
    db_ready: AtomicBool,
    if_ready: AtomicBool,
    dns_stats: RwLock<Option<Arc<dyn std::any::Any + Send + Sync>>>,
}

static INSTANCE: RwLock<Option<LanforgeContext>> = RwLock::new(None);

#[allow(clippy::missing_panics_doc)] // Temporary
impl LanforgeContext {
    /// Initializes the global context.
    pub fn init(bus: Arc<EventBus>, table: crate::state::DeviceTable, target_ifindex: Option<u32>) {
        let mut lock = INSTANCE.write();
        *lock = Some(Self::new(bus, table, target_ifindex));
    }

    /// Creates a new isolated context instance.
    #[must_use]
    pub fn new(
        bus: Arc<EventBus>,
        table: crate::state::DeviceTable,
        target_ifindex: Option<u32>,
    ) -> Self {
        Self {
            inner: Arc::new(LanforgeContextInner {
                bus,
                table: RwLock::new(table),
                target_ifindex,
                running: AtomicBool::new(true),
                db_ready: AtomicBool::new(false),
                if_ready: AtomicBool::new(false),
                dns_stats: RwLock::new(None),
            }),
        }
    }

    /// Resets the global context instance. Primarily for test isolation.
    pub fn reset_instance_for_tests() {
        let mut lock = INSTANCE.write();
        *lock = None;
    }

    /// Returns a clone of the global context instance.
    #[must_use]
    pub fn instance() -> Self {
        INSTANCE
            .read()
            .as_ref()
            .expect("LanforgeContext not initialized")
            .clone()
    }

    /// Returns the global event bus.
    #[must_use]
    pub fn bus() -> Arc<EventBus> {
        Self::instance().inner.bus.clone()
    }

    /// Internal access to the shared event bus.
    #[must_use]
    pub fn bus_instance(&self) -> Arc<EventBus> {
        self.inner.bus.clone()
    }

    /// Sets the system lifecycle to shutdown mode.
    pub fn terminate() {
        Self::instance().terminate_opt();
    }

    /// Sets the system lifecycle for this instance to shutdown mode.
    pub fn terminate_opt(&self) {
        self.inner.running.store(false, Ordering::SeqCst);
    }

    /// Resets all global states to their default values.
    #[deprecated(note = "Use reset_instance_for_tests instead")]
    pub fn reset_all_for_tests() {
        Self::reset_instance_for_tests();
    }

    /// Returns true if the system is currently running and hasn't been terminated.
    #[must_use]
    pub fn is_running() -> bool {
        Self::instance().is_running_opt()
    }

    /// Returns true if this instance is currently running.
    #[must_use]
    pub fn is_running_opt(&self) -> bool {
        self.inner.running.load(Ordering::Relaxed)
    }

    /// Sets the database readiness state.
    pub fn set_db_ready(ready: bool) {
        Self::instance()
            .inner
            .db_ready
            .store(ready, Ordering::SeqCst);
    }

    /// Returns true if the database is ready.
    #[must_use]
    pub fn is_db_ready() -> bool {
        Self::instance().inner.db_ready.load(Ordering::SeqCst)
    }

    /// Returns true if the network interfaces are ready.
    #[must_use]
    pub fn is_if_ready() -> bool {
        Self::instance().inner.if_ready.load(Ordering::SeqCst)
    }

    /// Blocks the current task until the database is ready.
    /// Safely handles the race condition where the event is published before subscription.
    ///
    /// # Errors
    ///
    /// Returns a `CoreError` if the underlying communication bus fails.
    pub async fn wait_for_db() -> crate::error::Result<()> {
        Self::instance().wait_for_db_opt().await
    }

    /// Blocks the current task until the network interfaces are ready.
    ///
    /// # Errors
    ///
    /// Returns a `CoreError` if the underlying communication bus fails.
    pub async fn wait_for_interfaces() -> crate::error::Result<()> {
        Self::instance().wait_for_interfaces_opt().await
    }

    /// Blocks the current THREAD (sync) until dependencies are ready.
    pub fn wait_for_db_sync(rx: &std::sync::mpsc::Receiver<crate::bus::TimedEvent>) {
        if Self::is_db_ready() {
            return;
        }
        while let Ok(timed_event) = rx.recv() {
            if matches!(timed_event.event, crate::bus::LanforgeEvent::DbReady) {
                break;
            }
            if matches!(timed_event.event, crate::bus::LanforgeEvent::Shutdown)
                || !Self::is_running()
            {
                break;
            }
        }
    }

    pub fn wait_for_interfaces_sync(rx: &std::sync::mpsc::Receiver<crate::bus::TimedEvent>) {
        if Self::is_if_ready() {
            return;
        }
        while let Ok(timed_event) = rx.recv() {
            if matches!(timed_event.event, crate::bus::LanforgeEvent::InterfaceReady) {
                break;
            }
            if matches!(timed_event.event, crate::bus::LanforgeEvent::Shutdown)
                || !Self::is_running()
            {
                break;
            }
        }
    }

    /// Sets the DNS statistics for the global instance.
    pub fn set_dns_stats<T: std::any::Any + Send + Sync>(stats: Arc<T>) {
        Self::instance().set_dns_stats_opt(stats);
    }

    /// Sets the DNS statistics for this instance.
    pub fn set_dns_stats_opt<T: std::any::Any + Send + Sync>(&self, stats: Arc<T>) {
        let mut lock = self.inner.dns_stats.write();
        *lock = Some(stats);
    }

    /// Returns the DNS statistics for the global instance.
    #[must_use]
    pub fn get_dns_stats<T: std::any::Any + Send + Sync>() -> Option<Arc<T>> {
        Self::instance().get_dns_stats_opt::<T>()
    }

    /// Returns the DNS statistics for this instance.
    #[must_use]
    pub fn get_dns_stats_opt<T: std::any::Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.inner
            .dns_stats
            .read()
            .as_ref()
            .and_then(|a| a.clone().downcast::<T>().ok())
    }

    /// Sets the interface readiness state.
    pub fn set_if_ready(ready: bool) {
        Self::instance().set_if_ready_opt(ready);
    }

    /// Sets the interface readiness state for this instance.
    pub fn set_if_ready_opt(&self, ready: bool) {
        self.inner.if_ready.store(ready, Ordering::SeqCst);
    }

    // -----------------------------------------------------------------------
    // Core Primitives
    // -----------------------------------------------------------------------
    /// Runs a read-only query against the device table.
    pub fn query<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&DeviceTable) -> R,
    {
        let table = self.inner.table.read();
        f(&table)
    }

    /// Retrieves a device by its MAC address (instance-level).
    #[must_use]
    pub fn get_device_opt(&self, mac: &MacAddr) -> Option<Arc<Device>> {
        self.query(|t| t.get_device(mac))
    }

    /// Retrieves a device by its configured hostname (instance-level).
    #[must_use]
    pub fn get_by_hostname_opt(&self, hostname: &str) -> Option<Arc<Device>> {
        self.query(|t| t.get_by_hostname(hostname))
    }

    /// Retrieves a device by any of its assigned IP addresses (instance-level).
    #[must_use]
    pub fn get_by_ip_opt(&self, ip: &IpAddr) -> Option<Arc<Device>> {
        self.query(|t| t.get_by_ip(ip))
    }

    /// Returns the target interface index for this context.
    #[must_use]
    pub fn target_ifindex_opt(&self) -> Option<u32> {
        self.inner.target_ifindex
    }

    /// Returns the current GUA and ULA prefixes for an interface (instance-level).
    #[must_use]
    pub fn get_interface_prefixes_opt(&self, ifindex: u32) -> (Option<Ipv6Addr>, Option<Ipv6Addr>) {
        self.query(|t| {
            let s = t.get_interface_ips(ifindex);
            (s.gua, s.ula)
        })
    }

    /// Helper to find a MAC address by its IP in the DNS index (instance-level).
    #[must_use]
    pub fn get_mac_by_ip_opt(&self, ip: IpAddr) -> Option<MacAddr> {
        self.query(|t| t.get_mac_by_ip(ip))
    }

    /// Produz um registro validado das configurações estáticas (instance-level).
    pub fn get_static_registry_opt(&self) -> crate::state::StaticRegistry {
        self.query(super::state::DeviceTable::get_static_registry)
    }

    /// Checks if a specific prefix is already delegated to any device (instance-level).
    #[must_use]
    pub fn is_prefix_delegated_opt(&self, prefix: Ipv6Addr, len: u8) -> bool {
        self.query(|t| t.is_prefix_delegated(prefix, len))
    }

    /// Helper to find the GUA prefix and its lifetimes for a specific interface (instance-level).
    #[must_use]
    pub fn get_interface_gua_at_opt(&self, ifindex: u32) -> Option<(Ipv6Addr, u32, u32)> {
        self.query(|t| t.get_interface_gua_at(ifindex))
    }

    /// Returns the full interface state for a given index (instance-level).
    #[must_use]
    pub fn get_interface_state_opt(&self, ifindex: u32) -> crate::state::InterfaceState {
        self.query(|t| t.get_interface_ips(ifindex))
    }

    /// Returns a full list of all devices (instance-level).
    #[must_use]
    pub fn all_devices_opt(&self) -> Vec<Arc<Device>> {
        self.query(|t| t.devices().collect())
    }

    /// Returns true if the database is ready (instance-level).
    #[must_use]
    pub fn is_db_ready_opt(&self) -> bool {
        self.inner
            .db_ready
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Returns true if the interfaces are ready (instance-level).
    #[must_use]
    pub fn is_if_ready_opt(&self) -> bool {
        self.inner
            .if_ready
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Blocks the current task until network interfaces are ready (instance-level).
    pub async fn wait_for_interfaces_opt(&self) -> crate::error::Result<()> {
        let mut rx = self.inner.bus.subscribe();
        if self.is_if_ready_opt() {
            return Ok(());
        }
        while let Ok(timed_event) = rx.recv().await {
            if !self.is_running_opt()
                || matches!(timed_event.event, crate::bus::LanforgeEvent::Shutdown)
            {
                return Ok(());
            }
            if matches!(timed_event.event, crate::bus::LanforgeEvent::InterfaceReady) {
                break;
            }
        }
        Ok(())
    }

    /// Blocks the current task until the database is ready (instance-level).
    pub async fn wait_for_db_opt(&self) -> crate::error::Result<()> {
        let mut rx = self.inner.bus.subscribe();
        if self.is_db_ready_opt() {
            return Ok(());
        }
        while let Ok(timed_event) = rx.recv().await {
            if !self.is_running_opt()
                || matches!(timed_event.event, crate::bus::LanforgeEvent::Shutdown)
            {
                return Ok(());
            }
            if matches!(timed_event.event, crate::bus::LanforgeEvent::DbReady) {
                break;
            }
        }
        Ok(())
    }

    /// Returns the global event bus for this context instance.
    pub fn bus_opt(&self) -> Arc<EventBus> {
        self.inner.bus.clone()
    }

    /// Performs a write operation on the table and publishes events to the bus.
    /// This is the primary entry point for all system state mutations.
    #[must_use]
    pub fn apply(&self, update: &DeviceUpdate) -> bool {
        let mut table = self.inner.table.write();

        let opt_mac = mac_of(update);
        let is_new = opt_mac.is_some_and(|mac| table.get_device(&mac).is_none());
        let change = device_change_of(update);

        // Pre-capture prefix state for comparison
        let mut prev_prefix = None;
        if let DeviceUpdate::InterfaceIpsChanged { ifindex, .. } = update {
            let is_primary = self
                .inner
                .target_ifindex
                .is_none_or(|target| target == *ifindex);
            if is_primary {
                let ips = table.get_interface_ips(*ifindex);
                prev_prefix = Some((ips.gua, ips.ula));
            }
        }

        let changed = table.apply_update(update.clone());
        if !changed {
            return false;
        }

        let mut events = Vec::new();
        if let Some(mac) = opt_mac {
            if is_new {
                events.push(LanforgeEvent::DeviceDiscovered { mac });
            }
            if let Some(change) = change {
                events.push(LanforgeEvent::DeviceUpdated { mac, change });
            }
            if let DeviceUpdate::HostRemoved { .. } = update {
                events.push(LanforgeEvent::DevicePurged { mac });
            }
        }

        if let DeviceUpdate::InterfaceIpsChanged {
            ifindex,
            gua,
            ula,
            preferred,
            valid,
            ..
        } = update
        {
            events.push(LanforgeEvent::InterfaceUpdated { ifindex: *ifindex });
            if let Some((prev_gua, prev_ula)) = prev_prefix
                && ((gua.is_some() && *gua != prev_gua) || (ula.is_some() && *ula != prev_ula))
            {
                events.push(LanforgeEvent::PrefixChanged {
                    gua: *gua,
                    ula: *ula,
                    preferred: *preferred,
                    valid: *valid,
                });
            }
        }

        drop(table);

        for event in events {
            let _ = self.inner.bus.publish(event);
        }
        let _ = self.inner.bus.publish(LanforgeEvent::DeviceTableDirty);
        true
    }

    // -----------------------------------------------------------------------
    // Query Methods (Facade)
    // -----------------------------------------------------------------------

    /// Retrieves a device by its MAC address.
    #[must_use]
    pub fn get_device(mac: &MacAddr) -> Option<Arc<Device>> {
        Self::instance().query(|t| t.get_device(mac))
    }

    /// Returns a list of all devices in the table.
    #[must_use]
    pub fn devices() -> Vec<Arc<Device>> {
        Self::instance().query(|t| t.devices().collect())
    }

    /// Retrieves a device by any of its assigned IP addresses.
    #[must_use]
    pub fn get_by_ip(ip: &IpAddr) -> Option<Arc<Device>> {
        Self::instance().query(|t| t.get_by_ip(ip))
    }

    /// Returns the primary interface index this daemon is managing.
    #[must_use]
    pub fn target_ifindex() -> Option<u32> {
        Self::instance().inner.target_ifindex
    }

    /// Retrieves a device by its configured hostname.
    #[must_use]
    pub fn get_by_hostname(hostname: &str) -> Option<Arc<Device>> {
        Self::instance().query(|t| t.get_by_hostname(hostname))
    }

    /// Helper to find a MAC address by its IP in the DNS index.
    #[must_use]
    pub fn get_mac_by_ip(ip: IpAddr) -> Option<MacAddr> {
        Self::instance().query(|t| t.get_mac_by_ip(ip))
    }

    /// Retrieves a device by its DUID.
    #[must_use]
    pub fn get_by_duid(duid: &Duid) -> Option<Arc<Device>> {
        Self::instance().query(|t| t.get_by_duid(duid))
    }

    /// Produz um registro validado das configurações estáticas.
    #[must_use]
    pub fn get_static_registry() -> crate::state::StaticRegistry {
        Self::instance().query(DeviceTable::get_static_registry)
    }

    /// Helper to find the GUA prefix and its lifetimes for a specific interface.
    #[must_use]
    pub fn get_interface_gua_at(ifindex: u32) -> Option<(Ipv6Addr, u32, u32)> {
        Self::instance().query(|t| t.get_interface_gua_at(ifindex))
    }

    /// Verifies if an IPv6 prefix is already delegated to any device.
    #[must_use]
    pub fn is_prefix_delegated(prefix: Ipv6Addr, len: u8) -> bool {
        Self::instance().query(|t| t.is_prefix_delegated(prefix, len))
    }

    /// Expires stale devices and leases from the table.
    /// Returns true if any changes were made.
    #[must_use]
    pub fn expire_stale() -> bool {
        Self::instance().trigger_garbage_collection();
        true // FIXME: Return actual change status if needed
    }

    /// Returns the current GUA and ULA prefixes for an interface.
    #[must_use]
    pub fn get_interface_prefixes(ifindex: u32) -> (Option<Ipv6Addr>, Option<Ipv6Addr>) {
        Self::instance().query(|t| {
            let s = t.get_interface_ips(ifindex);
            (s.gua, s.ula)
        })
    }

    /// Returns the full interface state for a given index.
    #[must_use]
    pub fn get_interface_state(ifindex: u32) -> crate::state::InterfaceState {
        Self::instance().query(|t| t.get_interface_ips(ifindex))
    }

    /// Returns a full snapshot of the underlying device table.
    #[must_use]
    pub fn get_table_snapshot() -> DeviceTable {
        Self::instance().query(Clone::clone)
    }

    // -----------------------------------------------------------------------
    // Action Methods (Facade)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Mutation Methods (Write Facade)
    // -----------------------------------------------------------------------

    /// Allocates an IPv4 lease for a device.
    #[must_use]
    pub fn allocate_v4_lease(mac: MacAddr, ip: Ipv4Addr, expires: SystemTime) -> bool {
        Self::instance().apply(&DeviceUpdate::V4LeaseGranted { mac, ip, expires })
    }

    /// Grants an IPv6 address lease via `DHCPv6`.
    #[must_use]
    pub fn grant_v6_lease(
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        ip: Ipv6Addr,
        expires: SystemTime,
    ) -> bool {
        Self::instance().apply(&DeviceUpdate::V6LeaseGranted {
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
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        prefix: Ipv6Addr,
        len: u8,
        expires: SystemTime,
    ) -> bool {
        Self::instance().apply(&DeviceUpdate::V6PrefixAssigned {
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
    pub fn associate_duid(mac: Option<MacAddr>, duid: Duid, iaid: u32) -> bool {
        Self::instance().apply(&DeviceUpdate::DuidAssociated { mac, duid, iaid })
    }

    /// Updates or hints a device hostname (e.g., via DHCP or mDNS).
    #[must_use]
    pub fn update_hostname(mac: MacAddr, hostname: String, _source: HostnameOrigin) -> bool {
        Self::instance().apply(&DeviceUpdate::DhcpHostnameHint { mac, hostname })
    }

    /// Tracks a neighbor seen via NDP (IPv6).
    #[must_use]
    pub fn track_ndp_neighbor(mac: MacAddr, ip: Ipv6Addr) -> bool {
        Self::instance().apply(&DeviceUpdate::NdpSeen { mac, ip })
    }

    /// Tracks a neighbor seen via ARP (IPv4).
    #[must_use]
    pub fn track_arp_neighbor(mac: MacAddr, ip: Ipv4Addr) -> bool {
        Self::instance().apply(&DeviceUpdate::ArpSeen { mac, ip })
    }

    /// Observes a single SLAAC address for a device.
    #[must_use]
    pub fn observe_slaac(mac: MacAddr, ip: Ipv6Addr) -> bool {
        Self::instance().apply(&DeviceUpdate::SlaacObserved { mac, addr: ip })
    }

    /// Performs a full synchronization of SLAAC addresses for a device.
    #[must_use]
    pub fn sync_slaac(mac: MacAddr, addresses: Vec<Ipv6Addr>) -> bool {
        Self::instance().apply(&DeviceUpdate::SlaacSynced { mac, addresses })
    }

    /// Signals a change in interface IP configuration.
    #[must_use]
    pub fn signal_interface_update(
        ifindex: u32,
        link_local: Option<Ipv6Addr>,
        gua: Option<Ipv6Addr>,
        ula: Option<Ipv6Addr>,
        preferred: u32,
        valid: u32,
    ) -> bool {
        Self::instance().apply(&DeviceUpdate::InterfaceIpsChanged {
            ifindex,
            link_local,
            gua,
            ula,
            preferred,
            valid,
        })
    }

    /// Signals a global IPv6 GUA change for an interface.
    #[must_use]
    pub fn signal_gua_change(ifindex: u32, gua: Ipv6Addr, preferred: u32, valid: u32) -> bool {
        Self::instance().apply(&DeviceUpdate::InterfaceIpsChanged {
            ifindex,
            link_local: None,
            gua: Some(gua),
            ula: None,
            preferred,
            valid,
        })
    }

    /// Explicitly removes a host from the system.
    #[must_use]
    pub fn remove_host(mac: MacAddr) -> bool {
        Self::instance().apply(&DeviceUpdate::HostRemoved { mac })
    }

    /// Releases a `DHCPv4` lease associated with a MAC.
    #[must_use]
    pub fn release_v4_lease(mac: MacAddr) -> bool {
        Self::instance().apply(&DeviceUpdate::LeaseReleased {
            mac,
            target: LeaseTarget::V4,
        })
    }

    /// Releases a `DHCPv6` address lease (`IA_NA`) for a MAC.
    #[must_use]
    pub fn release_v6_lease(mac: MacAddr, iaid: u32) -> bool {
        Self::instance().apply(&DeviceUpdate::LeaseReleased {
            mac,
            target: LeaseTarget::V6 { iaid },
        })
    }

    /// Releases a `DHCPv6` prefix delegation (`IA_PD`) for a MAC.
    #[must_use]
    pub fn release_v6_prefix(mac: MacAddr, iaid: u32) -> bool {
        Self::instance().apply(&DeviceUpdate::LeaseReleased {
            mac,
            target: LeaseTarget::V6Prefix { iaid },
        })
    }

    /// Deletes a specific neighbor IP.
    #[must_use]
    pub fn delete_ip(ip: IpAddr) -> bool {
        Self::instance().apply(&DeviceUpdate::IpDeleted { ip })
    }

    /// Triggers the background garbage collection process.
    ///
    /// This method identifies expired leases and stale devices, removes them from
    /// the table, and publishes granular `DeviceUpdated` events for each change.
    pub fn trigger_garbage_collection(&self) {
        let dead_leases = {
            let mut table = self.inner.table.write();
            table.expire_stale()
        };

        if !dead_leases.is_empty() {
            for (mac, change) in dead_leases {
                let _ = self
                    .inner
                    .bus
                    .publish(LanforgeEvent::DeviceUpdated { mac, change });
            }
            let _ = self.inner.bus.publish(LanforgeEvent::DeviceTableDirty);
        }
    }

    /// Adds or updates a static device reservation in the table.
    #[must_use]
    pub fn add_static_device(
        mac: MacAddr,
        hostname: String,
        v4_static: Option<Ipv4Addr>,
        v6_suffix: Option<Ipv6AddrOrSuffix>,
    ) -> bool {
        use crate::device::Origin;

        Self::instance().apply(&DeviceUpdate::CliHostUpdated {
            mac,
            hostname: FieldUpdate::Set(hostname),
            v4_static: v4_static.into(),
            v6_suffix: v6_suffix.into(),
            origin: Origin::Cli,
        })
    }

    /// Explicitly triggers a rebuild of the high-performance DNS lookup indices.
    pub fn rebuild_dns_indices() {
        let _ = Self::instance().apply(&DeviceUpdate::RebuildDnsIndices);
    }
}

// ---------------------------------------------------------------------------
// Helpers internos
// ---------------------------------------------------------------------------

/// Extracts the MAC address from any variant of [`DeviceUpdate`], if present.
const fn mac_of(update: &DeviceUpdate) -> Option<MacAddr> {
    match update {
        DeviceUpdate::V6LeaseGranted { mac, .. }
        | DeviceUpdate::V6PrefixAssigned { mac, .. }
        | DeviceUpdate::DuidAssociated { mac, .. } => *mac,
        DeviceUpdate::SlaacSynced { mac, .. }
        | DeviceUpdate::SlaacObserved { mac, .. }
        | DeviceUpdate::V4LeaseGranted { mac, .. }
        | DeviceUpdate::NdpSeen { mac, .. }
        | DeviceUpdate::ArpSeen { mac, .. }
        | DeviceUpdate::DhcpHostnameHint { mac, .. }
        | DeviceUpdate::MdnsHostnameHint { mac, .. }
        | DeviceUpdate::CliHostUpdated { mac, .. }
        | DeviceUpdate::SlaacCleared { mac }
        | DeviceUpdate::HostRemoved { mac }
        | DeviceUpdate::LeaseReleased { mac, .. } => Some(*mac),

        DeviceUpdate::IpDeleted { .. }
        | DeviceUpdate::InterfaceIpsChanged { .. }
        | DeviceUpdate::RebuildDnsIndices => None,
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
        DeviceUpdate::SlaacSynced { addresses, .. } => Some(DeviceChange::SlaacSynced {
            addresses: addresses.clone(),
        }),
        DeviceUpdate::DhcpHostnameHint { hostname, .. }
        | DeviceUpdate::MdnsHostnameHint { hostname, .. } => Some(DeviceChange::HostnameChanged {
            hostname: hostname.clone(),
        }),
        DeviceUpdate::DuidAssociated { .. } => Some(DeviceChange::DuidAssociated),
        DeviceUpdate::NdpSeen { .. } => Some(DeviceChange::NdpObserved),
        DeviceUpdate::ArpSeen { .. } => Some(DeviceChange::ArpObserved),
        DeviceUpdate::LeaseReleased { target, .. } => Some(DeviceChange::LeaseExpired {
            target: target.clone(),
        }),
        DeviceUpdate::HostRemoved { .. }
        | DeviceUpdate::IpDeleted { .. }
        | DeviceUpdate::SlaacCleared { .. }
        | DeviceUpdate::InterfaceIpsChanged { .. }
        | DeviceUpdate::RebuildDnsIndices => None,
        DeviceUpdate::CliHostUpdated {
            hostname,
            v4_static,
            v6_suffix,
            ..
        } => {
            if let FieldUpdate::Set(hn) = hostname {
                return Some(DeviceChange::HostnameChanged {
                    hostname: hn.clone(),
                });
            }
            if let FieldUpdate::Set(ip) = v4_static {
                return Some(DeviceChange::V4StaticChanged { ip: Some(*ip) });
            }
            if let FieldUpdate::Set(v6) = v6_suffix {
                return Some(DeviceChange::V6SuffixChanged {
                    suffix: Some(v6.clone()),
                });
            }
            None
        }
    }
}
