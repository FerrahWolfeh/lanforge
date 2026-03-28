//! `DeviceTable` and central Lanforge state types.
//!
//! The core model is a [`Device`] — a physical network entity that can possess
//! IPv4, IPv6, and SLAAC addresses simultaneously. Devices are primarily indexed by MAC.
//!
//! ## Writing to the Table
//!
//! No external module should ever modify a [`Device`]'s fields directly.
//! The correct path for all state transitions is:
//!
//! ```ignore
//! let update = DeviceUpdate::V4LeaseGranted { mac, ip, expires };
//! let changed = table.apply_update(update);
//! ```
//!
//! The `apply_update` method is the **sole authority** for merging logic and
//! precedence (e.g., Static > Dynamic). If it returns `true`, the caller is
//! responsible for emitting a `DeviceTableDirty` event on the `EventBus`.

pub mod expiry;
pub mod update;

#[cfg(test)]
pub mod tests;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::time::SystemTime;

use crate::device::{Device, Hostname, IPv4State, Origin};
use crate::identifiers::{Duid, MacAddr};
use crate::state::update::StaticEntry;

// ---------------------------------------------------------------------------
// DeviceTable
// ---------------------------------------------------------------------------

/// The central device table — typically shared via `Arc<RwLock<DeviceTable>>`.
///
/// It is the **sole authority** for system state. All state modifications
/// MUST pass through `apply_update`.
#[derive(Debug, Clone)]
pub struct DeviceTable {
    /// Global map of devices keyed by MAC address.
    devices: HashMap<MacAddr, Device>,
    /// Index: DUID -> MAC
    duid_index: HashMap<Duid, MacAddr>,
    /// Static entries from configuration files or database.
    static_entries: HashMap<MacAddr, StaticEntry>,
    /// Cache for Neighbor Discovery Protocol (NDP) lookups.
    ndp_cache: HashMap<Ipv6Addr, (MacAddr, SystemTime)>,
    /// IPv6 leases discovered before a corresponding MAC was known.
    orphaned_v6: HashMap<Ipv6Addr, (Duid, u32, SystemTime)>,

    // --- DNS Hot Path Indices ---
    /// Index: Hostname -> MAC
    name_index: HashMap<String, MacAddr>,
    /// Index: IP Address -> MAC
    ip_index: HashMap<IpAddr, MacAddr>,
}

impl DeviceTable {
    /// Creates a new, empty device table.
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
            duid_index: HashMap::new(),
            static_entries: HashMap::new(),
            ndp_cache: HashMap::new(),
            orphaned_v6: HashMap::new(),
            name_index: HashMap::new(),
            ip_index: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Public Queries
    // -----------------------------------------------------------------------

    /// Retrieves a device by its MAC address.
    pub fn get_device(&self, mac: &MacAddr) -> Option<&Device> {
        self.devices.get(mac)
    }

    /// Retrieves a mutable reference to a device by its MAC address.
    pub fn get_device_mut(&mut self, mac: &MacAddr) -> Option<&mut Device> {
        self.devices.get_mut(mac)
    }

    /// Retrieves a device by its configured hostname.
    pub fn get_by_hostname(&self, hostname: &str) -> Option<&Device> {
        self.name_index
            .get(hostname)
            .and_then(|mac| self.devices.get(mac))
    }

    /// Retrieves a device by any of its assigned IP addresses.
    pub fn get_by_ip(&self, ip: &IpAddr) -> Option<&Device> {
        self.ip_index.get(ip).and_then(|mac| self.devices.get(mac))
    }

    /// Helper to find a MAC address by its IP in the DNS index.
    pub fn get_mac_by_ip(&self, ip: IpAddr) -> Option<MacAddr> {
        self.ip_index.get(&ip).copied()
    }

    /// Retrieves a device by its DUID (DHCPv6 Unique Identifier).
    pub fn get_by_duid(&self, duid: &Duid) -> Option<&Device> {
        self.duid_index
            .get(duid)
            .and_then(|mac| self.devices.get(mac))
    }

    /// Retrieves the DUID associated with a MAC address, if already learned.
    pub fn get_duid_by_mac(&self, mac: MacAddr) -> Option<&Duid> {
        self.devices.get(&mac)?.duid.as_ref()
    }

    /// Returns an iterator over all known devices.
    pub fn devices(&self) -> impl Iterator<Item = &Device> {
        self.devices.values()
    }

    /// Returns an iterator over all static entries (configurations).
    pub fn static_entries(&self) -> impl Iterator<Item = &StaticEntry> {
        self.static_entries.values()
    }

    /// Retrieves a MAC address from the NDP cache for a given IPv6 address.
    pub fn get_mac_from_ndp_cache(&self, ip: &Ipv6Addr) -> Option<MacAddr> {
        self.ndp_cache.get(ip).map(|(mac, _)| *mac)
    }

    /// Returns an iterator over orphaned IPv6 leases (assigned but MAC unknown).
    pub fn iter_orphaned_v6(&self) -> impl Iterator<Item = (&Ipv6Addr, &(Duid, u32, SystemTime))> {
        self.orphaned_v6.iter()
    }

    // -----------------------------------------------------------------------
    // Helpers internos
    // -----------------------------------------------------------------------

    /// Retorna o device mutável, criando-o se não existir.
    /// Prefira `apply_update` para todo o código de protocolo.
    pub fn get_or_insert(&mut self, mac: MacAddr) -> &mut Device {
        self.devices.entry(mac).or_insert_with(|| Device {
            mac,
            hostname: Hostname::default(),
            origin: Origin::Dynamic,
            managed_at: None,
            duid: None,
            v4: IPv4State::None,
            v6: Vec::new(),
            v6_prefixes: Vec::new(),
            seen_v4: Vec::new(),
            last_seen: SystemTime::now(),
        })
    }

    /// Adiciona ou atualiza uma entrada estática. Usado principalmente na carga do DB.
    pub fn add_static_entry(&mut self, mac: MacAddr, entry: StaticEntry) {
        self.static_entries.insert(mac, entry);
    }
}

impl Default for DeviceTable {
    fn default() -> Self {
        Self::new()
    }
}
