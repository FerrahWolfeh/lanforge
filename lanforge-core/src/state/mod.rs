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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use std::sync::Arc;

use crate::device::{Device, Ipv6AddrOrSuffix};
use crate::identifiers::{Duid, MacAddr};
use crate::state::update::StaticEntry;

/// Represents the dynamic IP state of a local network interface.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InterfaceState {
    pub link_local: Option<Ipv6Addr>,
    pub gua: Option<Ipv6Addr>,
    pub ula: Option<Ipv6Addr>,
    pub gua_preferred: u32,
    pub gua_valid: u32,
}

// ---------------------------------------------------------------------------
// DeviceTable
// ---------------------------------------------------------------------------

/// The central device table — typically shared via `Arc<RwLock<DeviceTable>>`.
///
/// It now stores `Arc<Device>` to allow for zero-cost snapshots (COW).
#[derive(Debug, Clone)]
pub struct DeviceTable {
    /// Global map of devices keyed by MAC address.
    devices: HashMap<MacAddr, Arc<Device>>,
    /// Index: DUID -> MAC
    duid_index: HashMap<Duid, MacAddr>,
    /// Static entries from configuration files or database.
    static_entries: HashMap<MacAddr, StaticEntry>,
    /// Cache for Neighbor Discovery Protocol (NDP) lookups.
    ndp_cache: HashMap<Ipv6Addr, (MacAddr, SystemTime)>,
    /// IPv6 leases discovered before a corresponding MAC was known.
    orphaned_v6: HashMap<Ipv6Addr, (Duid, u32, SystemTime)>,

    /// Local interface IP address state (ifindex -> state).
    interface_ips: HashMap<u32, InterfaceState>,

    // --- DNS Hot Path Indices ---
    /// Index: Hostname -> MAC
    name_index: HashMap<String, MacAddr>,
    /// Index: IP Address -> MAC
    ip_index: HashMap<IpAddr, MacAddr>,
}

/// A validated snapshot of all static network reservations.
///
/// This registry is built by the `DeviceTable` after performing
/// consistency checks and collision detection. Services like
/// `DHCPv4` and `DHCPv6` use this to pre-allocate addresses.
#[derive(Debug, Clone, Default)]
pub struct StaticRegistry {
    /// Mapping: IPv4 -> MAC
    pub v4: HashMap<Ipv4Addr, MacAddr>,
    /// Mapping: IPv6 (Suffix or IP) -> MAC
    pub v6: HashMap<Ipv6AddrOrSuffix, MacAddr>,
}

impl StaticRegistry {
    /// Returns an iterator over all resolved static IPv4 addresses.
    pub fn v4_ips(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.v4.keys().copied()
    }

    /// Returns an iterator over all static IPv6 reservations (suffixes or full IPs).
    pub fn v6_reservations(&self) -> impl Iterator<Item = Ipv6AddrOrSuffix> + '_ {
        self.v6.keys().cloned()
    }
}

impl DeviceTable {
    /// Creates a new, empty device table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
            duid_index: HashMap::new(),
            static_entries: HashMap::new(),
            ndp_cache: HashMap::new(),
            orphaned_v6: HashMap::new(),
            interface_ips: HashMap::new(),
            name_index: HashMap::new(),
            ip_index: HashMap::new(),
        }
    }

    /// Manually inserts a pre-built device into the table. Useful for DB loading.
    pub fn insert_device(&mut self, mac: MacAddr, device: Device) {
        if let Some(duid) = &device.duid {
            self.duid_index.insert(duid.clone(), mac);
        }
        self.devices.insert(mac, Arc::new(device));
    }

    // -----------------------------------------------------------------------
    // Public Queries
    // -----------------------------------------------------------------------

    /// Retrieves a device by its MAC address.
    #[must_use]
    pub fn get_device(&self, mac: &MacAddr) -> Option<Arc<Device>> {
        self.devices.get(mac).cloned()
    }

    /// Retrieves a device by its configured hostname.
    #[must_use]
    pub fn get_by_hostname(&self, hostname: &str) -> Option<Arc<Device>> {
        self.name_index
            .get(hostname)
            .and_then(|mac| self.devices.get(mac).cloned())
    }

    /// Retrieves a device by any of its assigned IP addresses.
    #[must_use]
    pub fn get_by_ip(&self, ip: &IpAddr) -> Option<Arc<Device>> {
        self.ip_index
            .get(ip)
            .and_then(|mac| self.devices.get(mac).cloned())
    }

    /// Helper to find a MAC address by its IP in the DNS index.
    #[must_use]
    pub fn get_mac_by_ip(&self, ip: IpAddr) -> Option<MacAddr> {
        self.ip_index.get(&ip).copied()
    }

    /// Retrieves a device by its DUID (`DHCPv6` Unique Identifier).
    #[must_use]
    pub fn get_by_duid(&self, duid: &Duid) -> Option<Arc<Device>> {
        self.duid_index
            .get(duid)
            .and_then(|mac| self.devices.get(mac).cloned())
    }

    /// Retrieves the DUID associated with a MAC address, if already learned.
    #[must_use]
    pub fn get_duid_by_mac(&self, mac: MacAddr) -> Option<&Duid> {
        self.devices.get(&mac)?.duid.as_ref()
    }

    /// Returns an iterator over all known devices.
    pub fn devices(&self) -> impl Iterator<Item = Arc<Device>> + '_ {
        self.devices.values().cloned()
    }

    /// Returns an iterator over all static entries (configurations).
    pub fn static_entries(&self) -> impl Iterator<Item = &StaticEntry> {
        self.static_entries.values()
    }

    /// Retrieves a MAC address from the NDP cache for a given IPv6 address.
    #[must_use]
    pub fn get_mac_from_ndp_cache(&self, ip: &Ipv6Addr) -> Option<MacAddr> {
        self.ndp_cache.get(ip).map(|(mac, _)| *mac)
    }

    /// Returns an iterator over orphaned IPv6 leases (assigned but MAC unknown).
    pub fn iter_orphaned_v6(&self) -> impl Iterator<Item = (&Ipv6Addr, &(Duid, u32, SystemTime))> {
        self.orphaned_v6.iter()
    }

    /// Retrieves the cached IP configuration for a local interface.
    #[must_use]
    pub fn get_interface_ips(&self, ifindex: u32) -> InterfaceState {
        self.interface_ips
            .get(&ifindex)
            .cloned()
            .unwrap_or_default()
    }

    /// Helper to find the GUA prefix and its lifetimes for a specific interface.
    #[must_use]
    pub fn get_interface_gua_at(&self, ifindex: u32) -> Option<(Ipv6Addr, u32, u32)> {
        self.interface_ips
            .get(&ifindex)
            .and_then(|s| s.gua.map(|g| (g, s.gua_preferred, s.gua_valid)))
    }

    // -----------------------------------------------------------------------
    // Helpers internos
    // -----------------------------------------------------------------------

    /// Retorna o device recém-criado ou existente como Arc.
    /// Prefira `apply_update` para todo o código de protocolo.
    pub fn get_or_insert(&mut self, mac: MacAddr) -> Arc<Device> {
        if let Some(dev) = self.devices.get(&mac) {
            return dev.clone();
        }

        let dev = Arc::new(Device::new(mac));
        self.devices.insert(mac, dev.clone());
        dev
    }

    /// Returns the existing device or a new one, but does NOT insert it into the map.
    /// This is used by `apply_update` to perform "what-if" checks before persisting.
    #[must_use]
    pub fn get_device_or_new(&self, mac: MacAddr) -> Arc<Device> {
        self.devices
            .get(&mac)
            .cloned()
            .unwrap_or_else(|| Arc::new(Device::new(mac)))
    }

    /// Adiciona ou atualiza uma entrada estática. Usado principalmente na carga do DB.
    pub fn add_static_entry(&mut self, mac: MacAddr, entry: StaticEntry) {
        self.static_entries.insert(mac, entry);
    }

    /// Retorna estatísticas resumidas da tabela.
    #[must_use]
    pub fn stats(&self) -> DeviceTableStats {
        let total = self.devices.len();
        let online = self.devices.values().filter(|d| d.is_online()).count();
        let statics = self.static_entries.len();

        DeviceTableStats {
            total_devices: total,
            online_devices: online,
            static_entries: statics,
        }
    }

    /// Produz um registro validado das configurações estáticas.
    /// Realiza detecção de colisões e loga avisos para IPs duplicados.
    pub fn get_static_registry(&self) -> StaticRegistry {
        let mut registry = StaticRegistry::default();

        // Sort by MAC to guarantee deterministic "first-win" logic
        let mut sorted_entries: Vec<_> = self.static_entries.iter().collect::<Vec<_>>();
        sorted_entries.sort_by_key(|(mac, _)| **mac);

        for (&mac, entry) in sorted_entries {
            // 1. Validar IPv4
            if let Some(ip) = entry.v4_ip {
                if let Some(&owner) = registry.v4.get(&ip) {
                    if owner != mac {
                        tracing::warn!(
                            "❌ Colisão de IP Estático (v4): {} solicitado por {}, mas já pertence a {}",
                            ip,
                            mac,
                            owner
                        );
                    }
                } else {
                    registry.v4.insert(ip, mac);
                }
            }

            // 2. Validar IPv6 (Sufixo ou IP Full)
            if let Some(v6) = &entry.v6_suffix {
                if let Some(owner) = registry.v6.get(v6) {
                    if *owner != mac {
                        tracing::warn!(
                            "❌ Colisão de IP Estático (v6): {} solicitado por {}, mas já pertence a {}",
                            v6,
                            mac,
                            owner
                        );
                    }
                } else {
                    registry.v6.insert(v6.clone(), mac);
                }
            }
        }

        registry
    }
}

/// Estatísticas básicas da tabela de dispositivos.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTableStats {
    pub total_devices: usize,
    pub online_devices: usize,
    pub static_entries: usize,
}

impl Default for DeviceTable {
    fn default() -> Self {
        Self::new()
    }
}
