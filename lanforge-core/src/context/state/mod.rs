//! `State` — Central Lanforge device and interface state.

pub mod cache;
pub mod handlers;
pub mod indices;
#[cfg(test)]
pub mod jit_tests;
pub mod network;
#[cfg(test)]
pub mod tests;

use crate::bus::{DeviceChange, DeviceEvent, LanforgeEvent};
use crate::device::{Device, DeviceClass, Ipv6AddrOrSuffix, Origin};
use crate::identifiers::{Duid, MacAddr};
use lanforge_macros::UpdateDispatch;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

pub use self::cache::DiscoveryCache;
pub use self::indices::Indices;
pub use self::network::{InterfaceState, NetworkState};

// ---------------------------------------------------------------------------
// Types moved from state.rs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FieldUpdate<T> {
    #[serde(rename = "no_change")]
    #[default]
    NoChange,
    #[serde(rename = "clear")]
    Clear,
    #[serde(rename = "set")]
    Set(T),
}

impl<T> From<Option<T>> for FieldUpdate<T> {
    fn from(opt: Option<T>) -> Self {
        opt.map_or_else(|| Self::Clear, |val| Self::Set(val))
    }
}

impl<T> From<T> for FieldUpdate<T> {
    fn from(val: T) -> Self {
        Self::Set(val)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StaticEntry {
    pub mac: MacAddr,
    pub hostname: String,
    pub duid: Option<Duid>,
    pub v4_static: Option<Ipv4Addr>,
    pub v6_suffix: Option<Ipv6AddrOrSuffix>,
    pub boot_file: Option<String>,
    pub origin: Origin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CliHostUpdate {
    pub hostname: FieldUpdate<String>,
    pub duid: FieldUpdate<Duid>,
    pub v4_static: FieldUpdate<Ipv4Addr>,
    pub v6_suffix: FieldUpdate<Ipv6AddrOrSuffix>,
    pub boot_file: FieldUpdate<String>,
    pub origin: Origin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum LeaseTarget {
    V4,
    V6 { iaid: u32 },
    V6Prefix { iaid: u32 },
}

// ---------------------------------------------------------------------------
// DeviceUpdate & Dispatch
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, UpdateDispatch)]
pub enum DeviceUpdate {
    V4LeaseGranted {
        mac: MacAddr,
        ip: Ipv4Addr,
        expires: SystemTime,
    },
    V6LeaseGranted {
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        ip: Ipv6Addr,
        expires: SystemTime,
    },
    V6PrefixAssigned {
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        prefix: Ipv6Addr,
        len: u8,
        expires: SystemTime,
    },
    SlaacObserved {
        mac: MacAddr,
        addr: Ipv6Addr,
        is_active: bool,
    },
    NdpSeen {
        mac: MacAddr,
        ip: Ipv6Addr,
        is_active: bool,
    },
    ArpSeen {
        mac: MacAddr,
        ip: Ipv4Addr,
        is_active: bool,
    },
    #[handler("handle_hostname_hint_dhcp")]
    DhcpHostnameHint {
        mac: MacAddr,
        hostname: String,
    },
    #[handler("handle_hostname_hint_mdns")]
    MdnsHostnameHint {
        mac: MacAddr,
        hostname: String,
    },
    DuidAssociated {
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
    },
    CliHostUpdated {
        mac: MacAddr,
        update: CliHostUpdate,
    },
    HostRemoved {
        mac: MacAddr,
    },
    LeaseReleased {
        mac: MacAddr,
        target: LeaseTarget,
    },
    IpDeleted {
        ip: IpAddr,
    },
    IpOffline {
        ip: IpAddr,
    },
    InterfaceIpsChanged {
        ifindex: u32,
        state: InterfaceState,
    },
    PruneZombies,
    RebuildDnsIndices,
    ClassHint {
        mac: MacAddr,
        class: DeviceClass,
    },
    TopologyUpdated {
        mac: MacAddr,
        parent_mac: Option<MacAddr>,
        port: Option<String>,
        ifindex: u32,
    },
    Reset,
    NeighborBatch {
        entries: Vec<(MacAddr, IpAddr, bool)>,
    },
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    pub devices: HashMap<MacAddr, Arc<Device>>,
    pub static_entries: HashMap<MacAddr, StaticEntry>,
    pub indices: Indices,
    pub discovery: DiscoveryCache,
    pub network: NetworkState,

    #[serde(skip)]
    pub indexing_enabled: bool,
}

impl State {
    #[must_use]
    pub fn new() -> Self {
        Self {
            indexing_enabled: true,
            ..Default::default()
        }
    }

    pub fn index_device(&mut self, mac: MacAddr, dev: &Device) {
        if self.indexing_enabled || dev.is_static() {
            self.indices.index_device(mac, dev);
        }
    }

    pub fn unindex_device(&mut self, dev: &Device) {
        // We always allow unindexing to be safe, but we can also gate it if we want.
        // Usually it's better to always unindex to avoid stale entries.
        self.indices.unindex_device(dev);
    }

    // --- Getters ---

    #[must_use]
    pub fn get_device(&self, mac: &MacAddr) -> Option<Arc<Device>> {
        self.devices.get(mac).cloned()
    }

    #[must_use]
    pub fn get_by_hostname(&self, hostname: &str) -> Option<Arc<Device>> {
        let mac = self
            .indices
            .name_index
            .get(&hostname.to_ascii_lowercase())?;
        self.devices.get(mac).cloned()
    }

    #[must_use]
    pub fn get_by_ip(&self, ip: &IpAddr) -> Option<Arc<Device>> {
        let mac = self.indices.ip_index.get(ip)?;
        self.devices.get(mac).cloned()
    }

    #[must_use]
    pub fn get_by_duid(&self, duid: &Duid) -> Option<Arc<Device>> {
        let mac = self.indices.duid_index.get(duid)?;
        self.devices.get(mac).cloned()
    }

    #[must_use]
    pub fn get_mac_by_duid(&self, duid: &Duid) -> Option<MacAddr> {
        self.indices.duid_index.get(duid).copied()
    }

    #[must_use]
    pub fn get_mac_by_ip(&self, ip: IpAddr) -> Option<MacAddr> {
        self.indices.ip_index.get(&ip).copied()
    }

    #[must_use]
    pub fn get_static_registry(&self) -> StaticRegistry {
        let mut registry = StaticRegistry::default();
        let mut entries: Vec<_> = self.static_entries.values().collect();
        entries.sort_by_key(|e| e.mac); // Stable order

        for entry in entries {
            if let Some(v4) = entry.v4_static {
                registry.v4.entry(v4).or_insert(entry.mac);
            }
            if let Some(v6) = &entry.v6_suffix {
                registry.v6.entry(*v6).or_insert(entry.mac);
            }
        }
        registry
    }

    #[must_use]
    pub fn is_prefix_delegated(&self, prefix: Ipv6Addr, _len: u8) -> bool {
        self.devices
            .values()
            .any(|dev| dev.v6_prefixes.iter().any(|p| p.prefix == prefix))
    }

    #[must_use]
    pub fn get_interface_gua_at(&self, ifindex: u32) -> Option<(Ipv6Addr, u32, u32)> {
        let state = self.network.interface_ips.get(&ifindex)?;
        state
            .gua
            .map(|ip| (ip, state.gua_preferred, state.gua_valid))
    }

    #[must_use]
    pub fn get_interface_ips(&self, ifindex: u32) -> InterfaceState {
        self.network
            .interface_ips
            .get(&ifindex)
            .cloned()
            .unwrap_or_default()
    }
    #[must_use]
    pub fn get_mac_from_ndp_cache(&self, ip: &Ipv6Addr) -> Option<MacAddr> {
        self.discovery.ndp_cache.get(ip).map(|(m, _)| *m)
    }

    #[must_use]
    pub fn get_duid_by_mac(&self, mac: MacAddr) -> Option<&Duid> {
        self.devices.get(&mac).and_then(|d| d.duid.as_ref())
    }

    pub fn add_static_entry(&mut self, mac: MacAddr, entry: StaticEntry) {
        self.static_entries.insert(mac, entry);
    }

    pub fn add_static_device(
        &mut self,
        mac: MacAddr,
        hostname: String,
        duid: Option<Duid>,
        v4_static: Option<Ipv4Addr>,
        v6_suffix: Option<Ipv6AddrOrSuffix>,
        boot_file: Option<String>,
    ) {
        self.apply_update(DeviceUpdate::CliHostUpdated {
            mac,
            update: CliHostUpdate {
                hostname: hostname.into(),
                duid: duid.into(),
                v4_static: v4_static.into(),
                v6_suffix: v6_suffix.into(),
                boot_file: boot_file.into(),
                origin: Origin::Cli,
            },
        });
    }

    pub fn insert_device(&mut self, mac: MacAddr, dev: Device) {
        let dev = Arc::new(dev);
        self.unindex_device(&dev);
        self.indices.index_device(mac, &dev);
        self.devices.insert(mac, dev);
    }

    pub fn set_indexing_enabled(&mut self, enabled: bool) {
        self.indexing_enabled = enabled;
        if enabled {
            self.rebuild_indices();
        }
    }

    pub fn rebuild_indices(&mut self) {
        self.indices.clear();
        for (mac, dev) in &self.devices {
            self.indices.index_device(*mac, dev);
        }
    }

    pub fn devices(&self) -> impl Iterator<Item = Arc<Device>> + '_ {
        self.devices.values().cloned()
    }

    /// Centralized device mutation helper.
    pub(crate) fn mutate_device(
        &mut self,
        mac: MacAddr,
        f: impl FnOnce(&mut Device) -> Option<DeviceChange>,
    ) -> crate::bus::EventVec {
        let was_in_table = self.devices.contains_key(&mac);
        let mut dev_arc = self
            .devices
            .remove(&mac)
            .unwrap_or_else(|| Arc::new(Device::new(mac)));

        let was_worthy = was_in_table && dev_arc.is_worthy();
        let was_online = dev_arc.is_online();
        let mut events = crate::bus::EventVec::new();

        {
            let dev = Arc::make_mut(&mut dev_arc);
            self.unindex_device(dev);

            if let Some(change) = f(dev) {
                let is_worthy = dev.is_worthy();
                if is_worthy || was_worthy {
                    let hostname = Some(dev.hostname.name.clone());
                    if !was_worthy && is_worthy {
                        events.push(LanforgeEvent::Device(DeviceEvent::Discovered {
                            mac,
                            hostname: hostname.clone(),
                        }));
                    }
                    events.push(LanforgeEvent::Device(DeviceEvent::Updated {
                        mac,
                        change: Box::new(change),
                        hostname,
                    }));
                }
            }

            if dev.is_worthy() {
                self.index_device(mac, dev);
            }
        }

        let is_worthy = dev_arc.is_worthy();
        if is_worthy {
            let now_online = dev_arc.is_online();
            if was_online != now_online {
                let hostname = dev_arc.hostname.name.clone();
                events.push(LanforgeEvent::Device(DeviceEvent::Updated {
                    mac,
                    change: Box::new(DeviceChange::StatusChanged {
                        online: now_online,
                        hostname: Some(hostname.clone()),
                    }),
                    hostname: Some(hostname),
                }));
            }
            self.devices.insert(mac, dev_arc);
        } else if was_worthy {
            // Device was worthy but now isn't. Signal removal from active state and drop it.
            events.push(LanforgeEvent::Device(DeviceEvent::Purged { mac }));
        }

        events
    }

    pub fn find_mac_by_hostname_jit(
        &mut self,
        hostname: &str,
        last_seen_threshold: Option<Duration>,
    ) -> Option<MacAddr> {
        let hostname_lower = hostname.to_ascii_lowercase();
        let now = SystemTime::now();

        let found = self.devices.iter().find(|(_, dev)| {
            if let (Some(threshold), Ok(elapsed)) =
                (last_seen_threshold, now.duration_since(dev.last_seen))
                && elapsed > threshold
            {
                return false;
            }

            dev.hostname.name.to_ascii_lowercase() == hostname_lower
                || dev.dns_fallback == hostname_lower
        });

        if let Some((mac, dev)) = found {
            let mac = *mac;
            let dev = dev.clone();
            let prev_enabled = self.indexing_enabled;
            self.indexing_enabled = true;
            self.index_device(mac, &dev);
            self.indexing_enabled = prev_enabled;
            return Some(mac);
        }

        None
    }
}

#[derive(Debug, Clone, Default)]
pub struct StaticRegistry {
    pub v4: HashMap<Ipv4Addr, MacAddr>,
    pub v6: HashMap<Ipv6AddrOrSuffix, MacAddr>,
}

impl StaticRegistry {
    pub fn v4_ips(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.v4.keys().copied()
    }

    pub fn v6_reservations(&self) -> impl Iterator<Item = Ipv6AddrOrSuffix> + '_ {
        self.v6.keys().copied()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTableStats {
    pub total_devices: usize,
    pub online_devices: usize,
    pub static_entries: usize,
}
