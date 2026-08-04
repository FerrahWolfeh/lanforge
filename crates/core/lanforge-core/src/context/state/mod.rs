//! `State` — Central Lanforge device and interface state.

pub mod cache;
pub mod handlers;
pub mod indices;
#[cfg(test)]
pub mod jit_tests;
pub mod network;
#[cfg(test)]
pub mod tests;

use crate::bus::{AdminChange, DeviceEvent, LanforgeEvent, NetworkChange};
use lanforge_types::device::{
    Device, DeviceClass, DeviceStatus, Ipv6AddrOrSuffix, Origin, TransientHost,
};
use lanforge_types::events::EventVec;
use lanforge_types::identifiers::{Duid, MacAddr};
use lanforge_types::network::DnsReverseResolver;
use lanforge_types::update::{
    CliHostUpdate, DeviceUpdate, FieldUpdate, InterfaceState, LeaseTarget, StaticEntry,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

pub use self::cache::DiscoveryCache;
pub use self::indices::Indices;
pub use self::network::NetworkState;

// ---------------------------------------------------------------------------
// DeviceUpdate Dispatch
// ---------------------------------------------------------------------------

impl State {
    #[allow(clippy::too_many_lines)]
    pub fn apply_update(&mut self, update: DeviceUpdate) -> EventVec {
        match update {
            DeviceUpdate::V4LeaseGranted { mac, ip, expires } => {
                self.handle_v4_lease_granted(mac, ip, expires)
            }
            DeviceUpdate::V6LeaseGranted {
                mac,
                duid,
                iaid,
                ip,
                expires,
            } => self.handle_v6_lease_granted(mac, duid, iaid, ip, expires),
            DeviceUpdate::V6PrefixAssigned {
                mac,
                duid,
                iaid,
                prefix,
                len,
                expires,
            } => self.handle_v6_prefix_assigned(mac, duid, iaid, prefix, len, expires),
            DeviceUpdate::SlaacObserved {
                mac,
                addr,
                is_active,
            } => self.handle_slaac_observed(mac, addr, is_active),
            DeviceUpdate::NdpSeen { mac, ip, is_active } => {
                self.handle_ndp_seen(mac, ip, is_active)
            }
            DeviceUpdate::ArpSeen { mac, ip, is_active } => {
                self.handle_arp_seen(mac, ip, is_active)
            }
            DeviceUpdate::DhcpHostnameHint { mac, hostname } => {
                self.handle_hostname_hint_dhcp(mac, &hostname)
            }
            DeviceUpdate::MdnsHostnameHint { mac, hostname } => {
                self.handle_hostname_hint_mdns(mac, &hostname)
            }
            DeviceUpdate::DuidAssociated { mac, duid, iaid } => {
                self.handle_duid_associated(mac, duid, iaid)
            }
            DeviceUpdate::CliHostUpdated { mac, update } => {
                self.handle_cli_host_updated(mac, update)
            }
            DeviceUpdate::HostRemoved { mac }
            | DeviceUpdate::Remove(mac)
            | DeviceUpdate::Purge(mac) => self.handle_host_removed(mac),
            DeviceUpdate::LeaseReleased { mac, target } => self.handle_lease_released(mac, target),
            DeviceUpdate::IpDeleted { ip } => self.handle_ip_deleted(ip),
            DeviceUpdate::IpOffline { ip } => self.handle_ip_offline(ip),
            DeviceUpdate::InterfaceIpsChanged { ifindex, state } => {
                self.handle_interface_ips_changed(ifindex, &state)
            }
            DeviceUpdate::PruneZombies => self.handle_prune_zombies(),
            DeviceUpdate::RebuildDnsIndices => self.handle_rebuild_dns_indices(),
            DeviceUpdate::ClassHint { mac, class } => self.handle_class_hint(mac, class),
            DeviceUpdate::Reset => self.handle_reset(),
            DeviceUpdate::NeighborBatch { entries } => self.handle_neighbor_batch(entries),
            DeviceUpdate::TransientHostResolved {
                ip,
                hostname,
                origin,
            } => self.handle_transient_host_resolved(ip, hostname, origin),
            DeviceUpdate::AddReverseResolver { resolver } => {
                self.handle_add_reverse_resolver(resolver)
            }
            DeviceUpdate::RemoveReverseResolver { subnet } => {
                self.handle_remove_reverse_resolver(subnet)
            }
            DeviceUpdate::SetReverseResolvers { resolvers } => {
                self.handle_set_reverse_resolvers(resolvers)
            }
            DeviceUpdate::DhcpV4PoolUpdated { .. } => self.handle_dhcp_v4_pool_updated(&update),
            DeviceUpdate::DhcpV6PoolUpdated { .. } => self.handle_dhcp_v6_pool_updated(&update),
            DeviceUpdate::PppoeStatusUpdated { status } => self.handle_pppoe_status_updated(status),
        }
    }
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
    pub interfaces: NetworkState,

    #[serde(skip)]
    pub indexing_enabled: bool,

    #[serde(skip)]
    pub transient_hosts: HashMap<IpAddr, TransientHost>,
    #[serde(skip)]
    pub reverse_resolvers: Vec<DnsReverseResolver>,
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
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn get_by_hostname(&self, hostname: &str) -> Option<Arc<Device>> {
        let mac = if hostname.as_bytes().iter().any(u8::is_ascii_uppercase) {
            self.indices
                .name_index
                .get(&hostname.to_ascii_lowercase())?
        } else {
            self.indices.name_index.get(hostname)?
        };
        self.devices.get(mac).cloned()
    }

    #[must_use]
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
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
        let state = self.interfaces.interface_ips.get(&ifindex)?;
        state
            .gua
            .map(|ip| (ip, state.gua_preferred, state.gua_valid))
    }

    #[must_use]
    pub fn get_interface_ips(&self, ifindex: u32) -> InterfaceState {
        self.interfaces
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

    #[allow(clippy::too_many_arguments)]
    pub fn add_static_device(
        &mut self,
        mac: MacAddr,
        hostname: String,
        duid: Option<Duid>,
        v4_static: Option<Ipv4Addr>,
        v6_suffix: Option<Ipv6AddrOrSuffix>,
        boot_file: Option<String>,
        origin: Origin,
    ) {
        self.apply_update(DeviceUpdate::CliHostUpdated {
            mac,
            update: CliHostUpdate {
                hostname: hostname.into(),
                duid: duid.into(),
                v4_static: v4_static.into(),
                v6_suffix: v6_suffix.into(),
                boot_file: boot_file.into(),
                dns_fallback: FieldUpdate::NoChange,
                class: FieldUpdate::NoChange,
                origin,
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
        f: impl FnOnce(&mut Device) -> Option<NetworkChange>,
    ) -> EventVec {
        let was_in_table = self.devices.contains_key(&mac);
        let mut dev_arc = self
            .devices
            .remove(&mac)
            .unwrap_or_else(|| Arc::new(Device::new(mac)));

        let was_worthy = was_in_table && dev_arc.is_worthy();
        let was_status = dev_arc.status;
        let mut events = EventVec::new();

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
                    if change.is_persistent() {
                        events.push(LanforgeEvent::Device(DeviceEvent::NetworkUpdate {
                            mac,
                            change: Box::new(change),
                            hostname,
                        }));
                    } else {
                        events.push(LanforgeEvent::Device(DeviceEvent::NetworkActivity {
                            mac,
                            change: Box::new(change),
                            hostname,
                        }));
                    }
                }
            }

            dev.status = dev.evaluate_status(SystemTime::now(), None);

            if dev.is_worthy() {
                self.index_device(mac, dev);
            }
        }

        let is_worthy = dev_arc.is_worthy();
        if is_worthy {
            let now_status = dev_arc.status;
            if was_status != now_status {
                let hostname = dev_arc.hostname.name.clone();
                events.push(LanforgeEvent::Device(DeviceEvent::NetworkUpdate {
                    mac,
                    change: Box::new(NetworkChange::StatusChanged {
                        online: now_status == DeviceStatus::Online,
                        status: now_status,
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

    /// Centralized device mutation helper for administrative changes.
    pub(crate) fn mutate_device_admin(
        &mut self,
        mac: MacAddr,
        f: impl FnOnce(&mut Device) -> Option<AdminChange>,
    ) -> EventVec {
        let was_in_table = self.devices.contains_key(&mac);
        let mut dev_arc = self
            .devices
            .remove(&mac)
            .unwrap_or_else(|| Arc::new(Device::new(mac)));

        let was_worthy = was_in_table && dev_arc.is_worthy();
        let was_status = dev_arc.status;
        let mut events = EventVec::new();

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
                    events.push(LanforgeEvent::Device(DeviceEvent::AdminUpdate {
                        mac,
                        change: Box::new(change),
                        hostname,
                    }));
                }
            }

            dev.status = dev.evaluate_status(SystemTime::now(), None);

            if dev.is_worthy() {
                self.index_device(mac, dev);
            }
        }

        let is_worthy = dev_arc.is_worthy();
        if is_worthy {
            let now_status = dev_arc.status;
            if was_status != now_status {
                let hostname = dev_arc.hostname.name.clone();
                events.push(LanforgeEvent::Device(DeviceEvent::NetworkUpdate {
                    mac,
                    change: Box::new(NetworkChange::StatusChanged {
                        online: now_status == DeviceStatus::Online,
                        status: now_status,
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

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn find_mac_by_hostname_jit(
        &mut self,
        hostname: &str,
        last_seen_threshold: Option<Duration>,
    ) -> Option<MacAddr> {
        let now = SystemTime::now();

        let found = self.devices.iter().find(|(_, dev)| {
            if let (Some(threshold), Ok(elapsed)) =
                (last_seen_threshold, now.duration_since(dev.last_seen))
                && elapsed > threshold
            {
                return false;
            }

            dev.hostname.name.eq_ignore_ascii_case(hostname)
                || dev.dns_fallback.eq_ignore_ascii_case(hostname)
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
