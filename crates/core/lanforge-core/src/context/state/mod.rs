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
    Device, DeviceClass, DeviceStatus, IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin,
    TransientHost,
};
use lanforge_types::events::EventVec;
use lanforge_types::identifiers::{Duid, MacAddr};
use lanforge_types::network::DnsReverseResolver;
use lanforge_types::update::{
    CliHostUpdate, DeviceUpdate, FieldUpdate, InterfaceState, LeaseTarget,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

pub use self::cache::DiscoveryStore;
pub use self::indices::Indices;
pub use self::network::NetworkState;

// ---------------------------------------------------------------------------
// DeviceUpdate Dispatch
// ---------------------------------------------------------------------------

impl State {
    pub fn apply_update(&mut self, update: DeviceUpdate, discovery: &DiscoveryStore) -> EventVec {
        match update {
            DeviceUpdate::V4LeaseGranted { .. }
            | DeviceUpdate::V6LeaseGranted(_)
            | DeviceUpdate::V6PrefixAssigned(_)
            | DeviceUpdate::SlaacObserved { .. }
            | DeviceUpdate::LeaseReleased { .. }
            | DeviceUpdate::IpDeleted { .. }
            | DeviceUpdate::IpOffline { .. } => self.apply_addressing_update(update, discovery),

            DeviceUpdate::NdpSeen { .. }
            | DeviceUpdate::ArpSeen { .. }
            | DeviceUpdate::NeighborBatch { .. }
            | DeviceUpdate::DeviceInterfaceSeen { .. } => {
                self.apply_discovery_update(update, discovery)
            }

            DeviceUpdate::DhcpHostnameHint { .. }
            | DeviceUpdate::MdnsHostnameHint { .. }
            | DeviceUpdate::DuidAssociated { .. }
            | DeviceUpdate::CliHostUpdated { .. }
            | DeviceUpdate::IgnoreDnsLogSet { .. }
            | DeviceUpdate::IgnoredLogDomainsSet { .. }
            | DeviceUpdate::ClassHint { .. } => self.apply_host_meta_update(update, discovery),

            _ => self.apply_system_service_update(update, discovery),
        }
    }

    fn apply_addressing_update(
        &mut self,
        update: DeviceUpdate,
        discovery: &DiscoveryStore,
    ) -> EventVec {
        match update {
            DeviceUpdate::V4LeaseGranted { mac, ip, expires } => {
                self.handle_v4_lease_granted(mac, ip, expires)
            }
            DeviceUpdate::V6LeaseGranted(update) => self.handle_v6_lease_granted(
                update.mac,
                update.duid,
                update.iaid,
                update.ip,
                update.expires,
                discovery,
            ),
            DeviceUpdate::V6PrefixAssigned(update) => self.handle_v6_prefix_assigned(
                update.mac,
                update.duid,
                update.iaid,
                update.prefix,
                update.len,
                update.expires,
            ),
            DeviceUpdate::SlaacObserved {
                mac,
                addr,
                is_active,
            } => self.handle_slaac_observed(mac, addr, is_active),
            DeviceUpdate::LeaseReleased { mac, target } => self.handle_lease_released(mac, target),
            DeviceUpdate::IpDeleted { ip } => self.handle_ip_deleted(ip, discovery),
            DeviceUpdate::IpOffline { ip } => self.handle_ip_offline(ip),
            _ => unreachable!(),
        }
    }

    fn apply_discovery_update(
        &mut self,
        update: DeviceUpdate,
        discovery: &DiscoveryStore,
    ) -> EventVec {
        match update {
            DeviceUpdate::NdpSeen { mac, ip, is_active } => {
                self.handle_ndp_seen(mac, ip, is_active, discovery)
            }
            DeviceUpdate::ArpSeen { mac, ip, is_active } => {
                self.handle_arp_seen(mac, ip, is_active)
            }
            DeviceUpdate::NeighborBatch { entries } => {
                self.handle_neighbor_batch(entries, discovery)
            }
            DeviceUpdate::DeviceInterfaceSeen { mac, iface } => {
                self.handle_device_interface_seen(mac, iface)
            }
            _ => unreachable!(),
        }
    }

    fn apply_host_meta_update(
        &mut self,
        update: DeviceUpdate,
        discovery: &DiscoveryStore,
    ) -> EventVec {
        match update {
            DeviceUpdate::DhcpHostnameHint { mac, hostname } => {
                self.handle_hostname_hint_dhcp(mac, &hostname)
            }
            DeviceUpdate::MdnsHostnameHint { mac, hostname } => {
                self.handle_hostname_hint_mdns(mac, &hostname)
            }
            DeviceUpdate::DuidAssociated { mac, duid, iaid } => {
                self.handle_duid_associated(mac, duid, iaid, discovery)
            }
            DeviceUpdate::CliHostUpdated { mac, update } => {
                self.handle_cli_host_updated(mac, *update)
            }
            DeviceUpdate::IgnoreDnsLogSet { mac, ignore } => {
                self.handle_ignore_dns_log_set(mac, ignore)
            }
            DeviceUpdate::IgnoredLogDomainsSet { mac, domains } => {
                self.handle_ignored_log_domains_set(mac, domains)
            }
            DeviceUpdate::ClassHint { mac, class } => self.handle_class_hint(mac, class),
            _ => unreachable!(),
        }
    }

    fn apply_system_service_update(
        &mut self,
        update: DeviceUpdate,
        discovery: &DiscoveryStore,
    ) -> EventVec {
        match update {
            DeviceUpdate::HostRemoved { mac } => self.handle_host_removed(mac),
            DeviceUpdate::InterfaceIpsChanged { ifindex, state } => {
                self.handle_interface_ips_changed(ifindex, &state)
            }
            DeviceUpdate::PruneZombies => self.handle_prune_zombies(discovery),
            DeviceUpdate::RebuildDnsIndices => self.handle_rebuild_dns_indices(),
            DeviceUpdate::Reset => self.handle_reset(discovery),
            DeviceUpdate::TransientHostResolved(update) => {
                self.handle_transient_host_resolved(update.ip, update.hostname, update.origin)
            }
            DeviceUpdate::AddReverseResolver { resolver } => {
                self.handle_add_reverse_resolver(*resolver)
            }
            DeviceUpdate::RemoveReverseResolver { subnet } => {
                self.handle_remove_reverse_resolver(subnet)
            }
            DeviceUpdate::SetReverseResolvers { resolvers } => {
                self.handle_set_reverse_resolvers(resolvers)
            }
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    pub devices: HashMap<MacAddr, Arc<Device>>,
    pub indices: Indices,
    pub interfaces: NetworkState,

    #[serde(skip)]
    pub indexing_enabled: bool,

    #[serde(skip)]
    pub transient_hosts: HashMap<IpAddr, TransientHost>,
    #[serde(skip)]
    pub reverse_resolvers: Vec<DnsReverseResolver>,
    #[serde(skip)]
    pub static_registry: Arc<StaticRegistry>,
}

impl State {
    #[must_use]
    pub fn new() -> Self {
        Self {
            indexing_enabled: true,
            ..Default::default()
        }
    }

    #[must_use]
    pub fn active_ula_prefix(&self) -> Option<Ipv6Addr> {
        self.interfaces
            .interface_ips
            .values()
            .find_map(|i| i.ula)
            .or(self.interfaces.ra_ula_fallback)
    }

    #[must_use]
    pub fn active_gua_prefix(&self) -> Option<Ipv6Addr> {
        self.interfaces
            .interface_ips
            .values()
            .find_map(|i| i.gua)
            .or(self.interfaces.ra_gua_fallback)
    }

    pub fn index_device(&mut self, mac: MacAddr, dev: &Device) {
        if self.indexing_enabled || dev.is_static() {
            self.indices.index_device(mac, dev);
            let ula_prefix = self.active_ula_prefix();
            let gua_prefix = self.active_gua_prefix();

            for state in &dev.v6 {
                if let IPv6State::Static(Ipv6AddrOrSuffix::Suffix(suf), _) = state {
                    for prefix in [ula_prefix, gua_prefix].into_iter().flatten() {
                        let full_ip = suf.resolve(prefix);
                        self.indices.ip_index.insert(IpAddr::V6(full_ip), mac);
                    }
                }
            }
        }
    }

    pub fn unindex_device(&mut self, dev: &Device) {
        self.indices.unindex_device(dev);
        let ula_prefix = self.active_ula_prefix();
        let gua_prefix = self.active_gua_prefix();

        for state in &dev.v6 {
            if let IPv6State::Static(Ipv6AddrOrSuffix::Suffix(suf), _) = state {
                for prefix in [ula_prefix, gua_prefix].into_iter().flatten() {
                    let full_ip = suf.resolve(prefix);
                    self.indices.ip_index.remove(&IpAddr::V6(full_ip));
                }
            }
        }
    }

    // --- Getters ---

    #[must_use]
    pub fn get_device(&self, mac: &MacAddr) -> Option<Arc<Device>> {
        self.devices.get(mac).cloned()
    }

    #[must_use]
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn get_by_hostname(&self, hostname: &str) -> Option<Arc<Device>> {
        let bytes = hostname.as_bytes();
        let mac = if bytes.iter().any(u8::is_ascii_uppercase) {
            if bytes.len() <= 256 {
                let mut buf = [0u8; 256];
                for (dst, &src) in buf[..bytes.len()].iter_mut().zip(bytes) {
                    *dst = src.to_ascii_lowercase();
                }
                // SAFETY: `hostname` é UTF-8 válido e `to_ascii_lowercase` preserva UTF-8 válido.
                let lower = std::str::from_utf8(&buf[..bytes.len()]).ok()?;
                self.indices.name_index.get(lower)?
            } else {
                self.indices
                    .name_index
                    .get(&hostname.to_ascii_lowercase())?
            }
        } else {
            self.indices.name_index.get(hostname)?
        };
        self.devices.get(mac).cloned()
    }

    #[must_use]
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn get_by_ip(&self, ip: &IpAddr) -> Option<Arc<Device>> {
        let mac = self.get_mac_by_ip(*ip)?;
        self.devices.get(&mac).cloned()
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
        let canonical = ip.to_canonical();
        if let Some(mac) = self.indices.ip_index.get(&canonical).copied() {
            return Some(mac);
        }

        match canonical {
            IpAddr::V4(v4) => {
                if let Some(mac) = self.static_registry.v4.get(&v4) {
                    return Some(*mac);
                }
            }
            IpAddr::V6(v6) => {
                // 1. Check static entries (v6_suffix)
                for (suf, mac) in &self.static_registry.v6 {
                    if suf.matches(v6) {
                        return Some(*mac);
                    }
                }

                // 3. Check devices' v6 states
                for dev in self.devices.values() {
                    for state in &dev.v6 {
                        match state {
                            IPv6State::Static(suf, _) => {
                                if suf.matches(v6) {
                                    return Some(dev.mac);
                                }
                            }
                            IPv6State::Slaac(addr, _)
                            | IPv6State::LinkLocal(addr, _)
                            | IPv6State::Discovery(addr, _) => {
                                if *addr == v6 {
                                    return Some(dev.mac);
                                }
                            }
                            IPv6State::Dynamic(lease) => {
                                if lease.ip == v6 {
                                    return Some(dev.mac);
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    pub fn rebuild_static_registry(&mut self) {
        let mut registry = StaticRegistry::default();
        let mut static_devs: Vec<_> = self
            .devices
            .values()
            .filter(|d| d.is_static())
            .collect();
        static_devs.sort_by_key(|d| d.mac);

        for dev in static_devs {
            if let IPv4State::Static(v4) = dev.v4 {
                registry.v4.entry(v4).or_insert(dev.mac);
            }
            for state in &dev.v6 {
                if let IPv6State::Static(suf, _) = state {
                    registry.v6.entry(*suf).or_insert(dev.mac);
                }
            }
        }
        self.static_registry = Arc::new(registry);
    }

    #[must_use]
    pub fn get_static_registry(&self) -> Arc<StaticRegistry> {
        self.static_registry.clone()
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
    pub fn get_duid_by_mac(&self, mac: MacAddr) -> Option<&Duid> {
        self.devices.get(&mac).and_then(|d| d.duid.as_ref())
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
        self.handle_cli_host_updated(
            mac,
            CliHostUpdate {
                hostname: hostname.into(),
                duid: duid.into(),
                v4_static: v4_static.into(),
                v6_suffix: v6_suffix.into(),
                boot_file: boot_file.into(),
                dns_fallback: FieldUpdate::NoChange,
                class: FieldUpdate::NoChange,
                origin,
            },
        );
    }

    pub fn insert_device(&mut self, mac: MacAddr, dev: Device) {
        let dev = Arc::new(dev);
        self.unindex_device(&dev);
        self.index_device(mac, &dev);
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
        let ula_prefix = self.active_ula_prefix();
        let gua_prefix = self.active_gua_prefix();
        for (mac, dev) in &self.devices {
            self.indices.index_device(*mac, dev);
            for state in &dev.v6 {
                if let IPv6State::Static(Ipv6AddrOrSuffix::Suffix(suf), _) = state {
                    for prefix in [ula_prefix, gua_prefix].into_iter().flatten() {
                        let full_ip = suf.resolve(prefix);
                        self.indices.ip_index.insert(IpAddr::V6(full_ip), *mac);
                    }
                }
            }
        }
    }

    pub fn devices(&self) -> impl Iterator<Item = Arc<Device>> + '_ {
        self.devices.values().cloned()
    }

    /// Internal helper to mutate a device and map its change into a `DeviceEvent`.
    fn mutate_device_with<C>(
        &mut self,
        mac: MacAddr,
        f: impl FnOnce(&mut Device) -> Option<C>,
        make_event: impl FnOnce(MacAddr, C, Option<String>) -> DeviceEvent,
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
                    events.push(LanforgeEvent::Device(make_event(mac, change, hostname)));
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
            events.push(LanforgeEvent::Device(DeviceEvent::Purged { mac }));
        }

        events
    }

    /// Centralized device mutation helper for network changes.
    pub(crate) fn mutate_device(
        &mut self,
        mac: MacAddr,
        f: impl FnOnce(&mut Device) -> Option<NetworkChange>,
    ) -> EventVec {
        self.mutate_device_with(mac, f, |mac, change, hostname| {
            if change.is_persistent() {
                DeviceEvent::NetworkUpdate {
                    mac,
                    change: Box::new(change),
                    hostname,
                }
            } else {
                DeviceEvent::NetworkActivity {
                    mac,
                    change: Box::new(change),
                    hostname,
                }
            }
        })
    }

    /// Centralized device mutation helper for administrative changes.
    pub(crate) fn mutate_device_admin(
        &mut self,
        mac: MacAddr,
        f: impl FnOnce(&mut Device) -> Option<AdminChange>,
    ) -> EventVec {
        self.mutate_device_with(mac, f, |mac, change, hostname| DeviceEvent::AdminUpdate {
            mac,
            change: Box::new(change),
            hostname,
        })
    }

    pub fn promote_device_to_index(&mut self, mac: MacAddr) {
        if let Some(dev) = self.devices.get(&mac).cloned() {
            let prev_enabled = self.indexing_enabled;
            self.indexing_enabled = true;
            self.index_device(mac, &dev);
            self.indexing_enabled = prev_enabled;
        }
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn find_mac_by_hostname_jit(
        &mut self,
        hostname: &str,
        last_seen_threshold: Option<Duration>,
    ) -> Option<MacAddr> {
        let now = SystemTime::now();

        let found_mac = self.devices.iter().find_map(|(mac, dev)| {
            if let (Some(threshold), Ok(elapsed)) =
                (last_seen_threshold, now.duration_since(dev.last_seen))
                && elapsed > threshold
            {
                return None;
            }

            if dev.hostname.name.eq_ignore_ascii_case(hostname)
                || dev.dns_fallback.eq_ignore_ascii_case(hostname)
            {
                Some(*mac)
            } else {
                None
            }
        });

        found_mac.inspect(|&mac| {
            self.promote_device_to_index(mac);
        })
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
