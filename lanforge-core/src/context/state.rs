//! `State` — Central Lanforge device and interface state.
//!
//! This module replaces the old `DeviceTable` and is now integrated directly
//! into the `LanforgeContext`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{debug, warn};

use crate::bus::DeviceChange;
use crate::device::{
    Device, Hostname, HostnameOrigin, IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin, V4Lease,
    V6Lease, V6PrefixLease,
};
use crate::identifiers::{Duid, MacAddr};

// ---------------------------------------------------------------------------
// FieldUpdate
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

// ---------------------------------------------------------------------------
// StaticEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StaticEntry {
    pub mac: MacAddr,
    pub hostname: String,
    pub v4_ip: Option<Ipv4Addr>,
    pub v6_suffix: Option<Ipv6AddrOrSuffix>,
}

// ---------------------------------------------------------------------------
// LeaseTarget
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum LeaseTarget {
    V4,
    V6 { iaid: u32 },
    V6Prefix { iaid: u32 },
}

// ---------------------------------------------------------------------------
// InterfaceState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct InterfaceState {
    pub v4: Option<(Ipv4Addr, u8)>,
    pub link_local: Option<Ipv6Addr>,
    pub gua: Option<Ipv6Addr>,
    pub ula: Option<Ipv6Addr>,
    pub gua_preferred: u32,
    pub gua_valid: u32,
}

// ---------------------------------------------------------------------------
// DeviceUpdate
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
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
    SlaacSynced {
        mac: MacAddr,
        addresses: Vec<Ipv6Addr>,
    },
    SlaacObserved {
        mac: MacAddr,
        addr: Ipv6Addr,
    },
    NdpSeen {
        mac: MacAddr,
        ip: Ipv6Addr,
    },
    ArpSeen {
        mac: MacAddr,
        ip: Ipv4Addr,
    },
    DhcpHostnameHint {
        mac: MacAddr,
        hostname: String,
    },
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
        hostname: FieldUpdate<String>,
        v4_static: FieldUpdate<Ipv4Addr>,
        v6_suffix: FieldUpdate<Ipv6AddrOrSuffix>,
        origin: Origin,
    },
    SlaacCleared {
        mac: MacAddr,
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
    InterfaceIpsChanged {
        ifindex: u32,
        state: InterfaceState,
    },
    RebuildDnsIndices,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct State {
    pub devices: HashMap<MacAddr, Arc<Device>>,
    pub duid_index: HashMap<Duid, MacAddr>,
    pub static_entries: HashMap<MacAddr, StaticEntry>,
    pub ndp_cache: HashMap<Ipv6Addr, (MacAddr, SystemTime)>,
    pub orphaned_v6: HashMap<Ipv6Addr, (Duid, u32, SystemTime)>,
    pub interface_ips: HashMap<u32, InterfaceState>,
    pub name_index: HashMap<String, MacAddr>,
    pub ip_index: HashMap<IpAddr, MacAddr>,
}

impl State {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_update(&mut self, update: DeviceUpdate) -> bool {
        let changed = match update {
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
            DeviceUpdate::SlaacSynced { mac, addresses } => {
                self.handle_slaac_synced(mac, addresses)
            }
            DeviceUpdate::SlaacObserved { mac, addr } => self.handle_slaac_observed(mac, addr),
            DeviceUpdate::NdpSeen { mac, ip } => self.handle_ndp_seen(mac, ip),
            DeviceUpdate::ArpSeen { mac, ip } => self.handle_arp_seen(mac, ip),
            DeviceUpdate::DhcpHostnameHint { mac, hostname } => {
                self.handle_hostname_hint(mac, hostname, HostnameOrigin::Dhcp)
            }
            DeviceUpdate::MdnsHostnameHint { mac, hostname } => {
                self.handle_hostname_hint(mac, hostname, HostnameOrigin::Mdns)
            }
            DeviceUpdate::DuidAssociated { mac, duid, iaid } => {
                self.handle_duid_associated(mac, &duid, iaid)
            }
            DeviceUpdate::CliHostUpdated {
                mac,
                hostname,
                v4_static,
                v6_suffix,
                origin,
            } => self.handle_cli_host_updated(mac, hostname, v4_static, v6_suffix, origin),
            DeviceUpdate::SlaacCleared { mac } => self.handle_slaac_cleared(mac),
            DeviceUpdate::HostRemoved { mac } => self.handle_host_removed(mac),
            DeviceUpdate::LeaseReleased { mac, target } => self.handle_lease_released(mac, &target),
            DeviceUpdate::IpDeleted { ip } => self.handle_ip_deleted(ip),
            DeviceUpdate::InterfaceIpsChanged { ifindex, state } => {
                self.handle_interface_ips_changed(ifindex, &state)
            }
            DeviceUpdate::RebuildDnsIndices => {
                self.rebuild_dns_indices();
                true
            }
        };

        if changed {
            self.rebuild_dns_indices();
        }

        changed
    }

    fn handle_v4_lease_granted(&mut self, mac: MacAddr, ip: Ipv4Addr, expires: SystemTime) -> bool {
        let dev_arc = self.get_device_or_new(mac);
        let new_lease = V4Lease { ip, expires };

        let changed = match &dev_arc.v4 {
            IPv4State::Static(s_ip) if *s_ip == ip => false,
            IPv4State::Dynamic(old) if old.ip == ip && old.expires == expires => false,
            _ => true,
        };

        if changed {
            debug!("[state] V4 lease {} → {}", mac, ip);
            let mut dev = (*dev_arc).clone();
            dev.v4 = IPv4State::Dynamic(new_lease);
            dev.last_seen = SystemTime::now();
            self.devices.insert(mac, Arc::new(dev));
            return true;
        }
        false
    }

    fn handle_v6_lease_granted(
        &mut self,
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        ip: Ipv6Addr,
        expires: SystemTime,
    ) -> bool {
        let Some(m) = mac else {
            debug!("[state] V6 lease órfão → {}", ip);
            self.orphaned_v6.insert(ip, (duid, iaid, expires));
            return false;
        };
        self.duid_index.insert(duid.clone(), m);
        let dev_arc = self.get_device_or_new(m);
        let new_lease = V6Lease { ip, iaid, expires };
        let mut already_correct = false;
        for state in &dev_arc.v6 {
            if let IPv6State::Dynamic(old) = state
                && old.iaid == iaid
            {
                if old.ip == ip && old.expires == expires {
                    already_correct = true;
                }
                break;
            }
        }
        if already_correct {
            return false;
        }
        let mut dev = (*dev_arc).clone();
        let mut found = false;
        for state in &mut dev.v6 {
            if let IPv6State::Dynamic(old) = state
                && old.iaid == iaid
            {
                *state = IPv6State::Dynamic(new_lease.clone());
                found = true;
                break;
            }
        }
        if !found {
            dev.v6.push(IPv6State::Dynamic(new_lease));
        }
        dev.duid = Some(duid);
        dev.last_seen = SystemTime::now();
        self.devices.insert(m, Arc::new(dev));
        true
    }

    fn handle_v6_prefix_assigned(
        &mut self,
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        prefix: Ipv6Addr,
        len: u8,
        expires: SystemTime,
    ) -> bool {
        let Some(m) = mac else {
            return false;
        };
        self.duid_index.insert(duid.clone(), m);
        let dev_arc = self.get_device_or_new(m);
        let new_lease = V6PrefixLease {
            prefix,
            len,
            iaid,
            expires,
        };
        let mut already_correct = false;
        for old in &dev_arc.v6_prefixes {
            if old.iaid == iaid {
                if old.prefix == prefix && old.len == len && old.expires == expires {
                    already_correct = true;
                }
                break;
            }
        }
        if already_correct {
            return false;
        }
        let mut dev = (*dev_arc).clone();
        let mut found = false;
        for old in &mut dev.v6_prefixes {
            if old.iaid == iaid {
                *old = new_lease.clone();
                found = true;
                break;
            }
        }
        if !found {
            dev.v6_prefixes.push(new_lease);
        }
        dev.duid = Some(duid);
        dev.last_seen = SystemTime::now();
        self.devices.insert(m, Arc::new(dev));
        true
    }

    fn handle_slaac_synced(&mut self, mac: MacAddr, addresses: Vec<Ipv6Addr>) -> bool {
        let dev_arc = self.get_device_or_new(mac);
        let mut current_slaac: Vec<Ipv6Addr> = dev_arc
            .v6
            .iter()
            .filter_map(|s| match s {
                IPv6State::Slaac(a) => Some(*a),
                _ => None,
            })
            .collect();
        current_slaac.sort();
        let mut new_slaac = addresses;
        new_slaac.sort();
        if current_slaac == new_slaac {
            return false;
        }
        let mut dev = (*dev_arc).clone();
        dev.last_seen = SystemTime::now();
        dev.v6.retain(|s| !matches!(s, IPv6State::Slaac(_)));
        for addr in new_slaac {
            dev.v6.push(IPv6State::Slaac(addr));
            debug!("[state] SLAAC {} synced: {}", mac, addr);
        }
        let exists = self.devices.contains_key(&mac);
        if dev.is_worthy() || exists {
            self.devices.insert(mac, Arc::new(dev));
            return true;
        }
        false
    }

    fn handle_slaac_observed(&mut self, mac: MacAddr, addr: Ipv6Addr) -> bool {
        if let Some(owner_mac) = self.ip_index.get(&std::net::IpAddr::V6(addr)) {
            let owner = self.get_device_or_new(*owner_mac);
            let is_managed = owner.v6.iter().any(|s| match s {
                IPv6State::Dynamic(lease) if lease.ip == addr => true,
                IPv6State::Static(crate::device::Ipv6AddrOrSuffix::Full(ip)) if *ip == addr => true,
                _ => false,
            });
            if is_managed {
                let dev_arc = self.get_device_or_new(mac);
                let mut dev = (*dev_arc).clone();
                dev.last_seen = SystemTime::now();
                self.devices.insert(mac, Arc::new(dev));
                return true;
            }
        }
        let dev_arc = self.get_device_or_new(mac);
        let mut dev = (*dev_arc).clone();
        dev.last_seen = SystemTime::now();
        let exists = self.devices.contains_key(&mac);
        let mut changed = false;
        if !dev
            .v6
            .iter()
            .any(|s| matches!(s, IPv6State::Slaac(a) if *a == addr))
        {
            dev.v6.push(IPv6State::Slaac(addr));
            changed = true;
            debug!("[state] SLAAC {} → {}", mac, addr);
        }
        if dev.is_worthy() || exists {
            self.devices.insert(mac, Arc::new(dev));
            return changed || !exists;
        }
        false
    }

    fn handle_ndp_seen(&mut self, mac: MacAddr, ip: Ipv6Addr) -> bool {
        self.ndp_cache.insert(ip, (mac, SystemTime::now()));
        if let Some((duid, iaid, expires)) = self.orphaned_v6.remove(&ip) {
            self.apply_update(DeviceUpdate::V6LeaseGranted {
                mac: Some(mac),
                duid,
                iaid,
                ip,
                expires,
            });
            return true;
        }

        let dev_arc = self.get_device_or_new(mac);
        let old_seen = dev_arc.last_seen;

        let mut dev = (*dev_arc).clone();
        dev.last_seen = SystemTime::now();

        let exists = self.devices.contains_key(&mac);
        if dev.is_worthy() || exists {
            self.devices.insert(mac, Arc::new(dev.clone()));

            let elapsed = dev.last_seen.duration_since(old_seen).unwrap_or_default();
            // Prune activity logs: only return true (triggering BUS/DB) if it's been a while
            return elapsed.as_secs() > 300;
        }
        false
    }

    fn handle_arp_seen(&mut self, mac: MacAddr, ip: Ipv4Addr) -> bool {
        let dev_arc = self.get_device_or_new(mac);
        let old_seen = dev_arc.last_seen;

        let mut dev = (*dev_arc).clone();
        dev.last_seen = SystemTime::now();

        let is_new_ip = if dev.seen_v4.contains(&ip) {
            false
        } else {
            dev.seen_v4.push(ip);
            true
        };

        let exists = self.devices.contains_key(&mac);
        if dev.is_worthy() || exists {
            self.devices.insert(mac, Arc::new(dev.clone()));

            let elapsed = dev.last_seen.duration_since(old_seen).unwrap_or_default();
            // Prune activity logs: only return true (triggering BUS/DB) if significant
            return is_new_ip || elapsed.as_secs() > 300;
        }
        false
    }

    fn handle_hostname_hint(
        &mut self,
        mac: MacAddr,
        hostname: String,
        origin: HostnameOrigin,
    ) -> bool {
        let dev_arc = self.get_device_or_new(mac);
        if origin >= dev_arc.hostname.origin && dev_arc.hostname.name != hostname {
            let mut dev = (*dev_arc).clone();
            dev.hostname = Hostname {
                name: hostname,
                origin,
            };
            self.devices.insert(mac, Arc::new(dev));
            return true;
        }
        false
    }

    fn handle_duid_associated(&mut self, mac: Option<MacAddr>, duid: &Duid, iaid: u32) -> bool {
        let Some(m) = mac else {
            return false;
        };
        let mut changed = false;
        self.duid_index.insert(duid.clone(), m);
        let dev_arc = self.get_device_or_new(m);
        if dev_arc.duid.as_ref() != Some(duid) {
            let mut dev = (*dev_arc).clone();
            dev.duid = Some(duid.clone());
            if dev.is_worthy() || self.devices.contains_key(&m) {
                self.devices.insert(m, Arc::new(dev));
                changed = true;
            }
        }
        let mut resolved = Vec::new();
        for (&ip, (o_duid, o_iaid, _)) in &self.orphaned_v6 {
            if *o_duid == *duid && *o_iaid == iaid {
                resolved.push(ip);
            }
        }
        for ip in resolved {
            if let Some((duid, iaid, expires)) = self.orphaned_v6.remove(&ip) {
                debug!(
                    "[state] Resolvendo órfão via DuidAssociated: {} -> {}",
                    ip, m
                );
                self.apply_update(DeviceUpdate::V6LeaseGranted {
                    mac: Some(m),
                    duid,
                    iaid,
                    ip,
                    expires,
                });
                changed = true;
            }
        }
        changed
    }

    fn handle_cli_host_updated(
        &mut self,
        mac: MacAddr,
        hostname: FieldUpdate<String>,
        v4_static: FieldUpdate<Ipv4Addr>,
        v6_suffix: FieldUpdate<Ipv6AddrOrSuffix>,
        origin: Origin,
    ) -> bool {
        let dev_arc = self.get_or_insert(mac);
        if dev_arc.origin == Origin::Toml {
            warn!("Tentativa de modificar device estático do TOML: {}", mac);
            return false;
        }
        let mut dev = (*dev_arc).clone();
        let mut changed = false;
        match hostname {
            FieldUpdate::Set(hn) => {
                if dev.hostname.name != hn || dev.hostname.origin != HostnameOrigin::Static {
                    dev.hostname = Hostname {
                        name: hn,
                        origin: HostnameOrigin::Static,
                    };
                    changed = true;
                }
            }
            FieldUpdate::Clear => {
                if !dev.hostname.name.is_empty() {
                    dev.hostname = Hostname::default();
                    changed = true;
                }
            }
            FieldUpdate::NoChange => {}
        }
        match v4_static {
            FieldUpdate::Set(ip) => {
                if dev.v4 != IPv4State::Static(ip) {
                    dev.v4 = IPv4State::Static(ip);
                    changed = true;
                }
            }
            FieldUpdate::Clear => {
                if dev.v4 != IPv4State::None {
                    dev.v4 = IPv4State::None;
                    changed = true;
                }
            }
            FieldUpdate::NoChange => {}
        }
        match v6_suffix {
            FieldUpdate::Set(suf) => {
                let new_state = IPv6State::Static(suf);
                let mut found = false;
                for state in &mut dev.v6 {
                    if matches!(state, IPv6State::Static(_)) {
                        if *state != new_state {
                            *state = new_state.clone();
                            changed = true;
                        }
                        found = true;
                        break;
                    }
                }
                if !found {
                    dev.v6.push(new_state);
                    changed = true;
                }
            }
            FieldUpdate::Clear => {
                let initial_len = dev.v6.len();
                dev.v6.retain(|s| !matches!(s, IPv6State::Static(_)));
                if dev.v6.len() != initial_len {
                    changed = true;
                }
            }
            FieldUpdate::NoChange => {}
        }
        if changed {
            dev.origin = origin;
            dev.managed_at = Some(SystemTime::now());
            dev.last_seen = SystemTime::now();
            self.static_entries.insert(
                mac,
                StaticEntry {
                    mac,
                    hostname: dev.hostname.name.clone(),
                    v4_ip: match dev.v4 {
                        IPv4State::Static(ip) => Some(ip),
                        _ => None,
                    },
                    v6_suffix: dev.v6.iter().find_map(|s| {
                        if let IPv6State::Static(suffix) = s {
                            Some(suffix.clone())
                        } else {
                            None
                        }
                    }),
                },
            );
            self.devices.insert(mac, Arc::new(dev));
        }
        changed
    }

    fn handle_slaac_cleared(&mut self, mac: MacAddr) -> bool {
        if let Some(dev_arc) = self.devices.get(&mac) {
            let mut dev = (**dev_arc).clone();
            let initial_len = dev.v6.len();
            dev.v6.retain(|s| !matches!(s, IPv6State::Slaac(_)));
            if dev.v6.len() != initial_len {
                self.devices.insert(mac, Arc::new(dev));
                return true;
            }
        }
        false
    }

    fn handle_host_removed(&mut self, mac: MacAddr) -> bool {
        let changed_dev = if let Some(dev) = self.devices.remove(&mac) {
            if let Some(duid) = &dev.duid {
                self.duid_index.remove(duid);
            }
            true
        } else {
            false
        };
        let changed_static = self.static_entries.remove(&mac).is_some();
        changed_dev || changed_static
    }

    fn handle_lease_released(&mut self, mac: MacAddr, target: &LeaseTarget) -> bool {
        if let Some(dev_arc) = self.devices.get(&mac) {
            let mut dev = (**dev_arc).clone();
            let mut changed = false;
            match target {
                LeaseTarget::V4 => {
                    if !matches!(dev.v4, IPv4State::None) && !matches!(dev.v4, IPv4State::Static(_))
                    {
                        dev.v4 = IPv4State::None;
                        changed = true;
                    }
                }
                LeaseTarget::V6 { iaid } => {
                    let initial_v6_len = dev.v6.len();
                    dev.v6
                        .retain(|s| !matches!(s, IPv6State::Dynamic(l) if l.iaid == *iaid));
                    changed = dev.v6.len() != initial_v6_len;
                }
                LeaseTarget::V6Prefix { iaid } => {
                    let initial_len = dev.v6_prefixes.len();
                    dev.v6_prefixes.retain(|p| p.iaid != *iaid);
                    changed = dev.v6_prefixes.len() != initial_len;
                }
            }
            if changed {
                self.devices.insert(mac, Arc::new(dev));
                return true;
            }
        }
        false
    }

    fn handle_ip_deleted(&mut self, ip: IpAddr) -> bool {
        let changed_ndp = if let IpAddr::V6(ip6) = ip
            && self.ndp_cache.remove(&ip6).is_some()
        {
            true
        } else {
            false
        };
        let mut changed_devices = false;
        let mut updates = Vec::new();
        for (&mac, dev_arc) in &self.devices {
            let mut dev = (**dev_arc).clone();
            let mut local_changed = false;
            match ip {
                IpAddr::V6(ip6) => {
                    let initial_len = dev.v6.len();
                    dev.v6
                        .retain(|s| !matches!(s, IPv6State::Slaac(a) if *a == ip6));
                    if dev.v6.len() != initial_len {
                        local_changed = true;
                    }
                }
                IpAddr::V4(ip4) => {
                    if let Some(pos) = dev.seen_v4.iter().position(|&x| x == ip4) {
                        dev.seen_v4.remove(pos);
                        local_changed = true;
                    }
                }
            }
            if local_changed {
                updates.push((mac, Arc::new(dev)));
                changed_devices = true;
            }
        }
        for (mac, new_dev) in updates {
            self.devices.insert(mac, new_dev);
        }
        changed_ndp || changed_devices
    }

    fn handle_interface_ips_changed(&mut self, ifindex: u32, state: &InterfaceState) -> bool {
        let entry = self.interface_ips.entry(ifindex).or_default();
        if *entry == *state {
            false
        } else {
            *entry = state.clone();
            debug!(
                "[state] Interface {} IPs updated: V4={:?}, LL={:?}, GUA={:?}, ULA={:?} (pref={}, valid={})",
                ifindex,
                state.v4,
                state.link_local,
                state.gua,
                state.ula,
                state.gua_preferred,
                state.gua_valid
            );
            true
        }
    }

    // -----------------------------------------------------------------------
    // High-Performance DNS Hot-Path Indices
    // -----------------------------------------------------------------------

    /// Rebuilds the O(1) DNS lookup indices from scratch.
    ///
    /// This ensures that no "ghost" Hostnames or IPs remain in the cache after
    /// leases expire or SLAAC addresses rotate.
    pub(crate) fn rebuild_dns_indices(&mut self) {
        self.name_index.clear();
        self.ip_index.clear();

        for (&mac, device) in &self.devices {
            // 1. Index the explicit hostname (always lowercase)
            if !device.hostname.name.is_empty() {
                self.name_index
                    .insert(device.hostname.name.to_ascii_lowercase(), mac);
            }

            // 2. Index the mandatory fallback (host-<mac_no_colons>)
            let fallback =
                format!("host-{}", mac.to_string().replace(':', "")).to_ascii_lowercase();
            self.name_index.insert(fallback, mac);

            // 3. Index IPv4 (Dynamic and Static)
            if let Some(ip) = device.v4.ip() {
                self.ip_index.insert(IpAddr::V4(ip), mac);
            }

            // 4. Index IPv6 (DHCPv6, SLAAC, and Full Static)
            for state in &device.v6 {
                if let Some(ip) = state.ip() {
                    self.ip_index.insert(IpAddr::V6(ip), mac);
                }
            }

            // Note: IPs using static suffixes (e.g., ::1) composed with ULA/GUA
            // are not indexed here yet, as they depend on the runtime prefix.
        }

        self.name_index.shrink_to_fit();
        self.ip_index.shrink_to_fit();

        debug!(
            "[state] DNS indices rebuilt: {} names, {} IPs",
            self.name_index.len(),
            self.ip_index.len()
        );
    }

    pub fn expire_stale(&mut self) -> Vec<(MacAddr, DeviceChange)> {
        let now = SystemTime::now();
        let max_age = Duration::from_secs(7 * 24 * 3600);
        let ndp_max_age = Duration::from_secs(24 * 3600);
        let mut changed = false;
        let mut events = Vec::new();

        self.ndp_cache
            .retain(|_, (_, ts)| ts.elapsed().unwrap_or(Duration::ZERO) <= ndp_max_age);
        self.orphaned_v6.retain(|_, (_, _, expires)| *expires > now);

        let macs: Vec<_> = self.devices.keys().copied().collect();
        for mac in macs {
            if let Some(dev_arc) = self.devices.get(&mac) {
                let v4_expired = if let IPv4State::Dynamic(lease) = &dev_arc.v4 {
                    lease.expires < now
                } else {
                    false
                };
                let v6_expired_iaids: Vec<u32> = dev_arc
                    .v6
                    .iter()
                    .filter_map(|s| match s {
                        IPv6State::Dynamic(lease) if lease.expires < now => Some(lease.iaid),
                        _ => None,
                    })
                    .collect();
                let prefix_expired_iaids: Vec<u32> = dev_arc
                    .v6_prefixes
                    .iter()
                    .filter_map(|p| if p.expires < now { Some(p.iaid) } else { None })
                    .collect();

                if v4_expired || !v6_expired_iaids.is_empty() || !prefix_expired_iaids.is_empty() {
                    let mut dev = (**dev_arc).clone();
                    if v4_expired {
                        dev.v4 = IPv4State::None;
                        events.push((
                            mac,
                            DeviceChange::LeaseExpired {
                                target: LeaseTarget::V4,
                            },
                        ));
                    }
                    for iaid in v6_expired_iaids {
                        dev.v6.retain(|state| !matches!(state, IPv6State::Dynamic(lease) if lease.iaid == iaid));
                        events.push((
                            mac,
                            DeviceChange::LeaseExpired {
                                target: LeaseTarget::V6 { iaid },
                            },
                        ));
                    }
                    for iaid in prefix_expired_iaids {
                        dev.v6_prefixes.retain(|p| p.iaid != iaid);
                        events.push((
                            mac,
                            DeviceChange::LeaseExpired {
                                target: LeaseTarget::V6Prefix { iaid },
                            },
                        ));
                    }
                    self.devices.insert(mac, Arc::new(dev));
                    changed = true;
                }

                if let Some(dev) = self.devices.get(&mac)
                    && !dev.is_static()
                    && matches!(dev.v4, IPv4State::None)
                    && dev.v6.is_empty()
                    && dev.v6_prefixes.is_empty()
                    && dev.last_seen.elapsed().unwrap_or(Duration::ZERO) > max_age
                {
                    if let Some(dev) = self.devices.remove(&mac)
                        && let Some(duid) = &dev.duid
                    {
                        self.duid_index.remove(duid);
                    }
                    events.push((mac, DeviceChange::HostRemoved));
                    changed = true;
                }
            }
        }
        if changed {
            self.rebuild_dns_indices();
        }
        events
    }

    #[must_use]
    pub fn get_device_or_new(&self, mac: MacAddr) -> Arc<Device> {
        self.devices
            .get(&mac)
            .cloned()
            .unwrap_or_else(|| Arc::new(Device::new(mac)))
    }

    pub fn get_or_insert(&mut self, mac: MacAddr) -> Arc<Device> {
        if let Some(dev) = self.devices.get(&mac) {
            return dev.clone();
        }
        let dev = Arc::new(Device::new(mac));
        self.devices.insert(mac, dev.clone());
        dev
    }

    #[must_use]
    pub fn get_device(&self, mac: &MacAddr) -> Option<Arc<Device>> {
        self.devices.get(mac).cloned()
    }

    #[must_use]
    pub fn get_by_hostname(&self, hostname: &str) -> Option<Arc<Device>> {
        self.name_index
            .get(hostname)
            .and_then(|mac| self.devices.get(mac).cloned())
    }

    #[must_use]
    pub fn get_by_ip(&self, ip: &IpAddr) -> Option<Arc<Device>> {
        self.ip_index
            .get(ip)
            .and_then(|mac| self.devices.get(mac).cloned())
    }

    #[must_use]
    pub fn get_mac_by_ip(&self, ip: IpAddr) -> Option<MacAddr> {
        self.ip_index.get(&ip).copied()
    }

    #[must_use]
    pub fn get_by_duid(&self, duid: &Duid) -> Option<Arc<Device>> {
        self.duid_index
            .get(duid)
            .and_then(|mac| self.devices.get(mac).cloned())
    }

    #[must_use]
    pub fn get_interface_ips(&self, ifindex: u32) -> InterfaceState {
        self.interface_ips
            .get(&ifindex)
            .cloned()
            .unwrap_or_default()
    }

    #[must_use]
    pub fn get_interface_gua_at(&self, ifindex: u32) -> Option<(Ipv6Addr, u32, u32)> {
        self.interface_ips
            .get(&ifindex)
            .and_then(|s| s.gua.map(|g| (g, s.gua_preferred, s.gua_valid)))
    }

    #[must_use]
    pub fn is_prefix_delegated(&self, prefix: Ipv6Addr, len: u8) -> bool {
        self.devices.values().any(|dev| {
            dev.v6_prefixes
                .iter()
                .any(|p| p.prefix == prefix && p.len == len)
        })
    }

    pub fn get_static_registry(&self) -> StaticRegistry {
        let mut registry = StaticRegistry::default();
        let mut sorted_entries: Vec<_> = self.static_entries.iter().collect();
        sorted_entries.sort_by_key(|(mac, _)| **mac);
        for (&mac, entry) in sorted_entries {
            if let Some(ip) = entry.v4_ip {
                if let Some(&owner) = registry.v4.get(&ip) {
                    if owner != mac {
                        warn!(
                            "❌ Colisão de IP Estático (v4): {} solicitado por {}, mas já pertence a {}",
                            ip, mac, owner
                        );
                    }
                } else {
                    registry.v4.insert(ip, mac);
                }
            }
            if let Some(v6) = &entry.v6_suffix {
                if let Some(owner) = registry.v6.get(v6) {
                    if *owner != mac {
                        warn!(
                            "❌ Colisão de IP Estático (v6): {} solicitado por {}, mas já pertence a {}",
                            v6, mac, owner
                        );
                    }
                } else {
                    registry.v6.insert(v6.clone(), mac);
                }
            }
        }
        registry
    }

    pub fn add_static_device(
        &mut self,
        mac: MacAddr,
        hostname: String,
        v4_static: Option<Ipv4Addr>,
        v6_suffix: Option<Ipv6AddrOrSuffix>,
    ) -> bool {
        self.apply_update(DeviceUpdate::CliHostUpdated {
            mac,
            hostname: FieldUpdate::Set(hostname),
            v4_static: v4_static.into(),
            v6_suffix: v6_suffix.into(),
            origin: Origin::Cli,
        })
    }

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

    #[must_use]
    pub fn get_duid_by_mac(&self, mac: MacAddr) -> Option<&Duid> {
        self.devices.get(&mac)?.duid.as_ref()
    }

    #[must_use]
    pub fn get_mac_from_ndp_cache(&self, ip: &Ipv6Addr) -> Option<MacAddr> {
        self.ndp_cache.get(ip).map(|(mac, _)| *mac)
    }

    pub fn iter_orphaned_v6(&self) -> impl Iterator<Item = (&Ipv6Addr, &(Duid, u32, SystemTime))> {
        self.orphaned_v6.iter()
    }

    pub fn insert_device(&mut self, mac: MacAddr, device: Device) {
        if let Some(duid) = &device.duid {
            self.duid_index.insert(duid.clone(), mac);
        }
        self.devices.insert(mac, Arc::new(device));
    }

    pub fn add_static_entry(&mut self, mac: MacAddr, entry: StaticEntry) {
        self.static_entries.insert(mac, entry);
    }

    pub fn devices(&self) -> impl Iterator<Item = Arc<Device>> + '_ {
        self.devices.values().cloned()
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
        self.v6.keys().cloned()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTableStats {
    pub total_devices: usize,
    pub online_devices: usize,
    pub static_entries: usize,
}
