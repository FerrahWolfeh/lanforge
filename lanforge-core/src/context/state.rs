//! `State` — Central Lanforge device and interface state.
//!
//! This module contains the core state storage and mutation logic for all
//! discovered network devices and network interfaces.
//!
//! # Key Types
//!
//! | Type                | Description                                  |
//! |---------------------|----------------------------------------------|
//! | [`State`]           | Central device and interface state storage   |
//! | [`DeviceUpdate`]    | All possible state mutation commands         |
//! | [`FieldUpdate<T>`]  | Optional change specification (Set/Clear/NoChange) |
//! | [`StaticEntry`]     | Manual device reservation record             |
//! | [`LeaseTarget`]     | Identifies a specific lease type             |
//! | [`InterfaceState`]  | Network interface IP configuration           |
//! | [`StaticRegistry`]  | Validated static entry registry with collision detection |
//!
//! # State Structure
//!
//! The `State` struct contains:
//!
//! | Field              | Type                              | Description                    |
//! |--------------------|-----------------------------------|--------------------------------|
//! | `devices`          | `HashMap<MacAddr, Arc<Device>>`  | Main device table             |
//! | `duid_index`       | `HashMap<Duid, MacAddr>`         | DUID → MAC lookup             |
//! | `static_entries`   | `HashMap<MacAddr, StaticEntry>`   | Manual reservations           |
//! | `ndp_cache`        | `HashMap<Ipv6Addr, (MacAddr, Time)>` | NDP neighbor cache        |
//! | `orphaned_v6`      | `HashMap<Ipv6Addr, (Duid, IAID, Time)>` | Unresolved IPv6 leases |
//! | `interface_ips`    | `HashMap<u32, InterfaceState>`    | Interface IP configurations   |
//! | `name_index`       | `HashMap<String, MacAddr>`        | Hostname → MAC lookup         |
//! | `ip_index`         | `HashMap<IpAddr, MacAddr>`        | IP → MAC lookup (DNS hot path)|
//!
//! # Update Flow
//!
//! All state mutations go through [`State::apply_update`], which dispatches
//! to specific handlers based on the [`DeviceUpdate`] variant.
//!
//! # Example
//!
//! ```rust
//! use lanforge_core::context::state::{State, DeviceUpdate};
//! use lanforge_core::identifiers::MacAddr;
//! use std::time::{Duration, SystemTime};
//!
//! let mut state = State::new();
//! let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
//!
//! let update = DeviceUpdate::V4LeaseGranted {
//!     mac,
//!     ip: "192.168.1.10".parse().unwrap(),
//!     expires: SystemTime::now() + Duration::from_secs(3600),
//! };
//!
//! let changed = state.apply_update(update);
//! assert!(changed);
//! ```

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

/// Represents an optional field modification in a [`DeviceUpdate::CliHostUpdated`].
///
/// This enum allows partial updates — you can change one field without
/// affecting others.
///
/// # Variants
///
/// | Variant    | Behavior                        |
/// |------------|---------------------------------|
/// | `NoChange` | Leave the field as-is           |
/// | `Clear`    | Remove/reset the field          |
/// | `Set(T)`   | Replace with a new value        |
///
/// # Example
///
/// ```rust
/// use lanforge_core::state::FieldUpdate;
///
/// let update: FieldUpdate<String> = FieldUpdate::Set("new-hostname".to_string());
/// assert!(matches!(update, FieldUpdate::Set(_)));
///
/// // From Option
/// let from_some: FieldUpdate<i32> = Some(42).into();
/// let from_none: FieldUpdate<i32> = None.into();
/// assert!(matches!(from_some, FieldUpdate::Set(42)));
/// assert!(matches!(from_none, FieldUpdate::Clear));
/// ```
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

/// A manual device reservation stored in the state.
///
/// Created when a device is configured via CLI or TOML.
/// Tracks the relationship between MAC, hostname, and static IPs.
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

/// Identifies which type of lease to operate on.
///
/// Used by `LeaseReleased` and `LeaseExpired` events to specify
/// the target lease type (`IPv4`, `IPv6 IA_NA`, or `IPv6 IA_PD`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub enum LeaseTarget {
    /// `DHCPv4` lease.
    V4,
    /// `DHCPv6` `IA_NA` (Non-temporary Address) lease.
    V6 { iaid: u32 },
    /// `DHCPv6` `IA_PD` (Prefix Delegation) lease.
    V6Prefix { iaid: u32 },
}

// ---------------------------------------------------------------------------
// InterfaceState
// ---------------------------------------------------------------------------

/// Represents the IP configuration of a network interface.
///
/// Tracked by interface index (ifindex). The GUA and ULA prefixes
/// extracted from this state are used for SLAAC detection and
/// address resolution.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct InterfaceState {
    /// IPv4 address and prefix length.
    pub v4: Option<(Ipv4Addr, u8)>,
    /// Link-local IPv6 address (`fe80::/10`).
    pub link_local: Option<Ipv6Addr>,
    /// Global Unicast Address prefix (`2000::/3`).
    pub gua: Option<Ipv6Addr>,
    /// Unique Local Address prefix (`fc00::/7`).
    pub ula: Option<Ipv6Addr>,
    /// GUA preferred lifetime in seconds.
    pub gua_preferred: u32,
    /// GUA valid lifetime in seconds.
    pub gua_valid: u32,
}

// ---------------------------------------------------------------------------
// DeviceUpdate
// ---------------------------------------------------------------------------

/// A state mutation command for the device table.
///
/// This enum represents all possible ways to modify device and interface state.
/// Submit via [`LanforgeContext::apply`](crate::context::LanforgeContext::apply)
/// to apply changes and trigger event broadcasting.
///
/// # Categories
///
/// ## Lease Management
/// | Variant              | Description                           |
/// |----------------------|---------------------------------------|
/// | `V4LeaseGranted`     | Assign/renew a `DHCPv4` lease           |
/// | `V6LeaseGranted`     | Assign/renew a `DHCPv6` `IA_NA` lease     |
/// | `V6PrefixAssigned`   | Delegate a `DHCPv6` `IA_PD` prefix        |
/// | `LeaseReleased`      | Manually release a lease              |
///
/// ## Neighbor Discovery
/// | Variant              | Description                           |
/// |----------------------|---------------------------------------|
/// | `NdpSeen`            | IPv6 neighbor observed via NDP        |
/// | `ArpSeen`            | IPv4 neighbor observed via ARP        |
/// | `SlaacObserved`      | SLAAC address observed                |
/// | `SlaacSynced`        | Full SLAAC address synchronization    |
/// | `SlaacCleared`       | Clear all SLAAC addresses             |
///
/// ## Hostname
/// | Variant              | Description                           |
/// |----------------------|---------------------------------------|
/// | `DhcpHostnameHint`   | Hostname from DHCP Option 12          |
/// | `MdnsHostnameHint`   | Hostname from mDNS                    |
///
/// ## DUID
/// | Variant              | Description                           |
/// |----------------------|---------------------------------------|
/// | `DuidAssociated`     | Link a DUID to a MAC address          |
///
/// ## CLI/Manual
/// | Variant              | Description                           |
/// |----------------------|---------------------------------------|
/// | `CliHostUpdated`     | Add/update a static device entry      |
/// | `HostRemoved`        | Explicitly remove a device            |
///
/// ## IP Management
/// | Variant              | Description                           |
/// |----------------------|---------------------------------------|
/// | `IpDeleted`          | Remove a specific IP from state       |
/// | `IpOffline`          | Mark an IP as unreachable (`NUD_FAILED`)|
///
/// ## Interface
/// | Variant              | Description                           |
/// |----------------------|---------------------------------------|
/// | `InterfaceIpsChanged`| Update interface IP configuration     |
///
/// ## Maintenance
/// | Variant              | Description                           |
/// |----------------------|---------------------------------------|
/// | `PruneZombies`       | Remove unworthy dynamic devices       |
/// | `RebuildDnsIndices`  | Rebuild O(1) DNS lookup caches        |
#[derive(Debug, Clone)]
pub enum DeviceUpdate {
    /// Assign or renew a `DHCPv4` lease for a device.
    V4LeaseGranted {
        mac: MacAddr,
        ip: Ipv4Addr,
        expires: SystemTime,
    },
    /// Assign or renew a `DHCPv6` `IA_NA` lease for a device.
    /// MAC is optional — the DUID can be used to resolve it later.
    V6LeaseGranted {
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        ip: Ipv6Addr,
        expires: SystemTime,
    },
    /// Delegate an IPv6 prefix via `DHCPv6` `IA_PD`.
    V6PrefixAssigned {
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        prefix: Ipv6Addr,
        len: u8,
        expires: SystemTime,
    },
    /// Perform a full SLAAC address synchronization for a device.
    /// Replaces all existing SLAAC addresses with the provided list.
    SlaacSynced {
        mac: MacAddr,
        addresses: Vec<Ipv6Addr>,
    },
    /// Record a single SLAAC address observation.
    SlaacObserved { mac: MacAddr, addr: Ipv6Addr },
    /// Record an IPv6 neighbor observation via NDP.
    NdpSeen { mac: MacAddr, ip: Ipv6Addr },
    /// Record an IPv4 neighbor observation via ARP.
    ArpSeen { mac: MacAddr, ip: Ipv4Addr },
    /// Update a device's hostname based on a DHCP hint.
    DhcpHostnameHint { mac: MacAddr, hostname: String },
    /// Update a device's hostname based on an mDNS hint.
    MdnsHostnameHint { mac: MacAddr, hostname: String },
    /// Link a DUID to a MAC address for `DHCPv6` correlation.
    DuidAssociated {
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
    },
    /// Add or update a static device entry from the CLI.
    CliHostUpdated {
        mac: MacAddr,
        hostname: FieldUpdate<String>,
        v4_static: FieldUpdate<Ipv4Addr>,
        v6_suffix: FieldUpdate<Ipv6AddrOrSuffix>,
        origin: Origin,
    },
    /// Clear all SLAAC addresses for a device.
    SlaacCleared { mac: MacAddr },
    /// Explicitly remove a device from the table.
    HostRemoved { mac: MacAddr },
    /// Release a specific lease (`V4`, `V6`, or `V6Prefix`).
    LeaseReleased { mac: MacAddr, target: LeaseTarget },
    /// Remove a specific IP address from device state.
    IpDeleted { ip: IpAddr },
    /// Mark a device as unreachable via a specific IP.
    IpOffline { ip: IpAddr },
    /// Update the IP configuration of a network interface.
    InterfaceIpsChanged { ifindex: u32, state: InterfaceState },
    /// Trigger pruning of unworthy dynamic devices (zombie cleanup).
    PruneZombies,
    /// Trigger a full rebuild of the DNS lookup indices.
    RebuildDnsIndices,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Central Lanforge device and interface state storage.
///
/// This is the primary data structure holding all device information.
/// It is designed to be protected by a `parking_lot::RwLock` for concurrent access.
///
/// # Tables
///
/// | Table              | Key               | Value                    | Purpose                      |
/// |--------------------|-------------------|--------------------------|------------------------------|
/// | `devices`          | MAC address       | `Arc<Device>`            | Main device records          |
/// | `duid_index`       | DUID              | MAC address              | DUID → MAC resolution        |
/// | `static_entries`   | MAC address       | `StaticEntry`            | Manual reservations          |
/// | `ndp_cache`        | IPv6 address      | (MAC, timestamp)         | NDP neighbor observations    |
/// | `orphaned_v6`      | IPv6 address      | (DUID, IAID, expiry)     | Unresolved IPv6 leases       |
/// | `interface_ips`    | ifindex (u32)     | `InterfaceState`         | Interface configurations     |
/// | `name_index`       | hostname (lower)  | MAC address              | DNS hot-path: name → MAC     |
/// | `ip_index`         | IP address        | MAC address              | DNS hot-path: IP → MAC       |
///
/// # Performance
///
/// - DNS lookups (`name_index`, `ip_index`) are O(1) and rebuilt on demand
/// - Device lookups by MAC, IP, hostname, or DUID are all O(1)
/// - Updates unindex/reindex the affected device to maintain consistency
///
/// # Example
///
/// ```rust
/// use lanforge_core::context::state::State;
///
/// let mut state = State::new();
/// assert_eq!(state.devices.len(), 0);
/// assert_eq!(state.devices.len(), state.stats().total_devices);
/// ```
#[derive(Debug, Clone, Default)]
pub struct State {
    /// Main device table: MAC → Device.
    pub devices: HashMap<MacAddr, Arc<Device>>,
    /// DUID to MAC index for `DHCPv6` correlation.
    pub duid_index: HashMap<Duid, MacAddr>,
    /// Manual device reservations from CLI/TOML.
    pub static_entries: HashMap<MacAddr, StaticEntry>,
    /// NDP (Neighbor Discovery Protocol) cache for IPv6 link-local observations.
    pub ndp_cache: HashMap<Ipv6Addr, (MacAddr, SystemTime)>,
    /// IPv6 leases that haven't been resolved to a MAC yet (waiting for DUID association).
    pub orphaned_v6: HashMap<Ipv6Addr, (Duid, u32, SystemTime)>,
    /// Network interface IP configurations indexed by ifindex.
    pub interface_ips: HashMap<u32, InterfaceState>,
    /// DNS hot-path: hostname (lowercase) → MAC.
    pub name_index: HashMap<String, MacAddr>,
    /// DNS hot-path: IP address → MAC.
    pub ip_index: HashMap<IpAddr, MacAddr>,
}

impl State {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_update(&mut self, update: DeviceUpdate) -> bool {
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
            DeviceUpdate::IpOffline { ip } => self.handle_ip_offline(ip),
            DeviceUpdate::InterfaceIpsChanged { ifindex, state } => {
                self.handle_interface_ips_changed(ifindex, &state)
            }
            DeviceUpdate::PruneZombies => self.handle_prune_zombies(),
            DeviceUpdate::RebuildDnsIndices => {
                self.rebuild_dns_indices();
                true
            }
        }
    }

    fn handle_v4_lease_granted(&mut self, mac: MacAddr, ip: Ipv4Addr, expires: SystemTime) -> bool {
        let exists = self.devices.contains_key(&mac);
        let dev_arc = self.get_or_insert(mac);

        let changed = match &dev_arc.v4 {
            IPv4State::Static(s_ip) if *s_ip == ip => false,
            IPv4State::Dynamic(old) if old.ip == ip && old.expires == expires => false,
            _ => true,
        };

        if changed {
            debug!("[state] V4 lease {} → {}", mac, ip);
            // Temporarily remove to avoid borrow issues while indexing
            let mut dev_arc = self.devices.remove(&mac).unwrap();
            self.unindex_device(&dev_arc);
            {
                let dev = Arc::make_mut(&mut dev_arc);
                dev.v4 = IPv4State::Dynamic(V4Lease { ip, expires });
                dev.last_seen = SystemTime::now();
            }
            self.index_device(mac, &dev_arc);
            self.devices.insert(mac, dev_arc);
            return true;
        }
        !exists
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
        let exists = self.devices.contains_key(&m);
        let dev_arc = self.get_or_insert(m);

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
            return !exists;
        }

        let mut dev_arc = self.devices.remove(&m).unwrap();
        self.unindex_device(&dev_arc);
        {
            let dev = Arc::make_mut(&mut dev_arc);
            let mut found = false;
            for state in &mut dev.v6 {
                if let IPv6State::Dynamic(old) = state
                    && old.iaid == iaid
                {
                    *state = IPv6State::Dynamic(V6Lease { ip, iaid, expires });
                    found = true;
                    break;
                }
            }
            if !found {
                dev.v6
                    .push(IPv6State::Dynamic(V6Lease { ip, iaid, expires }));
            }
            dev.duid = Some(duid);
            dev.last_seen = SystemTime::now();
        }
        self.index_device(m, &dev_arc);
        self.devices.insert(m, dev_arc);
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
        let exists = self.devices.contains_key(&m);
        let dev_arc = self.get_or_insert(m);

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
            return !exists;
        }

        let mut dev_arc = self.devices.remove(&m).unwrap();
        {
            let dev = Arc::make_mut(&mut dev_arc);
            let mut found = false;
            for old in &mut dev.v6_prefixes {
                if old.iaid == iaid {
                    *old = V6PrefixLease {
                        prefix,
                        len,
                        iaid,
                        expires,
                    };
                    found = true;
                    break;
                }
            }
            if !found {
                dev.v6_prefixes.push(V6PrefixLease {
                    prefix,
                    len,
                    iaid,
                    expires,
                });
            }
            dev.duid = Some(duid);
            dev.last_seen = SystemTime::now();
        }
        self.devices.insert(m, dev_arc);
        true
    }

    fn handle_slaac_synced(&mut self, mac: MacAddr, addresses: Vec<Ipv6Addr>) -> bool {
        let exists = self.devices.contains_key(&mac);
        let dev_arc = self.get_or_insert(mac);

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
            return !exists;
        }

        let mut dev_arc = self.devices.remove(&mac).unwrap();
        self.unindex_device(&dev_arc);
        {
            let dev = Arc::make_mut(&mut dev_arc);
            dev.last_seen = SystemTime::now();
            dev.v6.retain(|s| !matches!(s, IPv6State::Slaac(_)));
            for addr in new_slaac {
                dev.v6.push(IPv6State::Slaac(addr));
                debug!("[state] SLAAC {} synced: {}", mac, addr);
            }
        }

        if !dev_arc.is_worthy() && !exists {
            // Not inserted back
            return false;
        }

        self.index_device(mac, &dev_arc);
        self.devices.insert(mac, dev_arc);
        true
    }

    fn handle_slaac_observed(&mut self, mac: MacAddr, addr: Ipv6Addr) -> bool {
        if let Some(&indexed_mac) = self.ip_index.get(&IpAddr::V6(addr))
            && indexed_mac == mac
        {
            if let Some(dev_arc) = self.devices.get_mut(&mac) {
                let dev = Arc::make_mut(dev_arc);
                dev.last_seen = SystemTime::now();
            }
            return false;
        }
        // ... else continue to normal check ...

        let exists = self.devices.contains_key(&mac);
        let dev_arc = self.get_or_insert(mac);

        let already_has = dev_arc
            .v6
            .iter()
            .any(|s| matches!(s, IPv6State::Slaac(a) if *a == addr));

        if already_has {
            let dev_arc_mut = self.devices.get_mut(&mac).unwrap();
            let dev = Arc::make_mut(dev_arc_mut);
            dev.last_seen = SystemTime::now();
            return !exists;
        }

        let mut dev_arc = self.devices.remove(&mac).unwrap();
        self.unindex_device(&dev_arc);
        {
            let dev = Arc::make_mut(&mut dev_arc);
            dev.last_seen = SystemTime::now();
            dev.v6.push(IPv6State::Slaac(addr));
            debug!("[state] SLAAC {} → {}", mac, addr);
        }

        if !dev_arc.is_worthy() && !exists {
            return false;
        }
        self.index_device(mac, &dev_arc);
        self.devices.insert(mac, dev_arc);
        true
    }

    fn handle_ndp_seen(&mut self, mac: MacAddr, ip: Ipv6Addr) -> bool {
        self.ndp_cache.insert(ip, (mac, SystemTime::now()));
        if let Some((duid, iaid, expires)) = self.orphaned_v6.remove(&ip) {
            self.handle_v6_lease_granted(Some(mac), duid, iaid, ip, expires);
            return true;
        }

        let exists = self.devices.contains_key(&mac);
        let dev_arc = self.get_or_insert(mac);
        let old_seen = dev_arc.last_seen;

        if !dev_arc.is_worthy() && !exists {
            self.devices.remove(&mac);
            return false;
        }

        let elapsed = SystemTime::now()
            .duration_since(old_seen)
            .unwrap_or_default();
        !exists || elapsed.as_secs() > 300
    }

    fn handle_arp_seen(&mut self, mac: MacAddr, ip: Ipv4Addr) -> bool {
        let exists = self.devices.contains_key(&mac);
        let dev_arc = self.get_or_insert(mac);
        let old_seen = dev_arc.last_seen;

        let is_new_ip = !dev_arc.seen_v4.contains(&ip);

        if is_new_ip {
            let mut dev_arc = self.devices.remove(&mac).unwrap();
            self.unindex_device(&dev_arc);
            {
                let dev = Arc::make_mut(&mut dev_arc);
                dev.seen_v4.push(ip);
                dev.last_seen = SystemTime::now();
            }
            self.index_device(mac, &dev_arc);
            self.devices.insert(mac, dev_arc);
        } else if let Some(dev_arc_mut) = self.devices.get_mut(&mac) {
            let dev = Arc::make_mut(dev_arc_mut);
            dev.last_seen = SystemTime::now();
        }

        if let Some(dev_arc) = self.devices.get(&mac)
            && !dev_arc.is_worthy()
            && !exists
        {
            self.devices.remove(&mac);
            return false;
        }

        let elapsed = SystemTime::now()
            .duration_since(old_seen)
            .unwrap_or_default();
        is_new_ip || !exists || elapsed.as_secs() > 300
    }

    fn handle_hostname_hint(
        &mut self,
        mac: MacAddr,
        hostname: String,
        origin: HostnameOrigin,
    ) -> bool {
        let exists = self.devices.contains_key(&mac);
        let dev_arc = self.get_or_insert(mac);

        if origin >= dev_arc.hostname.origin && dev_arc.hostname.name != hostname {
            let mut dev_arc = self.devices.remove(&mac).unwrap();
            self.unindex_device(&dev_arc);
            {
                let dev = Arc::make_mut(&mut dev_arc);
                dev.hostname = Hostname {
                    name: hostname,
                    origin,
                };
            }
            self.index_device(mac, &dev_arc);
            self.devices.insert(mac, dev_arc);
            return true;
        }
        !exists
    }

    fn handle_duid_associated(&mut self, mac: Option<MacAddr>, duid: &Duid, iaid: u32) -> bool {
        let Some(m) = mac else {
            return false;
        };
        let mut changed_info = false;
        self.duid_index.insert(duid.clone(), m);
        let exists = self.devices.contains_key(&m);
        let dev_arc = self.get_or_insert(m);

        if dev_arc.duid.as_ref() != Some(duid) {
            let mut dev_arc = self.devices.remove(&m).unwrap();
            {
                let dev = Arc::make_mut(&mut dev_arc);
                dev.duid = Some(duid.clone());
            }
            self.devices.insert(m, dev_arc);
            changed_info = true;
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
                if self.handle_v6_lease_granted(Some(m), duid, iaid, ip, expires) {
                    changed_info = true;
                }
            }
        }

        let dev_arc = self.devices.get(&m).unwrap();
        if !dev_arc.is_worthy() && !exists {
            self.devices.remove(&m);
            return false;
        }

        changed_info || !exists
    }

    fn handle_cli_host_updated(
        &mut self,
        mac: MacAddr,
        hostname: FieldUpdate<String>,
        v4_static: FieldUpdate<Ipv4Addr>,
        v6_suffix: FieldUpdate<Ipv6AddrOrSuffix>,
        origin: Origin,
    ) -> bool {
        let dev_arc_managed = self.get_or_insert(mac);
        if dev_arc_managed.origin == Origin::Toml {
            warn!("Tentativa de modificar device estático do TOML: {}", mac);
            return false;
        }
        drop(dev_arc_managed);

        let mut dev_arc = self.devices.remove(&mac).unwrap();
        let mut changed = false;

        self.unindex_device(&dev_arc);
        {
            let dev = Arc::make_mut(&mut dev_arc);
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
            }
        }
        self.index_device(mac, &dev_arc);
        self.devices.insert(mac, dev_arc);
        changed
    }

    fn handle_slaac_cleared(&mut self, mac: MacAddr) -> bool {
        if let Some(dev_arc) = self.devices.get(&mac) {
            let slaac_present = dev_arc.v6.iter().any(|s| matches!(s, IPv6State::Slaac(_)));
            if slaac_present {
                let mut dev_arc = self.devices.remove(&mac).unwrap();
                self.unindex_device(&dev_arc);
                {
                    let dev = Arc::make_mut(&mut dev_arc);
                    dev.v6.retain(|s| !matches!(s, IPv6State::Slaac(_)));
                }
                self.index_device(mac, &dev_arc);
                self.devices.insert(mac, dev_arc);
                return true;
            }
        }
        false
    }

    fn handle_host_removed(&mut self, mac: MacAddr) -> bool {
        if let Some(dev) = self.devices.remove(&mac) {
            self.unindex_device(&dev);
            if let Some(duid) = &dev.duid {
                self.duid_index.remove(duid);
            }
            self.static_entries.remove(&mac);
            return true;
        }
        self.static_entries.remove(&mac).is_some()
    }

    fn handle_prune_zombies(&mut self) -> bool {
        let initial_count = self.devices.len();
        let mut to_remove = Vec::new();

        for (mac, dev) in &self.devices {
            if !dev.is_worthy() {
                debug!("[state] Candidate for pruning: {} (not worthy)", mac);
                to_remove.push(*mac);
            }
        }

        for mac in to_remove {
            self.handle_host_removed(mac);
        }

        self.devices.len() != initial_count
    }

    fn handle_lease_released(&mut self, mac: MacAddr, target: &LeaseTarget) -> bool {
        if self.devices.contains_key(&mac) {
            let mut dev_arc = self.devices.remove(&mac).unwrap();
            self.unindex_device(&dev_arc);
            let mut changed = false;
            {
                let dev = Arc::make_mut(&mut dev_arc);
                match target {
                    LeaseTarget::V4 => {
                        if !matches!(dev.v4, IPv4State::None)
                            && !matches!(dev.v4, IPv4State::Static(_))
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
            }
            self.index_device(mac, &dev_arc);
            self.devices.insert(mac, dev_arc);
            return changed;
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
        let macs: Vec<_> = self.devices.keys().copied().collect();
        for mac in macs {
            let mut local_changed = false;
            if let Some(dev_arc) = self.devices.get(&mac) {
                match ip {
                    IpAddr::V6(ip6) => {
                        if dev_arc
                            .v6
                            .iter()
                            .any(|s| matches!(s, IPv6State::Slaac(a) if *a == ip6))
                        {
                            local_changed = true;
                        }
                    }
                    IpAddr::V4(ip4) => {
                        if dev_arc.seen_v4.contains(&ip4) {
                            local_changed = true;
                        }
                    }
                }
            }

            if local_changed {
                let mut dev_arc = self.devices.remove(&mac).unwrap();
                self.unindex_device(&dev_arc);
                {
                    let dev = Arc::make_mut(&mut dev_arc);
                    match ip {
                        IpAddr::V6(ip6) => {
                            dev.v6
                                .retain(|s| !matches!(s, IPv6State::Slaac(a) if *a == ip6));
                        }
                        IpAddr::V4(ip4) => {
                            if let Some(pos) = dev.seen_v4.iter().position(|&x| x == ip4) {
                                dev.seen_v4.remove(pos);
                            }
                        }
                    }
                }
                self.index_device(mac, &dev_arc);
                self.devices.insert(mac, dev_arc);
                changed_devices = true;
            }
        }
        changed_ndp || changed_devices
    }

    fn handle_ip_offline(&mut self, ip: IpAddr) -> bool {
        let mac = if let Some(mac) = self.ip_index.get(&ip) {
            *mac
        } else if let IpAddr::V6(ip6) = ip
            && let Some((mac, _)) = self.ndp_cache.get(&ip6)
        {
            *mac
        } else {
            return false;
        };

        let mut local_changed = false;
        if let Some(dev_arc) = self.devices.get(&mac) {
            match ip {
                IpAddr::V6(ip6) => {
                    if dev_arc
                        .v6
                        .iter()
                        .any(|s| matches!(s, IPv6State::Slaac(a) if *a == ip6))
                    {
                        local_changed = true;
                    }
                }
                IpAddr::V4(ip4) => {
                    if dev_arc.seen_v4.contains(&ip4) {
                        local_changed = true;
                    }
                }
            }
        }

        if local_changed {
            let mut dev_arc = self.devices.remove(&mac).unwrap();
            self.unindex_device(&dev_arc);
            {
                let dev = Arc::make_mut(&mut dev_arc);
                dev.remove_ip(&ip);
            }
            self.index_device(mac, &dev_arc);
            self.devices.insert(mac, dev_arc);
            return true;
        }
        false
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

        let devices: Vec<_> = self
            .devices
            .iter()
            .map(|(&mac, dev)| (mac, Arc::clone(dev)))
            .collect();

        for (mac, device) in devices {
            self.index_device(mac, &device);
        }

        self.name_index.shrink_to_fit();
        self.ip_index.shrink_to_fit();

        debug!(
            "[state] DNS indices rebuilt: {} names, {} IPs",
            self.name_index.len(),
            self.ip_index.len()
        );
    }

    fn index_device(&mut self, mac: MacAddr, dev: &Device) {
        if !dev.hostname.name.is_empty() {
            self.name_index
                .insert(dev.hostname.name.to_ascii_lowercase(), mac);
        }
        self.name_index.insert(dev.dns_fallback.clone(), mac);

        if let Some(ip) = dev.v4.ip() {
            self.ip_index.insert(IpAddr::V4(ip), mac);
        }
        for &ip in &dev.seen_v4 {
            self.ip_index.insert(IpAddr::V4(ip), mac);
        }
        for state in &dev.v6 {
            if let Some(ip) = state.ip() {
                self.ip_index.insert(IpAddr::V6(ip), mac);
            }
        }
    }

    fn unindex_device(&mut self, dev: &Device) {
        if !dev.hostname.name.is_empty() {
            self.name_index
                .remove(&dev.hostname.name.to_ascii_lowercase());
        }
        self.name_index.remove(&dev.dns_fallback);

        if let Some(ip) = dev.v4.ip() {
            self.ip_index.remove(&IpAddr::V4(ip));
        }
        for &ip in &dev.seen_v4 {
            self.ip_index.remove(&IpAddr::V4(ip));
        }
        for state in &dev.v6 {
            if let Some(ip) = state.ip() {
                self.ip_index.remove(&IpAddr::V6(ip));
            }
        }
    }

    pub fn expire_stale(&mut self) -> Vec<(MacAddr, Option<String>, DeviceChange)> {
        let now = SystemTime::now();
        let max_age = Duration::from_hours(168);
        let ndp_max_age = Duration::from_hours(24);
        let mut events = Vec::new();

        self.ndp_cache
            .retain(|_, (_, ts)| ts.elapsed().unwrap_or(Duration::ZERO) <= ndp_max_age);
        self.orphaned_v6.retain(|_, (_, _, expires)| *expires > now);

        let mut to_unindex = Vec::new();
        let mut to_reindex = Vec::new();

        self.devices.retain(|&mac, dev_arc| {
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

            let changed =
                v4_expired || !v6_expired_iaids.is_empty() || !prefix_expired_iaids.is_empty();

            if changed {
                to_unindex.push(Arc::clone(dev_arc));
                let hostname = Some(dev_arc.hostname.name.clone());

                if v4_expired {
                    events.push((
                        mac,
                        hostname.clone(),
                        DeviceChange::LeaseExpired {
                            target: LeaseTarget::V4,
                        },
                    ));
                }

                for &iaid in &v6_expired_iaids {
                    events.push((
                        mac,
                        hostname.clone(),
                        DeviceChange::LeaseExpired {
                            target: LeaseTarget::V6 { iaid },
                        },
                    ));
                }

                for &iaid in &prefix_expired_iaids {
                    events.push((
                        mac,
                        hostname.clone(),
                        DeviceChange::LeaseExpired {
                            target: LeaseTarget::V6Prefix { iaid },
                        },
                    ));
                }

                let dev = Arc::make_mut(dev_arc);
                if v4_expired {
                    dev.v4 = IPv4State::None;
                }
                for iaid in v6_expired_iaids {
                    dev.v6.retain(
                        |state| !matches!(state, IPv6State::Dynamic(lease) if lease.iaid == iaid),
                    );
                }
                for iaid in prefix_expired_iaids {
                    dev.v6_prefixes.retain(|p| p.iaid != iaid);
                }
                to_reindex.push((mac, Arc::clone(dev_arc)));
            }

            // Cleanup dynamic zombies
            if !dev_arc.is_static()
                && matches!(dev_arc.v4, IPv4State::None)
                && dev_arc.v6.is_empty()
                && dev_arc.v6_prefixes.is_empty()
                && dev_arc.last_seen.elapsed().unwrap_or(Duration::ZERO) > max_age
            {
                if !changed {
                    to_unindex.push(Arc::clone(dev_arc));
                }
                events.push((
                    mac,
                    Some(dev_arc.hostname.name.clone()),
                    DeviceChange::HostRemoved,
                ));
                return false;
            }

            true
        });

        for old in to_unindex {
            self.unindex_device(&old);
        }
        for (mac, new) in to_reindex {
            self.index_device(mac, &new);
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
