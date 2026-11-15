//! Names that `dev:<name>` port forwards, IPv6 pinholes and DNS rewrites target.
//!
//! Anyone on the LAN can announce any hostname (DHCP, mDNS), and a name follows whoever
//! announces it: a phone that re-randomizes its MAC keeps its adblock group by name. A name a
//! port forward, pinhole or DNS rewrite targets is bound to the MAC that held it at its first
//! mention (or to the first device announcing it after): another MAC announcing it is refused,
//! so a LAN device cannot take a forward or a rewrite by announcing a name. The binding goes
//! when the admin deletes the device or no reference names it anymore. Adblock references
//! never bind. A static host's name is pinned by `[hosts]` and is never bound.

use std::collections::HashSet;

use lanforge_types::device::{Device, Hostname, HostnameOrigin};
use lanforge_types::events::StorageEvent;
use lanforge_types::identifiers::MacAddr;
use tracing::{info, warn};

use crate::bus::{DeviceEvent, EventVec, LanforgeEvent, NetworkChange};
use crate::context::state::State;

/// Whether `dev` holds `name` (lowercase) as its hostname or DNS fallback.
fn holds(dev: &Device, name: &str) -> bool {
    dev.hostname.name.eq_ignore_ascii_case(name) || dev.dns_fallback.eq_ignore_ascii_case(name)
}

fn bindings_changed() -> EventVec {
    vec![LanforgeEvent::Storage(StorageEvent::NameBindingsChanged)].into()
}

impl State {
    /// A hostname `mac` announces. A name bound to another MAC is refused (the device keeps the
    /// name it had: its DNS fallback for a new one); a referenced name nobody is bound to yet is
    /// bound to `mac` once it holds it.
    pub(crate) fn claim_hostname(
        &mut self,
        mac: MacAddr,
        hostname: &str,
        origin: HostnameOrigin,
    ) -> EventVec {
        let name = Hostname::sanitize(hostname);
        let key = name.to_ascii_lowercase();
        if let Some(&owner) = self.name_bindings.get(&key)
            && owner != mac
        {
            return self.refuse_hostname(mac, name, owner);
        }
        self.hostname_refusals.remove(&mac);
        let mut events = self.mutate_device(mac, |dev| dev.apply_hostname_hint(hostname, origin));
        if self.name_references.contains(&key)
            && !self.name_bindings.contains_key(&key)
            && !self.static_holds(&key)
            && self.devices.get(&mac).is_some_and(|dev| holds(dev, &key))
        {
            events.extend(self.bind_name(key, mac));
        }
        events
    }

    /// Reports a refused name once per device and name (DHCP renewals and mDNS announcements
    /// repeat it): a warning and a `HostnameRefused` change for the activity feed.
    fn refuse_hostname(&mut self, mac: MacAddr, name: String, owner: MacAddr) -> EventVec {
        if self
            .hostname_refusals
            .get(&mac)
            .is_some_and(|last| last.eq_ignore_ascii_case(&name))
        {
            return EventVec::new();
        }
        warn!(
            device = %mac,
            hostname = %name,
            holder = %owner,
            "Hostname refused: a port forward or DNS rewrite binds it to another device \
             (delete that device or drop the reference to free it)"
        );
        let current = self
            .devices
            .get(&mac)
            .map(|dev| dev.hostname.name.clone())
            .filter(|n| !n.is_empty());
        self.hostname_refusals.insert(mac, name.clone());
        vec![LanforgeEvent::Device(DeviceEvent::NetworkUpdate {
            mac,
            hostname: current,
            change: Box::new(NetworkChange::HostnameRefused {
                hostname: name,
                holder: owner,
            }),
        })]
        .into()
    }

    /// Replaces the referenced names (lowercase): the bindings of names no longer referenced
    /// go, and each referenced name is bound to the device holding it now, if any.
    pub(crate) fn set_name_references(&mut self, references: HashSet<String>) -> EventVec {
        let before = self.name_bindings.len();
        self.name_bindings.retain(|name, mac| {
            let keep = references.contains(name);
            if !keep {
                info!(name = %name, device = %mac, "Name unbound: no port forward or DNS rewrite targets it anymore");
            }
            keep
        });
        let mut changed = self.name_bindings.len() != before;
        self.name_references = references;
        let unbound: Vec<String> = self
            .name_references
            .iter()
            .filter(|name| !self.name_bindings.contains_key(*name))
            .cloned()
            .collect();
        for name in unbound {
            if let Some(mac) = self.dynamic_holder(&name) {
                changed |= !self.bind_name(name, mac).is_empty();
            }
        }
        if changed {
            bindings_changed()
        } else {
            EventVec::new()
        }
    }

    /// Restores the bindings kept in redb (at start, before any announcement is applied).
    pub(crate) fn restore_name_bindings(
        &mut self,
        bindings: impl IntoIterator<Item = (String, MacAddr)>,
    ) {
        self.name_bindings = bindings.into_iter().collect();
    }

    /// The device `name` (lowercase) is bound to, if it still exists.
    #[must_use]
    pub fn bound_device(&self, name: &str) -> Option<MacAddr> {
        self.name_bindings
            .get(name)
            .copied()
            .filter(|mac| self.devices.contains_key(mac))
    }

    /// Drops the bindings to `mac` (the admin deleted the device).
    pub(crate) fn unbind_names_of(&mut self, mac: MacAddr) -> EventVec {
        let before = self.name_bindings.len();
        self.name_bindings.retain(|_, bound| *bound != mac);
        if self.name_bindings.len() == before {
            EventVec::new()
        } else {
            bindings_changed()
        }
    }

    fn bind_name(&mut self, name: String, mac: MacAddr) -> EventVec {
        info!(name = %name, device = %mac, "Name bound to its device: a port forward or DNS rewrite targets it");
        self.name_bindings.insert(name, mac);
        bindings_changed()
    }

    fn static_holds(&self, name: &str) -> bool {
        self.devices
            .values()
            .any(|dev| dev.is_static() && holds(dev, name))
    }

    /// The non-static device holding `name` now: the one the name index points to, else any.
    /// `None` when a static host holds it (`[hosts]` pins it).
    fn dynamic_holder(&self, name: &str) -> Option<MacAddr> {
        if self.static_holds(name) {
            return None;
        }
        if let Some(mac) = self.indices.name_index.get(name)
            && self.devices.get(mac).is_some_and(|dev| holds(dev, name))
        {
            return Some(*mac);
        }
        self.devices
            .iter()
            .find(|(_, dev)| holds(dev, name))
            .map(|(mac, _)| *mac)
    }
}
