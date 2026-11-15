//! Linked addresses: addresses a device uses that the LAN does not assign it.
//!
//! A tailnet peer's `100.x` / `fd7a:` address, for one. They only attribute a DNS client to its
//! device (query log, top clients) and let `dev:` adblock selectors match it; DNS answers,
//! rewrites, port forwards, pinholes and the firewall never see them (`get_mac_by_ip` does not
//! know them). Kept in redb; deleting the device drops them.

use std::collections::BTreeMap;
use std::net::IpAddr;

use lanforge_types::events::StorageEvent;
use lanforge_types::identifiers::MacAddr;

use crate::bus::{EventVec, LanforgeEvent};
use crate::context::state::State;

fn linked_changed() -> EventVec {
    vec![LanforgeEvent::Storage(StorageEvent::LinkedAddressesChanged)].into()
}

impl State {
    /// The device `ip` is linked to, if it still exists.
    #[must_use]
    pub fn linked_device(&self, ip: IpAddr) -> Option<MacAddr> {
        self.linked_addresses
            .get(&ip.to_canonical())
            .copied()
            .filter(|mac| self.devices.contains_key(mac))
    }

    /// The addresses linked to `mac`, sorted.
    #[must_use]
    pub fn linked_addresses_of(&self, mac: MacAddr) -> Vec<IpAddr> {
        let mut addresses: Vec<IpAddr> = self
            .linked_addresses
            .iter()
            .filter(|(_, linked)| **linked == mac)
            .map(|(ip, _)| *ip)
            .collect();
        addresses.sort_unstable();
        addresses
    }

    /// Whether any address is linked to `mac` (it is then never pruned).
    #[must_use]
    pub fn has_linked_addresses(&self, mac: MacAddr) -> bool {
        self.linked_addresses.values().any(|linked| *linked == mac)
    }

    /// The device of a DNS client at `ip`: the one holding the address, else the one it is
    /// linked to.
    #[must_use]
    pub fn client_device(&self, ip: IpAddr) -> Option<MacAddr> {
        self.get_mac_by_ip(ip).or_else(|| self.linked_device(ip))
    }

    /// Replaces the addresses linked to `mac` (already checked by the API).
    pub(crate) fn set_linked_addresses(
        &mut self,
        mac: MacAddr,
        addresses: Vec<IpAddr>,
    ) -> EventVec {
        let mut wanted: Vec<IpAddr> = addresses.into_iter().map(|ip| ip.to_canonical()).collect();
        wanted.sort_unstable();
        wanted.dedup();
        if self.linked_addresses_of(mac) == wanted {
            return EventVec::new();
        }
        self.linked_addresses.retain(|_, linked| *linked != mac);
        self.linked_addresses
            .extend(wanted.into_iter().map(|ip| (ip, mac)));
        linked_changed()
    }

    /// Drops the addresses linked to `mac` (the admin deleted the device).
    pub(crate) fn unlink_addresses_of(&mut self, mac: MacAddr) -> EventVec {
        if self.has_linked_addresses(mac) {
            self.linked_addresses.retain(|_, linked| *linked != mac);
            linked_changed()
        } else {
            EventVec::new()
        }
    }

    /// Restores the links kept in redb (at start).
    pub(crate) fn restore_linked_addresses(&mut self, links: BTreeMap<IpAddr, MacAddr>) {
        self.linked_addresses = links.into_iter().collect();
    }
}
