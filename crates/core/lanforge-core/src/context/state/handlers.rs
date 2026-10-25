use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use crate::bus::{
    AdminChange, DeviceEvent, EventVec, LanforgeEvent, NetworkChange, NetworkEvent,
    PrefixChangeDetails,
};
use crate::context::state::cache::DiscoveryStore;
use crate::context::state::{
    CliHostUpdate, DeviceClass, InterfaceState, LeaseTarget, State,
};
use lanforge_types::device::{
    DeviceStatus, Hostname, HostnameOrigin, IPv4State, IPv6State, IpClassification, Origin,
    TransientHost, TransientOrigin, V6ObservationOrigin, classify_ipv6,
};
use lanforge_types::identifiers::{Duid, MacAddr};
use lanforge_types::network::Ipv6AddrOrSuffix;

type ProcessedNeighbor = (
    IpAddr,
    bool,
    V6ObservationOrigin,
    Option<(Duid, u32, SystemTime)>,
);

impl State {
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub(crate) fn handle_v4_lease_granted(
        &mut self,
        mac: MacAddr,
        ip: Ipv4Addr,
        expires: SystemTime,
    ) -> EventVec {
        self.mutate_device(mac, |dev| dev.apply_v4_lease(ip, expires))
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub(crate) fn handle_v6_lease_granted(
        &mut self,
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        ip: Ipv6Addr,
        expires: SystemTime,
        discovery: &DiscoveryStore,
    ) -> EventVec {
        let m = if let Some(m) = mac {
            m
        } else if let Some(m) = self.indices.duid_index.get(&duid) {
            *m
        } else {
            discovery.insert_orphan(ip, duid, iaid, expires);
            return EventVec::new();
        };

        self.mutate_device(m, |dev| dev.apply_v6_lease(&duid, iaid, ip, expires))
    }

    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn handle_v6_prefix_assigned(
        &mut self,
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        prefix: Ipv6Addr,
        len: u8,
        expires: SystemTime,
    ) -> EventVec {
        let m = if let Some(m) = mac {
            m
        } else if let Some(m) = self.indices.duid_index.get(&duid) {
            *m
        } else {
            return EventVec::new(); // IA_PD usually requires a prior IA_NA to link DUID to MAC
        };

        self.mutate_device(m, |dev| {
            dev.apply_v6_prefix(&duid, iaid, prefix, len, expires)
        })
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub(crate) fn handle_slaac_observed(
        &mut self,
        mac: MacAddr,
        addr: Ipv6Addr,
        is_active: bool,
    ) -> EventVec {
        self.mutate_device(mac, |dev| {
            dev.apply_v6_observation(addr, is_active, V6ObservationOrigin::SlaacTracker)
        })
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub(crate) fn handle_ndp_seen(
        &mut self,
        mac: MacAddr,
        ip: Ipv6Addr,
        is_active: bool,
        discovery: &DiscoveryStore,
    ) -> EventVec {
        discovery.insert_ndp(ip, mac);

        let orphaned = discovery.remove_orphan(&ip);
        let orphaned_info = orphaned.clone();
        let origin = if self.is_managed_slaac_prefix(&ip) {
            V6ObservationOrigin::SlaacTracker
        } else {
            V6ObservationOrigin::NdpMonitor
        };

        let mut events = self.mutate_device(mac, |dev| {
            let mut change = if let Some((duid, iaid, expires)) = &orphaned {
                let old_duid = dev.duid.clone();
                let c = dev.apply_v6_lease(duid, *iaid, ip, *expires);

                if let Some(old) = old_duid
                    && old != *duid
                {
                    if dev.is_static() {
                        tracing::warn!(
                            "State: DUID change detected for static host {} ({}). Saved DUID is {:?}, but client sent {:?}. Please update static configuration.",
                            dev.display_hostname(),
                            mac,
                            old,
                            duid
                        );
                    } else {
                        tracing::info!(
                            "State: DUID migrated for host {} ({}): {:?} -> {:?}",
                            dev.display_hostname(),
                            mac,
                            old,
                            duid
                        );
                    }
                }
                c
            } else {
                None
            };

            if let Some(c) = dev.apply_v6_observation(ip, is_active, origin) {
                // If it's Link-Local and we are already worthy, don't trigger a dirty update.
                // This keeps NdpSeen events quiet for background traffic.
                if classify_ipv6(&ip) == IpClassification::LinkLocal && dev.is_worthy() {
                    return change;
                }

                if change.is_none() {
                    change = Some(c);
                }
            }
            change
        });

        // Safety check: if we just linked an orphaned dynamic lease to a static device,
        // and the assigned IP is NOT the static one, trigger a RECONFIGURE.
        if let Some((duid, iaid, _)) = orphaned_info
            && let Some(dev) = self.devices.get(&mac)
            && dev.is_static()
            && dev.duid.as_ref() == Some(&duid)
        {
            let has_static_match = dev.v6.iter().any(|s| match s {
                IPv6State::Static(s, _) => s.matches(ip),
                _ => false,
            });

            if !has_static_match {
                tracing::info!(
                    "📡 Triggering DHCPv6 Reconfigure for {} ({}) to move from temporary {} to static assignment.",
                    dev.display_hostname(),
                    mac,
                    ip
                );
                events.push(LanforgeEvent::Device(DeviceEvent::LeaseRenew {
                    mac,
                    target: LeaseTarget::V6 { iaid },
                }));
            }
        }

        let transient_name = self
            .transient_hosts
            .get(&IpAddr::V6(ip))
            .map(|t| t.hostname.name.clone());
        if let Some(name) = transient_name
            && let Some(dev) = self.devices.get(&mac)
            && dev.hostname.name.is_empty()
        {
            let h_events = self.handle_hostname_hint_mdns(mac, &name);
            events.extend(h_events);
        }

        events
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub(crate) fn handle_arp_seen(
        &mut self,
        mac: MacAddr,
        ip: Ipv4Addr,
        is_active: bool,
    ) -> EventVec {
        let mut events = self.mutate_device(mac, |dev| dev.apply_arp_observation(ip, is_active));
        let transient_name = self
            .transient_hosts
            .get(&IpAddr::V4(ip))
            .map(|t| t.hostname.name.clone());
        if let Some(name) = transient_name
            && let Some(dev) = self.devices.get(&mac)
            && dev.hostname.name.is_empty()
        {
            let h_events = self.handle_hostname_hint_mdns(mac, &name);
            events.extend(h_events);
        }
        events
    }

    pub(crate) fn handle_hostname_hint_dhcp(&mut self, mac: MacAddr, hostname: &str) -> EventVec {
        self.mutate_device(mac, |dev| {
            dev.apply_hostname_hint(hostname, HostnameOrigin::Dhcp)
        })
    }

    pub(crate) fn handle_hostname_hint_mdns(&mut self, mac: MacAddr, hostname: &str) -> EventVec {
        self.mutate_device(mac, |dev| {
            dev.apply_hostname_hint(hostname, HostnameOrigin::Mdns)
        })
    }

    pub(crate) fn handle_duid_associated(
        &mut self,
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        discovery: &DiscoveryStore,
    ) -> EventVec {
        let mac = if let Some(m) = mac {
            m
        } else if let Some(m) = self.indices.duid_index.get(&duid) {
            *m
        } else {
            return EventVec::new();
        };

        let orphan_data = discovery.remove_orphans_by_duid(&duid);

        self.mutate_device(mac, |dev| {
            let mut last_change = dev.associate_duid(duid, iaid);
            for (ip, (d, iaid, exp)) in orphan_data {
                if let Some(c) = dev.apply_v6_lease(&d, iaid, ip, exp) {
                    last_change = Some(c);
                }
            }
            last_change
        })
    }

    pub(crate) fn handle_cli_host_updated(
        &mut self,
        mac: MacAddr,
        update: CliHostUpdate,
    ) -> EventVec {
        let events = self.mutate_device_admin(mac, |dev| Some(dev.apply_cli_update(update)));
        self.rebuild_static_registry();
        events
    }

    pub(crate) fn handle_ignore_dns_log_set(&mut self, mac: MacAddr, ignore: bool) -> EventVec {
        self.mutate_device(mac, |dev| {
            dev.identity_mut().ignore_dns_log = ignore;
            None
        });
        EventVec::new()
    }

    pub(crate) fn handle_ignored_log_domains_set(
        &mut self,
        mac: MacAddr,
        domains: Vec<String>,
    ) -> EventVec {
        self.mutate_device(mac, |dev| {
            dev.identity_mut().ignored_log_domains = domains;
            None
        });
        EventVec::new()
    }

    pub(crate) fn handle_host_removed(&mut self, mac: MacAddr) -> EventVec {
        if let Some(dev) = self.devices.remove(&mac) {
            self.unindex_device(&dev);
            self.rebuild_static_registry();
            return vec![LanforgeEvent::Device(DeviceEvent::Purged { mac })].into();
        }
        EventVec::new()
    }

    pub(crate) fn handle_lease_released(&mut self, mac: MacAddr, target: LeaseTarget) -> EventVec {
        self.mutate_device(mac, |dev| dev.release_lease(target))
    }

    pub(crate) fn handle_ip_deleted(&mut self, ip: IpAddr, discovery: &DiscoveryStore) -> EventVec {
        let mac = self.indices.ip_index.get(&ip).copied();
        mac.map_or_else(EventVec::new, |mac| {
            let events = self.mutate_device(mac, |dev| {
                if dev.delete_ip(ip) {
                    Some(NetworkChange::IpDeleted { ip })
                } else {
                    None
                }
            });

            // Cleanup discovery caches
            if let IpAddr::V6(v6) = ip {
                let _ = discovery.remove_ndp(&v6);
            }

            events
        })
    }

    pub(crate) fn handle_ip_offline(&mut self, ip: IpAddr) -> EventVec {
        let mac = self.indices.ip_index.get(&ip).copied();
        mac.map_or_else(EventVec::new, |mac| {
            self.mutate_device(mac, |dev| {
                if dev.mark_ip_offline(ip) {
                    Some(NetworkChange::IpOffline { ip })
                } else {
                    None
                }
            })
        })
    }

    pub(crate) fn handle_interface_ips_changed(
        &mut self,
        ifindex: u32,
        state: &InterfaceState,
    ) -> EventVec {
        let mut merged = state.clone();
        if let Some(old) = self.interfaces.interface_ips.get(&ifindex) {
            if merged.mac.is_none() {
                merged.mac = old.mac;
            }
            if merged.link_local.is_none() {
                merged.link_local = old.link_local;
            }
            if merged.v4.is_none() {
                merged.v4 = old.v4;
            }
            if merged.ula.is_none() {
                merged.ula = old.ula;
            }
            if merged.gua.is_none() {
                merged.gua = old.gua;
                merged.gua_preferred = old.gua_preferred;
                merged.gua_valid = old.gua_valid;
            }
        }

        let old_state = self.interfaces.interface_ips.get(&ifindex);
        let prefix_changed = old_state.map_or_else(
            || merged.gua.is_some() || merged.ula.is_some(),
            |old| old.gua != merged.gua || old.ula != merged.ula,
        );

        self.interfaces
            .interface_ips
            .insert(ifindex, merged.clone());
        let mut events: EventVec = vec![LanforgeEvent::Network(NetworkEvent::InterfaceUpdated {
            ifindex,
        })]
        .into();

        if prefix_changed {
            self.rebuild_indices();
            events.push(LanforgeEvent::Network(NetworkEvent::PrefixChanged(
                Box::new(PrefixChangeDetails {
                    gua: merged.gua,
                    ula: merged.ula,
                    preferred: merged.gua_preferred,
                    valid: merged.gua_valid,
                }),
            )));
        }

        // Update the System device (the host itself) if it exists
        if let Some((mac, _)) = self
            .devices
            .iter()
            .find(|(_, d)| d.origin == Origin::System)
        {
            let mac = *mac;
            let mut system_events = self.mutate_device(mac, |dev| {
                let mut changed = false;

                // Sync IPv4
                if let Some((v4, _)) = state.v4 {
                    let new_v4 = IPv4State::Static(v4);
                    if dev.v4 != new_v4 {
                        dev.v4 = new_v4;
                        changed = true;
                    }
                }

                // Sync IPv6 (Link-Local, GUA, ULA)
                // We treat system IPs as static entries in the device state
                let mut new_v6 = Vec::new();
                let now = SystemTime::now();

                if let Some(ll) = state.link_local {
                    new_v6.push(IPv6State::Static(Ipv6AddrOrSuffix::Full(ll), now));
                }
                if let Some(gua) = state.gua {
                    new_v6.push(IPv6State::Static(Ipv6AddrOrSuffix::Full(gua), now));
                }
                if let Some(ula) = state.ula {
                    new_v6.push(IPv6State::Static(Ipv6AddrOrSuffix::Full(ula), now));
                }

                // Only update if the set of IPs actually changed
                if dev.v6.len() != new_v6.len()
                    || dev.v6.iter().zip(new_v6.iter()).any(|(a, b)| a != b)
                {
                    dev.v6 = new_v6;
                    changed = true;
                }

                if changed {
                    Some(NetworkChange::StatusChanged {
                        online: true,
                        status: DeviceStatus::Online,
                        hostname: None,
                    })
                } else {
                    None
                }
            });
            events.append(&mut system_events);
        }

        events
    }

    pub(crate) fn handle_class_hint(&mut self, mac: MacAddr, class: DeviceClass) -> EventVec {
        self.mutate_device_admin(mac, |dev| {
            if dev.class == class {
                None
            } else {
                dev.identity_mut().class = class;
                Some(AdminChange::Classified { class })
            }
        })
    }

    #[allow(clippy::too_many_lines)]
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub(crate) fn handle_neighbor_batch(
        &mut self,
        entries: Vec<(MacAddr, IpAddr, bool)>,
        discovery: &DiscoveryStore,
    ) -> EventVec {
        if entries.is_empty() {
            return EventVec::new();
        }

        // FAST-PATH: If all entries belong to the same MAC (very common during discovery bursts for one device)
        let first_mac = entries[0].0;
        if entries.iter().all(|(mac, _, _)| *mac == first_mac) {
            let processed_entries: Vec<ProcessedNeighbor> = entries
                .iter()
                .map(|(_, ip, active)| match ip {
                    IpAddr::V4(_) => (*ip, *active, V6ObservationOrigin::NdpMonitor, None),
                    IpAddr::V6(v6) => {
                        let origin = if self.is_managed_slaac_prefix(v6) {
                            V6ObservationOrigin::SlaacTracker
                        } else {
                            V6ObservationOrigin::NdpMonitor
                        };
                        let orphaned = discovery.remove_orphan(v6);
                        (*ip, *active, origin, orphaned)
                    }
                })
                .collect();

            let events = self.mutate_device(first_mac, |dev| {
                let mut first_change = None;
                for (ip, active, origin, orphaned) in &processed_entries {
                    if let (IpAddr::V6(v6), Some((duid, iaid, expires))) = (ip, orphaned) {
                        let c = dev.apply_v6_lease(duid, *iaid, *v6, *expires);
                        if first_change.is_none() {
                            first_change = c;
                        }
                    }
                    let change = match ip {
                        IpAddr::V4(v4) => dev.apply_arp_observation(*v4, *active),
                        IpAddr::V6(v6) => {
                            let c = dev.apply_v6_observation(*v6, *active, *origin);
                            if classify_ipv6(v6) == IpClassification::LinkLocal && dev.is_worthy() {
                                None
                            } else {
                                c
                            }
                        }
                    };
                    if let Some(c) = change
                        && first_change.is_none()
                    {
                        first_change = Some(c);
                    }
                }
                first_change
            });

            // Update discovery cache
            for (_, ip, _) in &entries {
                if let IpAddr::V6(v6) = ip {
                    discovery.insert_ndp(*v6, first_mac);
                }
            }
            let matched_name = entries.iter().find_map(|(_, ip, _)| {
                self.transient_hosts
                    .get(ip)
                    .map(|t| t.hostname.name.clone())
            });
            if let Some(name) = matched_name
                && let Some(dev) = self.devices.get(&first_mac)
                && dev.hostname.name.is_empty()
            {
                let mut events = events;
                let h_events = self.handle_hostname_hint_mdns(first_mac, &name);
                events.extend(h_events);
                return events;
            }
            return events;
        }

        // SLOW-PATH: Multiple MACs in the same batch
        let mut grouped_updates: HashMap<MacAddr, Vec<ProcessedNeighbor>> = HashMap::new();
        for (mac, ip, active) in entries {
            let (origin, orphaned) = match &ip {
                IpAddr::V4(_) => (V6ObservationOrigin::NdpMonitor, None),
                IpAddr::V6(v6) => {
                    let origin = if self.is_managed_slaac_prefix(v6) {
                        V6ObservationOrigin::SlaacTracker
                    } else {
                        V6ObservationOrigin::NdpMonitor
                    };
                    let orphaned = discovery.remove_orphan(v6);
                    (origin, orphaned)
                }
            };
            grouped_updates
                .entry(mac)
                .or_default()
                .push((ip, active, origin, orphaned));
        }

        let mut events = EventVec::new();
        for (mac, updates) in grouped_updates {
            let mut dev_events = self.mutate_device(mac, |dev| {
                let mut first_change = None;
                for (ip, active, origin, orphaned) in &updates {
                    if let (IpAddr::V6(v6), Some((duid, iaid, expires))) = (ip, orphaned) {
                        let c = dev.apply_v6_lease(duid, *iaid, *v6, *expires);
                        if first_change.is_none() {
                            first_change = c;
                        }
                    }
                    let change = match ip {
                        IpAddr::V4(v4) => dev.apply_arp_observation(*v4, *active),
                        IpAddr::V6(v6) => {
                            let c = dev.apply_v6_observation(*v6, *active, *origin);
                            if classify_ipv6(v6) == IpClassification::LinkLocal && dev.is_worthy() {
                                None
                            } else {
                                c
                            }
                        }
                    };
                    if let Some(c) = change
                        && first_change.is_none()
                    {
                        first_change = Some(c);
                    }
                }
                first_change
            });
            events.append(&mut dev_events);

            for (ip, _, _, _) in &updates {
                if let IpAddr::V6(v6) = ip {
                    discovery.insert_ndp(*v6, mac);
                }
            }

            let matched_name = updates.iter().find_map(|(ip, _, _, _)| {
                self.transient_hosts
                    .get(ip)
                    .map(|t| t.hostname.name.clone())
            });
            if let Some(name) = matched_name
                && let Some(dev) = self.devices.get(&mac)
                && dev.hostname.name.is_empty()
            {
                let h_events = self.handle_hostname_hint_mdns(mac, &name);
                events.extend(h_events);
            }
        }
        events
    }

    pub fn expire_stale(&mut self, stale_timeout: Duration) -> EventVec {
        let now = SystemTime::now();
        let mut events = EventVec::new();

        let macs: Vec<MacAddr> = self.devices.keys().copied().collect();
        for mac in macs {
            let mut dev_events = self.mutate_device(mac, |dev| {
                let changes = dev.expire_stale_inner(now, stale_timeout);
                changes.into_iter().next()
            });
            events.append(&mut dev_events);
        }
        events
    }

    pub(crate) fn handle_transient_host_resolved(
        &mut self,
        ip: IpAddr,
        hostname: Hostname,
        origin: TransientOrigin,
    ) -> EventVec {
        let mut events = EventVec::new();
        if let Some(&mac) = self.indices.ip_index.get(&ip)
            && let Some(dev) = self.devices.get(&mac)
            && dev.hostname.name.is_empty()
        {
            let h_events = self.handle_hostname_hint_mdns(mac, &hostname.name);
            events.extend(h_events);
        }

        let host = TransientHost::new(hostname, origin);
        if self.transient_hosts.len() >= 1000 && !self.transient_hosts.contains_key(&ip) {
            let mut oldest_ip = None;
            let mut oldest_time = SystemTime::now();
            for (curr_ip, curr_host) in &self.transient_hosts {
                if curr_host.last_seen < oldest_time {
                    oldest_time = curr_host.last_seen;
                    oldest_ip = Some(*curr_ip);
                }
            }
            if let Some(to_remove) = oldest_ip {
                self.transient_hosts.remove(&to_remove);
            }
        }
        self.transient_hosts.insert(ip, host);

        events
    }

    pub(crate) fn handle_device_interface_seen(
        &mut self,
        mac: MacAddr,
        iface: String,
    ) -> EventVec {
        self.mutate_device(mac, |dev| {
            if dev.iface.as_deref() != Some(&iface) {
                dev.identity_mut().iface = Some(iface);
            }
            None
        })
    }
}
