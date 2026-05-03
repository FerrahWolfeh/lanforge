use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use crate::bus::{DeviceChange, DeviceEvent, LanforgeEvent, NetworkEvent};
use crate::context::state::{
    DeviceClass, FieldUpdate, InterfaceState, LeaseTarget, State, StaticEntry,
};
use crate::device::{
    Hostname, HostnameOrigin, IPv4State, IPv6State, IpClassification, Ipv6AddrOrSuffix, Origin,
    TopologyInfo, classify_ipv6,
};
use crate::identifiers::{Duid, MacAddr};

impl State {
    pub(crate) fn handle_v4_lease_granted(
        &mut self,
        mac: MacAddr,
        ip: Ipv4Addr,
        expires: SystemTime,
    ) -> Vec<LanforgeEvent> {
        self.mutate_device(mac, |dev| dev.apply_v4_lease(ip, expires))
    }

    pub(crate) fn handle_v6_lease_granted(
        &mut self,
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
        ip: Ipv6Addr,
        expires: SystemTime,
    ) -> Vec<LanforgeEvent> {
        let m = if let Some(m) = mac {
            m
        } else if let Some(m) = self.indices.duid_index.get(&duid) {
            *m
        } else {
            self.discovery.orphaned_v6.insert(ip, (duid, iaid, expires));
            return Vec::new();
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
    ) -> Vec<LanforgeEvent> {
        let m = if let Some(m) = mac {
            m
        } else if let Some(m) = self.indices.duid_index.get(&duid) {
            *m
        } else {
            return Vec::new(); // IA_PD usually requires a prior IA_NA to link DUID to MAC
        };

        self.mutate_device(m, |dev| {
            dev.apply_v6_prefix(&duid, iaid, prefix, len, expires)
        })
    }

    pub(crate) fn handle_slaac_observed(
        &mut self,
        mac: MacAddr,
        addr: Ipv6Addr,
        is_active: bool,
    ) -> Vec<LanforgeEvent> {
        self.mutate_device(mac, |dev| dev.apply_slaac_observation(addr, is_active))
    }

    pub(crate) fn handle_ndp_seen(
        &mut self,
        mac: MacAddr,
        ip: Ipv6Addr,
        is_active: bool,
    ) -> Vec<LanforgeEvent> {
        self.discovery
            .ndp_cache
            .insert(ip, (mac, SystemTime::now()));

        let orphaned = self.discovery.orphaned_v6.remove(&ip);

        self.mutate_device(mac, |dev| {
            let mut change = if let Some((duid, iaid, expires)) = orphaned {
                dev.apply_v6_lease(&duid, iaid, ip, expires)
            } else {
                None
            };

            if let Some(c) = dev.apply_slaac_observation(ip, is_active) {
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
        })
    }

    pub(crate) fn handle_arp_seen(
        &mut self,
        mac: MacAddr,
        ip: Ipv4Addr,
        is_active: bool,
    ) -> Vec<LanforgeEvent> {
        self.mutate_device(mac, |dev| dev.apply_arp_observation(ip, is_active))
    }

    pub(crate) fn handle_hostname_hint_dhcp(
        &mut self,
        mac: MacAddr,
        hostname: String,
    ) -> Vec<LanforgeEvent> {
        self.mutate_device(mac, |dev| {
            dev.apply_hostname_hint(hostname, HostnameOrigin::Dhcp)
        })
    }

    pub(crate) fn handle_hostname_hint_mdns(
        &mut self,
        mac: MacAddr,
        hostname: String,
    ) -> Vec<LanforgeEvent> {
        self.mutate_device(mac, |dev| {
            dev.apply_hostname_hint(hostname, HostnameOrigin::Mdns)
        })
    }

    pub(crate) fn handle_duid_associated(
        &mut self,
        mac: Option<MacAddr>,
        duid: Duid,
        iaid: u32,
    ) -> Vec<LanforgeEvent> {
        let mac = if let Some(m) = mac {
            m
        } else if let Some(m) = self.indices.duid_index.get(&duid) {
            *m
        } else {
            return Vec::new();
        };

        // Find all orphans for this DUID
        let orphans: Vec<_> = self
            .discovery
            .orphaned_v6
            .iter()
            .filter(|(_, (d, _, _))| d == &duid)
            .map(|(ip, _)| *ip)
            .collect();

        let mut orphan_data = Vec::new();
        for ip in orphans {
            if let Some(data) = self.discovery.orphaned_v6.remove(&ip) {
                orphan_data.push((ip, data));
            }
        }

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
        hostname: FieldUpdate<String>,
        duid: FieldUpdate<Duid>,
        v4_static: FieldUpdate<Ipv4Addr>,
        v6_suffix: FieldUpdate<Ipv6AddrOrSuffix>,
        boot_file: FieldUpdate<String>,
        origin: Origin,
    ) -> Vec<LanforgeEvent> {
        let events = self.mutate_device(mac, |dev| {
            if let FieldUpdate::Set(h) = hostname {
                dev.hostname = Hostname {
                    name: h,
                    origin: HostnameOrigin::Static,
                };
            }
            if let FieldUpdate::Set(d) = duid {
                dev.duid = Some(d);
            }
            if let FieldUpdate::Set(v4) = v4_static {
                dev.v4 = IPv4State::Static(v4);
            }
            if let FieldUpdate::Set(v6) = v6_suffix {
                dev.v6.retain(|s| !matches!(s, IPv6State::Static(_, _)));
                dev.v6.push(IPv6State::Static(v6, SystemTime::now()));
            }
            if let FieldUpdate::Set(bf) = boot_file {
                dev.boot_file = Some(bf);
            } else if boot_file == FieldUpdate::Clear {
                dev.boot_file = None;
            }
            dev.origin = origin;
            dev.managed_at = Some(SystemTime::now());
            Some(DeviceChange::CliHostUpdated)
        });

        // Update static entries table
        if let Some(dev) = self.devices.get(&mac) {
            self.static_entries.insert(
                mac,
                StaticEntry {
                    mac,
                    hostname: dev.hostname.name.clone(),
                    duid: dev.duid.clone(),
                    v4_static: dev.v4.ip(),
                    v6_suffix: dev.v6.iter().find_map(|s| match s {
                        IPv6State::Static(s, _) => Some(s.clone()),
                        _ => None,
                    }),
                    boot_file: dev.boot_file.clone(),
                    origin,
                },
            );
        }

        events
    }

    pub(crate) fn handle_host_removed(&mut self, mac: MacAddr) -> Vec<LanforgeEvent> {
        if let Some(dev) = self.devices.remove(&mac) {
            self.indices.unindex_device(&dev);
            if let Some(duid) = &dev.duid {
                self.indices.duid_index.remove(duid);
            }
            self.static_entries.remove(&mac);
            return vec![LanforgeEvent::Device(DeviceEvent::Purged { mac })];
        }
        Vec::new()
    }

    pub(crate) fn handle_lease_released(
        &mut self,
        mac: MacAddr,
        target: LeaseTarget,
    ) -> Vec<LanforgeEvent> {
        self.mutate_device(mac, |dev| {
            let changed = match target {
                LeaseTarget::V4 => {
                    if matches!(dev.v4, IPv4State::None) {
                        false
                    } else {
                        dev.v4 = IPv4State::None;
                        true
                    }
                }
                LeaseTarget::V6 { iaid } => {
                    let initial_len = dev.v6.len();
                    dev.v6
                        .retain(|s| !matches!(s, IPv6State::Dynamic(l) if l.iaid == iaid));
                    dev.v6.len() != initial_len
                }
                LeaseTarget::V6Prefix { iaid } => {
                    let initial_len = dev.v6_prefixes.len();
                    dev.v6_prefixes.retain(|p| p.iaid != iaid);
                    dev.v6_prefixes.len() != initial_len
                }
            };

            if changed {
                Some(DeviceChange::LeaseExpired { target })
            } else {
                None
            }
        })
    }

    pub(crate) fn handle_ip_deleted(&mut self, ip: IpAddr) -> Vec<LanforgeEvent> {
        let mac = self.indices.ip_index.get(&ip).copied();
        if let Some(mac) = mac {
            let events = self.mutate_device(mac, |dev| {
                if dev.delete_ip(ip) {
                    Some(DeviceChange::IpDeleted { ip })
                } else {
                    None
                }
            });

            // Cleanup discovery caches
            if let IpAddr::V6(v6) = ip {
                self.discovery.ndp_cache.remove(&v6);
            }

            events
        } else {
            Vec::new()
        }
    }

    pub(crate) fn handle_ip_offline(&mut self, ip: IpAddr) -> Vec<LanforgeEvent> {
        let mac = self.indices.ip_index.get(&ip).copied();
        mac.map_or_else(Vec::new, |mac| {
            self.mutate_device(mac, |dev| {
                if dev.mark_ip_offline(ip) {
                    Some(DeviceChange::IpOffline { ip })
                } else {
                    None
                }
            })
        })
    }

    pub(crate) fn handle_interface_ips_changed(
        &mut self,
        ifindex: u32,
        state: InterfaceState,
    ) -> Vec<LanforgeEvent> {
        self.network.interface_ips.insert(ifindex, state);
        vec![LanforgeEvent::Network(NetworkEvent::InterfaceUpdated {
            ifindex,
        })]
    }

    pub(crate) fn handle_prune_zombies(&mut self) -> Vec<LanforgeEvent> {
        let max_age = Duration::from_hours(1);
        let mut removed = Vec::new();
        self.devices.retain(|mac, dev| {
            if dev.is_zombie(max_age) {
                removed.push(*mac);
                false
            } else {
                true
            }
        });

        if !removed.is_empty() {
            self.rebuild_indices();
            return removed
                .into_iter()
                .map(|mac| LanforgeEvent::Device(DeviceEvent::Purged { mac }))
                .collect();
        }
        Vec::new()
    }

    pub(crate) fn handle_rebuild_dns_indices(&mut self) -> Vec<LanforgeEvent> {
        self.indices.clear();
        for (mac, dev) in &self.devices {
            self.indices.index_device(*mac, dev);
        }
        Vec::new()
    }

    pub(crate) fn handle_class_hint(
        &mut self,
        mac: MacAddr,
        class: DeviceClass,
    ) -> Vec<LanforgeEvent> {
        self.mutate_device(mac, |dev| {
            if dev.class == class {
                None
            } else {
                dev.class = class;
                Some(DeviceChange::Classified { class })
            }
        })
    }

    pub(crate) fn handle_topology_updated(
        &mut self,
        mac: MacAddr,
        parent_mac: Option<MacAddr>,
        port: Option<String>,
        ifindex: u32,
    ) -> Vec<LanforgeEvent> {
        self.mutate_device(mac, |dev| {
            let new_topo = TopologyInfo {
                parent_mac,
                port: port.clone(),
                local_ifindex: ifindex,
                last_updated: SystemTime::now(),
            };

            if let Some(old) = &dev.topology {
                let same_topo = old.parent_mac == new_topo.parent_mac
                    && old.port == new_topo.port
                    && old.local_ifindex == new_topo.local_ifindex;

                if same_topo {
                    return None;
                }
            }

            dev.topology = Some(new_topo);
            Some(DeviceChange::TopologyChanged { parent_mac, port })
        })
    }

    pub(crate) fn handle_reset(&mut self) -> Vec<LanforgeEvent> {
        self.devices.clear();
        self.static_entries.clear();
        self.indices.clear();
        self.discovery.clear();
        self.network.clear();
        Vec::new()
    }

    pub(crate) fn handle_neighbor_batch(
        &mut self,
        entries: Vec<(MacAddr, IpAddr, bool)>,
    ) -> Vec<LanforgeEvent> {
        let mut grouped: HashMap<MacAddr, Vec<(IpAddr, bool)>> = HashMap::new();
        for (mac, ip, active) in entries {
            grouped.entry(mac).or_default().push((ip, active));
        }
        let mut events = Vec::new();
        for (mac, updates) in &grouped {
            let mac = *mac;
            let mut dev_events = self.mutate_device(mac, |dev| {
                let mut first_change = None;
                for (ip, active) in updates {
                    match ip {
                        IpAddr::V4(v4) => {
                            if let Some(c) = dev.apply_arp_observation(*v4, *active)
                                && first_change.is_none()
                            {
                                first_change = Some(c);
                            }
                        }
                        IpAddr::V6(v6) => {
                            if let Some(c) = dev.apply_slaac_observation(*v6, *active)
                                && first_change.is_none()
                            {
                                first_change = Some(c);
                            }
                        }
                    }
                }
                first_change
            });
            events.append(&mut dev_events);

            // Re-handle NDP cache update
            for (ip, _) in updates {
                if let IpAddr::V6(v6) = ip {
                    self.discovery
                        .ndp_cache
                        .insert(*v6, (mac, SystemTime::now()));
                }
            }
        }
        events
    }

    pub fn expire_stale(&mut self, ip_expiry_threshold: Duration) -> Vec<LanforgeEvent> {
        let now = SystemTime::now();
        let mut events = Vec::new();

        let macs: Vec<MacAddr> = self.devices.keys().copied().collect();
        for mac in macs {
            let mut dev_events = self.mutate_device(mac, |dev| {
                let changes = dev.expire_stale_inner(now, ip_expiry_threshold);
                changes.into_iter().next()
            });
            events.append(&mut dev_events);
        }
        events
    }
}
