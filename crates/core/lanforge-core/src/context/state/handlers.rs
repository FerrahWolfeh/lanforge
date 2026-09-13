use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use crate::bus::{
    AdminChange, DeviceEvent, EventVec, LanforgeEvent, NetworkChange, NetworkEvent,
    PrefixChangeDetails,
};
use crate::context::state::cache::DiscoveryStore;
use crate::context::state::network::DhcpPoolStats;
use crate::context::state::{
    CliHostUpdate, DeviceClass, FieldUpdate, InterfaceState, LeaseTarget, State, StaticEntry,
};
use lanforge_types::device::{
    DeviceStatus, Hostname, HostnameOrigin, IPv4State, IPv6State, IpClassification, Origin,
    TransientHost, TransientOrigin, V6ObservationOrigin, classify_ipv6,
};
use lanforge_types::identifiers::{Duid, MacAddr};
use lanforge_types::network::{DnsReverseResolver, IpSubnet, Ipv6AddrOrSuffix};
use lanforge_types::update::{DhcpV4PoolUpdate, DhcpV6PoolUpdate};

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

            if let Some(c) = dev.apply_v6_observation(ip, is_active, V6ObservationOrigin::NdpMonitor) {
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

        events
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub(crate) fn handle_arp_seen(
        &mut self,
        mac: MacAddr,
        ip: Ipv4Addr,
        is_active: bool,
    ) -> EventVec {
        self.mutate_device(mac, |dev| dev.apply_arp_observation(ip, is_active))
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
        let events = self.mutate_device_admin(mac, |dev| {
            #[allow(clippy::useless_let_if_seq)]
            let mut result = AdminChange::CliHostUpdated;

            if let FieldUpdate::Set(h) = update.hostname {
                let sanitized = Hostname::sanitize(&h);
                dev.hostname = Hostname {
                    name: sanitized.clone(),
                    origin: HostnameOrigin::Static,
                };
                result = AdminChange::HostnameChanged {
                    hostname: sanitized,
                };
            }
            if let FieldUpdate::Set(d) = update.duid {
                dev.duid = Some(d);
            }
            if let FieldUpdate::Set(v4) = update.v4_static {
                dev.v4 = IPv4State::Static(v4);
                result = AdminChange::V4StaticChanged { ip: Some(v4) };
            } else if update.v4_static == FieldUpdate::Clear {
                dev.v4 = IPv4State::None;
                result = AdminChange::V4StaticChanged { ip: None };
            }
            if let FieldUpdate::Set(v6) = update.v6_suffix {
                dev.v6.retain(|s| !matches!(s, IPv6State::Static(_, _)));
                dev.v6.push(IPv6State::Static(v6, SystemTime::now()));
                result = AdminChange::V6SuffixChanged { suffix: Some(v6) };
            } else if update.v6_suffix == FieldUpdate::Clear {
                dev.v6.retain(|s| !matches!(s, IPv6State::Static(_, _)));
                result = AdminChange::V6SuffixChanged { suffix: None };
            }
            if let FieldUpdate::Set(bf) = update.boot_file {
                let sanitized = bf.replace('\0', "").trim().to_string();
                dev.boot_file = if sanitized.is_empty() {
                    None
                } else {
                    Some(sanitized)
                };
            } else if update.boot_file == FieldUpdate::Clear {
                dev.boot_file = None;
            }
            if let FieldUpdate::Set(df) = update.dns_fallback {
                dev.dns_fallback = df;
            }
            if let FieldUpdate::Set(c) = update.class {
                dev.class = c;
                result = AdminChange::Classified { class: c };
            }
            dev.origin = update.origin;
            dev.managed_at = Some(SystemTime::now());
            Some(result)
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
                        IPv6State::Static(s, _) => Some(*s),
                        _ => None,
                    }),
                    boot_file: dev.boot_file.clone(),
                    origin: update.origin,
                    ignore_dns_log: dev.ignore_dns_log,
                    ignored_log_domains: dev.ignored_log_domains.clone(),
                },
            );
            self.rebuild_static_registry();
        }

        events
    }

    pub(crate) fn handle_ignore_dns_log_set(&mut self, mac: MacAddr, ignore: bool) -> EventVec {
        self.mutate_device(mac, |dev| {
            dev.ignore_dns_log = ignore;
            None
        });
        if let Some(entry) = self.static_entries.get_mut(&mac) {
            entry.ignore_dns_log = ignore;
        }
        EventVec::new()
    }

    pub(crate) fn handle_ignored_log_domains_set(
        &mut self,
        mac: MacAddr,
        domains: Vec<String>,
    ) -> EventVec {
        self.mutate_device(mac, |dev| {
            dev.ignored_log_domains.clone_from(&domains);
            None
        });
        if let Some(entry) = self.static_entries.get_mut(&mac) {
            entry.ignored_log_domains = domains;
        }
        EventVec::new()
    }

    pub(crate) fn handle_host_removed(&mut self, mac: MacAddr) -> EventVec {
        if let Some(dev) = self.devices.remove(&mac) {
            self.indices.unindex_device(&dev);
            if let Some(duid) = &dev.duid {
                self.indices.duid_index.remove(duid);
            }
            self.static_entries.remove(&mac);
            self.rebuild_static_registry();
            return vec![LanforgeEvent::Device(DeviceEvent::Purged { mac })].into();
        }
        EventVec::new()
    }

    pub(crate) fn handle_lease_released(&mut self, mac: MacAddr, target: LeaseTarget) -> EventVec {
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
                Some(NetworkChange::LeaseExpired { target })
            } else {
                None
            }
        })
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

    pub(crate) fn handle_prune_zombies(&mut self, discovery: &DiscoveryStore) -> EventVec {
        let max_age = Duration::from_hours(1);
        let mut removed = Vec::new();
        self.devices.retain(|mac, dev| {
            if dev.origin != Origin::System && dev.is_zombie(max_age) {
                removed.push(*mac);
                false
            } else {
                true
            }
        });

        // Prune discovery caches
        let cache_max_age = Duration::from_hours(2);
        discovery.prune_stale(cache_max_age);

        // Prune transient hosts older than 4 hours
        let now = SystemTime::now();
        let transient_max_age = Duration::from_hours(4);
        self.transient_hosts.retain(|_, host| {
            now.duration_since(host.last_seen)
                .is_ok_and(|d| d < transient_max_age)
        });

        if !removed.is_empty() {
            self.rebuild_indices();
            return removed
                .into_iter()
                .map(|mac| LanforgeEvent::Device(DeviceEvent::Purged { mac }))
                .collect();
        }
        EventVec::new()
    }

    pub(crate) fn handle_rebuild_dns_indices(&mut self) -> EventVec {
        self.indices.clear();
        for (mac, dev) in &self.devices {
            self.indices.index_device(*mac, dev);
        }
        EventVec::new()
    }

    pub(crate) fn handle_class_hint(&mut self, mac: MacAddr, class: DeviceClass) -> EventVec {
        self.mutate_device_admin(mac, |dev| {
            if dev.class == class {
                None
            } else {
                dev.class = class;
                Some(AdminChange::Classified { class })
            }
        })
    }

    pub(crate) fn handle_reset(&mut self, discovery: &DiscoveryStore) -> EventVec {
        self.devices.clear();
        self.static_entries.clear();
        self.rebuild_static_registry();
        self.indices.clear();
        discovery.clear();
        self.interfaces.clear();
        self.transient_hosts.clear();
        self.reverse_resolvers.clear();
        EventVec::new()
    }

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
            let events = self.mutate_device(first_mac, |dev| {
                let mut first_change = None;
                for (_, ip, active) in &entries {
                    let change = match ip {
                        IpAddr::V4(v4) => dev.apply_arp_observation(*v4, *active),
                        IpAddr::V6(v6) => {
                            dev.apply_v6_observation(*v6, *active, V6ObservationOrigin::NdpMonitor)
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
            return events;
        }

        // SLOW-PATH: Multiple MACs in the same batch
        // Re-implementing slow path more clearly
        let mut grouped_updates: HashMap<MacAddr, Vec<(IpAddr, bool)>> = HashMap::new();
        for (mac, ip, active) in entries {
            grouped_updates.entry(mac).or_default().push((ip, active));
        }

        let mut events = EventVec::new();
        for (mac, updates) in grouped_updates {
            let mut dev_events = self.mutate_device(mac, |dev| {
                let mut first_change = None;
                for (ip, active) in &updates {
                    let change = match ip {
                        IpAddr::V4(v4) => dev.apply_arp_observation(*v4, *active),
                        IpAddr::V6(v6) => {
                            dev.apply_v6_observation(*v6, *active, V6ObservationOrigin::NdpMonitor)
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

            for (ip, _) in &updates {
                if let IpAddr::V6(v6) = ip {
                    discovery.insert_ndp(*v6, mac);
                }
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
        EventVec::new()
    }

    pub(crate) fn handle_add_reverse_resolver(&mut self, resolver: DnsReverseResolver) -> EventVec {
        self.reverse_resolvers
            .retain(|r| r.subnet != resolver.subnet);
        self.reverse_resolvers.push(resolver);
        EventVec::new()
    }

    pub(crate) fn handle_remove_reverse_resolver(&mut self, subnet: IpSubnet) -> EventVec {
        self.reverse_resolvers.retain(|r| r.subnet != subnet);
        EventVec::new()
    }

    pub(crate) fn handle_set_reverse_resolvers(
        &mut self,
        resolvers: Vec<DnsReverseResolver>,
    ) -> EventVec {
        self.reverse_resolvers = resolvers;
        EventVec::new()
    }

    pub(crate) fn handle_dhcp_v4_pool_updated(&mut self, update: &DhcpV4PoolUpdate) -> EventVec {
        self.interfaces.v4_pool = Some(DhcpPoolStats {
            range_start: Some(IpAddr::V4(update.range_start)),
            range_end: Some(IpAddr::V4(update.range_end)),
            prefix: None,
            prefix_len: None,
            total: update.total,
            used: update.used,
            available: update.available,
            utilization_percent: update.utilization_percent,
        });
        EventVec::new()
    }

    pub(crate) fn handle_dhcp_v6_pool_updated(&mut self, update: &DhcpV6PoolUpdate) -> EventVec {
        self.interfaces.v6_pools.insert(
            update.pool_id,
            DhcpPoolStats {
                range_start: None,
                range_end: None,
                prefix: Some(IpAddr::V6(update.prefix)),
                prefix_len: Some(update.prefix_len),
                total: update.total,
                used: update.used,
                available: update.available,
                utilization_percent: update.utilization_percent,
            },
        );
        EventVec::new()
    }

    pub(crate) fn handle_pppoe_status_updated(
        &mut self,
        status: Option<Box<lanforge_types::system::PppoeStatusResponse>>,
    ) -> EventVec {
        self.interfaces.pppoe_status = status;
        EventVec::new()
    }

    pub(crate) fn handle_ra_status_updated(
        &mut self,
        status: Option<Box<lanforge_types::system::RaStatusResponse>>,
    ) -> EventVec {
        let old_ula = self.interfaces.ra_status.as_ref().and_then(|r| r.active_ula_prefix);
        let new_ula = status.as_ref().and_then(|r| r.active_ula_prefix);
        self.interfaces.ra_status = status;
        if old_ula != new_ula {
            self.rebuild_indices();
        }
        EventVec::new()
    }


    pub(crate) fn handle_device_interface_seen(
        &mut self,
        mac: MacAddr,
        iface: String,
    ) -> EventVec {
        self.mutate_device(mac, |dev| {
            if dev.iface.as_deref() != Some(&iface) {
                dev.iface = Some(iface);
            }
            None
        })
    }
}
