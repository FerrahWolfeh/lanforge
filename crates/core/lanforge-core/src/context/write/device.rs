//! Device-specific mutation wrappers.

use crate::context::LanforgeContext;
use lanforge_types::device::{Origin, StaticHost};
use lanforge_types::identifiers::{DeviceIdentifier, MacAddr};
use lanforge_types::network::dns::adblock::RewriteAnswer;
use lanforge_types::network::firewall::ForwardTarget;
use lanforge_types::update::{CliHostUpdate, DeviceUpdate, FieldUpdate};
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, SystemTime};

#[cfg(test)]
use lanforge_types::device::Device;
#[cfg(test)]
use lanforge_types::device::Ipv6AddrOrSuffix;
#[cfg(test)]
use lanforge_types::identifiers::Duid;
#[cfg(test)]
use std::net::Ipv4Addr;

impl LanforgeContext {
    /// The static hosts in the device table (by hostname, then MAC): what `[hosts]` holds.
    #[must_use]
    pub fn static_hosts(&self) -> Vec<StaticHost> {
        let mut hosts: Vec<_> = self.with_state(|state| {
            state
                .devices
                .values()
                .filter_map(|dev| dev.static_host())
                .collect()
        });
        hosts.sort_by(|a, b| {
            (a.hostname.to_lowercase(), a.mac).cmp(&(b.hostname.to_lowercase(), b.mac))
        });
        hosts
    }

    /// Makes the device table's static hosts exactly `hosts` (`[hosts]`, its only source): a
    /// listed host is (re)reserved where it differs, a static host no longer listed becomes a
    /// discovered device again (`HostDemoted`). Returns one message per host not applied: the
    /// router itself cannot be a static host.
    #[must_use = "the messages name hosts that were not applied"]
    pub fn apply_static_hosts(&self, hosts: &[StaticHost]) -> Vec<String> {
        let mut issues = Vec::new();
        for host in hosts {
            let live = self.get_device(&host.mac);
            if live.as_ref().is_some_and(|d| d.origin == Origin::System) {
                issues.push(format!(
                    "[hosts.\"{}\"] mac = \"{}\" is this router; not a static host",
                    host.hostname, host.mac
                ));
                continue;
            }
            if live.and_then(|d| d.static_host()).as_ref() == Some(host) {
                continue;
            }
            let _ = self.apply(DeviceUpdate::CliHostUpdated {
                mac: host.mac,
                update: Box::new(CliHostUpdate {
                    hostname: if host.hostname.is_empty() {
                        FieldUpdate::NoChange
                    } else {
                        FieldUpdate::Set(host.hostname.clone())
                    },
                    duid: FieldUpdate::NoChange,
                    v4_static: host.v4.into(),
                    v6_suffix: host.v6.into(),
                    boot_file: host.boot_file.clone().into(),
                    dns_fallback: FieldUpdate::NoChange,
                    class: FieldUpdate::NoChange,
                    origin: Origin::Static,
                }),
            });
        }
        for live in self.static_hosts() {
            if !hosts.iter().any(|h| h.mac == live.mac) {
                let _ = self.apply(DeviceUpdate::HostDemoted { mac: live.mac });
            }
        }
        // A demoted host's name is no longer pinned by `[hosts]`: a reference binds it now,
        // before any other device can announce it.
        self.refresh_name_references();
        issues
    }

    /// The names `dev:<name>` port forwards, IPv6 pinholes and DNS rewrites target, lowercase.
    /// Adblock references never bind (see `state/names.rs`).
    fn referenced_device_names(&self) -> HashSet<String> {
        let mut names = HashSet::new();
        if let Some(fw) = self.get_firewall_config() {
            for pf in &fw.port_forwards {
                if let ForwardTarget::Device(DeviceIdentifier::Name(name)) = &pf.internal_ip {
                    names.insert(name.to_ascii_lowercase());
                }
            }
        }
        self.with_config(|cfg| {
            for rule in &cfg.dns_rewrites {
                let mut answer = Some(&rule.answer);
                while let Some(RewriteAnswer::Device {
                    identifier,
                    fallback,
                }) = answer
                {
                    if let DeviceIdentifier::Name(name) = identifier {
                        names.insert(name.to_ascii_lowercase());
                    }
                    answer = fallback.as_deref();
                }
            }
        });
        names
    }

    /// Binds the names the forwards and rewrites target now and unbinds the ones they dropped:
    /// at start (after the saved bindings are restored), on every firewall or rewrite change
    /// and after `[hosts]` changes.
    pub fn refresh_name_references(&self) {
        let names = self.referenced_device_names();
        let events = self.with_state_mut(|state| state.set_name_references(names));
        self.publish_events(&events);
    }

    /// Restores the name bindings saved in redb. Call it at start, before `[hosts]` and the
    /// references are applied and before any service runs.
    pub fn restore_name_bindings(&self, bindings: BTreeMap<String, MacAddr>) {
        self.with_state_mut(|state| state.restore_name_bindings(bindings));
    }

    /// The names bound to devices (lowercase name → MAC), as redb keeps them.
    #[must_use]
    pub fn name_bindings(&self) -> BTreeMap<String, MacAddr> {
        self.with_state(|state| {
            state
                .name_bindings
                .iter()
                .map(|(name, mac)| (name.clone(), *mac))
                .collect()
        })
    }

    /// Triggers the background garbage collection process.
    pub fn expire_stale(&self, interval: Duration) {
        let events = self.with_state_mut(|state| state.expire_stale(interval));
        self.inner.discovery.prune_stale(Duration::from_hours(2));

        self.publish_events(&events);
    }

    /// Attempts a Just-In-Time lookup for a hostname.
    /// If found, the device is promoted to the hot-path index.
    #[must_use]
    pub fn find_mac_by_hostname_jit(
        &self,
        hostname: &str,
        last_seen_threshold: Option<Duration>,
    ) -> Option<MacAddr> {
        let found_mac = {
            let state = self.read();
            let now = SystemTime::now();
            state.devices.iter().find_map(|(mac, dev)| {
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
            })
        };

        found_mac.inspect(|&mac| {
            self.with_state_mut(|state| state.promote_device_to_index(mac));
        })
    }

    /// Adds a static device to the registry (test-only helper).
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn add_static_device(
        &self,
        mac: MacAddr,
        hostname: String,
        duid: Option<Duid>,
        v4_static: Option<Ipv4Addr>,
        v6_suffix: Option<Ipv6AddrOrSuffix>,
        boot_file: Option<String>,
        origin: Origin,
    ) {
        let _ = self.apply(DeviceUpdate::CliHostUpdated {
            mac,
            update: Box::new(CliHostUpdate {
                hostname: FieldUpdate::from(Some(hostname)),
                duid: FieldUpdate::from(duid),
                v4_static: FieldUpdate::from(v4_static),
                v6_suffix: FieldUpdate::from(v6_suffix),
                origin,
                boot_file: FieldUpdate::from(boot_file),
                dns_fallback: FieldUpdate::NoChange,
                class: FieldUpdate::NoChange,
            }),
        });
    }

    /// Mutates a device directly (test-only helper).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutation closure is not executed, which would
    /// indicate a logical error in the state transition.
    #[cfg(test)]
    pub fn mutate_device<F, R>(&self, mac: MacAddr, f: F) -> R
    where
        F: FnOnce(&mut Device) -> R,
    {
        let mut res = None;
        self.with_state_mut(|state| {
            state.mutate_device(mac, |dev| {
                res = Some(f(dev));
                None // No event emitted by this helper itself
            });
        });
        res.expect("mutation failed")
    }

    /// Sets whether indexing is enabled (test-only helper).
    #[cfg(test)]
    pub fn set_indexing_enabled(&self, enabled: bool) {
        self.with_state_mut(|state| state.set_indexing_enabled(enabled));
    }

    /// Inserts a device directly (test-only helper).
    #[cfg(test)]
    pub fn insert_device(&self, mac: MacAddr, dev: Device) {
        self.with_state_mut(|state| state.insert_device(mac, dev));
    }
}
