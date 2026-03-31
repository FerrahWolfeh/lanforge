//! Periodic maintenance and high-performance DNS lookup indexing.

use std::time::SystemTime;
use std::{net::IpAddr, sync::Arc};

use tracing::debug;

use crate::device::{IPv4State, IPv6State};

use super::DeviceTable;

impl DeviceTable {
    /// Removes expired leases and inactive dynamic devices from the table.
    ///
    /// Returns `true` if any changes were made, signalling that a
    /// `DeviceTableDirty` event should be dispatched.
    pub fn expire_stale(&mut self) -> bool {
        let now = SystemTime::now();
        let max_age = std::time::Duration::from_secs(7 * 24 * 3600);
        let ndp_max_age = std::time::Duration::from_secs(24 * 3600);
        let mut changed = false;

        let initial_ndp_len = self.ndp_cache.len();
        self.ndp_cache
            .retain(|_, (_, ts)| ts.elapsed().unwrap_or(std::time::Duration::ZERO) <= ndp_max_age);
        if self.ndp_cache.len() != initial_ndp_len {
            changed = true;
        }

        // Limpa leases órfãos expirados
        let initial_orphaned_len = self.orphaned_v6.len();
        self.orphaned_v6.retain(|_, (_, _, expires)| *expires > now);
        if self.orphaned_v6.len() != initial_orphaned_len {
            changed = true;
        }

        let macs: Vec<_> = self.devices.keys().copied().collect();
        for mac in macs {
            let mut remove_device = false;

            if let Some(dev_arc) = self.devices.get(&mac) {
                // Check if anything *would* change first to avoid unnecessary clones
                let v4_expired = if let IPv4State::Dynamic(lease) = &dev_arc.v4 {
                    lease.expires < now
                } else {
                    false
                };

                let v6_expired = dev_arc.v6.iter().any(|s| match s {
                    IPv6State::Dynamic(lease) => lease.expires < now,
                    _ => false,
                });

                let prefix_expired = dev_arc.v6_prefixes.iter().any(|p| p.expires < now);

                if v4_expired || v6_expired || prefix_expired {
                    let mut dev = (**dev_arc).clone();
                    if v4_expired {
                        dev.v4 = IPv4State::None;
                    }
                    if v6_expired {
                        dev.v6.retain(|state| match state {
                            IPv6State::Dynamic(lease) => lease.expires > now,
                            _ => true,
                        });
                    }
                    if prefix_expired {
                        dev.v6_prefixes.retain(|p| p.expires > now);
                    }
                    self.devices.insert(mac, Arc::new(dev));
                    changed = true;
                }

                // Re-get the potentially updated device to check if it should be removed
                if let Some(dev) = self.devices.get(&mac)
                    && !dev.is_static()
                    && matches!(dev.v4, IPv4State::None)
                    && dev.v6.is_empty()
                    && dev.v6_prefixes.is_empty()
                    && dev.last_seen.elapsed().unwrap_or(std::time::Duration::ZERO) > max_age
                {
                    remove_device = true;
                }
            }

            if remove_device {
                if let Some(dev) = self.devices.remove(&mac)
                    && let Some(duid) = &dev.duid
                {
                    self.duid_index.remove(duid);
                }
                changed = true;
                debug!("[state] Removed stale dynamic device {}", mac);
            }
        }

        if changed {
            self.rebuild_dns_indices();
        }

        changed
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
            let _static_entry = self.static_entries.get(&mac);

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
}
