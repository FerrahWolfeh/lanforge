use lanforge_types::device::Device;
use lanforge_types::identifiers::{Duid, MacAddr};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// High-performance DNS hot-path indices.
///
/// Encapsulates all lookup tables used for O(1) resolution of devices
/// by name, IP, or DUID.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Indices {
    /// DUID to MAC index for `DHCPv6` correlation.
    pub duid_index: HashMap<Duid, MacAddr>,
    /// Hostname (lowercase) → MAC index.
    #[serde(skip)]
    pub name_index: HashMap<String, MacAddr>,
    /// IP address → MAC index.
    #[serde(skip)]
    pub ip_index: HashMap<IpAddr, MacAddr>,
}

impl Indices {
    pub fn clear(&mut self) {
        self.duid_index.clear();
        self.name_index.clear();
        self.ip_index.clear();
    }

    pub fn shrink_to_fit(&mut self) {
        self.name_index.shrink_to_fit();
        self.ip_index.shrink_to_fit();
    }

    /// Removes `name` only if it points at `mac`: a device losing a name another device holds
    /// must not unindex the holder.
    fn release_name(&mut self, name: &str, mac: MacAddr) {
        if self.name_index.get(name) == Some(&mac) {
            self.name_index.remove(name);
        }
    }

    /// Indexes `dev` under `mac`. A name follows the last device indexed with it, except that a
    /// non-static device never takes a static host's name (`is_static` tells which MACs are):
    /// the admin named that host in `[hosts]`, and `dev:<name>` already resolves it first.
    pub fn index_device(
        &mut self,
        mac: MacAddr,
        dev: &Device,
        is_static: impl Fn(&MacAddr) -> bool,
    ) {
        if !dev.hostname.name.is_empty() {
            let key = if dev.hostname.name.bytes().any(|b| b.is_ascii_uppercase()) {
                dev.hostname.name.to_ascii_lowercase()
            } else {
                dev.hostname.name.clone()
            };
            let static_holder = self
                .name_index
                .get(&key)
                .is_some_and(|held| *held != mac && is_static(held));
            if dev.is_static() || !static_holder {
                self.name_index.insert(key, mac);
            }
        }
        self.name_index.insert(dev.dns_fallback.clone(), mac);

        if let Some(duid) = &dev.duid {
            self.duid_index.insert(duid.clone(), mac);
        }

        if let Some(ip) = dev.v4.ip() {
            self.ip_index.insert(IpAddr::V4(ip), mac);
        }
        for state in &dev.v6 {
            if let Some(ip) = state.ip() {
                self.ip_index.insert(IpAddr::V6(ip), mac);
            }
        }
    }

    pub fn unindex_device(&mut self, dev: &Device) {
        if !dev.hostname.name.is_empty() {
            if dev.hostname.name.bytes().any(|b| b.is_ascii_uppercase()) {
                self.release_name(&dev.hostname.name.to_ascii_lowercase(), dev.mac);
            } else {
                self.release_name(dev.hostname.name.as_str(), dev.mac);
            }
        }
        self.release_name(dev.dns_fallback.as_str(), dev.mac);

        if let Some(duid) = &dev.duid {
            self.duid_index.remove(duid);
        }

        if let Some(ip) = dev.v4.ip() {
            self.ip_index.remove(&IpAddr::V4(ip));
        }
        for state in &dev.v6 {
            if let Some(ip) = state.ip() {
                self.ip_index.remove(&IpAddr::V6(ip));
            }
        }
    }
}
