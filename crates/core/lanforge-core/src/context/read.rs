//! Read-only operations on the device state.
//!
//! This module implements all query methods on [`LanforgeContext`](super::LanforgeContext).
//! These operations acquire a read lock on the state and can be executed
//! concurrently by multiple threads.
//!
//! # Query Types
//!
//! | Method                | Lookup By     | Returns          |
//! |-----------------------|---------------|------------------|
//! | `get_device`          | MAC address   | `Option<Device>` |
//! | `get_by_hostname`     | Hostname      | `Option<Device>` |
//! | `get_by_ip`           | IP address    | `Option<Device>` |
//! | `get_by_duid`         | DUID          | `Option<Device>` |
//! | `get_mac_by_ip`       | IP address    | `Option<MacAddr>`|
//! | `all_devices`         | —             | `Vec<Device>`    |
//!
//! # Prefix Queries
//!
//! | Method                    | Description                        |
//! |---------------------------|------------------------------------|
//! | `is_prefix_delegated`     | Check if a prefix is in use        |
//! | `get_interface_gua_at`    | Get GUA prefix for an interface    |
//! | `get_interface_prefixes_opt` | Get GUA and ULA for interface   |
//!
//! # Example
//!
//! ```rust
//! use lanforge_core::context::LanforgeContext;
//! use lanforge_core::bus::EventBus;
//! use lanforge_types::identifiers::MacAddr;
//! use std::sync::Arc;
//!
//! let bus = Arc::new(EventBus::new());
//! let ctx = LanforgeContext::new(bus, Default::default(), None);
//!
//! let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
//! if let Some(device) = ctx.get_device(&mac) {
//!     println!("Found device: {}", device.display_hostname());
//! }
//! ```

use std::{
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
};

use lanforge_types::{
    device::{Device, TransientHost},
    dhcp::{Dhcpv4Stats, Dhcpv6Stats},
    identifiers::{Duid, MacAddr},
    network::DnsReverseResolver,
    network::dns::upstream::UpstreamTarget,
    update::InterfaceState,
};
use arc_swap::Guard;

use crate::{
    context::state::State,
    context::{LanforgeContext, state::StaticRegistry},
};

impl LanforgeContext {
    /// Provides direct read access to the underlying device state.
    #[must_use]
    pub fn read(&self) -> Guard<Arc<State>> {
        self.inner.state.load()
    }

    /// Captures a point-in-time snapshot of the authoritative state behind an `Arc`.
    #[must_use]
    pub fn snapshot(&self) -> Arc<State> {
        self.inner.state.load_full()
    }

    /// Executes a read-only closure with direct access to the State.
    /// Wait-free load without holding any lock.
    ///
    /// **Prefer this over individual getter methods** when performing
    /// multiple lookups in a single operation.
    pub fn with_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&State) -> R,
    {
        f(&self.inner.state.load())
    }

    /// Retrieves a device by its MAC address.
    #[must_use]
    pub fn get_device(&self, mac: &MacAddr) -> Option<Arc<Device>> {
        self.read().get_device(mac)
    }

    /// Retrieves a device by its configured hostname.
    #[must_use]
    pub fn get_by_hostname(&self, hostname: &str) -> Option<Arc<Device>> {
        self.read().get_by_hostname(hostname)
    }

    /// Retrieves a device by any of its assigned IP addresses.
    #[must_use]
    pub fn get_by_ip(&self, ip: &IpAddr) -> Option<Arc<Device>> {
        let mac = self.get_mac_by_ip(*ip)?;
        self.get_device(&mac)
    }

    /// Retrieves a device by its DUID.
    #[must_use]
    pub fn get_by_duid(&self, duid: &Duid) -> Option<Arc<Device>> {
        self.read().get_by_duid(duid)
    }

    /// Helper to find a MAC address by its DUID.
    #[must_use]
    pub fn get_mac_by_duid(&self, duid: &Duid) -> Option<MacAddr> {
        self.read().get_mac_by_duid(duid)
    }

    /// Helper to find a MAC address by its IP in the authoritative index or discovery store.
    #[must_use]
    pub fn get_mac_by_ip(&self, ip: IpAddr) -> Option<MacAddr> {
        let state = self.read();
        let canonical = ip.to_canonical();
        if let Some(mac) = state.indices.ip_index.get(&canonical).copied() {
            return Some(mac);
        }
        if let IpAddr::V6(v6) = canonical
            && let Some(mac) = self.inner.discovery.get_mac(&v6)
        {
            return Some(mac);
        }
        state.get_mac_by_ip(ip)
    }

    /// Helper to find a MAC address from the raw NDP cache.
    #[must_use]
    pub fn get_mac_from_ndp_cache(&self, ip: &Ipv6Addr) -> Option<MacAddr> {
        self.inner.discovery.get_mac(ip)
    }

    /// Produz um registro validado das configurações estáticas.
    #[must_use]
    pub fn get_static_registry(&self) -> Arc<StaticRegistry> {
        self.read().get_static_registry()
    }

    /// Checks if a prefix is already delegated.
    #[must_use]
    pub fn is_prefix_delegated(&self, prefix: Ipv6Addr, len: u8) -> bool {
        self.read().is_prefix_delegated(prefix, len)
    }

    /// Helper path to find GUA prefix for an interface.
    #[must_use]
    pub fn get_interface_gua_at(&self, ifindex: u32) -> Option<(Ipv6Addr, u32, u32)> {
        self.read().get_interface_gua_at(ifindex)
    }

    /// Returns all devices.
    #[must_use]
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn all_devices(&self) -> Vec<Arc<Device>> {
        self.read().devices().collect()
    }

    /// Returns the network state for a specific interface.
    #[must_use]
    pub fn get_interface_state(&self, ifindex: u32) -> InterfaceState {
        self.read().get_interface_ips(ifindex)
    }

    /// Returns GUA and ULA prefixes for an interface (Legacy API).
    #[must_use]
    pub fn get_interface_prefixes_opt(&self, ifindex: u32) -> (Option<Ipv6Addr>, Option<Ipv6Addr>) {
        let state = self.read().get_interface_ips(ifindex);
        (state.gua, state.ula)
    }

    /// Returns the `DHCPv4` stats concretely.
    #[must_use]
    pub fn dhcpv4_stats(&self) -> Arc<Dhcpv4Stats> {
        self.inner.runtime.dhcpv4_stats.clone()
    }

    /// Returns the `DHCPv6` stats concretely.
    #[must_use]
    pub fn dhcpv6_stats(&self) -> Arc<Dhcpv6Stats> {
        self.inner.runtime.dhcpv6_stats.clone()
    }

    /// Retrieves a cached transient host by its IP.
    #[must_use]
    pub fn get_transient_host(&self, ip: &IpAddr) -> Option<TransientHost> {
        self.read().transient_hosts.get(ip).cloned()
    }

    /// Returns all cached transient hosts.
    #[must_use]
    pub fn all_transient_hosts(&self) -> Vec<(IpAddr, TransientHost)> {
        self.read()
            .transient_hosts
            .iter()
            .map(|(ip, host)| (*ip, host.clone()))
            .collect()
    }

    /// Finds a configured reverse DNS resolver target that contains the target IP.
    #[must_use]
    pub fn find_reverse_resolver(&self, ip: IpAddr) -> Option<UpstreamTarget> {
        let state = self.read();
        for resolver in &state.reverse_resolvers {
            if resolver.subnet.contains(ip) {
                return Some(resolver.resolver.clone());
            }
        }
        drop(state);
        None
    }

    /// Returns all configured reverse DNS resolvers.
    #[must_use]
    pub fn all_reverse_resolvers(&self) -> Vec<DnsReverseResolver> {
        self.read().reverse_resolvers.clone()
    }
}
