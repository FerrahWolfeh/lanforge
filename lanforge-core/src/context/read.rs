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
//! use lanforge_core::state::State;
//! use lanforge_core::bus::EventBus;
//! use lanforge_core::identifiers::MacAddr;
//! use std::sync::Arc;
//!
//! let bus = Arc::new(EventBus::new());
//! let ctx = LanforgeContext::new(bus, State::new(), None);
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

use parking_lot::RwLockReadGuard;

use crate::{
    context::{LanforgeContext, state::StaticRegistry},
    device::Device,
    identifiers::{Duid, MacAddr},
    state::{InterfaceState, State},
};

impl LanforgeContext {
    /// Provides direct read access to the underlying device state.
    pub fn read(&self) -> RwLockReadGuard<'_, State> {
        self.inner.state.read()
    }

    /// Runs a read-only query against the device state.
    pub fn query<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&State) -> R,
    {
        f(&self.read())
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
        self.read().get_by_ip(ip)
    }

    /// Retrieves a device by its DUID.
    #[must_use]
    pub fn get_by_duid(&self, duid: &Duid) -> Option<Arc<Device>> {
        self.read().get_by_duid(duid)
    }

    /// Helper to find a MAC address by its IP in the DNS index.
    #[must_use]
    pub fn get_mac_by_ip(&self, ip: IpAddr) -> Option<MacAddr> {
        self.read().get_mac_by_ip(ip)
    }

    /// Produz um registro validado das configurações estáticas.
    #[must_use]
    pub fn get_static_registry(&self) -> StaticRegistry {
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

    /// Returns the current DNS statistics.
    #[must_use]
    pub fn get_dns_stats(&self) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
        self.inner.dns_stats.read().clone()
    }
}
