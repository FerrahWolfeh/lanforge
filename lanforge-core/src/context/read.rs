// ---------------------------------------------------------------------------
// Read Operations
// ---------------------------------------------------------------------------

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
