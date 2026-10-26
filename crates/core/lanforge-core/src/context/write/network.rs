//! Network-specific mutation wrappers.

use crate::context::LanforgeContext;
use lanforge_types::network::Ipv6Prefix;
use lanforge_types::update::{DeviceUpdate, InterfaceState};
use std::net::Ipv6Addr;

impl LanforgeContext {
    /// Signals a global IPv6 GUA change for an interface using a specific host address.
    #[must_use]
    pub fn signal_gua_change(
        &self,
        ifindex: u32,
        gua: Ipv6Addr,
        preferred: u32,
        valid: u32,
    ) -> bool {
        let state = InterfaceState {
            gua: Some(gua),
            gua_preferred: preferred,
            gua_valid: valid,
            ..Default::default()
        };
        self.apply(DeviceUpdate::InterfaceIpsChanged {
            ifindex,
            state: Box::new(state),
        })
    }

    /// Signals a global IPv6 GUA change for an interface using a network prefix.
    #[must_use]
    pub fn signal_gua_prefix_change(
        &self,
        ifindex: u32,
        prefix: Ipv6Prefix,
        preferred: u32,
        valid: u32,
    ) -> bool {
        self.signal_gua_change(ifindex, prefix.to_addr(), preferred, valid)
    }
}
