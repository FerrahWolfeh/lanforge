//! Network-specific mutation wrappers.

use std::net::Ipv6Addr;
use crate::{
    context::LanforgeContext,
    state::{DeviceUpdate, InterfaceState},
};

impl LanforgeContext {
    /// Signals a global IPv6 GUA change for an interface.
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
        self.apply(DeviceUpdate::InterfaceIpsChanged { ifindex, state })
    }
}
