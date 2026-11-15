//! Addresses linked to a device: addresses it uses outside the LAN's assignment (its tailnet
//! address), so DNS stats and `dev:` adblock selectors see it as the device. They never reach
//! DNS answers, rewrites, forwards or the firewall.

use crate::ClientContext;
use lanforge_api::api::{Response, SimpleSuccess};
use lanforge_core::context::state::State;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::update::DeviceUpdate;
use std::net::IpAddr;

/// Addresses one device may have linked.
pub const MAX_LINKED_ADDRESSES: usize = 16;

/// Why `ip` cannot be linked at all (not a unicast address a client queries from).
fn unlinkable(ip: IpAddr) -> Option<&'static str> {
    if ip.is_unspecified() || ip.is_multicast() || ip.is_loopback() {
        return Some("not a unicast client address");
    }
    match ip {
        IpAddr::V4(v4) if v4.is_link_local() || v4.is_broadcast() => {
            Some("not a routable client address")
        }
        IpAddr::V6(v6) if v6.is_unicast_link_local() => Some("a link-local address"),
        _ => None,
    }
}

/// Why `ip` cannot be linked to `mac`.
fn refusal(state: &State, mac: MacAddr, ip: IpAddr) -> Option<String> {
    let name = |m: MacAddr| state.device_name(m).unwrap_or_else(|| m.to_string());
    if let Some(why) = unlinkable(ip) {
        return Some(why.to_string());
    }
    if let Some(holder) = state.get_mac_by_ip(ip) {
        return Some(format!("the LAN address of {}", name(holder)));
    }
    let other = state.linked_device(ip).filter(|m| *m != mac)?;
    Some(format!("already linked to {}", name(other)))
}

impl ClientContext {
    /// Replaces the addresses linked to `mac`. Refused: an address the LAN assigns to a device
    /// (it already names its device), one linked to another device, more than
    /// [`MAX_LINKED_ADDRESSES`].
    pub async fn handle_device_linked_addresses_set(
        &self,
        mac: MacAddr,
        addresses: Vec<IpAddr>,
    ) -> Response {
        let mut addresses: Vec<IpAddr> =
            addresses.into_iter().map(|ip| ip.to_canonical()).collect();
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.len() > MAX_LINKED_ADDRESSES {
            return Response::Rejected {
                error: format!("A device takes at most {MAX_LINKED_ADDRESSES} linked addresses"),
            };
        }
        let refusal = self.ctx.with_state(|state| {
            if !state.devices.contains_key(&mac) {
                return Some(Response::NotFound {
                    error: format!("No device {mac}"),
                });
            }
            addresses.iter().find_map(|&ip| {
                refusal(state, mac, ip).map(|why| Response::Rejected {
                    error: format!("{ip} cannot be linked: {why}"),
                })
            })
        });
        if let Some(refusal) = refusal {
            return refusal;
        }
        let count = addresses.len();
        let _ = self
            .ctx
            .apply(DeviceUpdate::LinkedAddressesSet { mac, addresses });
        Response::Success(SimpleSuccess {
            message: format!("Device {mac}: {count} linked address(es)"),
        })
    }
}
