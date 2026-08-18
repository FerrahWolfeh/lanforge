//! Interface address discovery and monitoring helpers.

use futures::stream::TryStreamExt;
use lanforge_core::context::LanforgeContext;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::update::{DeviceUpdate, InterfaceState};
use rtnetlink::Handle;
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::link::LinkAttribute;
use std::net::IpAddr;

use crate::error::NetworkError;

/// Queries the kernel for all IP addresses (IPv4, Link-Local, GUA, ULA) and MAC address
/// for the specified interface index, applying the resulting state to the context.
pub async fn refresh_interface(
    handle: &Handle,
    ifindex: u32,
    ctx: &LanforgeContext,
) -> Result<InterfaceState, NetworkError> {
    let mut stream = handle
        .address()
        .get()
        .set_link_index_filter(ifindex)
        .execute();

    let mut state = InterfaceState::default();

    while let Some(msg) = stream.try_next().await? {
        for attr in &msg.attributes {
            match attr {
                AddressAttribute::Address(IpAddr::V4(v4)) => {
                    state.v4 = Some((*v4, msg.header.prefix_len));
                }
                AddressAttribute::Address(IpAddr::V6(v6)) => {
                    let o = v6.octets();
                    if o[0] == 0xFE && (o[1] & 0xC0) == 0x80 {
                        state.link_local = Some(*v6);
                    } else if (0x20..=0x3F).contains(&o[0]) {
                        state.gua = Some(*v6);
                    } else if o[0] == 0xFD {
                        state.ula = Some(*v6);
                    }
                }
                AddressAttribute::CacheInfo(info) => {
                    state.gua_preferred = info.ifa_preferred;
                    state.gua_valid = info.ifa_valid;
                }
                _ => {}
            }
        }
    }

    // Fetch MAC address via rtnetlink link query
    let mut link_stream = handle.link().get().match_index(ifindex).execute();
    if let Some(msg) = link_stream.try_next().await? {
        for attr in &msg.attributes {
            if let LinkAttribute::Address(addr_bytes) = attr {
                state.mac = MacAddr::from_slice(addr_bytes);
                break;
            }
        }
    }

    // Update global context table
    let _ = ctx.apply(DeviceUpdate::InterfaceIpsChanged {
        ifindex,
        state: state.clone(),
    });

    Ok(state)
}
