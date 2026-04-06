//! SLAAC address tracker via Linux kernel netlink NDP events.
//!
//! This module is responsible for discovering IPv6 addresses generated via SLAAC
//! by querying the Linux kernel's neighbor table (NDP cache).
//!
//! ## Discovery Flow
//!
//! ```mermaid
//! graph TD
//!     K[Kernel: IPv6 Neighbor Table]
//!     N[netlink::get_ipv6_neighbors]
//!     E[NeighborEvent]
//!     C[LanforgeContext]
//!
//!     K -->|Dump| N
//!     N -->|Map| E
//!     E -->|SlaacCleared| C
//!     E -->|SlaacObserved / NdpSeen| C
//! ```
//!
//! The scan cycle clears known SLAAC addresses for a MAC before repopulating them,
//! ensuring the internal state does not contain stale addresses.

use crate::error::NetworkError;
use crate::netlink;
use lanforge_core::context::LanforgeContext;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::DeviceUpdate;
use rtnetlink::Handle;
use std::net::Ipv6Addr;

/// Performs a full dump of the IPv6 neighbor table (State Synchronization).
///
/// In the event-driven model, this function is NOT called on every event.
/// It should be invoked only:
/// 1. During startup (Initial Bootstrap).
/// 2. During dynamic GUA prefix changes (RA).
/// 3. In long-interval fallback timers (Consistency guarantee).
pub async fn bootstrap_table(
    ctx: &LanforgeContext,
    target_prefix: &str,
    handle: &Handle,
    gua: Option<Ipv6Addr>,
    ula: Option<Ipv6Addr>,
    target_ifindex: Option<u32>,
) -> Result<(), NetworkError> {
    let neighbors = netlink::get_ipv6_neighbors(handle, target_prefix, target_ifindex).await?;

    let mut mac_groups: std::collections::HashMap<MacAddr, Vec<Ipv6Addr>> =
        std::collections::HashMap::new();

    for event in neighbors {
        if let Some(target) = target_ifindex
            && event.ifindex() != target
        {
            continue;
        }

        if let Some(mac) = event.mac() {
            let update = event.to_device_update(gua.as_ref(), ula.as_ref());
            match update {
                DeviceUpdate::SlaacObserved { addr, .. } => {
                    mac_groups.entry(mac).or_default().push(addr);
                }
                DeviceUpdate::NdpSeen { ip, .. } => {
                    let _ = ctx.apply(&DeviceUpdate::NdpSeen { mac, ip });
                }
                DeviceUpdate::ArpSeen { ip, .. } => {
                    let _ = ctx.apply(&DeviceUpdate::ArpSeen { mac, ip });
                }
                DeviceUpdate::IpDeleted { ip } => {
                    let _ = ctx.apply(&DeviceUpdate::IpDeleted { ip });
                }
                _ => {}
            }
        }
    }

    for (mac, addresses) in mac_groups {
        let _ = ctx.apply(&DeviceUpdate::SlaacSynced { mac, addresses });
    }

    Ok(())
}
