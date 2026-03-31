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
//!     T[ManagedTable]
//!
//!     K -->|Dump| N
//!     N -->|Map| E
//!     E -->|SlaacCleared| T
//!     E -->|SlaacObserved / NdpSeen| T
//! ```
//!
//! The scan cycle clears known SLAAC addresses for a MAC before repopulating them,
//! ensuring the internal state does not contain stale addresses.

use crate::error::Result;
use lanforge_core::state::update::DeviceUpdate;
use rtnetlink::Handle;
use std::collections::HashSet;

use crate::netlink;
use lanforge_core::context::LanforgeContext;
use lanforge_core::identifiers::MacAddr;

/// Performs a full dump of the IPv6 neighbor table (State Synchronization).
///
/// In the event-driven model, this function is NOT called on every event.
/// It should be invoked only:
/// 1. During startup (Initial Bootstrap).
/// 2. During dynamic GUA prefix changes (RA).
/// 3. In long-interval fallback timers (Consistency guarantee).
pub async fn bootstrap_table(
    target_prefix: &str,
    handle: &Handle,
    gua: Option<std::net::Ipv6Addr>,
) -> Result<()> {
    let neighbors = netlink::get_ipv6_neighbors(handle, target_prefix).await?;

    let mut seen_macs: HashSet<MacAddr> = HashSet::new();

    for event in neighbors {
        // Clear old addresses for this MAC only the first time
        // we encounter it during this specific dump.
        if let Some(mac) = event.mac()
            && seen_macs.insert(mac)
        {
            let t = LanforgeContext::table();
            let _ = t.update(&DeviceUpdate::SlaacCleared { mac });
        }

        let update = event.to_device_update(gua.as_ref());
        let t = LanforgeContext::table();
        let _ = t.update(&update);
    }

    Ok(())
}
