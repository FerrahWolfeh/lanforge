//! SLAAC (Stateless Address Autoconfiguration) bootstrap via kernel neighbor table.
//!
//! Discovers IPv6 addresses generated via SLAAC by querying the Linux kernel's
//! NDP neighbor table. This is used to synchronize the `LanforgeContext` with
//! addresses that clients autoconfigured from Router Advertisements.
//!
//! ## Discovery Flow
//!
//! ```mermaid
//! graph TD
//!     K["Kernel NDP Table"] --> D["dump neighbors via netlink"]
//!     D --> E["NeighborEvent parsing"]
//!     E --> F["filter by target prefix"]
//!     E --> G["group IPv6 addresses by MAC"]
//!     E --> H["apply NdpSeen, ArpSeen, IpDeleted"]
//!     G --> I["apply SlaacSynced bulk update"]
//! ```
//!
//! ## When to Call `bootstrap_table()`
//!
//! | Trigger | Reason |
//! | :--- | :--- |
//! | Daemon startup | Initial state synchronization |
//! | GUA prefix change (RA) | Clients will generate new addresses |
//! | Periodic fallback (long interval) | Consistency guarantee against drift |
//!
//! The scan cycle clears known SLAAC addresses for a MAC before repopulating them,
//! ensuring the internal state does not contain stale addresses.

use crate::error::NetworkError;
use crate::ndp::utils::{get_ipv4_neighbors, get_ipv6_neighbors};
use lanforge_core::context::LanforgeContext;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::DeviceUpdate;
use rtnetlink::Handle;
use std::collections::HashMap;
use std::net::Ipv6Addr;

/// Performs a full dump of the kernel's IPv6 and IPv4 neighbor tables.
///
/// This function synchronizes the `LanforgeContext` with the current state of
/// the kernel's NDP/ARP cache. It is NOT called on every neighbor event —
/// instead it is invoked during bootstrap or after major network topology changes.
///
/// # Arguments
///
/// * `ctx` — global context for applying `DeviceUpdate` events
/// * `target_prefix` — string prefix for filtering relevant addresses (e.g., `"fe80"`)
/// * `handle` — rtnetlink handle for neighbor table queries
/// * `gua` — current Global Unicast Address for prefix matching
/// * `ula` — current Unique Local Address for prefix matching
/// * `target_ifindex` — optional interface index filter (if `None`, all interfaces are scanned)
///
/// # Behavior
///
/// For each neighbor entry, the function:
/// 1. Filters by `target_ifindex` if provided
/// 2. Converts the raw netlink message to a `NeighborEvent`
/// 3. Classifies the event via `to_device_update()` (SLAAC, NDP, ARP, or deletion)
/// 4. Groups SLAAC addresses by MAC for bulk `SlaacSynced` updates
/// 5. Applies individual `NdpSeen`, `ArpSeen`, and `IpDeleted` updates immediately
pub async fn bootstrap_table(
    ctx: &LanforgeContext,
    target_prefix: &str,
    handle: &Handle,
    gua: Option<Ipv6Addr>,
    ula: Option<Ipv6Addr>,
    target_ifindex: Option<u32>,
) -> Result<(), NetworkError> {
    let mut neighbors = get_ipv6_neighbors(handle, target_prefix, target_ifindex).await?;
    neighbors.extend(get_ipv4_neighbors(handle, target_ifindex).await?);

    let mut mac_groups: HashMap<MacAddr, Vec<Ipv6Addr>> = HashMap::new();

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
