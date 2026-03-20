//! Tracker de endereços SLAAC via eventos netlink NDP.
//!
//! Consulta a tabela de vizinhos do kernel para o prefixo alvo e atualiza
//! o `ManagedTable` com os endereços SLAAC observados.
//!
//! ## Integração com o Manager
//!
//! ```text
//! kernel (dump de vizinhos IPv6)
//!     └─► netlink::get_ipv6_neighbors()  →  Vec<NeighborEvent>
//!                   │
//!                   ▼
//!     NeighborEvent::to_device_update(gua_prefix)
//!                   │
//!         ┌─────────┴──────────┐
//!         ▼                    ▼
//!   SlaacObserved          NdpSeen
//!   (dirty → DNS/DB)       (só cache)
//!                   │
//!                   ▼
//!           ManagedTable::update()
//! ```
//!
//! O ciclo limpa os endereços SLAAC de cada MAC antes de repopulá-los,
//! garantindo que endereços obsoletos não persistam entre scans.

use anyhow::Result;
use rtnetlink::Handle;
use std::collections::HashSet;
use std::sync::Arc;

use crate::bus::ManagedTable;
use crate::netlink;
use crate::state::{DeviceUpdate, MacAddr};

/// Executa um ciclo de scan SLAAC:
///
/// 1. Faz dump dos vizinhos IPv6 no `target_prefix` via netlink.
/// 2. Para cada MAC novo neste ciclo, limpa os endereços SLAAC anteriores.
/// 3. Aplica cada endereço observado via `ManagedTable::update`.
///
/// `gua` é o prefixo GUA atual, aprendido dinamicamente pelo RA via
/// `PrefixChanged`. Se `None` (RA ainda não anunciou, ou ISP sem IPv6),
/// todos os eventos viram `NdpSeen` — comportamento conservador correto.
pub async fn process_cycle_v2(
    target_prefix: &str,
    handle: &Handle,
    table: &Arc<ManagedTable>,
    gua: Option<std::net::Ipv6Addr>,
) -> Result<()> {
    let neighbors = netlink::get_ipv6_neighbors(handle, target_prefix).await?;

    let mut seen_macs: HashSet<MacAddr> = HashSet::new();

    for event in neighbors {
        if seen_macs.insert(event.mac) {
            table
                .update(DeviceUpdate::SlaacCleared { mac: event.mac })
                .await;
        }

        let update = event.to_device_update(gua.as_ref());
        table.update(update).await;
    }

    Ok(())
}
