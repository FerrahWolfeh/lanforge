//! Tracker de endereços SLAAC via eventos netlink NDP.
//!
//! Este módulo é responsável por descobrir endereços IPv6 gerados via SLAAC
//! consultando a tabela de vizinhos (neighbor table) do kernel Linux.
//!
//! ## Fluxo de Descoberta
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
//! O ciclo de scan limpa os endereços SLAAC conhecidos antes de repopulá-los,
//! garantindo que o estado interno não contenha endereços obsoletos (stale).

use anyhow::Result;
use rtnetlink::Handle;
use std::collections::HashSet;
use std::sync::Arc;

use crate::bus::ManagedTable;
use crate::netlink;
use crate::state::{DeviceUpdate, MacAddr};

/// Executa um dump completo da tabela de vizinhos IPv6 (Sincronização de Estado).
///
/// No modelo event-driven, esta função NÃO é mais chamada a cada evento.
/// Deve ser invocada apenas:
/// 1. No startup (Bootstrap inicial).
/// 2. Em trocas dinâmicas de prefixo GUA (RA).
/// 3. Em timers de fallback longos (garantia de consistência).
pub async fn bootstrap_table(
    target_prefix: &str,
    handle: &Handle,
    table: &Arc<ManagedTable>,
    gua: Option<std::net::Ipv6Addr>,
) -> Result<()> {
    let neighbors = netlink::get_ipv6_neighbors(handle, target_prefix).await?;

    let mut seen_macs: HashSet<MacAddr> = HashSet::new();

    for event in neighbors {
        // Limpa os endereços antigos daquele MAC apenas na primeira vez
        // que o encontramos durante este dump específico.
        if let Some(mac) = event.mac()
            && seen_macs.insert(mac)
        {
            table.update(DeviceUpdate::SlaacCleared { mac }).await;
        }

        let update = event.to_device_update(gua.as_ref());
        table.update(update).await;
    }

    Ok(())
}
