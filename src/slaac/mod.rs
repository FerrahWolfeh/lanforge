//! Tracker de endereços SLAAC via eventos netlink NDP.
//!
//! Resolve hostname imediatamente: config estática → lease v4 → omitido.
//!
//! Dois modos de operação:
//! - v1 (legado): lê dnsmasq.leases + dnsmasq-dhcp.conf (será removido na Fase 2C)
//! - v2: usa DeviceTable diretamente (ativo quando DeviceTable é passada)

use anyhow::Result;
use rtnetlink::Handle;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::netlink;
use crate::state::{DeviceTable, MacAddr};

// ---------------------------------------------------------------------------
// v2 — DeviceTable-based (new path)
// ---------------------------------------------------------------------------

/// Processo de scan v2: consulta vizinhos IPv6 via netlink, atualiza DeviceTable,
/// e regenera o hosts file a partir da tabela.
pub async fn process_cycle_v2(
    target_prefix: &str,
    handle: &Handle,
    table: &Arc<RwLock<DeviceTable>>,
) -> Result<()> {
    let neighbors = netlink::get_ipv6_neighbors(handle, target_prefix).await?;

    {
        let mut t = table.write().await;

        // Collect all MACs we'll see this cycle to clear stale SLAAC addrs
        let mut seen_macs: HashSet<MacAddr> = HashSet::new();

        for (ip_str, mac_str) in &neighbors {
            let Some(mac) = MacAddr::parse(mac_str) else {
                continue;
            };
            let Ok(addr) = ip_str.parse::<Ipv6Addr>() else {
                continue;
            };

            if !seen_macs.contains(&mac) {
                // First time seeing this MAC in this cycle → clear old SLAAC entries
                t.clear_slaac(mac);
                seen_macs.insert(mac);
            }

            t.record_slaac(mac, addr);
        }
    }

    Ok(())
}


