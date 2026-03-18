//! Tracker de endereços SLAAC via eventos netlink NDP.
//!
//! Resolve hostname imediatamente: config estática → lease v4 → omitido.
//!
//! Dois modos de operação:
//! - v1 (legado): lê dnsmasq.leases + dnsmasq-dhcp.conf (será removido na Fase 2C)
//! - v2: usa DeviceTable diretamente (ativo quando DeviceTable é passada)

use anyhow::{Context, Result};
use rtnetlink::Handle;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::hosts;
use crate::netlink;
use crate::state::{DeviceTable, MacAddr};

// ---------------------------------------------------------------------------
// v2 — DeviceTable-based (new path)
// ---------------------------------------------------------------------------

/// Processo de scan v2: consulta vizinhos IPv6 via netlink, atualiza DeviceTable,
/// e regenera o hosts file a partir da tabela.
pub async fn process_cycle_v2(
    target_prefix: &str,
    output_file: &str,
    dns_process: &str,
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

        // Write hosts file from table state
        let changed = hosts::write_hosts_from_table(&t, output_file)?;
        if changed {
            drop(t); // release lock before async DNS reload
            hosts::reload_dns(dns_process).await;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// v1 — Legacy dnsmasq-based (kept for fallback during transition)
// ---------------------------------------------------------------------------

/// Ciclo legado: lê dnsmasq.leases + dnsmasq-dhcp.conf.
/// Será removido na Fase 2C.
pub async fn process_cycle_legacy(
    leases_file: &str,
    dnsmasq_config: &str,
    target_prefix: &str,
    output_file: &str,
    dns_process: &str,
    handle: &Handle,
) -> Result<()> {
    let mac_map = get_mac_hostname_map(leases_file).unwrap_or_else(|e| {
        warn!("Could not read leases (may be temporary): {e}");
        HashMap::new()
    });

    if mac_map.is_empty() {
        info!("No leases found at the moment.");
    }

    let static_suffixes = get_static_suffixes(dnsmasq_config).unwrap_or_else(|e| {
        warn!("Failed to read {dnsmasq_config}: {e}");
        HashMap::new()
    });

    let neighbors = netlink::get_ipv6_neighbors(handle, target_prefix).await?;

    let mut new_lines: HashSet<String> = HashSet::new();

    for (ip, mac) in neighbors {
        let mac_norm = mac.to_lowercase();

        if let Some(hostname) = mac_map.get(&mac_norm) {
            let is_static_ip = static_suffixes
                .get(&mac_norm)
                .map(|suffix| ip.ends_with(suffix.trim_matches(|c| c == '[' || c == ']')))
                .unwrap_or(false);

            let entry = if is_static_ip {
                format!("{ip} {hostname}")
            } else {
                format!("{ip} {hostname} {hostname}-slaac")
            };
            new_lines.insert(entry);
        }
    }

    let changed = hosts::update_file_if_changed_legacy(output_file, new_lines)?;
    if changed {
        hosts::reload_dns(dns_process).await;
    }
    Ok(())
}

fn get_mac_hostname_map(leases_file: &str) -> Result<HashMap<String, String>> {
    let file = File::open(leases_file).with_context(|| format!("Failed to open {leases_file}"))?;
    let reader = BufReader::new(file);
    let mut map = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let mac = parts[1].to_lowercase();
            let hostname = parts[3].to_string();
            if hostname != "*" {
                map.insert(mac, hostname);
            }
        }
    }
    Ok(map)
}

fn get_static_suffixes(dnsmasq_config: &str) -> Result<HashMap<String, String>> {
    let file =
        File::open(dnsmasq_config).with_context(|| format!("Failed to open {dnsmasq_config}"))?;
    let reader = BufReader::new(file);
    let mut map = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if !line.starts_with("dhcp-host=") {
            continue;
        }

        let content = line.trim_start_matches("dhcp-host=");
        let parts: Vec<&str> = content.split(',').collect();

        let mut mac = None;
        let mut ipv6_suffix = None;

        for part in parts {
            let part = part.trim();
            if part.contains(':') && !part.contains('[') && part.len() == 17 {
                mac = Some(part.to_string());
            } else if part.starts_with('[') && part.ends_with(']') {
                ipv6_suffix = Some(part.to_string());
            }
        }

        if let (Some(m), Some(s)) = (mac, ipv6_suffix) {
            map.insert(m, s);
        }
    }
    Ok(map)
}
