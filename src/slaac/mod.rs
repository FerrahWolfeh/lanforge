//! Tracker de endereços SLAAC via eventos netlink NDP.
//!
//! Resolve hostname imediatamente: config estática → lease v4.
//! Sem hostname na config/lease → entrada omitida do hosts file.
//!
//! Atualmente lê hostnames do dnsmasq leases file e sufixos estáticos
//! do dnsmasq-dhcp.conf. Nas fases seguintes, passará a usar a DeviceTable
//! interna e o EventBus.

use anyhow::{Context, Result};
use rtnetlink::Handle;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use tracing::{info, warn};

use crate::hosts;
use crate::netlink;

/// Ciclo principal de processamento: lê leases, lê config estática,
/// consulta vizinhos IPv6 via netlink e atualiza o arquivo de hosts.
pub async fn process_cycle(
    leases_file: &str,
    dnsmasq_config: &str,
    target_prefix: &str,
    output_file: &str,
    dns_process: &str,
    handle: &Handle,
) -> Result<()> {
    let mac_map = get_mac_hostname_map(leases_file).unwrap_or_else(|e| {
        warn!("Could not read leases (may be temporary): {}", e);
        HashMap::new()
    });

    if mac_map.is_empty() {
        info!("No leases found at the moment.");
    }

    let static_suffixes = get_static_suffixes(dnsmasq_config).unwrap_or_else(|e| {
        warn!("Failed to read {}: {}", dnsmasq_config, e);
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
                format!("{} {}", ip, hostname)
            } else {
                format!("{} {} {}-slaac", ip, hostname, hostname)
            };
            new_lines.insert(entry);
        }
    }

    let changed = hosts::update_file_if_changed(output_file, new_lines)?;
    if changed {
        hosts::reload_dns(dns_process).await;
    }
    Ok(())
}

/// Lê o arquivo de leases do dnsmasq e retorna um mapa MAC → hostname.
fn get_mac_hostname_map(leases_file: &str) -> Result<HashMap<String, String>> {
    let file =
        File::open(leases_file).with_context(|| format!("Failed to open {}", leases_file))?;
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

/// Lê sufixos IPv6 estáticos do arquivo de config do dnsmasq (dhcp-host entries).
fn get_static_suffixes(dnsmasq_config: &str) -> Result<HashMap<String, String>> {
    let file = File::open(dnsmasq_config)
        .with_context(|| format!("Failed to open {}", dnsmasq_config))?;
    let reader = BufReader::new(file);
    let mut map = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if !line.starts_with("dhcp-host=") {
            continue;
        }

        // Example: dhcp-host=e0:d5:5e:e2:d4:89,[::1057:cafe],192.168.0.2,Archie,infinite
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
