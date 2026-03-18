//! Escrita do arquivo de hosts para pihole-FTL e recarregamento do DNS.
//!
//! Gera o arquivo a partir da DeviceTable e envia SIGHUP
//! para o processo DNS configurado quando o conteúdo muda.

use crate::state::DeviceTable;
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use tracing::{debug, info, warn};

/// Gera o hosts file a partir da DeviceTable.
///
/// Para cada Device com hostname conhecido, escreve:
/// - `<v4_ip> <hostname>` (se tiver lease v4)
/// - `<v6_ip> <hostname>` (se tiver lease v6)
/// - `<slaac_ip> <hostname>-slaac` (para cada endereço SLAAC)
///
/// Retorna `true` se o arquivo mudou (e precisa de SIGHUP).
pub fn write_hosts_from_table(table: &DeviceTable, output_file: &str) -> Result<bool> {
    let mut new_lines = BTreeSet::new();

    for device in table.devices() {
        let Some(hostname) = table.hostname_for(&device.mac) else {
            continue;
        };

        if let Some(v4) = &device.v4 {
            new_lines.insert(format!("{} {}", v4.ip, hostname));
        }

        if let Some(v6) = &device.v6 {
            new_lines.insert(format!("{} {}", v6.ip, hostname));
        }

        // Verifica se o suffixo estático existe para marcar corretamente
        let v6_suffix = table.v6_suffix_for(&device.mac);

        for addr in &device.slaac {
            let addr_str = addr.to_string();
            let is_static_ip = v6_suffix
                .map(|suffix| {
                    let clean = suffix.trim_start_matches("::");
                    addr_str.ends_with(clean)
                })
                .unwrap_or(false);

            if is_static_ip {
                new_lines.insert(format!("{addr} {hostname}"));
            } else {
                new_lines.insert(format!("{addr} {hostname} {hostname}-slaac"));
            }
        }
    }

    update_file_if_changed(output_file, new_lines)
}

/// Compara `new_lines` com o conteúdo atual do arquivo.
/// Escreve apenas se houver diferença. Retorna `true` se escreveu.
pub fn update_file_if_changed(output_file: &str, new_lines: BTreeSet<String>) -> Result<bool> {
    let mut old_lines: BTreeSet<String> = BTreeSet::new();

    if let Ok(file) = File::open(output_file) {
        for l in BufReader::new(file).lines().map_while(Result::ok) {
            let trimmed = l.trim().to_string();
            if !trimmed.is_empty() {
                old_lines.insert(trimmed);
            }
        }
    }

    let added: Vec<_> = new_lines.difference(&old_lines).collect();
    let removed: Vec<_> = old_lines.difference(&new_lines).collect();

    if !added.is_empty() {
        info!("Adding:");
        for item in &added {
            info!("  + {item}");
        }
    }
    if !removed.is_empty() {
        info!("Removing:");
        for item in &removed {
            info!("  - {item}");
        }
    }

    if !added.is_empty() || !removed.is_empty() {
        let mut file = File::create(output_file).context("Error writing hosts file")?;
        for line in &new_lines {
            writeln!(file, "{line}")?;
        }
        Ok(true)
    } else {
        debug!("No changes.");
        Ok(false)
    }
}

/// Envia SIGHUP ao processo DNS.
pub async fn reload_dns(process_name: &str) {
    match tokio::process::Command::new("pkill")
        .args(["-HUP", process_name])
        .status()
        .await
    {
        Ok(status) if status.success() => {
            info!("Sent SIGHUP to '{process_name}'.");
        }
        Ok(_) => {
            warn!("Could not find process '{process_name}' to reload.");
        }
        Err(e) => {
            warn!("Failed to run pkill: {e}");
        }
    }
}


