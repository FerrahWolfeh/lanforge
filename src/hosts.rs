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
        info!("[hosts] Adding:");
        for item in &added {
            info!("[hosts]   + {item}");
        }
    }
    if !removed.is_empty() {
        info!("[hosts] Removing:");
        for item in &removed {
            info!("[hosts]   - {item}");
        }
    }

    if !added.is_empty() || !removed.is_empty() {
        let mut file = File::create(output_file).context("Error writing hosts file")?;
        for line in &new_lines {
            writeln!(file, "{line}")?;
        }
        Ok(true)
    } else {
        debug!("[hosts] No changes.");
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
            info!("[hosts] Sent SIGHUP to '{process_name}'.");
        }
        Ok(_) => {
            warn!("[hosts] Could not find process '{process_name}' to reload.");
        }
        Err(e) => {
            warn!("[hosts] Failed to run pkill: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StaticDeviceCfg;
    use crate::state::{MacAddr, V4Lease, V6Lease};
    use std::fs;
    use std::time::SystemTime;

    #[test]
    fn writes_correct_host_formats_for_v4_v6_and_slaac() {
        let dir = std::env::temp_dir();
        let file_path = dir.join("lanforge_format_hosts.txt");
        let path_str = file_path.to_str().unwrap();
        let _ = fs::remove_file(&file_path);

        let mut table = DeviceTable::new();
        let mac = MacAddr::parse("e0:d5:5e:e2:d4:89").unwrap();

        // Simulando a configuração estática com sufixo customizado
        table.load_static_devices(&[StaticDeviceCfg {
            mac: "e0:d5:5e:e2:d4:89".into(),
            hostname: "Archie".into(),
            v4_ip: None,
            v6_suffix: Some("::1057:cafe".into()),
        }]);

        let dev = table.get_or_insert(mac);
        dev.v4 = Some(V4Lease {
            ip: "192.168.0.2".parse().unwrap(),
            expires: SystemTime::now(),
        });
        dev.v6 = Some(V6Lease {
            ip: "fd97::100".parse().unwrap(),
            expires: SystemTime::now(),
        });

        // SLAAC 1: Bate com o sufixo estático (NÃO deve ter o alias -slaac)
        table.record_slaac(mac, "fd97:f00d:cafe:3731::1057:cafe".parse().unwrap());
        // SLAAC 2: IP aleatório de Privacy Extension (DEVE ter o alias -slaac)
        table.record_slaac(
            mac,
            "fd97:f00d:cafe:3731:7c5a:23c3:41dc:7d9e".parse().unwrap(),
        );

        // Executa a função
        let changed = write_hosts_from_table(&table, path_str).unwrap();
        assert!(changed, "Deveria acusar mudança no arquivo novo");

        let content = fs::read_to_string(&file_path).unwrap();

        assert!(content.contains("192.168.0.2 Archie"), "Faltou V4");
        assert!(content.contains("fd97::100 Archie"), "Faltou V6 dinâmico");
        assert!(
            content.contains("fd97:f00d:cafe:3731::1057:cafe Archie\n")
                || content.contains("fd97:f00d:cafe:3731::1057:cafe Archie\r"),
            "SLAAC que bate com o sufixo não deve ganhar alias -slaac"
        );
        assert!(
            content.contains("fd97:f00d:cafe:3731:7c5a:23c3:41dc:7d9e Archie Archie-slaac"),
            "SLAAC aleatório deve ganhar alias -slaac"
        );
    }

    #[test]
    fn updates_file_only_when_content_differs() {
        let dir = std::env::temp_dir();
        let file_path = dir.join("lanforge_diff_hosts.txt");
        let path_str = file_path.to_str().unwrap();
        let _ = fs::remove_file(&file_path);

        let mut lines = BTreeSet::new();
        lines.insert("192.168.0.10 test-host".to_string());
        lines.insert("fe80::10 test-v6".to_string());

        // 1ª Escrita: Arquivo novo, deve retornar true
        assert!(update_file_if_changed(path_str, lines.clone()).unwrap());

        // 2ª Escrita: Mesmo conteúdo, deve pular (false) e não fazer I/O inútil
        assert!(!update_file_if_changed(path_str, lines.clone()).unwrap());

        // 3ª Escrita: Adicionou linha, deve retornar true
        lines.insert("192.168.0.11 new-host".to_string());
        assert!(update_file_if_changed(path_str, lines).unwrap());
    }
}
