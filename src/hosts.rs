//! Escrita do arquivo de hosts para pihole-FTL e recarregamento do DNS.
//!
//! Gera o arquivo a partir dos mapeamentos conhecidos e envia SIGHUP
//! para o processo DNS configurado quando o conteúdo muda.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use tracing::{debug, info, warn};

/// Compara `new_lines` com o conteúdo atual de `output_file`.
/// Escreve o arquivo apenas se houver diferença. Retorna `true` se escreveu.
pub fn update_file_if_changed(output_file: &str, new_lines: HashSet<String>) -> Result<bool> {
    let mut old_lines: HashSet<String> = HashSet::new();

    if let Ok(file) = File::open(output_file) {
        for l in BufReader::new(file).lines().map_while(Result::ok) {
            old_lines.insert(l.trim().to_string());
        }
    }

    let added: Vec<_> = new_lines.difference(&old_lines).collect();
    let removed: Vec<_> = old_lines.difference(&new_lines).collect();

    if !added.is_empty() {
        info!("Adding:");
        for item in &added {
            info!("  + {}", item);
        }
    }
    if !removed.is_empty() {
        info!("Removing:");
        for item in &removed {
            info!("  - {}", item);
        }
    }

    if !added.is_empty() || !removed.is_empty() {
        let mut content: Vec<_> = new_lines.into_iter().collect();
        content.sort();

        let mut file = File::create(output_file).context("Error writing hosts file")?;
        for line in &content {
            writeln!(file, "{}", line)?;
        }
        Ok(true)
    } else {
        debug!("No changes.");
        Ok(false)
    }
}

/// Envia SIGHUP ao processo DNS (ex: pihole-FTL) para recarregar o hosts file.
pub async fn reload_dns(process_name: &str) {
    match tokio::process::Command::new("pkill")
        .args(["-HUP", process_name])
        .status()
        .await
    {
        Ok(status) if status.success() => {
            info!("Sent SIGHUP to '{}'.", process_name);
        }
        Ok(_) => {
            warn!("Could not find process '{}' to reload.", process_name);
        }
        Err(e) => {
            warn!("Failed to run pkill: {}", e);
        }
    }
}
