//! src/control.rs — Interface de controle via Unix Domain Socket (UDS)
//!
//! Permite que ferramentas de CLI ou interfaces locais consultem e controlem
//! o daemon usando JSON sobre um socket Unix local.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{debug, error, info};

use crate::bus::{EventBus, LanforgeEvent, ManagedTable};

// ---------------------------------------------------------------------------
// Protocolo (JSON)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "lowercase")]
pub enum Command {
    /// Status geral do sistema
    Status,
    /// Lista completa de dispositivos gerenciados
    Devices,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Response {
    Status {
        version: String,
        interfaces: Interfaces,
        gua_prefix: Option<String>,
        device_count: usize,
    },
    Devices(Vec<crate::state::Device>),
    Error {
        error: String,
    },
}

#[derive(Debug, Serialize, Clone)]
pub struct Interfaces {
    pub lan: String,
}

// ---------------------------------------------------------------------------
// Serviço
// ---------------------------------------------------------------------------

/// Inicia o serviço de controle UDS.
pub async fn control_service(
    path: String,
    ifaces: Interfaces,
    table: Arc<ManagedTable>,
    bus: Arc<EventBus>,
) -> Result<()> {
    let path_ref = Path::new(&path);

    // Limpeza prévia do socket
    if path_ref.exists() {
        debug!("Limpando socket antigo: {}", path_ref.display());
        fs::remove_file(path_ref).context("falha ao remover socket antigo")?;
    }

    // Garante que o diretório pai existe
    if let Some(parent) = path_ref.parent()
        && !parent.exists()
    {
        debug!("Criando diretório do socket: {}", parent.display());
        fs::create_dir_all(parent).context("falha ao criar diretório para o socket")?;
    }

    let listener = UnixListener::bind(path_ref).context("falha ao bindar socket Unix")?;

    // Define permissões 0666 para facilitar acesso local durante desenvolvimento.
    // Em produção, o systemd RuntimeDirectory pode gerenciar isso.
    if let Err(e) = fs::set_permissions(path_ref, fs::Permissions::from_mode(0o666)) {
        debug!("Aviso: não foi possível setar permissões 0666 no socket: {e}");
    }

    info!("🔌 Controle UDS pronto em {}", path_ref.display());

    let mut bus_rx = bus.subscribe();
    let mut current_gua: Option<String> = None;

    loop {
        tokio::select! {
            // Monitora mudanças de prefixo GUA para reportar no 'status'
            msg = bus_rx.recv() => {
                match msg {
                    Ok(LanforgeEvent::PrefixChanged { gua }) => {
                        current_gua = gua.map(|ip| ip.to_string());
                    }
                    Ok(LanforgeEvent::Shutdown) => {
                        debug!("Control: shutdown recebido");
                        break;
                    }
                    _ => {}
                }
            }

            // Aceita novas conexões CLI
            connection = listener.accept() => {
                match connection {
                    Ok((stream, _)) => {
                        let table = table.clone();
                        let gua = current_gua.clone();
                        let ifaces = ifaces.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, ifaces, table, gua).await {
                                debug!("Control: erro atendendo cliente: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        error!("Control: erro ao aceitar conexão: {e}");
                    }
                }
            }
        }
    }

    // Cleanup gracioso
    if path_ref.exists() {
        let _ = fs::remove_file(path_ref);
    }

    Ok(())
}

async fn handle_client(
    mut stream: tokio::net::UnixStream,
    ifaces: Interfaces,
    table: Arc<ManagedTable>,
    current_gua: Option<String>,
) -> Result<()> {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Loop de REPL JSON
    while reader.read_line(&mut line).await? > 0 {
        let trim_line = line.trim();
        if trim_line.is_empty() {
            line.clear();
            continue;
        }

        let req: Result<Command, _> = serde_json::from_str(trim_line);
        let resp = match req {
            Ok(Command::Status) => {
                let device_count = table.read().await.devices().count();
                Response::Status {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    interfaces: ifaces.clone(),
                    gua_prefix: current_gua.clone(),
                    device_count,
                }
            }
            Ok(Command::Devices) => {
                let devices: Vec<_> = table.read().await.devices().cloned().collect();
                Response::Devices(devices)
            }
            Err(e) => Response::Error {
                error: format!("Comando inválido ou JSON malformado: {e}"),
            },
        };

        if let Ok(json_resp) = serde_json::to_string(&resp) {
            writer.write_all(json_resp.as_bytes()).await?;
            writer.write_all(b"\n").await?;
        }

        line.clear();
    }

    Ok(())
}
