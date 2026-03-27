use anyhow::{Context, Result};
use lanforge_core::bus::{EventBus, LanforgeEvent, ManagedTable};
use lanforge_core::device::Ipv6AddrOrSuffix;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::update::DeviceUpdate;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{debug, error, info};

use crate::control::api::{Command, Interfaces, Response, SimpleSuccess};

/// Inicia o serviço de controle UDS.
pub async fn control_service(
    path: String,
    ifaces: Interfaces,
    table: Arc<ManagedTable>,
    bus: Arc<EventBus>,
    cfg: Arc<crate::config::Config>,
) -> Result<()> {
    // Retemos a referência do bus para enviar comandos do Control.
    let ctrl_bus = bus.clone();

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

    let startup_time = std::time::Instant::now();
    let mut last_scan = std::time::Instant::now();

    loop {
        tokio::select! {
            // Monitora mudanças de prefixo GUA para reportar no 'status'
            msg = bus_rx.recv() => {
                match msg {
                    Ok(LanforgeEvent::PrefixChanged {gua, .. }) => {
                        current_gua = gua.map(|ip| ip.to_string());
                    }
                    Ok(LanforgeEvent::ReloadConfig) => {
                        last_scan = std::time::Instant::now();
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
                        let ctrl_bus = ctrl_bus.clone();
                        let uptime = startup_time.elapsed().as_secs();
                        let scan_ago = last_scan.elapsed().as_secs();
                        let cfg = cfg.clone();
                        tokio::spawn(async move {
                            let ctx = ClientContext {
                                ifaces,
                                table,
                                current_gua: gua,
                                bus: ctrl_bus,
                                uptime_secs: uptime,
                                last_scan_secs_ago: scan_ago,
                                cfg,
                            };
                            if let Err(e) = handle_client(stream, ctx).await {
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

// ---------------------------------------------------------------------------
// ClientContext
// ---------------------------------------------------------------------------

pub(crate) struct ClientContext {
    pub(crate) ifaces: Interfaces,
    pub(crate) table: Arc<ManagedTable>,
    pub(crate) current_gua: Option<String>,
    pub(crate) bus: Arc<EventBus>,
    pub(crate) uptime_secs: u64,
    pub(crate) last_scan_secs_ago: u64,
    pub(crate) cfg: Arc<crate::config::Config>,
}

// ---------------------------------------------------------------------------
// handle_client — command dispatch
// ---------------------------------------------------------------------------

async fn handle_client(mut stream: tokio::net::UnixStream, ctx: ClientContext) -> Result<()> {
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
            Ok(Command::Status) => ctx.handle_status().await,
            Ok(Command::Devices { filter, .. }) => ctx.handle_devices(filter).await,
            Ok(Command::Reload) => {
                ctx.bus.publish(LanforgeEvent::ReloadConfig);
                Response::Success(SimpleSuccess {
                    message: "Reload signal sent successfully".to_string(),
                })
            }
            Ok(Command::Scan) => {
                ctx.bus.publish(LanforgeEvent::ReloadConfig); // Hack: reload triggers scan right now
                Response::Success(SimpleSuccess {
                    message: "Scan disparado".to_string(),
                })
            }
            Ok(Command::Shutdown) => {
                ctx.bus.publish(LanforgeEvent::Shutdown);
                Response::Success(SimpleSuccess {
                    message: "Desligando graciosa e instantaneamente".to_string(),
                })
            }
            Ok(Command::Log { .. } | Command::Watch) => {
                // Return immediate success first, then stream events
                let ok_resp = Response::Success(SimpleSuccess {
                    message: "Iniciando stream de eventos...".to_string(),
                });
                if let Ok(json_resp) = serde_json::to_string(&ok_resp) {
                    writer.write_all(json_resp.as_bytes()).await?;
                    writer.write_all(b"\n").await?;
                }

                let mut rx = ctx.bus.subscribe();
                while let Ok(event) = rx.recv().await {
                    if let Ok(json_resp) = serde_json::to_string(&Response::Event(event)) {
                        if writer.write_all(json_resp.as_bytes()).await.is_err() {
                            break;
                        }
                        if writer.write_all(b"\n").await.is_err() {
                            break;
                        }
                    }
                }
                break; // Break the command loop after streaming ends
            }
            Ok(Command::HostAdd {
                mac,
                hostname,
                v4,
                v6_suffix,
            }) => {
                if let Some(m) = mac {
                    if let Some(mac_addr) = MacAddr::parse(&m) {
                        let v4_static = v4.and_then(|s| s.parse().ok());
                        let v6_suffix_parsed = v6_suffix.and_then(|s| Ipv6AddrOrSuffix::parse(&s));
                        ctx.table
                            .update(DeviceUpdate::CliHostUpdated {
                                mac: mac_addr,
                                hostname: hostname.map(Some),
                                v4_static: Some(v4_static),
                                v6_suffix: Some(v6_suffix_parsed),
                            })
                            .await;

                        Response::Success(SimpleSuccess {
                            message: "Host adicionado e persistido.".to_string(),
                        })
                    } else {
                        Response::Error {
                            error: "MAC inválido".to_string(),
                        }
                    }
                } else {
                    Response::Error {
                        error: "Sem fallback iterativo. Especifique o MAC via args.".to_string(),
                    }
                }
            }
            Ok(Command::HostSet { mac, field, value }) => {
                if let Some(mac_addr) = MacAddr::parse(&mac) {
                    let mut hn = None;
                    let mut v4s = None;
                    let mut v6s = None;

                    let err_msg = match field.as_str() {
                        "hostname" => {
                            hn = Some(Some(value.clone()));
                            None
                        }
                        "v4" | "ipv4" => {
                            if value.is_empty() {
                                v4s = Some(None);
                                None
                            } else if let Ok(ip) = value.parse() {
                                v4s = Some(Some(ip));
                                None
                            } else {
                                Some("IPv4 inválido")
                            }
                        }
                        "v6_suffix" | "v6" => {
                            if value.is_empty() {
                                v6s = Some(None);
                                None
                            } else if let Some(suf) = Ipv6AddrOrSuffix::parse(&value) {
                                v6s = Some(Some(suf));
                                None
                            } else {
                                Some("Interface ID (sufixo) ou IPv6 inválido")
                            }
                        }
                        _ => Some("Campo desconhecido"),
                    };

                    if let Some(e) = err_msg {
                        Response::Error {
                            error: e.to_string(),
                        }
                    } else {
                        ctx.table
                            .update(DeviceUpdate::CliHostUpdated {
                                mac: mac_addr,
                                hostname: hn,
                                v4_static: v4s,
                                v6_suffix: v6s,
                            })
                            .await;

                        Response::Success(SimpleSuccess {
                            message: format!("Host {mac} atualizado: {field}={value}"),
                        })
                    }
                } else {
                    Response::Error {
                        error: "MAC inválido".to_string(),
                    }
                }
            }
            Ok(Command::HostList) => ctx.handle_hosts().await,

            Ok(Command::HostRemove { mac }) => {
                if let Some(mac_addr) = MacAddr::parse(&mac) {
                    ctx.table
                        .update(DeviceUpdate::HostRemoved { mac: mac_addr })
                        .await;
                    Response::Success(SimpleSuccess {
                        message: format!("Host removido (MAC {mac})"),
                    })
                } else {
                    Response::Error {
                        error: "MAC inválido".to_string(),
                    }
                }
            }
            Ok(Command::LeaseRenew { mac }) => {
                if let Ok(mac_addr) = mac.parse::<MacAddr>() {
                    ctx.bus.publish(LanforgeEvent::LeaseRenew { mac: mac_addr });
                    Response::Success(SimpleSuccess {
                        message: format!("Solicitando renovação (forcerenew) para {mac}"),
                    })
                } else {
                    Response::Error {
                        error: format!("MAC inválido: {mac}"),
                    }
                }
            }
            Ok(Command::LeaseRelease { mac }) => {
                if let Ok(mac_addr) = mac.parse::<MacAddr>() {
                    ctx.table
                        .update(DeviceUpdate::LeaseReleased { mac: mac_addr })
                        .await;
                    ctx.bus
                        .publish(LanforgeEvent::LeaseRelease { mac: mac_addr });
                    Response::Success(SimpleSuccess {
                        message: format!("Liberando lease para {mac}"),
                    })
                } else {
                    Response::Error {
                        error: format!("MAC inválido: {mac}"),
                    }
                }
            }
            Ok(Command::DbVacuum) => {
                ctx.bus.publish(LanforgeEvent::DbVacuum);
                Response::Success(SimpleSuccess {
                    message: "Iniciando vacuum do sqlite...".to_string(),
                })
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
