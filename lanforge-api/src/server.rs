use crate::api::{Command, Response, SimpleSuccess};
use lanforge_db::log_engine::LogDb;

use crate::config::ApiConfig;
use crate::error::{ApiError, Result};
use lanforge_core::bus::{EventBus, LanforgeEvent, ManagedTable};
use lanforge_core::device::{Ipv6AddrOrSuffix, Origin};
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::update::DeviceUpdate;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener};
use tracing::{debug, error, info};

/// Starts the Unix Domain Socket (UDS) control service.
///
/// This service listens for local connections on the configured socket path,
/// processes JSON commands, and integrates with the daemon's internal state
/// and event bus.
///
/// # Architecture
///
/// The service runs a main loop using `tokio::select!` to multiplex between:
/// 1. **Internal Events**: Monitoring the `EventBus` for global signals like prefix changes or shutdown.
/// 2. **Client Connections**: Accepting new UDS connections and spawning a worker task for each.
///
/// ```mermaid
/// flowchart TD
///     Start([Start Service]) --> Cleanup[Cleanup Old Socket]
///     Cleanup --> Bind[Bind UDS Listener]
///     Bind --> Loop{Main Select Loop}
///
///     Loop -->|Bus Event| HandleBus[Update Internal State / Break if Shutdown]
///     HandleBus --> Loop
///
///     Loop -->|New Connection| Accept[Accept Client]
///     Accept --> Spawn[Spawn handle_client Task]
///     Spawn --> Loop
///
///     HandleBus -->|Shutdown| End([Stop Service])
/// ```
pub async fn control_service(
    table: Arc<ManagedTable>,
    bus: Arc<EventBus>,
    cfg: Arc<ApiConfig>,
) -> Result<()> {
    // Retemos a referência do bus para enviar comandos do Control.
    let ctrl_bus = bus.clone();

    let path_ref = Path::new(&cfg.socket_path);

    // Limpeza prévia do socket
    if path_ref.exists() {
        debug!("Limpando socket antigo: {}", path_ref.display());
        fs::remove_file(path_ref).map_err(|e| ApiError::SocketCleanup {
            path: cfg.socket_path.clone(),
            source: e,
        })?;
    }

    // Garante que o diretório pai existe
    if let Some(parent) = path_ref.parent()
        && !parent.exists()
    {
        debug!("Criando diretório do socket: {}", parent.display());
        fs::create_dir_all(parent).map_err(|e| ApiError::DirCreation {
            path: parent.display().to_string(),
            source: e,
        })?;
    }

    let listener = UnixListener::bind(path_ref).map_err(|e| ApiError::Bind {
        path: cfg.socket_path.clone(),
        source: e,
    })?;

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

    // TCP Listener opcional para debug
    let tcp_listener = if let Some(port) = cfg.tcp_port {
        let addr = format!("0.0.0.0:{port}");
        match TcpListener::bind(&addr).await {
            Ok(l) => {
                info!("🔌 Controle TCP (debug) pronto em {}", addr);
                Some(l)
            }
            Err(e) => {
                error!("Falha ao subir controle TCP em {addr}: {e}");
                None
            }
        }
    } else {
        None
    };

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

            // Aceita novas conexões UDS
            connection = listener.accept() => {
                match connection {
                    Ok((stream, _)) => {
                        let ctx = ClientContext {
                            table: table.clone(),
                            current_gua: current_gua.clone(),
                            bus: ctrl_bus.clone(),
                            uptime_secs: startup_time.elapsed().as_secs(),
                            last_scan_secs_ago: last_scan.elapsed().as_secs(),
                            cfg: cfg.clone(),
                        };
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, ctx).await {
                                debug!("Control (UDS): erro atendendo cliente: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        error!("Control: erro ao aceitar conexão UDS: {e}");
                    }
                }
            }

            // Aceita novas conexões TCP (se habilitado)
            tcp_res = async {
                if let Some(ref l) = tcp_listener {
                    l.accept().await.ok()
                } else {
                    None
                }
            }, if tcp_listener.is_some() => {
                if let Some((stream, _)) = tcp_res {
                    let ctx = ClientContext {
                        table: table.clone(),
                        current_gua: current_gua.clone(),
                        bus: ctrl_bus.clone(),
                        uptime_secs: startup_time.elapsed().as_secs(),
                        last_scan_secs_ago: last_scan.elapsed().as_secs(),
                        cfg: cfg.clone(),
                    };
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, ctx).await {
                            debug!("Control (TCP): erro atendendo cliente: {e:#}");
                        }
                    });
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

/// Internal context for a specific client connection.
///
/// Groups shared state and configuration to facilitate command handling.
pub(crate) struct ClientContext {
    /// Reference to the device table.
    pub(crate) table: Arc<ManagedTable>,
    /// Currently known Global Unicast Address prefix.
    pub(crate) current_gua: Option<String>,
    /// Reference to the event bus for publishing commands.
    pub(crate) bus: Arc<EventBus>,
    /// Uptime of the daemon in seconds.
    pub(crate) uptime_secs: u64,
    /// Seconds since the last network scan.
    pub(crate) last_scan_secs_ago: u64,
    /// API server configuration.
    pub(crate) cfg: Arc<ApiConfig>,
}

// ---------------------------------------------------------------------------
// handle_client — command dispatch
// ---------------------------------------------------------------------------

/// Main worker task for a client connection.
///
/// Reads JSON lines from the stream, dispatches them to the appropriate
/// handler in `ClientContext`, and writes back the JSON response.
async fn handle_client<S>(stream: S, ctx: ClientContext) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Loop de REPL JSON
    while reader.read_line(&mut line).await? > 0 {
        let trim_line = line.trim();
        if trim_line.is_empty() {
            line.clear();
            continue;
        }

        let req: std::result::Result<Command, _> = serde_json::from_str(trim_line);
        let resp = match req {
            Ok(Command::Status) => ctx.handle_status().await,
            Ok(Command::Devices { filter, .. }) => ctx.handle_devices(filter).await,
            Ok(Command::Reload) => {
                let _ = ctx.bus.publish(LanforgeEvent::ReloadConfig);
                Response::Success(SimpleSuccess {
                    message: "Reload signal sent successfully".to_string(),
                })
            }
            Ok(Command::Scan) => {
                let _ = ctx.bus.publish(LanforgeEvent::ScanRequested);
                Response::Success(SimpleSuccess {
                    message: "mDNS Discovery Scan disparado".to_string(),
                })
            }
            Ok(Command::Shutdown) => {
                let _ = ctx.bus.publish(LanforgeEvent::Shutdown);
                Response::Success(SimpleSuccess {
                    message: "Desligando graciosa e instantaneamente".to_string(),
                })
            }
            Ok(Command::Log { .. } | Command::Watch) => {
                // Fetch history if it's a log command
                let history = if matches!(req, Ok(Command::Log { .. })) {
                    let log_db_path = ctx.cfg.log_db_path.clone();
                    tokio::task::spawn_blocking(move || {
                        LogDb::open(Path::new(&log_db_path))
                            .and_then(|db| db.get_history(100))
                            .unwrap_or_default()
                    })
                    .await
                    .unwrap_or_default()
                } else {
                    Vec::new()
                };

                // Return immediate success first, then stream events
                let ok_resp = Response::Success(SimpleSuccess {
                    message: format!(
                        "Iniciando stream de eventos ({} históricos)...",
                        history.len()
                    ),
                });
                if let Ok(json_resp) = serde_json::to_string(&ok_resp) {
                    writer.write_all(json_resp.as_bytes()).await?;
                    writer.write_all(b"\n").await?;
                }

                // Send history
                for event in history {
                    if let Ok(json_resp) = serde_json::to_string(&Response::Event(event)) {
                        let _ = writer.write_all(json_resp.as_bytes()).await;
                        let _ = writer.write_all(b"\n").await;
                    }
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
                        ctx.table.update(DeviceUpdate::CliHostUpdated {
                            mac: mac_addr,
                            hostname: hostname.map(Some),
                            v4_static: Some(v4_static),
                            v6_suffix: Some(v6_suffix_parsed),
                            origin: Origin::Cli,
                        });

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
                        ctx.table.update(DeviceUpdate::CliHostUpdated {
                            mac: mac_addr,
                            hostname: hn,
                            v4_static: v4s,
                            v6_suffix: v6s,
                            origin: Origin::Cli,
                        });

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
                        .update(DeviceUpdate::HostRemoved { mac: mac_addr });
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
                    let _ = ctx.bus.publish(LanforgeEvent::LeaseRenew { mac: mac_addr });
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
                        .update(DeviceUpdate::LeaseReleased { mac: mac_addr });
                    let _ = ctx
                        .bus
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
                let _ = ctx.bus.publish(LanforgeEvent::DbVacuum);
                Response::Success(SimpleSuccess {
                    message: "Iniciando vacuum do sqlite...".to_string(),
                })
            }
            Ok(Command::Purge { mac }) => {
                if let Some(mac_addr) = MacAddr::parse(&mac) {
                    ctx.table
                        .update(DeviceUpdate::HostRemoved { mac: mac_addr });
                    Response::Success(SimpleSuccess {
                        message: format!("Dispositivo expurgado da memória: {mac}"),
                    })
                } else {
                    Response::Error {
                        error: format!("MAC inválido: {mac}"),
                    }
                }
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
