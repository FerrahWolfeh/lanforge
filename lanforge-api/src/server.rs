use crate::api::{Command, Response, SimpleSuccess};
use lanforge_db::log_engine::LogDb;

use crate::config::ApiConfig;
use crate::error::Result;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::device::{Ipv6AddrOrSuffix, Origin};
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::update::{DeviceUpdate, FieldUpdate};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener};
use tracing::{debug, error, info};

use lanforge_core::service::{AsyncService, LanforgeService};

pub struct ControlService {
    cfg: Arc<ApiConfig>,
}

impl ControlService {
    pub fn new(cfg: Arc<ApiConfig>) -> Self {
        Self { cfg }
    }
}

impl LanforgeService for ControlService {
    fn meta(&self) -> lanforge_core::service::ServiceMeta {
        lanforge_core::service::ServiceMeta {
            id: "control",
            display_name: "Control API",
            critical: true,
            max_retries: 0,
            base_backoff: std::time::Duration::from_secs(1),
            max_backoff: std::time::Duration::from_secs(30),
            stack_kb: 512,
        }
    }

    fn describe(&self) -> String {
        format!("Control API at {}", self.cfg.socket_path)
    }
}

impl AsyncService for ControlService {
    async fn run(&mut self) -> lanforge_core::error::Result<()> {
        let cfg = self.cfg.clone();

        let path_ref = Path::new(&cfg.socket_path);

        // Limpeza prévia do socket
        if path_ref.exists() {
            debug!("Limpando socket antigo: {}", path_ref.display());
            fs::remove_file(path_ref).map_err(lanforge_core::error::CoreError::Io)?;
        }

        // Garante que o diretório pai existe
        if let Some(parent) = path_ref.parent()
            && !parent.exists()
        {
            debug!("Criando diretório do socket: {}", parent.display());
            fs::create_dir_all(parent).map_err(lanforge_core::error::CoreError::Io)?;
        }

        let listener = UnixListener::bind(path_ref).map_err(lanforge_core::error::CoreError::Io)?;

        // Define permissões 0666 para facilitar acesso local durante desenvolvimento.
        if let Err(e) = fs::set_permissions(path_ref, fs::Permissions::from_mode(0o666)) {
            debug!("Aviso: não foi possível setar permissões 0666 no socket: {e}");
        }

        let mut bus_rx = LanforgeContext::bus().subscribe();
        let mut current_gua: Option<String> = None;

        let startup_time = std::time::Instant::now();
        let mut last_scan = std::time::Instant::now();

        // TCP Listener opcional para debug
        let tcp_listener = if let Some(port) = cfg.tcp_port {
            let addr = format!("0.0.0.0:{port}");
            match TcpListener::bind(&addr).await {
                Ok(l) => {
                    info!("Control: TCP debug ready at {}", addr);
                    Some(l)
                }
                Err(e) => {
                    error!("Control: TCP bind failed at {addr}: {e}");
                    None
                }
            }
        } else {
            None
        };

        loop {
            if !LanforgeContext::is_running() {
                break;
            }
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
                            debug!("Control: shutdown received");
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
                                current_gua: current_gua.clone(),
                                uptime_secs: startup_time.elapsed().as_secs(),
                                last_scan_secs_ago: last_scan.elapsed().as_secs(),
                                cfg: cfg.clone(),
                            };
                            tokio::spawn(async move {
                                if let Err(e) = handle_client(stream, ctx).await {
                                    debug!("Control (UDS): error serving client: {e:#}");
                                }
                            });
                        }
                        Err(e) => {
                            error!("Control: UDS accept error: {e}");
                        }
                    }
                }

                // Aceita novas conexões TCP
                tcp_res = async {
                    if let Some(ref l) = tcp_listener {
                        l.accept().await.ok()
                    } else {
                        None
                    }
                }, if tcp_listener.is_some() => {
                    if let Some((stream, _)) = tcp_res {
                        let ctx = ClientContext {
                            current_gua: current_gua.clone(),
                            uptime_secs: startup_time.elapsed().as_secs(),
                            last_scan_secs_ago: last_scan.elapsed().as_secs(),
                            cfg: cfg.clone(),
                        };
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, ctx).await {
                                debug!("Control (TCP): error serving client: {e:#}");
                            }
                        });
                    }
                }
            }
        }

        // Cleanup
        if path_ref.exists() {
            let _ = fs::remove_file(path_ref);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ClientContext
// ---------------------------------------------------------------------------

/// Internal context for a specific client connection.
///
/// Groups shared state and configuration to facilitate command handling.
pub(crate) struct ClientContext {
    /// Currently known Global Unicast Address prefix.
    pub(crate) current_gua: Option<String>,
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
                let _ = LanforgeContext::bus().publish(LanforgeEvent::ReloadConfig);
                Response::Success(SimpleSuccess {
                    message: "Reload signal sent successfully".to_string(),
                })
            }
            Ok(Command::Scan) => {
                let _ = LanforgeContext::bus().publish(LanforgeEvent::ScanRequested);
                Response::Success(SimpleSuccess {
                    message: "mDNS Discovery Scan disparado".to_string(),
                })
            }
            Ok(Command::Shutdown) => {
                let _ = LanforgeContext::bus().publish(LanforgeEvent::Shutdown);
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

                let mut rx = LanforgeContext::bus().subscribe();
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
                        let _ = LanforgeContext::table().update(&DeviceUpdate::CliHostUpdated {
                            mac: mac_addr,
                            hostname: hostname.map_or(FieldUpdate::NoChange, FieldUpdate::Set),
                            v4_static: v4_static.map_or(FieldUpdate::NoChange, FieldUpdate::Set),
                            v6_suffix: v6_suffix_parsed
                                .map_or(FieldUpdate::NoChange, FieldUpdate::Set),
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
                    let mut hn = FieldUpdate::NoChange;
                    let mut v4s = FieldUpdate::NoChange;
                    let mut v6s = FieldUpdate::NoChange;

                    let err_msg = match field.as_str() {
                        "hostname" => {
                            hn = FieldUpdate::Set(value.clone());
                            None
                        }
                        "v4" | "ipv4" => {
                            if value.is_empty() {
                                v4s = FieldUpdate::Clear;
                                None
                            } else if let Ok(ip) = value.parse() {
                                v4s = FieldUpdate::Set(ip);
                                None
                            } else {
                                Some("IPv4 inválido")
                            }
                        }
                        "v6_suffix" | "v6" => {
                            if value.is_empty() {
                                v6s = FieldUpdate::Clear;
                                None
                            } else if let Some(suf) = Ipv6AddrOrSuffix::parse(&value) {
                                v6s = FieldUpdate::Set(suf);
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
                        let _ = LanforgeContext::table().update(&DeviceUpdate::CliHostUpdated {
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
                    let _ = LanforgeContext::table()
                        .update(&DeviceUpdate::HostRemoved { mac: mac_addr });
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
                    let _ =
                        LanforgeContext::bus().publish(LanforgeEvent::LeaseRenew { mac: mac_addr });
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
                    let _ = LanforgeContext::table()
                        .update(&DeviceUpdate::LeaseReleased { mac: mac_addr });
                    let _ = LanforgeContext::bus()
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
                let _ = LanforgeContext::bus().publish(LanforgeEvent::DbVacuum);
                Response::Success(SimpleSuccess {
                    message: "Iniciando vacuum do sqlite...".to_string(),
                })
            }
            Ok(Command::Purge { mac }) => {
                if let Some(mac_addr) = MacAddr::parse(&mac) {
                    let _ = LanforgeContext::table()
                        .update(&DeviceUpdate::HostRemoved { mac: mac_addr });
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
