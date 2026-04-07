use crate::api::{Command, Response, SimpleSuccess};
use lanforge_core::error::CoreError;
use lanforge_db::log_engine::LogDb;
use tokio::task::spawn_blocking;

use crate::config::ApiConfig;
use crate::error::ApiError;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::{DeviceUpdate, FieldUpdate, LeaseTarget};
use lanforge_core::device::{IPv4State, IPv6State, Ipv6AddrOrSuffix, Origin};
use lanforge_core::identifiers::MacAddr;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, split};
use tokio::net::{TcpListener, UnixListener};
use tracing::{debug, error, info};

use lanforge_core::service::{AsyncService, LanforgeService, ServiceMeta};

pub struct ControlService {
    cfg: Arc<ApiConfig>,
    ctx: LanforgeContext,
}

impl ControlService {
    pub fn new(cfg: Arc<ApiConfig>, ctx: LanforgeContext) -> Self {
        Self { cfg, ctx }
    }
}

impl LanforgeService for ControlService {
    fn meta(&self) -> ServiceMeta {
        ServiceMeta {
            id: "control",
            display_name: "Control API",
            critical: true,
            max_retries: 0,
            base_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            stack_kb: 512,
        }
    }

    fn describe(&self) -> String {
        format!("Control API at {}", self.cfg.socket_path)
    }
}

impl AsyncService for ControlService {
    async fn run(&mut self) -> Result<(), CoreError> {
        let cfg = self.cfg.clone();

        let path_ref = Path::new(&cfg.socket_path);

        // Old socket cleanup
        if path_ref.exists() {
            debug!("Cleaning up old socket: {}", path_ref.display());
            fs::remove_file(path_ref).map_err(CoreError::Io)?;
        }

        // Ensure parent directory exists
        if let Some(parent) = path_ref.parent()
            && !parent.exists()
        {
            debug!("Creating socket directory: {}", parent.display());
            fs::create_dir_all(parent).map_err(CoreError::Io)?;
        }

        let listener = UnixListener::bind(path_ref).map_err(CoreError::Io)?;

        // Set 0666 permissions for easy local access during development.
        if let Err(e) = fs::set_permissions(path_ref, Permissions::from_mode(0o666)) {
            debug!("Warning: could not set 0666 permissions on socket: {e}");
        }

        let mut bus_rx = self.ctx.bus().subscribe();
        let mut current_gua: Option<String> = None;

        let startup_time = Instant::now();
        let mut last_scan = Instant::now();

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
            if !self.ctx.is_running() {
                break;
            }
            tokio::select! {
                // Monitora mudanças de prefixo GUA para reportar no 'status'
                msg = bus_rx.recv() => {
                    if let Ok(event) = msg { match event.event {
                        LanforgeEvent::PrefixChanged {gua, .. } => {
                            current_gua = gua.map(|ip| ip.to_string());
                        }
                        LanforgeEvent::ReloadConfig => {
                            last_scan = Instant::now();
                        }
                        LanforgeEvent::Shutdown => {
                            debug!("Control: shutdown received");
                            break;
                        }
                        _ => {}
                    } }
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
                                ctx: self.ctx.clone(),
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
                            ctx: self.ctx.clone(),
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
    /// Lanforge Context.
    pub(crate) ctx: LanforgeContext,
}

// ---------------------------------------------------------------------------
// handle_client — command dispatch
// ---------------------------------------------------------------------------

/// Main worker task for a client connection.
///
/// Reads JSON lines from the stream, dispatches them to the appropriate
/// handler in `ClientContext`, and writes back the JSON response.
async fn handle_client<S>(stream: S, ctx: ClientContext) -> Result<(), ApiError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = split(stream);
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
            Ok(Command::Devices {
                filter,
                vendor,
                method,
                ..
            }) => ctx.handle_devices(filter, vendor, method).await,
            Ok(Command::Reload) => {
                let _ = ctx.ctx.bus().publish(LanforgeEvent::ReloadConfig);
                Response::Success(SimpleSuccess {
                    message: "Reload signal sent successfully".to_string(),
                })
            }
            Ok(Command::Scan) => {
                let _ = ctx.ctx.bus().publish(LanforgeEvent::ScanRequested);
                let _ = ctx.ctx.bus().publish(LanforgeEvent::NeighborScanRequested);
                Response::Success(SimpleSuccess {
                    message: "Active network scans (mDNS and ARP) triggered".to_string(),
                })
            }
            Ok(Command::Shutdown) => {
                let _ = ctx.ctx.bus().publish(LanforgeEvent::Shutdown);
                Response::Success(SimpleSuccess {
                    message: "Shutting down gracefully and instantly".to_string(),
                })
            }
            Ok(Command::Purge { mac }) => {
                let mac_addr = MacAddr::from_str(&mac).map_err(ApiError::Generic)?;
                let _ = ctx
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::DevicePurged { mac: mac_addr });
                Response::Success(SimpleSuccess {
                    message: format!("Device {mac} purged from memory"),
                })
            }
            Ok(Command::Wol { target }) => ctx.handle_wol(target).await,
            Ok(Command::Whois { target }) => ctx.handle_whois(target).await,
            Ok(Command::DnsStats) => ctx.handle_dns_stats().await,
            Ok(Command::DnsQuery { name, record_type }) => {
                ctx.handle_dns_query(name, record_type).await
            }
            Ok(req_cmd @ (Command::Log { follow: _ } | Command::Watch)) => {
                let is_follow = match req_cmd {
                    Command::Log { follow } => follow,
                    Command::Watch => true,
                    _ => unreachable!(),
                };

                // Fetch history if it's a log command
                let history = if let Command::Log { .. } = req_cmd {
                    let log_db_path = ctx.cfg.log_db_path.clone();
                    spawn_blocking(move || {
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
                    message: format!("Starting event stream ({} historical)...", history.len()),
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

                if !is_follow {
                    break;
                }

                let mut rx = ctx.ctx.bus().subscribe();
                while let Ok(msg) = rx.recv().await {
                    if !ctx.ctx.is_running() || matches!(msg.event, LanforgeEvent::Shutdown) {
                        break;
                    }
                    if let Ok(json_resp) = serde_json::to_string(&Response::Event(msg)) {
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
                        let _ = ctx.ctx.apply(&DeviceUpdate::CliHostUpdated {
                            mac: mac_addr,
                            hostname: hostname.map_or(FieldUpdate::NoChange, FieldUpdate::Set),
                            v4_static: v4
                                .and_then(|s| s.parse().ok())
                                .map_or(FieldUpdate::NoChange, FieldUpdate::Set),
                            v6_suffix: v6_suffix
                                .and_then(|s| Ipv6AddrOrSuffix::parse(&s))
                                .map_or(FieldUpdate::NoChange, FieldUpdate::Set),
                            origin: Origin::Cli,
                        });

                        Response::Success(SimpleSuccess {
                            message: "Host added and persisted.".to_string(),
                        })
                    } else {
                        Response::Error {
                            error: "Invalid MAC".to_string(),
                        }
                    }
                } else {
                    Response::Error {
                        error: "No interactive fallback. Specify MAC via args.".to_string(),
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
                                Some("Invalid IPv4")
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
                                Some("Invalid IPv6 interface ID (suffix) or address")
                            }
                        }
                        _ => Some("Unknown field"),
                    };

                    if let Some(e) = err_msg {
                        Response::Error {
                            error: e.to_string(),
                        }
                    } else {
                        let _ = ctx.ctx.apply(&DeviceUpdate::CliHostUpdated {
                            mac: mac_addr,
                            hostname: hn,
                            v4_static: v4s,
                            v6_suffix: v6s,
                            origin: Origin::Cli,
                        });

                        Response::Success(SimpleSuccess {
                            message: format!("Host {mac} updated: {field}={value}"),
                        })
                    }
                } else {
                    Response::Error {
                        error: "Invalid MAC".to_string(),
                    }
                }
            }
            Ok(Command::HostList) => ctx.handle_hosts().await,

            Ok(Command::HostRemove { mac }) => {
                if let Some(mac_addr) = MacAddr::parse(&mac) {
                    let _ = ctx.ctx.remove_host(mac_addr);
                    Response::Success(SimpleSuccess {
                        message: format!("Host removed (MAC {mac})"),
                    })
                } else {
                    Response::Error {
                        error: "Invalid MAC".to_string(),
                    }
                }
            }
            Ok(Command::LeaseRenew { mac, target }) => {
                if let Ok(mac_addr) = mac.parse::<MacAddr>() {
                    let targets = if let Some(t) = target {
                        vec![t]
                    } else if let Some(dev) = ctx.ctx.get_device(&mac_addr) {
                        let mut t = Vec::new();
                        if dev.v4.ip().is_some() && !matches!(dev.v4, IPv4State::Static(_)) {
                            t.push(LeaseTarget::V4);
                        }
                        for v6 in &dev.v6 {
                            if let IPv6State::Dynamic(lease) = v6 {
                                t.push(LeaseTarget::V6 { iaid: lease.iaid });
                            }
                        }
                        for prefix in &dev.v6_prefixes {
                            t.push(LeaseTarget::V6Prefix { iaid: prefix.iaid });
                        }
                        t
                    } else {
                        Vec::new()
                    };

                    for t in targets {
                        let _ = ctx.ctx.bus().publish(LanforgeEvent::LeaseRenew {
                            mac: mac_addr,
                            target: t,
                        });
                    }

                    Response::Success(SimpleSuccess {
                        message: format!("Requesting renewal (forcerenew) for {mac}"),
                    })
                } else {
                    Response::Error {
                        error: format!("Invalid MAC: {mac}"),
                    }
                }
            }
            Ok(Command::LeaseRelease { mac, target }) => {
                if let Ok(mac_addr) = mac.parse::<MacAddr>() {
                    let targets = if let Some(t) = target {
                        vec![t]
                    } else if let Some(dev) = ctx.ctx.get_device(&mac_addr) {
                        let mut t = Vec::new();
                        if dev.v4.ip().is_some() && !matches!(dev.v4, IPv4State::Static(_)) {
                            t.push(LeaseTarget::V4);
                        }
                        for v6 in &dev.v6 {
                            if let IPv6State::Dynamic(lease) = v6 {
                                t.push(LeaseTarget::V6 { iaid: lease.iaid });
                            }
                        }
                        for prefix in &dev.v6_prefixes {
                            t.push(LeaseTarget::V6Prefix { iaid: prefix.iaid });
                        }
                        t
                    } else {
                        Vec::new()
                    };

                    for t in targets {
                        let _ = ctx.ctx.apply(&DeviceUpdate::LeaseReleased {
                            mac: mac_addr,
                            target: t.clone(),
                        });
                        let _ = ctx.ctx.bus().publish(LanforgeEvent::LeaseRelease {
                            mac: mac_addr,
                            target: t,
                        });
                    }

                    Response::Success(SimpleSuccess {
                        message: format!("Releasing lease for {mac}"),
                    })
                } else {
                    Response::Error {
                        error: format!("Invalid MAC: {mac}"),
                    }
                }
            }
            Ok(Command::DbLogClean) => {
                let _ = ctx.ctx.bus().publish(LanforgeEvent::DbLogClean);
                Response::Success(SimpleSuccess {
                    message: "Clearing transient log database...".to_string(),
                })
            }
            Ok(Command::DbVacuum) => {
                let _ = ctx.ctx.bus().publish(LanforgeEvent::DbVacuum);
                Response::Success(SimpleSuccess {
                    message: "Starting sqlite vacuum...".to_string(),
                })
            }
            Err(e) => Response::Error {
                error: format!("Invalid command or malformed JSON: {e}"),
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
