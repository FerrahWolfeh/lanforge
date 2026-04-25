use crate::api::{Command, Response, SimpleSuccess};
use lanforge_core::error::CoreError;
use lanforge_db::log_engine::LogDb;

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
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, split,
};
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
pub struct ClientContext {
    /// Currently known Global Unicast Address prefix.
    pub current_gua: Option<String>,
    /// Uptime of the daemon in seconds.
    pub uptime_secs: u64,
    /// Seconds since the last network scan.
    pub last_scan_secs_ago: u64,
    /// API server configuration.
    pub cfg: Arc<ApiConfig>,
    /// Lanforge Context.
    pub ctx: LanforgeContext,
}

// ---------------------------------------------------------------------------
// handle_client — command dispatch
// ---------------------------------------------------------------------------

async fn write_response<W>(
    writer: &mut W,
    response: &Response,
    encoding: crate::api::Encoding,
    compression: crate::api::Compression,
) -> Result<(), ApiError>
where
    W: AsyncWrite + Unpin,
{
    let data = match encoding {
        crate::api::Encoding::Json => {
            let mut s = serde_json::to_string(response)?;
            s.push('\n');
            s.into_bytes()
        }
        crate::api::Encoding::Bincode => {
            bincode::serialize(response).map_err(|e| ApiError::Bincode(e.to_string()))?
        }
    };

    let mut data = data;
    if compression == crate::api::Compression::Zstd {
        #[cfg(feature = "zstd")]
        {
            data = zstd::stream::encode_all(&data[..], 3)
                .map_err(|e| ApiError::Zstd(e.to_string()))?;
        }
        #[cfg(not(feature = "zstd"))]
        {
            return Err(ApiError::Zstd(
                "Zstd support not enabled in this binary".into(),
            ));
        }
    }

    // Framing: Bincode or Compressed responses are length-prefixed (u32 BE).
    // JSON remains line-based unless compressed.
    if encoding == crate::api::Encoding::Bincode || compression != crate::api::Compression::None {
        let len = data.len() as u32;
        writer.write_all(&len.to_be_bytes()).await?;
    }

    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}

/// Main worker task for a client connection.
///
/// Reads JSON lines or Bincode from the stream, dispatches them to the appropriate
/// handler in `ClientContext`, and writes back the response.
pub async fn handle_client<S>(stream: S, ctx: ClientContext) -> Result<(), ApiError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = split(stream);
    let mut reader = BufReader::new(reader);

    loop {
        // Peek the first byte to determine protocol
        let first_byte = {
            let buf = reader.fill_buf().await?;
            if buf.is_empty() {
                break;
            }
            buf[0]
        };

        let (req_res, req_encoding) = if first_byte == b'{' {
            // JSON line-based protocol
            let mut line = String::new();
            if reader.read_line(&mut line).await? == 0 {
                break;
            }
            let trim_line = line.trim();
            if trim_line.is_empty() {
                continue;
            }
            (
                serde_json::from_str::<Command>(trim_line).map_err(ApiError::from),
                crate::api::Encoding::Json,
            )
        } else {
            // Bincode framed protocol (u32 BE length prefix)
            let mut len_bytes = [0u8; 4];
            if let Err(e) = reader.read_exact(&mut len_bytes).await {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(ApiError::Io(e));
            }
            let len = u32::from_be_bytes(len_bytes);
            let mut buf = vec![0u8; len as usize];
            reader.read_exact(&mut buf).await?;
            (
                bincode::deserialize::<Command>(&buf).map_err(|e| ApiError::Bincode(e.to_string())),
                crate::api::Encoding::Bincode,
            )
        };

        let req = match req_res {
            Ok(r) => r,
            Err(e) => {
                let err_resp = Response::Error {
                    error: format!("Invalid command: {e}"),
                };
                let _ = write_response(
                    &mut writer,
                    &err_resp,
                    req_encoding,
                    crate::api::Compression::None,
                )
                .await;
                continue;
            }
        };

        // Determine response encoding and compression
        let resp_encoding = req.encoding.unwrap_or(req_encoding);
        let resp_compression = req.compression.unwrap_or(crate::api::Compression::None);

        use crate::api::CommandAction;

        let resp = match req.action {
            CommandAction::Status => ctx.handle_status().await,
            CommandAction::Devices {
                filter,
                vendor: _,
                method,
                format: _,
                ..
            } => ctx.handle_devices(filter, None, method).await,
            CommandAction::Reload => {
                let _ = ctx.ctx.bus().publish(LanforgeEvent::ReloadConfig);
                Response::Success(SimpleSuccess {
                    message: "Reload signal sent successfully".to_string(),
                })
            }
            CommandAction::Scan => {
                let _ = ctx.ctx.bus().publish(LanforgeEvent::ScanRequested);
                let _ = ctx.ctx.bus().publish(LanforgeEvent::NeighborScanRequested);
                Response::Success(SimpleSuccess {
                    message: "Active network scans triggered".to_string(),
                })
            }
            CommandAction::Shutdown => {
                let _ = ctx.ctx.bus().publish(LanforgeEvent::Shutdown);
                Response::Success(SimpleSuccess {
                    message: "Shutting down gracefully".to_string(),
                })
            }
            CommandAction::Purge { mac } => {
                if let Some(mac_addr) = MacAddr::parse(&mac) {
                    let _ = ctx
                        .ctx
                        .bus()
                        .publish(LanforgeEvent::DevicePurged { mac: mac_addr });
                    Response::Success(SimpleSuccess {
                        message: format!("Device {mac} purged"),
                    })
                } else {
                    Response::Error {
                        error: "Invalid MAC".to_string(),
                    }
                }
            }
            CommandAction::Wol { target } => ctx.handle_wol(target).await,
            CommandAction::Whois { target } => ctx.handle_whois(target).await,
            CommandAction::DnsStats => ctx.handle_dns_stats().await,
            CommandAction::DnsQuery { name, record_type } => {
                ctx.handle_dns_query(name, record_type).await
            }
            CommandAction::Log { follow, n } => {
                let n_lines = n.unwrap_or(100);
                let history = if let Ok(db) = LogDb::open(&ctx.cfg.log_db_url).await {
                    db.get_history(n_lines).await.unwrap_or_default()
                } else {
                    Vec::new()
                };

                let ok_resp = Response::Success(SimpleSuccess {
                    message: format!("Starting event stream ({} historical)...", history.len()),
                });
                write_response(&mut writer, &ok_resp, resp_encoding, resp_compression).await?;

                for event in history {
                    write_response(
                        &mut writer,
                        &Response::Event(event),
                        resp_encoding,
                        resp_compression,
                    )
                    .await?;
                }

                if !follow {
                    break;
                }

                let mut rx = ctx.ctx.bus().subscribe();
                while let Ok(msg) = rx.recv().await {
                    if !ctx.ctx.is_running() || matches!(msg.event, LanforgeEvent::Shutdown) {
                        break;
                    }
                    if write_response(
                        &mut writer,
                        &Response::Event(msg),
                        resp_encoding,
                        resp_compression,
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                break;
            }
            CommandAction::Watch => {
                let ok_resp = Response::Success(SimpleSuccess {
                    message: "Starting watch stream...".to_string(),
                });
                write_response(&mut writer, &ok_resp, resp_encoding, resp_compression).await?;

                let mut rx = ctx.ctx.bus().subscribe();
                while let Ok(msg) = rx.recv().await {
                    if !ctx.ctx.is_running() || matches!(msg.event, LanforgeEvent::Shutdown) {
                        break;
                    }
                    if write_response(
                        &mut writer,
                        &Response::Event(msg),
                        resp_encoding,
                        resp_compression,
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                break;
            }
            CommandAction::HostAdd {
                mac,
                hostname,
                v4,
                v6_suffix,
            } => {
                if let Some(m) = mac.as_deref().and_then(MacAddr::parse) {
                    let _ = ctx.ctx.apply(&DeviceUpdate::CliHostUpdated {
                        mac: m,
                        hostname: hostname.map_or(FieldUpdate::NoChange, FieldUpdate::Set),
                        duid: FieldUpdate::NoChange,
                        v4_static: v4
                            .as_deref()
                            .and_then(|s| s.parse().ok())
                            .map_or(FieldUpdate::NoChange, FieldUpdate::Set),
                        v6_suffix: v6_suffix
                            .as_deref()
                            .and_then(Ipv6AddrOrSuffix::parse)
                            .map_or(FieldUpdate::NoChange, FieldUpdate::Set),
                        origin: Origin::Cli,
                    });
                    Response::Success(SimpleSuccess {
                        message: "Host added/updated".to_string(),
                    })
                } else {
                    Response::Error {
                        error: "Invalid or missing MAC".to_string(),
                    }
                }
            }
            CommandAction::HostSet { mac, field, value } => {
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
                            duid: FieldUpdate::NoChange,
                            v4_static: v4s,
                            v6_suffix: v6s,
                            origin: Origin::Cli,
                        });
                        Response::Success(SimpleSuccess {
                            message: format!("Host {mac} updated"),
                        })
                    }
                } else {
                    Response::Error {
                        error: "Invalid MAC".to_string(),
                    }
                }
            }
            CommandAction::HostList => ctx.handle_hosts().await,
            CommandAction::HostRemove { mac } => {
                if let Some(mac_addr) = MacAddr::parse(&mac) {
                    let _ = ctx.ctx.remove_host(mac_addr);
                    Response::Success(SimpleSuccess {
                        message: format!("Host {mac} removed"),
                    })
                } else {
                    Response::Error {
                        error: "Invalid MAC".to_string(),
                    }
                }
            }
            CommandAction::LeaseRenew { mac, target } => ctx.handle_lease_renew(mac, target).await,
            CommandAction::LeaseRelease { mac, target } => {
                ctx.handle_lease_release(mac, target).await
            }
            CommandAction::DbVacuum => {
                let _ = ctx.ctx.bus().publish(LanforgeEvent::DbVacuum);
                Response::Success(SimpleSuccess {
                    message: "Vacuum triggered".to_string(),
                })
            }
            CommandAction::DbLogClean => {
                let _ = ctx.ctx.bus().publish(LanforgeEvent::DbLogClean);
                Response::Success(SimpleSuccess {
                    message: "Log cleanup triggered".to_string(),
                })
            }
            CommandAction::DbPrune => {
                let _ = ctx.ctx.apply(&DeviceUpdate::PruneZombies);
                let _ = ctx.ctx.bus().publish(LanforgeEvent::DbPrune);
                Response::Success(SimpleSuccess {
                    message: "Pruning triggered".to_string(),
                })
            }
            CommandAction::ContextDump {
                only_devices,
                only_orphans,
            } => ctx.handle_context_dump(only_devices, only_orphans).await,
            CommandAction::DbReset => ctx.handle_db_reset().await,
        };

        if let Err(e) = write_response(&mut writer, &resp, resp_encoding, resp_compression).await {
            error!("[server] Failed to write response: {e}");
            break;
        }
    }

    Ok(())
}

// Additional helpers needed for server.rs since I used them in handle_client
impl ClientContext {
    pub(crate) async fn handle_lease_renew(
        &self,
        mac: String,
        target: Option<LeaseTarget>,
    ) -> Response {
        if let Ok(mac_addr) = mac.parse::<MacAddr>() {
            let targets = if let Some(t) = target {
                vec![t]
            } else if let Some(dev) = self.ctx.get_device(&mac_addr) {
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
                let _ = self.ctx.bus().publish(LanforgeEvent::LeaseRenew {
                    mac: mac_addr,
                    target: t,
                });
            }

            Response::Success(SimpleSuccess {
                message: format!("Requesting renewal for {mac}"),
            })
        } else {
            Response::Error {
                error: format!("Invalid MAC: {mac}"),
            }
        }
    }

    pub(crate) async fn handle_lease_release(
        &self,
        mac: String,
        target: Option<LeaseTarget>,
    ) -> Response {
        if let Ok(mac_addr) = mac.parse::<MacAddr>() {
            let targets = if let Some(t) = target {
                vec![t]
            } else if let Some(dev) = self.ctx.get_device(&mac_addr) {
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
                let _ = self.ctx.apply(&DeviceUpdate::LeaseReleased {
                    mac: mac_addr,
                    target: t.clone(),
                });
                let _ = self.ctx.bus().publish(LanforgeEvent::LeaseRelease {
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
}
