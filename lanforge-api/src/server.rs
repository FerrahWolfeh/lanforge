use crate::api::{Command, Response};
use lanforge_core::error::CoreError;

use crate::config::ApiConfig;
use crate::error::ApiError;
use lanforge_core::bus::{LanforgeEvent, NetworkEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_db::log_engine::LogDb;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, split,
};
use tokio::net::{TcpListener, UnixListener};
use tracing::{debug, error, info};

use lanforge_core::service::{AsyncService, ServiceControl};

#[lanforge_macros::lanforge_service(
    id = "control",
    name = "Control API",
    critical = true,
    retries = 0,
    base_backoff = 1,
    max_backoff = 30,
    describe = format!("Control API at {}", self.cfg.socket_path)
)]
pub struct ControlService {
    cfg: Arc<ApiConfig>,
    ctx: LanforgeContext,
}

impl ControlService {
    pub fn new(cfg: Arc<ApiConfig>, ctx: LanforgeContext) -> Self {
        Self { cfg, ctx }
    }
}

impl AsyncService for ControlService {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
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

        ctrl.signal_ready();

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
                    if let Ok(timed_event) = msg {
                        lanforge_core::match_event!(timed_event, {
                            LanforgeEvent::Network(NetworkEvent::PrefixChanged { gua, .. }) => {
                                current_gua = gua.map(|ip| ip.to_string());
                            }
                            LanforgeEvent::System(SystemEvent::ReloadConfig) => {
                                last_scan = Instant::now();
                            }
                            LanforgeEvent::System(SystemEvent::Shutdown) => {
                                debug!("Control: shutdown received");
                                break;
                            }
                        });
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
        crate::api::Encoding::Bincode => bincode::serialize(response)
            .map_err(|e| ApiError::Bincode(format!("Bincode serialize error: {}", e)))?,
    };

    let data = if compression == crate::api::Compression::Zstd {
        #[cfg(feature = "zstd")]
        {
            zstd::stream::encode_all(&data[..], 3).map_err(|e| ApiError::Zstd(e.to_string()))?
        }
        #[cfg(not(feature = "zstd"))]
        {
            return Err(ApiError::Zstd(
                "Zstd support not enabled in this binary".into(),
            ));
        }
    } else {
        data
    };

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

        let resp = req.action.dispatch(&ctx).await;

        if let CommandAction::Log { follow, n } = req.action {
            let n_lines = n.unwrap_or(100);
            let history = if let Ok(db) = LogDb::open(&ctx.cfg.log_db_url).await {
                db.get_history(n_lines).await.unwrap_or_default()
            } else {
                Vec::new()
            };

            // Write initial "Starting..." response
            write_response(&mut writer, &resp, resp_encoding, resp_compression).await?;

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
                continue;
            }

            let mut rx = ctx.ctx.bus().subscribe();
            while let Ok(msg) = rx.recv().await {
                if !ctx.ctx.is_running()
                    || matches!(msg.event, LanforgeEvent::System(SystemEvent::Shutdown))
                {
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
        } else if let CommandAction::Watch = req.action {
            // Write initial response
            write_response(&mut writer, &resp, resp_encoding, resp_compression).await?;

            let mut rx = ctx.ctx.bus().subscribe();
            while let Ok(msg) = rx.recv().await {
                if !ctx.ctx.is_running()
                    || matches!(msg.event, LanforgeEvent::System(SystemEvent::Shutdown))
                {
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

        if let Err(e) = write_response(&mut writer, &resp, resp_encoding, resp_compression).await {
            error!("[server] Failed to write response: {e}");
            break;
        }
    }

    Ok(())
}

// Additional helpers needed for server.rs since I used them in handle_client
