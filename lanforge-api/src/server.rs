use crate::api::{Command, CommandAction, Compression, Encoding, Response};
use lanforge_core::error::CoreError;
use lanforge_db::engine::LeaseDb;

use crate::config::ApiConfig;
use crate::error::ApiError;
use futures::StreamExt;
use lanforge_core::bus::{LanforgeEvent, NetworkEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_db::log_engine::LogDb;
use std::fs::{self, Permissions};
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, split,
};
use tokio::net::{TcpListener, UnixListener};
use tracing::{debug, error, info, warn};

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
    db: Arc<LeaseDb>,
    log_db: Arc<LogDb>,
}

impl ControlService {
    #[must_use]
    pub const fn new(
        cfg: Arc<ApiConfig>,
        ctx: LanforgeContext,
        db: Arc<LeaseDb>,
        log_db: Arc<LogDb>,
    ) -> Self {
        Self {
            cfg,
            ctx,
            db,
            log_db,
        }
    }

    fn setup_unix_listener(path: &str) -> Result<UnixListener, CoreError> {
        let path_ref = Path::new(path);
        if path_ref.exists() {
            fs::remove_file(path_ref).map_err(CoreError::Io)?;
        }
        if let Some(parent) = path_ref.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent).map_err(CoreError::Io)?;
        }
        let listener = UnixListener::bind(path_ref).map_err(CoreError::Io)?;
        let _ = fs::set_permissions(path_ref, Permissions::from_mode(0o666));
        Ok(listener)
    }

    async fn setup_tcp_listener(&self, port: Option<u16>) -> Option<TcpListener> {
        if let Some(port) = port {
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
        }
    }

    fn spawn_client_handler<S>(&self, stream: S, current_gua: Option<String>, startup_time: Instant)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let ctx = ClientContext {
            current_gua,
            uptime_secs: startup_time.elapsed().as_secs(),
            last_scan_secs_ago: self.ctx.last_scan_secs_ago(),
            cfg: self.cfg.clone(),
            ctx: self.ctx.clone(),
            db: self.db.clone(),
            log_db: self.log_db.clone(),
            active_clients: self.ctx.active_clients(),
        };
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream, ctx).await {
                debug!("Control: error serving client: {e:#}");
            }
        });
    }
}

impl AsyncService for ControlService {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        let cfg = self.cfg.clone();
        let listener = Self::setup_unix_listener(&cfg.socket_path)?;
        ctrl.signal_ready();

        let mut bus_rx = self.ctx.bus().subscribe();
        let mut current_gua: Option<String> = None;
        let startup_time = Instant::now();

        let tcp_listener = self.setup_tcp_listener(cfg.tcp_port).await;

        loop {
            if !self.ctx.is_running() {
                break;
            }
            tokio::select! {
                msg = bus_rx.recv() => {
                    match msg {
                        Ok(timed_event) => {
                            lanforge_core::match_event!(timed_event, {
                                LanforgeEvent::Network(NetworkEvent::PrefixChanged { gua, .. }) => {
                                    current_gua = gua.map(|ip| ip.to_string());
                                }
                                LanforgeEvent::System(SystemEvent::Shutdown) => break,
                                _ => {}
                            });
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!(service = "ControlAPI", lost = n, "Event bus lagged");
                        }
                        Err(_) => break,
                    }
                }
                connection = listener.accept() => {
                    if let Ok((stream, _)) = connection {
                        self.spawn_client_handler(stream, current_gua.clone(), startup_time);
                    }
                }
                tcp_res = async {
                    if let Some(ref l) = tcp_listener { l.accept().await.ok() } else { std::future::pending().await }
                } => {
                    if let Some((stream, _)) = tcp_res {
                        self.spawn_client_handler(stream, current_gua.clone(), startup_time);
                    }
                }
            }
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
#[derive(Clone)]
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
    /// Shared lease database.
    pub db: Arc<LeaseDb>,
    /// Shared log database.
    pub log_db: Arc<LogDb>,
    /// Active client counter.
    pub active_clients: Arc<AtomicUsize>,
}

// ---------------------------------------------------------------------------
// handle_client — command dispatch
// ---------------------------------------------------------------------------

#[cfg_attr(feature = "hotpath", hotpath::measure)]
async fn write_response<W>(
    writer: &mut W,
    response: &Response,
    encoding: Encoding,
    compression: Compression,
    buf: &mut Vec<u8>,
) -> Result<(), ApiError>
where
    W: AsyncWrite + Unpin,
{
    buf.clear();
    match encoding {
        Encoding::Json => {
            serde_json::to_writer(buf as &mut Vec<u8>, response)?;
            if compression == Compression::None {
                buf.push(b'\n');
            }
        }
        Encoding::Bincode => {
            bincode::serialize_into(buf as &mut Vec<u8>, response)
                .map_err(|e| ApiError::Bincode(e.to_string()))?;
        }
    }

    if compression == Compression::Zstd {
        #[cfg(feature = "zstd")]
        {
            let compressed = zstd::stream::encode_all(&buf[..], 3)
                .map_err(|e| crate::error::ApiError::Zstd(e.to_string()))?;
            let len = u32::try_from(compressed.len())
                .map_err(|_| ApiError::EncodingError("Response too large".into()))?;
            writer.write_all(&len.to_be_bytes()).await?;
            writer.write_all(&compressed).await?;
            writer.flush().await?;
        }
        #[cfg(not(feature = "zstd"))]
        {
            return Err(crate::error::ApiError::Zstd(
                "Zstd support not enabled in this binary".into(),
            ));
        }
    }

    // Framing: Bincode responses are length-prefixed (u32 BE).
    // JSON remains line-based.
    if encoding == Encoding::Bincode {
        let len = u32::try_from(buf.len())
            .map_err(|_| ApiError::EncodingError("Response too large".into()))?;
        writer.write_all(&len.to_be_bytes()).await?;
    }
    writer.write_all(buf).await?;

    writer.flush().await?;
    Ok(())
}

/// Main worker task for a client connection.
pub async fn handle_client<S>(stream: S, ctx: ClientContext) -> Result<(), ApiError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ctx.active_clients.fetch_add(1, Ordering::Relaxed);
    #[cfg(feature = "hotpath")]
    {
        hotpath::gauge!("active_api_connections")
            .set(ctx.active_clients.load(Ordering::Relaxed) as f64);
    }

    let res = handle_client_inner(stream, ctx.clone()).await;

    ctx.active_clients.fetch_sub(1, Ordering::Relaxed);
    #[cfg(feature = "hotpath")]
    {
        hotpath::gauge!("active_api_connections")
            .set(ctx.active_clients.load(Ordering::Relaxed) as f64);
    }

    res
}

async fn handle_client_inner<S>(stream: S, ctx: ClientContext) -> Result<(), ApiError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, mut writer) = split(stream);
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::with_capacity(4096);
    let line_protocol_only = false;

    loop {
        // Peek the first byte to determine protocol
        let first_byte = {
            let peek_buf = reader.fill_buf().await?;
            if peek_buf.is_empty() {
                break;
            }
            peek_buf[0]
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
                Encoding::Json,
            )
        } else {
            // Bincode framed protocol (u32 BE length prefix)
            let mut len_bytes = [0u8; 4];
            if let Err(e) = reader.read_exact(&mut len_bytes).await {
                if e.kind() == ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(ApiError::Io(e));
            }
            let len = u32::from_be_bytes(len_bytes);
            buf.resize(len as usize, 0);
            reader.read_exact(&mut buf).await?;
            (
                bincode::deserialize::<Command>(&buf).map_err(|e| ApiError::Bincode(e.to_string())),
                Encoding::Bincode,
            )
        };

        let cmd = match req_res {
            Ok(r) => r,
            Err(e) => {
                let err_resp = Response::Error {
                    error: format!("Invalid command: {e}"),
                };
                write_response(
                    &mut writer,
                    &err_resp,
                    req_encoding,
                    Compression::None,
                    &mut buf,
                )
                .await?;
                continue;
            }
        };

        let encoding = cmd.encoding.unwrap_or(req_encoding);
        let compression = cmd.compression.unwrap_or(Compression::None);

        if line_protocol_only && encoding == Encoding::Bincode {
            return Err(ApiError::EncodingError(
                "Bincode not supported on this stream".into(),
            ));
        }

        match cmd.action {
            CommandAction::Log { follow, n } => {
                if follow {
                    handle_log_stream(&mut writer, reader, ctx, encoding, n, &mut buf).await?;
                    break; // Stream takes over
                }
                let resp = cmd.action.dispatch(&ctx).await;
                write_response(&mut writer, &resp, encoding, compression, &mut buf).await?;
            }
            CommandAction::Watch => {
                handle_watch_stream(&mut writer, reader, ctx, encoding, &mut buf).await?;
                break;
            }
            _ => {
                let resp = cmd.action.dispatch(&ctx).await;
                write_response(&mut writer, &resp, encoding, compression, &mut buf).await?;
            }
        }
    }

    Ok(())
}

/// Handles the 'Log' command by streaming historical and/or live events.
pub async fn handle_log_stream<W, R>(
    writer: &mut W,
    mut reader: R,
    ctx: ClientContext,
    encoding: Encoding,
    n: Option<usize>,
    buf: &mut Vec<u8>,
) -> Result<(), ApiError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let n_lines = n.unwrap_or(100);
    let mut history = ctx.log_db.stream_history(n_lines);

    while let Some(res) = history.next().await {
        let event = res?;
        write_response(
            writer,
            &Response::Event(event),
            encoding,
            Compression::None,
            buf,
        )
        .await?;
    }

    let mut bus_rx = ctx.ctx.bus().subscribe();
    let mut eof_buf = [0u8; 1];

    loop {
        tokio::select! {
            res = bus_rx.recv() => {
                match res {
                    Ok(event) => {
                        write_response(writer, &Response::Event(event), encoding, Compression::None, buf).await?;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => break,
                }
            }
            // Monitor for client disconnect
            read_res = reader.read(&mut eof_buf) => {
                match read_res {
                    Ok(0) | Err(_) => break, // EOF or error
                    Ok(_) => {} // Junk or heartbeat, ignore
                }
            }
        }
    }
    Ok(())
}

/// Handles the 'Watch' command by streaming live events.
async fn handle_watch_stream<W, R>(
    writer: &mut W,
    mut reader: R,
    ctx: ClientContext,
    encoding: Encoding,
    buf: &mut Vec<u8>,
) -> Result<(), ApiError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut bus_rx = ctx.ctx.bus().subscribe();
    let mut eof_buf = [0u8; 1];

    loop {
        tokio::select! {
            res = bus_rx.recv() => {
                match res {
                    Ok(event) => {
                        write_response(writer, &Response::Event(event), encoding, Compression::None, buf).await?;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(_) => break,
                }
            }
            // Monitor for client disconnect
            read_res = reader.read(&mut eof_buf) => {
                match read_res {
                    Ok(0) | Err(_) => break, // EOF or error
                    Ok(_) => {} // Junk or heartbeat, ignore
                }
            }
        }
    }
    Ok(())
}
