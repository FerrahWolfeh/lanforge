use lanforge_api::api::EventKind;
use lanforge_api::rpc::{LanforgeRpcDispatcher, RpcRequest, RpcResponse};
use lanforge_api_dispatch::ClientContext;
use tokio::sync::Mutex;

use crate::config::ApiConfig;
use crate::error::UdsError;
use lanforge_core::bus::{LanforgeEvent, NetworkEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_db_core::{DatabaseStore, LogStore};
use std::fs::{self, Permissions};
use std::io::ErrorKind;
use std::net::Ipv6Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, split};
use tokio::net::{TcpListener, UnixListener};
use tracing::{debug, error, info, warn};

use lanforge_core::service::{AsyncService, ServiceDependency};

#[lanforge_macros::lanforge_service(
    id = "control",
    name = "Control API",
    critical = true,
    retries = 0,
    base_backoff = 1,
    max_backoff = 30,
    describe = format!("Control API at {}", self.cfg.socket_path)
)]
#[derive(Clone)]
pub struct ControlService {
    cfg: Arc<ApiConfig>,
    ctx: LanforgeContext,
    db: Arc<dyn DatabaseStore>,
    log_db: Arc<dyn LogStore>,
}

impl ControlService {
    #[must_use]
    pub const fn new(
        cfg: Arc<ApiConfig>,
        ctx: LanforgeContext,
        db: Arc<dyn DatabaseStore>,
        log_db: Arc<dyn LogStore>,
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
        let _ = fs::set_permissions(path_ref, Permissions::from_mode(0o660));
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

    fn spawn_client_handler<S>(
        &self,
        stream: S,
        current_gua: Option<Ipv6Addr>,
        startup_time: Instant,
    ) where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let ctx = ClientContext {
            current_gua,
            uptime_secs: startup_time.elapsed().as_secs(),
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
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[ServiceDependency::Database]
    }

    fn stats(&self, ctx: &LanforgeContext) -> Vec<(std::borrow::Cow<'static, str>, String)> {
        let mut stats = vec![
            (
                std::borrow::Cow::Borrowed("socket_path"),
                self.cfg.socket_path.clone(),
            ),
            (
                std::borrow::Cow::Borrowed("active_clients"),
                ctx.active_clients()
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .to_string(),
            ),
        ];
        if let Some(p) = self.cfg.tcp_port {
            stats.push((std::borrow::Cow::Borrowed("tcp_port"), p.to_string()));
        }
        stats
    }

    async fn serve(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        let cfg = self.cfg.clone();
        let listener = Self::setup_unix_listener(&cfg.socket_path)?;

        let mut bus_rx = ctx.bus().subscribe();
        let mut current_gua: Option<Ipv6Addr> = None;
        let startup_time = Instant::now();

        let tcp_listener = self.setup_tcp_listener(cfg.tcp_port).await;

        loop {
            if !ctx.is_running() {
                break;
            }
            tokio::select! {
                msg = bus_rx.recv() => {
                    match msg {
                        Ok(timed_event) => {
                            lanforge_core::match_event!(timed_event, {
                                LanforgeEvent::Network(NetworkEvent::PrefixChanged { gua, .. }) => {
                                    current_gua = *gua;
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
                        self.spawn_client_handler(stream, current_gua, startup_time);
                    }
                }
                tcp_res = async {
                    if let Some(ref l) = tcp_listener { l.accept().await.ok() } else { std::future::pending().await }
                } => {
                    if let Some((stream, _)) = tcp_res {
                        self.spawn_client_handler(stream, current_gua, startup_time);
                    }
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------

/// Main worker task for a client connection.
///
/// # Errors
///
/// Returns a `UdsError` if the client connection fails or a protocol error occurs.
pub async fn handle_client<S>(stream: S, ctx: ClientContext) -> Result<(), UdsError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    use std::sync::atomic::Ordering;
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

async fn handle_client_inner<S>(stream: S, ctx: ClientContext) -> Result<(), UdsError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (reader, writer) = split(stream);
    let mut reader = BufReader::new(reader);
    let writer = Arc::new(Mutex::new(writer));
    let buf = Arc::new(Mutex::new(Vec::with_capacity(8192)));

    loop {
        // Read framing: u32 BE length
        let mut len_bytes = [0u8; 4];
        if let Err(e) = reader.read_exact(&mut len_bytes).await {
            if e.kind() == ErrorKind::UnexpectedEof {
                break;
            }
            return Err(UdsError::Io(e));
        }
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > 10 * 1024 * 1024 {
            return Err(UdsError::EncodingError(format!(
                "Request length limit exceeded: {len} bytes (max: 10MB)"
            )));
        }

        // Read payload
        let mut req_buf = vec![0u8; len];
        reader.read_exact(&mut req_buf).await?;

        // Deserialize request
        let req: RpcRequest =
            postcard::from_bytes(&req_buf).map_err(|e| UdsError::EncodingError(e.to_string()))?;

        // Handle RPC requests
        match req {
            RpcRequest::Log { follow, n, filter } => {
                handle_log_stream(
                    writer.clone(),
                    reader,
                    ctx.clone(),
                    n,
                    buf.clone(),
                    follow,
                    filter,
                )
                .await?;
                return Ok(());
            }
            RpcRequest::DnsQueryLog {
                follow,
                n,
                client,
                offset,
            } => {
                let resp = ctx
                    .dispatch(RpcRequest::DnsQueryLog {
                        follow,
                        n,
                        client: client.clone(),
                        offset,
                    })
                    .await;
                {
                    let mut writer_lock = writer.lock().await;
                    let mut buf_lock = buf.lock().await;
                    write_rpc_response(&mut *writer_lock, &resp, &mut buf_lock).await?;
                    drop(buf_lock);
                    drop(writer_lock);
                }
                if follow {
                    handle_dns_query_log_stream(
                        writer.clone(),
                        reader,
                        ctx.clone(),
                        client,
                        buf.clone(),
                    )
                    .await?;
                }
                return Ok(());
            }
            _ => {
                let resp = ctx.dispatch(req).await;

                let mut writer_lock = writer.lock().await;
                let mut buf_lock = buf.lock().await;

                buf_lock.clear();
                let buffer = std::mem::take(&mut *buf_lock);
                let buffer = postcard::to_extend(&resp, buffer)
                    .map_err(|e| UdsError::EncodingError(e.to_string()))?;
                *buf_lock = buffer;
                #[allow(clippy::cast_possible_truncation)]
                let resp_len = buf_lock.len() as u32;

                // Write response framing and payload
                writer_lock.write_all(&resp_len.to_be_bytes()).await?;
                writer_lock.write_all(&buf_lock).await?;
                writer_lock.flush().await?;
                drop(buf_lock);
                drop(writer_lock);
            }
        }
    }

    Ok(())
}

/// Handles the 'Log' command by streaming historical and/or live events.
///
/// # Errors
///
/// Returns a `UdsError` if the database query fails or the client disconnects unexpectedly.
pub async fn handle_log_stream<W, R>(
    writer: Arc<Mutex<W>>,
    mut reader: R,
    ctx: ClientContext,
    n: Option<usize>,
    buf: Arc<Mutex<Vec<u8>>>,
    follow: bool,
    filter: Option<Vec<EventKind>>,
) -> Result<(), UdsError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let n_lines = n.unwrap_or(100);
    let history = ctx.log_db.get_history(n_lines).await?;

    {
        let mut writer_lock = writer.lock().await;
        let mut buf_lock = buf.lock().await;
        write_rpc_response(&mut *writer_lock, &RpcResponse::Log(()), &mut buf_lock).await?;
        for event in history {
            if let Some(ref filters) = filter
                && !filters.iter().any(|f| f.matches(&event.event))
            {
                continue;
            }
            write_rpc_response(&mut *writer_lock, &RpcResponse::Event(event), &mut buf_lock)
                .await?;
        }
        drop(writer_lock);
        drop(buf_lock);
    }

    if !follow {
        return Ok(());
    }

    let mut bus_rx = ctx.ctx.bus().subscribe();
    let mut eof_buf = [0u8; 1];

    loop {
        tokio::select! {
            res = bus_rx.recv() => {
                match res {
                    Ok(event) => {
                        if let Some(ref filters) = filter
                            && !filters.iter().any(|f| f.matches(&event.event)) {
                                continue;
                            }
                        let mut writer_lock = writer.lock().await;
                        let mut buf_lock = buf.lock().await;
                        write_rpc_response(&mut *writer_lock, &RpcResponse::Event(event), &mut buf_lock).await?;
                        drop(buf_lock);
                        drop(writer_lock);
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

/// Handles the 'DnsQueryLog' command by streaming live DNS query events.
async fn handle_dns_query_log_stream<W, R>(
    writer: Arc<Mutex<W>>,
    mut reader: R,
    ctx: ClientContext,
    client_filter: Option<String>,
    buf: Arc<Mutex<Vec<u8>>>,
) -> Result<(), UdsError>
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
                        if let lanforge_types::events::LanforgeEvent::Dns(lanforge_types::events::DnsEvent::QueryResolved(ref q)) = event.event {
                            if let Some(ref client_ip) = client_filter
                                && q.src_ip.to_string() != *client_ip {
                                    continue;
                                }
                            let mut writer_lock = writer.lock().await;
                            let mut buf_lock = buf.lock().await;
                            write_rpc_response(&mut *writer_lock, &RpcResponse::Event(event), &mut buf_lock).await?;
                            drop(buf_lock);
                            drop(writer_lock);
                        }
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

async fn write_rpc_response<W>(
    writer: &mut W,
    resp: &RpcResponse,
    buf: &mut Vec<u8>,
) -> Result<(), UdsError>
where
    W: AsyncWrite + Unpin,
{
    buf.clear();
    let buffer = std::mem::take(buf);
    let buffer =
        postcard::to_extend(resp, buffer).map_err(|e| UdsError::EncodingError(e.to_string()))?;
    *buf = buffer;
    #[allow(clippy::cast_possible_truncation)]
    let len = buf.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(buf).await?;
    writer.flush().await?;
    Ok(())
}
