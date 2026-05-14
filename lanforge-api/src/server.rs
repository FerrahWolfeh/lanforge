use crate::api::{
    DevicesResponse, LeasesResponse, Response, RpcCallError, SimpleSuccess, StatusResponse,
    TopologyResponse,
};
use lanforge_core::context::state::State;
use lanforge_core::error::CoreError;
use lanforge_db::engine::LeaseDb;
use tokio::sync::Mutex;

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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, split};
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

/// Main worker task for a client connection.
///
/// # Errors
///
/// Returns an `ApiError` if the client connection fails or a protocol error occurs.
pub async fn handle_client<S>(stream: S, ctx: ClientContext) -> Result<(), ApiError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
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

use crate::rpc::{LanforgeRpc, LanforgeRpcDispatcher, RpcRequest, RpcResponse};

pub struct RpcServer<W> {
    ctx: ClientContext,
    writer: Arc<Mutex<W>>,
    buf: Arc<Mutex<Vec<u8>>>,
}

impl<W> RpcServer<W> {
    fn map_error(err: String) -> RpcCallError {
        if err.contains("Invalid MAC") {
            RpcCallError::InvalidMac(err)
        } else if err.contains("not found") {
            RpcCallError::DeviceNotFound(err)
        } else if err.contains("Failed to update") {
            RpcCallError::UpdateFailed
        } else {
            RpcCallError::Internal(err)
        }
    }
}

#[async_trait::async_trait]
impl<W> LanforgeRpc for RpcServer<W>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    async fn status(&self) -> Result<Box<StatusResponse>, RpcCallError> {
        match self.ctx.handle_status().await {
            Response::Status(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn list_devices(
        &self,
        filter: Option<String>,
        vendor: Option<String>,
        method: Option<String>,
        format: Option<String>,
    ) -> Result<DevicesResponse, RpcCallError> {
        match self
            .ctx
            .handle_devices(filter, vendor, method, format)
            .await
        {
            Response::Devices(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn reload(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_reload().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn watch(&self) -> Result<(), RpcCallError> {
        Ok(())
    }
    async fn log(&self, _follow: bool, _n: Option<usize>) -> Result<(), RpcCallError> {
        Ok(())
    }

    async fn scan(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_scan().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn shutdown(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_shutdown().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn host_add(
        &self,
        mac: Option<String>,
        hostname: Option<String>,
        v4: Option<String>,
        v6_suffix: Option<String>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_host_add(mac, hostname, v4, v6_suffix).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn host_set(
        &self,
        mac: String,
        field: String,
        value: String,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_host_set(mac, field, value).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn host_remove(&self, mac: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_host_remove(mac).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn host_list(&self) -> Result<crate::api::HostsResponse, RpcCallError> {
        match self.ctx.handle_hosts().await {
            Response::Hosts(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn lease_renew(
        &self,
        mac: String,
        target: Option<lanforge_core::types::LeaseTarget>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_lease_renew(mac, target).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn lease_release(
        &self,
        mac: String,
        target: Option<lanforge_core::types::LeaseTarget>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_lease_release(mac, target).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dhcp_pools(&self) -> Result<crate::api::DhcpPoolsResponse, RpcCallError> {
        match self.ctx.handle_dhcp_pools().await {
            Response::DhcpPools(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn db_vacuum(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_db_vacuum().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn db_log_clean(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_db_log_clean().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn db_prune(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_db_prune().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn purge(&self, mac: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_purge(mac).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn wol(&self, target: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_wol(target).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn whois(&self, target: String) -> Result<Box<crate::api::WhoisResponse>, RpcCallError> {
        match self.ctx.handle_whois(target).await {
            Response::Whois(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_stats(&self) -> Result<crate::api::DnsStatsResponse, RpcCallError> {
        match self.ctx.handle_dns_stats().await {
            Response::DnsStats(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_analytics(
        &self,
        limit: Option<usize>,
    ) -> Result<crate::api::DnsAnalyticsResponse, RpcCallError> {
        match self.ctx.handle_dns_analytics(limit).await {
            Response::DnsAnalytics(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_upstreams(&self) -> Result<crate::api::DnsUpstreamsResponse, RpcCallError> {
        match self.ctx.handle_dns_upstreams().await {
            Response::DnsUpstreams(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_query(
        &self,
        name: String,
        record_type: Option<String>,
    ) -> Result<crate::api::DnsQueryResponse, RpcCallError> {
        match self.ctx.handle_dns_query(name, record_type).await {
            Response::DnsQuery(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_cache_flush(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_dns_cache_flush().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_cache_dump(&self) -> Result<crate::api::DnsCacheResponse, RpcCallError> {
        match self.ctx.handle_dns_cache_dump().await {
            Response::DnsCache(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_adblock_set(
        &self,
        enabled: bool,
        duration_secs: Option<u64>,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self
            .ctx
            .handle_dns_adblock_set(enabled, duration_secs)
            .await
        {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_adblock_reload(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_dns_adblock_reload().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_query_log(
        &self,
        limit: Option<usize>,
        client: Option<String>,
        follow: bool,
    ) -> Result<crate::api::DnsQueryLogResponse, RpcCallError> {
        let res = match self
            .ctx
            .handle_dns_query_log(limit, client.clone(), follow)
            .await
        {
            Response::DnsQueryLog(res) => res,
            Response::Error { error } => return Err(Self::map_error(error)),
            _ => return Err(RpcCallError::InvalidResponseType),
        };

        if follow {
            let mut sub = self.ctx.ctx.bus().subscribe();
            let writer = self.writer.clone();
            let buf = self.buf.clone();
            let filter = client.clone();
            let ctx_inner = self.ctx.ctx.clone();

            tokio::spawn(async move {
                let mut writer = writer.lock().await;
                let mut buf = buf.lock().await;
                while let Ok(event) = sub.recv().await {
                    if let LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::QueryResolved(entry)) =
                        &event.event
                    {
                        // Resolve hostname for filtering
                        let src_hostname = ctx_inner
                            .get_mac_by_ip(entry.src_ip)
                            .and_then(|m| ctx_inner.get_device(&m))
                            .map(|d| d.display_hostname().to_string());

                        // Check filter
                        if let Some(f) = &filter
                            && &entry.src_ip.to_string() != f
                            && src_hostname.as_ref() != Some(f)
                        {
                            continue;
                        }

                        if let Err(e) =
                            write_rpc_response(&mut *writer, &RpcResponse::Event(event), &mut buf)
                                .await
                        {
                            eprintln!("Failed to send DNS log event: {e}");
                            break;
                        }
                    }
                }
            });
        }

        Ok(res)
    }

    async fn dns_adblock_status(
        &self,
    ) -> Result<crate::api::DnsAdblockStatusResponse, RpcCallError> {
        match self.ctx.handle_dns_adblock_status().await {
            Response::DnsAdblockStatus(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_block(&self, domain: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_dns_block(domain).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_allow(&self, domain: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_dns_allow(domain).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_unallow(&self, domain: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_dns_unallow(domain).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_rewrite_add(
        &self,
        domain: String,
        answer: String,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_dns_rewrite_add(domain, answer).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_rewrite_remove(&self, domain: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_dns_rewrite_remove(domain).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_rewrites(&self) -> Result<crate::api::DnsRewritesResponse, RpcCallError> {
        match self.ctx.handle_dns_rewrites().await {
            Response::DnsRewrites(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_allowlist(&self) -> Result<crate::api::DnsAllowlistResponse, RpcCallError> {
        match self.ctx.handle_dns_allowlist().await {
            Response::DnsAllowlist(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_adblock_url_add(
        &self,
        url: String,
        kind: String,
    ) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_dns_adblock_url_add(url, kind).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_adblock_url_remove(&self, url: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_dns_adblock_url_remove(url).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn dns_adblock_url_list(
        &self,
    ) -> Result<crate::api::DnsAdblockUrlsResponse, RpcCallError> {
        match self.ctx.handle_dns_adblock_urls().await {
            Response::DnsAdblockUrls(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn context_dump(
        &self,
        only_devices: bool,
        only_orphans: bool,
    ) -> Result<Box<State>, RpcCallError> {
        match self
            .ctx
            .handle_context_dump(only_devices, only_orphans)
            .await
        {
            Response::ContextDump(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn db_reset(&self) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_db_reset().await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn leases(&self, count: bool) -> Result<LeasesResponse, RpcCallError> {
        match self.ctx.handle_leases(count).await {
            Response::Leases(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn topology(&self) -> Result<TopologyResponse, RpcCallError> {
        match self.ctx.handle_topology().await {
            Response::Topology(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn config_set_password(&self, password: String) -> Result<SimpleSuccess, RpcCallError> {
        match self.ctx.handle_config_set_password(password).await {
            Response::Success(s) => Ok(s),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }

    async fn auth_generate_token(
        &self,
        name: String,
    ) -> Result<crate::api::AuthTokenResponse, RpcCallError> {
        match self.ctx.handle_auth_generate_token(name).await {
            Response::AuthToken(r) => Ok(r),
            Response::Error { error } => Err(Self::map_error(error)),
            _ => Err(RpcCallError::InvalidResponseType),
        }
    }
}

async fn handle_client_inner<S>(stream: S, ctx: ClientContext) -> Result<(), ApiError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (reader, writer) = split(stream);
    let mut reader = BufReader::new(reader);
    let writer = Arc::new(Mutex::new(writer));
    let buf = Arc::new(Mutex::new(Vec::with_capacity(8192)));
    let rpc_server = RpcServer {
        ctx: ctx.clone(),
        writer: writer.clone(),
        buf: buf.clone(),
    };

    loop {
        // Read framing: u32 BE length
        let mut len_bytes = [0u8; 4];
        if let Err(e) = reader.read_exact(&mut len_bytes).await {
            if e.kind() == ErrorKind::UnexpectedEof {
                break;
            }
            return Err(ApiError::Io(e));
        }
        let len = u32::from_be_bytes(len_bytes) as usize;

        // Read payload
        let mut req_buf = vec![0u8; len];
        reader.read_exact(&mut req_buf).await?;

        // Deserialize request
        let req: RpcRequest =
            postcard::from_bytes(&req_buf).map_err(|e| ApiError::EncodingError(e.to_string()))?;

        // Handle RPC requests
        match req {
            RpcRequest::Watch {} => {
                handle_watch_stream(writer.clone(), reader, ctx.clone(), buf.clone()).await?;
                return Ok(());
            }
            RpcRequest::Log { follow, n } => {
                handle_log_stream(writer.clone(), reader, ctx.clone(), n, buf.clone(), follow)
                    .await?;
                return Ok(());
            }
            _ => {
                let resp = rpc_server.dispatch(req).await;

                let mut writer_lock = writer.lock().await;
                let mut buf_lock = buf.lock().await;

                buf_lock.clear();
                let buffer = std::mem::take(&mut *buf_lock);
                let buffer = postcard::to_extend(&resp, buffer)
                    .map_err(|e| ApiError::EncodingError(e.to_string()))?;
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
/// Returns an `ApiError` if the database query fails or the client disconnects unexpectedly.
pub async fn handle_log_stream<W, R>(
    writer: Arc<Mutex<W>>,
    mut reader: R,
    ctx: ClientContext,
    n: Option<usize>,
    buf: Arc<Mutex<Vec<u8>>>,
    follow: bool,
) -> Result<(), ApiError>
where
    W: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let n_lines = n.unwrap_or(100);
    let mut history = ctx.log_db.stream_history(n_lines);

    {
        let mut writer_lock = writer.lock().await;
        let mut buf_lock = buf.lock().await;
        while let Some(res) = history.next().await {
            let event = res?;
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

/// Handles the 'Watch' command by streaming live state changes.
async fn handle_watch_stream<W, R>(
    writer: Arc<Mutex<W>>,
    mut reader: R,
    ctx: ClientContext,
    buf: Arc<Mutex<Vec<u8>>>,
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

async fn write_rpc_response<W>(
    writer: &mut W,
    resp: &RpcResponse,
    buf: &mut Vec<u8>,
) -> Result<(), ApiError>
where
    W: AsyncWrite + Unpin,
{
    buf.clear();
    let buffer = std::mem::take(buf);
    let buffer =
        postcard::to_extend(resp, buffer).map_err(|e| ApiError::EncodingError(e.to_string()))?;
    *buf = buffer;
    #[allow(clippy::cast_possible_truncation)]
    let len = buf.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(buf).await?;
    writer.flush().await?;
    Ok(())
}
