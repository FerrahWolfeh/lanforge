use crate::{
    error::DnsError,
    response::ResponseBuilder,
    stats::DnsStatsSnapshot,
    wire::{WireHeader, WireOptScanner, WireQuestion, qtypes::QType},
};
use hickory_proto::{
    op::Message,
    rr::{Name, RecordType},
    serialize::binary::BinDecodable,
};
use lanforge_core::{
    bus::{SystemEvent, TimedEvent},
    context::LanforgeContext,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{net::IpAddr, str::FromStr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::broadcast::Receiver,
    task::JoinHandle,
};
use tracing::info;

use crate::{
    config::DnsConfig, resolver::LocalResolver, stats::DnsStats, utils::extract_local_hostname_wire,
};
use crate::{
    upstream::{UpstreamManager, forward_to_upstream},
    utils::parse_arpa_wire,
};
use crate::{
    utils::{extract_local_hostname, fast_lowercase},
    wire::WireResponseWriter,
};
#[allow(unused_imports)]
use lanforge_core::bus::{DnsEvent, LanforgeEvent};

#[cfg(feature = "adblock")]
use crate::filter::{AdBlocker, labels_to_domain};

/// Shared, immutable service state for the DNS hot path.
///
/// A single `Arc<DnsContext>` replaces several individual `Arc` clones per query,
/// reducing atomic reference counting overhead in the fast path.
pub struct DnsContext {
    pub cfg: DnsConfig,
    /// List of upstream managers, one per target, sorted by priority.
    pub upstreams: Vec<Arc<UpstreamManager>>,
    pub stats: Arc<DnsStats>,
    pub ctx: LanforgeContext,
    #[cfg(feature = "adblock")]
    pub adblocker: Option<Arc<AdBlocker>>,

    // Pre-computed SOA names for NXDOMAIN/NODATA responses
    pub soa_zone: Name,
    pub soa_master_ns: Name,
    pub soa_mailbox: Name,
}

use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceControl};

#[lanforge_macros::lanforge_service(
    id = "dns",
    name = "DNS Server",
    critical = true,
    retries = 0,
    base_backoff = 2,
    max_backoff = 30,
    multi_threaded = true,
    describe = format!(
        "DNS on {} ({} upstreams, domains: {:?})",
        self.cfg.listen, self.cfg.upstreams.len(), self.cfg.search_domains
    )
)]
pub struct DnsService {
    cfg: DnsConfig,
    stats: Arc<DnsStats>,
    ctx: LanforgeContext,
}

impl DnsService {
    #[must_use]
    pub fn new(cfg: DnsConfig, ctx: LanforgeContext) -> Self {
        let stats = Arc::new(DnsStats::new());
        ctx.set_dns_stats(Arc::clone(&stats));
        Self { cfg, stats, ctx }
    }

    /// Returns a snapshot of the current DNS statistics.
    #[must_use]
    pub fn stats_snapshot(&self) -> DnsStatsSnapshot {
        self.stats.snapshot()
    }

    fn bind_udp_reuseport(&self) -> Result<UdpSocket, CoreError> {
        let addr = self.cfg.listen;
        let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| CoreError::Generic(format!("Socket Creation Error: {e}")))?;

        socket
            .set_reuse_address(true)
            .map_err(|e| CoreError::Generic(format!("SO_REUSEADDR Error: {e}")))?;

        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        socket
            .set_reuse_port(true)
            .map_err(|e| CoreError::Generic(format!("SO_REUSEPORT Error: {e}")))?;

        socket
            .bind(&addr.into())
            .map_err(|e| CoreError::Generic(format!("Socket Bind Error: {e}")))?;

        socket
            .set_nonblocking(true)
            .map_err(|e| CoreError::Generic(format!("Socket Nonblocking Error: {e}")))?;

        UdpSocket::from_std(socket.into())
            .map_err(|e| CoreError::Generic(format!("UdpSocket Conversion Error: {e}")))
    }

    async fn bind_tcp(&self) -> Result<TcpListener, CoreError> {
        TcpListener::bind(self.cfg.listen)
            .await
            .map_err(|e| CoreError::Generic(format!("TCP Bind Error: {e}")))
    }

    /// Initializes a `DnsContext` for manual query handling.
    pub async fn init_dns_context(&self) -> Result<Arc<DnsContext>, CoreError> {
        let mut upstreams = Vec::new();
        for prioritized in &self.cfg.upstreams {
            if let Ok(mgr) = UpstreamManager::new(&prioritized.target).await {
                upstreams.push(mgr);
            }
        }

        #[cfg(feature = "adblock")]
        let adblocker = if self.cfg.adblock_enabled && !upstreams.is_empty() {
            Some(Arc::new(AdBlocker::new()))
        } else {
            None
        };

        let domain_base = self
            .cfg
            .search_domains
            .first()
            .map_or("lan", |d| d.as_str());

        let soa_zone = Name::from_str(&format!("{domain_base}.")).unwrap_or_else(|_| Name::root());
        let soa_master_ns =
            Name::from_str(&format!("ns.{domain_base}.")).unwrap_or_else(|_| Name::root());
        let soa_mailbox =
            Name::from_str(&format!("hostmaster.{domain_base}.")).unwrap_or_else(|_| Name::root());

        Ok(Arc::new(DnsContext {
            cfg: self.cfg.clone(),
            upstreams,
            stats: Arc::clone(&self.stats),
            ctx: self.ctx.clone(),
            #[cfg(feature = "adblock")]
            adblocker,
            soa_zone,
            soa_master_ns,
            soa_mailbox,
        }))
    }

    fn spawn_udp_handler(&self, dns_ctx: Arc<DnsContext>, sock: Arc<UdpSocket>) -> JoinHandle<()> {
        let ctx_udp = self.ctx.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                tokio::select! {
                    res = sock.recv_from(&mut buf) => {
                        let Ok((len, src)) = res else { continue; };
                        if let Ok(Some(response)) = handle_query(&buf[..len], &dns_ctx, src.ip()).await {
                            let _ = sock.send_to(&response, src).await;
                        }
                    }
                    () = tokio::time::sleep(Duration::from_millis(100)) => {
                         if !ctx_udp.is_running() { break; }
                    }
                }
            }
        })
    }

    #[cfg(feature = "adblock")]
    fn spawn_adblock_manager(&self, dns_ctx: &Arc<DnsContext>) -> JoinHandle<()> {
        let bus = self.ctx.bus();
        let mut rx = bus.subscribe();
        let adblocker = dns_ctx.adblocker.clone();
        let urls = self.cfg.adblock_urls.clone();
        let initial_enabled = self.cfg.adblock_enabled;

        tokio::spawn(async move {
            let Some(adblocker) = adblocker else {
                return;
            };

            // 1. Initial Load
            if !urls.is_empty() {
                let a = Arc::clone(&adblocker);
                let u = urls.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Ok(list) = a.load_from_urls(&u) {
                        a.replace_blocklist(list);
                        if initial_enabled {
                            a.set_enabled(true);
                        }
                    }
                })
                .await;
            }

            // 2. Event Loop
            let mut reenable_at: Option<std::time::Instant> = None;
            loop {
                let sleep_duration = reenable_at.map_or_else(
                    || Duration::from_hours(1),
                    |at| at.saturating_duration_since(std::time::Instant::now()),
                );

                tokio::select! {
                    res = rx.recv() => {
                        match res {
                            Ok(TimedEvent { event: LanforgeEvent::Dns(DnsEvent::AdblockToggle { enabled, duration_secs }), .. }) => {
                                adblocker.set_enabled(enabled);
                                if enabled {
                                    reenable_at = None;
                                    info!("Adblock: enabled");
                                } else if let Some(secs) = duration_secs {
                                    reenable_at = Some(std::time::Instant::now() + Duration::from_secs(secs));
                                    info!("Adblock: disabled for {} seconds", secs);
                                } else {
                                    reenable_at = None;
                                    info!("Adblock: disabled permanently");
                                }
                            }
                            Ok(TimedEvent { event: LanforgeEvent::Dns(DnsEvent::AdblockReload), .. }) => {
                                let a = Arc::clone(&adblocker);
                                let u = urls.clone();
                                let _ = tokio::task::spawn_blocking(move || {
                                    if let Ok(list) = a.load_from_urls(&u) {
                                        a.replace_blocklist(list);
                                    }
                                }).await;
                            }
                            _ => {}
                        }
                    }
                    () = tokio::time::sleep(sleep_duration), if reenable_at.is_some() => {
                        if let Some(at) = reenable_at
                            && at <= std::time::Instant::now() {
                                adblocker.set_enabled(true);
                                reenable_at = None;
                                info!("Adblock: timer expired, re-enabled automatically");
                            }
                    }
                }
            }
        })
    }

    fn spawn_tcp_handler(&self, dns_ctx: Arc<DnsContext>, listener: TcpListener) -> JoinHandle<()> {
        let ctx_tcp = self.ctx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    res = listener.accept() => {
                        if let Ok((mut stream, _)) = res {
                            let c = Arc::clone(&dns_ctx);
                            tokio::spawn(async move {
                                let _ = tokio::time::timeout(Duration::from_secs(5), async {
                                    let mut len_buf = [0u8; 2];
                                    stream.read_exact(&mut len_buf).await?;
                                    let len = u16::from_be_bytes(len_buf) as usize;
                                    let mut query_buf = vec![0u8; len];
                                    stream.read_exact(&mut query_buf).await?;

                                    if let Ok(Some(response)) = handle_query(&query_buf, &c, stream.peer_addr()?.ip()).await {
                                        let resp_len = u16::try_from(response.len()).unwrap_or(u16::MAX).to_be_bytes();
                                        stream.write_all(&resp_len).await?;
                                        stream.write_all(&response).await?;
                                    }
                                    Ok::<(), std::io::Error>(())
                                }).await;
                            });
                        }
                    }
                    () = tokio::time::sleep(Duration::from_millis(100)) => {
                        if !ctx_tcp.is_running() { break; }
                    }
                }
            }
        })
    }

    async fn wait_for_shutdown(&self, mut rx: Receiver<TimedEvent>) {
        let ctx_main = self.ctx.clone();
        loop {
            tokio::select! {
                Ok(TimedEvent { event: LanforgeEvent::System(SystemEvent::Shutdown), .. }) = rx.recv() => {
                    info!("DNS service: shutdown received");
                    break;
                }
                () = tokio::time::sleep(Duration::from_millis(500)) => {
                    if !ctx_main.is_running() { break; }
                }
            }
        }
    }
}

impl AsyncService for DnsService {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        if !self.cfg.enabled {
            info!("DNS Service disabled in config");
            return Ok(());
        }

        let bus = self.ctx.bus();

        // 1. Synchronize dependencies
        info!("DNS: Waiting for database engine...");
        self.ctx.wait_for_db().await?;

        // 2. Initialize networking and context
        let tcp_listener = self.bind_tcp().await?;
        let dns_ctx = self.init_dns_context().await?;

        // Expose context for other services (DoT/DoH)
        self.ctx.set_dns_context(Arc::clone(&dns_ctx));

        // 3. Determine scaling factor
        let parallelism = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);

        info!(
            "Starting DNS service with {} UDP handlers (SO_REUSEPORT enabled)",
            parallelism
        );

        // 4. Spawn UDP handlers
        let mut udp_handlers = Vec::with_capacity(parallelism);
        for i in 0..parallelism {
            let sock = Arc::new(self.bind_udp_reuseport()?);
            let handle = self.spawn_udp_handler(Arc::clone(&dns_ctx), sock);
            udp_handlers.push(handle);
            tracing::trace!("Spawned DNS UDP worker #{}", i);
        }

        // 5. Spawn other protocol managers
        let tcp_handle = self.spawn_tcp_handler(Arc::clone(&dns_ctx), tcp_listener);
        #[cfg(feature = "adblock")]
        let adblock_handle = self.spawn_adblock_manager(&dns_ctx);

        #[cfg(feature = "dot")]
        let dot_task = if self.cfg.dot_enabled
            && let Some(listen_addr) = self.cfg.dot_listen
        {
            use crate::dot::DotService;
            info!("DoT: Starting listener on {}", listen_addr);
            let mut dot_svc = DotService::new(Arc::new(self.cfg.clone()), self.ctx.clone());
            let dot_ctrl = ctrl.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = dot_svc.run(dot_ctrl).await {
                    tracing::error!("DoT Service error: {}", e);
                }
            }))
        } else {
            None
        };

        ctrl.signal_ready();

        // 6. Enter main process loop
        self.wait_for_shutdown(bus.subscribe()).await;

        // 7. Cleanup
        for h in udp_handlers {
            h.abort();
        }
        tcp_handle.abort();
        #[cfg(feature = "adblock")]
        adblock_handle.abort();
        #[cfg(feature = "dot")]
        if let Some(t) = dot_task {
            t.abort();
        }

        Ok(())
    }
}

/// The extra-hot path: Initial query triage and routing.
///
/// This function uses the zero-allocation wire parser to decide how to handle
/// the query before performing a full parse.
///
/// ```mermaid
/// flowchart TD
///     Start[Inbound Query] --> WireHeader[WireHeader::parse]
///     WireHeader -->|Valid Query| WireQuestion[WireQuestion::parse]
///     WireQuestion -->|Simple Name| Local{Local Resolution?}
///     Local -->|Found| Return[Local Response]
///     Local -->|Not Found| Upstream[forward_to_upstream]
///     WireQuestion -->|Complex Name/Pointers| Fallback[handle_query_fallback]
///     Fallback --> Local2{Local Resolution?}
///     Local2 -->|Found| Return
///     Local2 -->|Not Found| Upstream
/// ```
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub async fn handle_query(
    data: &[u8],
    ctx: &DnsContext,
    src_addr: IpAddr,
) -> Result<Option<Vec<u8>>, DnsError> {
    ctx.stats.inc_requests();

    let _ = src_addr;

    // PHASE 1: Zero-Alloc Triage
    let Some(header) = WireHeader::parse(data) else {
        return Ok(None);
    };
    if !header.is_query() {
        return Ok(None);
    }

    let Some(question) = WireQuestion::parse(data) else {
        return handle_query_fallback(data, ctx, src_addr).await;
    };

    // PHASE 2: Local Resolution Attempt
    if let Some(resp) = resolve_local_wire(data, &header, &question, ctx)? {
        ctx.stats.inc_auth();
        ctx.stats.inc_cache_hit();
        return Ok(Some(resp));
    }

    ctx.stats.inc_cache_miss();

    // PHASE 2.5: Adblock Filtering
    #[cfg(feature = "adblock")]
    if let Some(adblocker) = &ctx.adblocker
        && adblocker.is_enabled()
    {
        let domain = labels_to_domain(question.labels());
        if adblocker.should_block(&domain) {
            ctx.stats.inc_blocked();
            ctx.ctx.inc_dns_blocked();
            adblocker.inc_ip_stats(src_addr);

            let edns = WireOptScanner::scan(data, &header, &question);
            let ra = !ctx.cfg.upstreams.is_empty();
            return Ok(Some(WireResponseWriter::write_error_response(
                data,
                &question,
                3, // NXDOMAIN
                edns.as_ref(),
                ra,
            )));
        }
    }

    // PHASE 3: Recursive Forwarding
    if !ctx.upstreams.is_empty() {
        ctx.stats.inc_recursive();
        for mgr in &ctx.upstreams {
            if let Ok(resp) = forward_to_upstream(data, &mgr.target, mgr).await {
                return Ok(Some(resp));
            }
        }
    }

    let edns = WireOptScanner::scan(data, &header, &question);
    let ra = !ctx.upstreams.is_empty();
    Ok(Some(WireResponseWriter::write_error_response(
        data,
        &question,
        3, // NXDOMAIN (or ServFail if upstreams failed? RFC says NXDOMAIN is fine if we are authoritative for nothing)
        edns.as_ref(),
        ra,
    )))
}

/// Helper function for local resolution using wire-parsed data.
fn resolve_local_wire(
    data: &[u8],
    header: &WireHeader,
    question: &WireQuestion<'_>,
    ctx: &DnsContext,
) -> Result<Option<Vec<u8>>, DnsError> {
    let raw_qtype = question.qtype();
    let qtype = QType::from(raw_qtype);

    match qtype {
        QType::A | QType::AAAA | QType::Any => {
            let mut labels = question.labels();
            if let Some(hostname_slice) =
                extract_local_hostname_wire(&mut labels, &ctx.cfg.multi_search_labels)
            {
                let safe_hostname = fast_lowercase(hostname_slice);
                let qname = Name::from_bytes(question.qname_raw())?;
                let edns = WireOptScanner::scan(data, header, question);
                let rb = ResponseBuilder::from_wire(
                    header.id(),
                    qname,
                    RecordType::from(raw_qtype),
                    edns,
                    ctx,
                );

                let resp = LocalResolver::new(&ctx.cfg, &ctx.ctx).resolve_ip(
                    &rb,
                    &safe_hostname,
                    RecordType::from(raw_qtype),
                )?;
                return Ok(Some(resp));
            }
        }
        QType::PTR => {
            if let Some(_target_ip) = parse_arpa_wire(question.labels()) {
                let qname = Name::from_bytes(question.qname_raw())?;
                let edns = WireOptScanner::scan(data, header, question);
                let rb = ResponseBuilder::from_wire(
                    header.id(),
                    qname.clone(),
                    RecordType::from(raw_qtype),
                    edns,
                    ctx,
                );

                let resp = LocalResolver::new(&ctx.cfg, &ctx.ctx).resolve_ptr(&rb, &qname)?;
                if let Some(r) = resp {
                    return Ok(Some(r));
                }
            }
        }
        _ => {}
    }
    Ok(None)
}

/// Fallback logic for queries that are too complex for the zero-alloc wire parser.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
async fn handle_query_fallback(
    data: &[u8],
    ctx: &DnsContext,
    src_addr: IpAddr,
) -> Result<Option<Vec<u8>>, DnsError> {
    let _ = src_addr;

    let Ok(query) = Message::from_bytes(data) else {
        return Ok(None);
    };
    let rb = ResponseBuilder::new(&query, ctx);
    let question = query.queries.first().ok_or(DnsError::WireParseError)?;
    let qname = question.name();
    let qtype = question.query_type();

    if matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
        if let Some(hostname_slice) = extract_local_hostname(qname, &ctx.cfg.multi_search_labels) {
            let safe_hostname = fast_lowercase(hostname_slice);
            ctx.stats.inc_auth();
            ctx.stats.inc_cache_hit();
            let resp =
                LocalResolver::new(&ctx.cfg, &ctx.ctx).resolve_ip(&rb, &safe_hostname, qtype)?;
            return Ok(Some(resp));
        }
    } else if qtype == RecordType::PTR {
        let resp = LocalResolver::new(&ctx.cfg, &ctx.ctx).resolve_ptr(&rb, qname)?;
        if let Some(response) = resp {
            ctx.stats.inc_auth();
            ctx.stats.inc_cache_hit();
            return Ok(Some(response));
        }
    }

    ctx.stats.inc_cache_miss();

    // Adblock check for fallback path
    #[cfg(feature = "adblock")]
    if let Some(adblocker) = &ctx.adblocker
        && adblocker.is_enabled()
    {
        let mut domain = qname.to_string();
        if domain.ends_with('.') {
            domain.pop();
        }
        domain.make_ascii_lowercase();

        if adblocker.should_block(&domain) {
            ctx.stats.inc_blocked();
            ctx.ctx.inc_dns_blocked();
            adblocker.inc_ip_stats(src_addr);
            return Ok(Some(rb.nxdomain()?));
        }
    }

    if !ctx.upstreams.is_empty() {
        ctx.stats.inc_recursive();
        for mgr in &ctx.upstreams {
            if let Ok(resp) = forward_to_upstream(data, &mgr.target, mgr).await {
                return Ok(Some(resp));
            }
        }
    }

    Ok(Some(rb.nxdomain()?))
}
