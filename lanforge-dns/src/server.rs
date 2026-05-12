use crate::stats::DnsStatsSnapshot;
use hickory_proto::rr::Name;
use lanforge_core::{
    bus::{SystemEvent, TimedEvent},
    context::LanforgeContext,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{collections::HashSet, str::FromStr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::broadcast::{Receiver, error::RecvError},
    task::JoinHandle,
};
use tracing::info;

pub use crate::handler::process_query as handle_query;
use crate::query_log::QueryRing;
use crate::{config::DnsConfig, stats::DnsStats};
use crate::{strategy::UpstreamStrategy, upstream::UpstreamManager};
#[allow(unused_imports)]
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
use lanforge_core::types::network::{QueryLogEntry, QueryResult};
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "adblock")]
use crate::filter::AdBlocker;

/// Shared, immutable service state for the DNS hot path.
///
/// A single `Arc<DnsContext>` replaces several individual `Arc` clones per query,
/// reducing atomic reference counting overhead in the fast path.
pub struct DnsContext {
    pub cfg: DnsConfig,
    /// List of upstream managers, one per target, sorted by priority.
    pub upstreams: Vec<Arc<UpstreamManager>>,
    /// Strategy for recursive resolution.
    pub upstream_strategy: Arc<UpstreamStrategy>,
    pub stats: Arc<DnsStats>,
    pub ctx: LanforgeContext,
    #[cfg(feature = "adblock")]
    pub adblocker: Option<Arc<AdBlocker>>,
    pub query_log: Option<Arc<QueryRing>>,

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

        let upstream_strategy = Arc::new(UpstreamStrategy::new(
            self.cfg.upstream_mode,
            upstreams.clone(),
        ));

        let query_log = if self.cfg.query_log.enabled {
            Some(Arc::new(QueryRing::new(self.cfg.query_log.ring_size)))
        } else {
            None
        };

        Ok(Arc::new(DnsContext {
            cfg: self.cfg.clone(),
            upstreams,
            upstream_strategy,
            stats: Arc::clone(&self.stats),
            ctx: self.ctx.clone(),
            #[cfg(feature = "adblock")]
            adblocker,
            soa_zone,
            soa_master_ns,
            soa_mailbox,
            query_log,
        }))
    }
}

impl DnsContext {
    pub fn record_log(
        &self,
        src_ip: std::net::IpAddr,
        domain: String,
        qtype: u16,
        result: QueryResult,
        upstream_us: u32,
        cached: bool,
    ) {
        if let Some(log) = &self.query_log {
            let entry = QueryLogEntry {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                src_ip,
                domain,
                qtype,
                result,
                upstream_us,
                cached,
            };
            log.push(entry.clone());

            if self.cfg.query_log.persist {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Dns(DnsEvent::QueryResolved(entry)));
            }
        }
    }
}

impl DnsService {
    fn spawn_udp_handler(&self, dns_ctx: Arc<DnsContext>, sock: Arc<UdpSocket>) -> JoinHandle<()> {
        let ctx_udp = self.ctx.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let mut resp_buf = Vec::with_capacity(512);
            loop {
                tokio::select! {
                    res = sock.recv_from(&mut buf) => {
                        let Ok((len, src)) = res else { continue; };
                        if matches!(crate::handler::process_query(&buf[..len], &dns_ctx, src.ip(), &mut resp_buf).await, Ok(true)) {
                            let _ = sock.send_to(&resp_buf, src).await;
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
        let rewrites = dns_ctx.cfg.rewrites.clone();
        let allowlist = dns_ctx.cfg.allowlist.clone();

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

            // 2. Initial Rewrites & Allowlist from config
            {
                adblocker.rewrites.write().clone_from(&rewrites);
                let mut allow = HashSet::new();
                for domain in &allowlist {
                    allow.insert(domain.to_lowercase());
                }
                adblocker.replace_allowlist(allow);
            }

            // 3. Event Loop
            loop {
                let sleep_duration = adblocker
                    .timer
                    .remaining_secs()
                    .map_or(Duration::from_hours(1), Duration::from_secs);

                tokio::select! {
                    res = rx.recv() => {
                        match res {
                            Ok(TimedEvent { event: LanforgeEvent::Dns(DnsEvent::AdblockToggle { enabled, duration_secs }), .. }) => {
                                adblocker.set_enabled(enabled);
                                if enabled {
                                    info!("Adblock: enabled");
                                } else if let Some(secs) = duration_secs {
                                    let until = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs() + secs;
                                    adblocker.timer.disabled_until.store(until, Ordering::Relaxed);
                                    info!("Adblock: disabled for {} seconds", secs);
                                } else {
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
                            Ok(TimedEvent { event: LanforgeEvent::Dns(DnsEvent::AdblockBlock(domain)), .. }) => {
                                adblocker.add_block(&domain);
                            }
                            Ok(TimedEvent { event: LanforgeEvent::Dns(DnsEvent::AdblockAllow(domain)), .. }) => {
                                adblocker.add_allow(&domain);
                            }
                            _ => {}
                        }
                    }
                    () = tokio::time::sleep(sleep_duration), if adblocker.timer.remaining_secs().is_some() => {
                        if let Some(rem) = adblocker.timer.remaining_secs() && rem == 0 {
                            adblocker.set_enabled(true);
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

                                    let mut resp_buf = Vec::with_capacity(512);
                                    if matches!(crate::handler::process_query(&query_buf, &c, stream.peer_addr()?.ip(), &mut resp_buf).await, Ok(true)) {
                                        let resp_len = u16::try_from(resp_buf.len()).unwrap_or(u16::MAX).to_be_bytes();
                                        stream.write_all(&resp_len).await?;
                                        stream.write_all(&resp_buf).await?;
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

    fn spawn_cache_handler(&self, dns_ctx: Arc<DnsContext>) -> JoinHandle<()> {
        let bus = self.ctx.bus();
        let mut rx = bus.subscribe();

        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(TimedEvent {
                        event: LanforgeEvent::Dns(DnsEvent::CacheFlush),
                        ..
                    }) => {
                        for upstream in &dns_ctx.upstreams {
                            upstream.cache.invalidate_all();
                        }
                        info!("DNS cache flushed for all upstreams");
                    }
                    Err(RecvError::Closed) => break,
                    _ => {}
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

        let cache_handle = self.spawn_cache_handler(Arc::clone(&dns_ctx));

        ctrl.signal_ready();

        // 6. Enter main process loop
        self.wait_for_shutdown(bus.subscribe()).await;

        // 7. Cleanup
        for h in udp_handlers {
            h.abort();
        }
        tcp_handle.abort();
        cache_handle.abort();
        #[cfg(feature = "adblock")]
        adblock_handle.abort();
        #[cfg(feature = "dot")]
        if let Some(t) = dot_task {
            t.abort();
        }

        Ok(())
    }
}
