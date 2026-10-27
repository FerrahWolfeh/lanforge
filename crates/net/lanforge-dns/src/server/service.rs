use crate::config::DnsConfig;
use crate::pipeline::DnsPipelineRequest;
use crate::pipeline::{Pipeline, middleware::*};
#[cfg(feature = "adblock")]
use crate::resolver::AdBlocker;
use crate::resolver::recursive::cache::CacheKey;
use crate::resolver::{
    LocalResolver, RewriteStore,
    recursive::{DnsCache, UpstreamManager, UpstreamStrategy},
};
use crate::server::{CompiledIgnoreClients, DnsContext};
use crate::telemetry::{DnsStats, DnsStatsSnapshot, QueryRing};
use futures::future::join_all;
#[cfg(feature = "adblock")]
use lanforge_core::context::ConfigSubscription;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceCommand, ServiceHandle};
use lanforge_dns_wire::{WireDecoder, WireEncoder, WireHeader, WireQuestion};
use lanforge_transport::{TransportSnapshot, TransportStats};
#[cfg(feature = "adblock")]
use lanforge_types::config::DnsAllowlist;
#[cfg(feature = "adblock")]
use lanforge_types::network::dns::adblock::AdblockRuleEntry;
use lanforge_types::network::dns::{
    AdblockCheckResponse, AdblockSourceMatch, AdblockSourceStatus, DnsAdblockSourcesResponse,
    DnsCacheEntry, DnsCacheResponse, DnsCacheStatsExtResponse, DnsClass, DnsLifetimeStats,
    DnsMessage, DnsQuestion, DnsRecordEntry, DnsRecordType, DnsRequest, DnsResponse,
    DnsStatsResponse, FilterMatch, FilterOrigin, TransportProtocol,
    adblock::{AdblockDbConfig, RewriteRule},
    upstream::{UpstreamMode, UpstreamProtocol, UpstreamTarget},
};
use lanforge_types::system::{DormantReason, PppoeSessionState, ServiceId, ServiceState};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::sync::broadcast::error::RecvError;
use tracing::{debug, error, info};

#[derive(Clone)]
pub struct DnsService {
    cfg: Arc<DnsConfig>,
    stats: Arc<DnsStats>,
    ctx: LanforgeContext,
    custom_transport: Option<lanforge_transport::UdpTransport>,
}

impl DnsService {
    /// Static identifier for the service.
    pub const SERVICE_ID: ServiceId = ServiceId::Dns;
    #[must_use]
    pub fn new(cfg: DnsConfig, ctx: LanforgeContext) -> Self {
        let lifetime = ctx
            .get_shared::<DnsLifetimeStats>()
            .map(|arc| (*arc).clone())
            .unwrap_or_default();
        Self::with_lifetime(cfg, ctx, lifetime)
    }

    #[must_use]
    pub fn with_lifetime(cfg: DnsConfig, ctx: LanforgeContext, lifetime: DnsLifetimeStats) -> Self {
        let stats = Arc::new(DnsStats::with_lifetime(&lifetime));
        ctx.provide_shared(Arc::clone(&stats));
        Self {
            cfg: Arc::new(cfg),
            stats,
            ctx,
            custom_transport: None,
        }
    }

    #[must_use]
    pub fn with_transport(
        cfg: DnsConfig,
        ctx: LanforgeContext,
        transport: lanforge_transport::UdpTransport,
    ) -> Self {
        let stats = Arc::new(DnsStats::with_lifetime(&DnsLifetimeStats::default()));
        ctx.provide_shared(Arc::clone(&stats));
        Self {
            cfg: Arc::new(cfg),
            stats,
            ctx,
            custom_transport: Some(transport),
        }
    }

    #[must_use]
    pub fn inert(
        cfg: DnsConfig,
        ctx: LanforgeContext,
    ) -> (lanforge_transport::InertHandle<SocketAddr>, Self) {
        let (handle, transport) = lanforge_transport::UdpTransport::inert();
        (handle, Self::with_transport(cfg, ctx, transport))
    }

    #[must_use]
    pub fn stats_snapshot(&self) -> DnsStatsSnapshot {
        self.stats.snapshot()
    }

    pub async fn init_dns_context(&self) -> Result<Arc<DnsContext>, CoreError> {
        let cache = Arc::new(DnsCache::new(
            self.cfg.cache_size,
            self.cfg.cache_min_ttl,
            Some(Arc::clone(&self.stats)),
        ));
        self.stats
            .cache_capacity
            .store(self.cfg.cache_size, Ordering::Relaxed);
        let upstreams = build_upstreams(&effective_upstream_targets(&self.ctx), &cache).await;

        if upstreams.is_empty() && self.cfg.enabled && !self.cfg.search_domains.is_empty() {
            tracing::warn!("No upstreams configured — only local resolution active");
        }
        #[cfg(feature = "adblock")]
        let db_adblock = self.ctx.get_dns_adblock();
        let db_rewrites = self.ctx.get_dns_rewrites();
        let rewrites = Arc::new(RewriteStore::new());
        rewrites.replace_rules(db_rewrites);

        #[cfg(feature = "adblock")]
        let filter = {
            let adblock_enabled = db_adblock.enabled;
            debug!("Adblock filter initializing (enabled: {})", adblock_enabled,);
            let blocker = AdBlocker::new(adblock_enabled);
            blocker.sync_from_context(&self.ctx);
            blocker.replace_config(
                db_adblock.blocking_mode,
                db_adblock.blocking_ip_v4,
                db_adblock.blocking_ip_v6,
            );
            Some(Arc::new(blocker))
        };

        let domain_base = self
            .cfg
            .search_domains
            .first()
            .map_or("lan", |d| d.as_str());
        let soa_zone: Arc<str> = Arc::from(domain_base.to_string());
        let soa_master_ns: Arc<str> = Arc::from(format!("ns.{domain_base}"));
        let soa_mailbox: Arc<str> = Arc::from(format!("hostmaster.{domain_base}"));

        let initial_mode = self.ctx.get_dns_upstream_mode();
        let mode = if initial_mode != UpstreamMode::Sequential {
            initial_mode
        } else {
            self.cfg.upstream_mode
        };
        let recursive = Arc::new(UpstreamStrategy::new(mode, upstreams));

        let query_log = if self.cfg.query_log.enabled {
            Some(Arc::new(QueryRing::new(self.cfg.query_log.ring_size)))
        } else {
            None
        };

        let mut pipeline = Pipeline::new();
        pipeline.push(RewriteMiddleware::new());
        pipeline.push(LocalResolverMiddleware::new());
        #[cfg(feature = "adblock")]
        pipeline.push(AdblockMiddleware::new());
        pipeline.push(CacheMiddleware::new());
        pipeline.push(UpstreamMiddleware::new());

        let dns_ctx = DnsContext {
            cfg: Arc::clone(&self.cfg),
            stats: Arc::clone(&self.stats),
            bus: self.ctx.bus(),
            ctx: self.ctx.clone(),
            query_log,
            pipeline,
            local: LocalResolver::new(Arc::clone(&self.cfg), self.ctx.clone()),
            recursive,
            cache: Arc::clone(&cache),
            rewrites,
            #[cfg(feature = "adblock")]
            filter,
            soa_zone,
            soa_master_ns,
            soa_mailbox,
            reverse_managers: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            resolving_ips: Arc::new(parking_lot::Mutex::new(HashSet::new())),
            compiled_ignore_clients: CompiledIgnoreClients::compile(
                &self.cfg.query_log.ignore_clients,
            ),
        };

        let dns_ctx = Arc::new(dns_ctx);
        Ok(dns_ctx)
    }
}

const DNS_DEPS: &[lanforge_core::service::Edge] = &[
    lanforge_core::service::Edge::after(ServiceId::Db),
    lanforge_core::service::Edge::wants(ServiceId::Wan),
    lanforge_core::service::Edge::wants(ServiceId::Interfaces),
    lanforge_core::service::Edge::wants(ServiceId::Dhcp4),
    lanforge_core::service::Edge::wants(ServiceId::Dhcp6),
];

impl lanforge_core::service::LanforgeService for DnsService {
    fn spec(&self) -> lanforge_core::service::ServiceSpec {
        lanforge_core::service::ServiceSpec {
            id: Self::SERVICE_ID,
            display_name: "DNS Server",
            runtime: lanforge_core::service::RuntimeClass::Dedicated {
                multi_thread: true,
                worker_threads: None,
            },
            restart: lanforge_core::service::RestartPolicy {
                base_backoff: std::time::Duration::from_secs(2),
                max_backoff: std::time::Duration::from_secs(30),
                max_retries: 0,
                healthy_uptime: std::time::Duration::from_secs(30),
            },
            shutdown_timeout: std::time::Duration::from_secs(3),
            deps: DNS_DEPS,
            condition: lanforge_core::service::Condition {
                sections: &[lanforge_types::config::ConfigDomain::DnsListen],
                eval: |ctx| {
                    if !ctx.get_dns_listen().listen.as_slice().is_empty() {
                        lanforge_core::service::Activation::Active
                    } else {
                        lanforge_core::service::Activation::Dormant(
                            lanforge_types::system::DormantReason::disabled("dns.listen"),
                        )
                    }
                },
            },
        }
    }

    fn describe(&self) -> String {
        format!("DNS on {}", self.cfg.listen)
    }
}

impl TransportStats for DnsService {
    fn snapshot(&self) -> TransportSnapshot {
        self.custom_transport
            .as_ref()
            .map(TransportStats::snapshot)
            .unwrap_or_default()
    }
}

impl AsyncService for DnsService {
    fn transport_snapshot(&self, _ctx: &LanforgeContext) -> Option<TransportSnapshot> {
        self.custom_transport.as_ref().map(TransportStats::snapshot)
    }

    fn stats(&self, _ctx: &LanforgeContext) -> Vec<(std::borrow::Cow<'static, str>, String)> {
        let snap = self.stats.snapshot();
        let total = snap.requests_total;
        let hits = snap.cache_hits;
        let hit_rate = if total > 0 {
            (hits as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        #[cfg(feature = "adblock")]
        let blocked = snap.blocked_queries;
        #[cfg(not(feature = "adblock"))]
        let blocked = 0u64;

        let mut stats = vec![
            (
                std::borrow::Cow::Borrowed("listen"),
                self.cfg.listen.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("upstream_mode"),
                format!("{:?}", self.cfg.upstream_mode),
            ),
            (
                std::borrow::Cow::Borrowed("requests_total"),
                total.to_string(),
            ),
            (std::borrow::Cow::Borrowed("cache_hits"), hits.to_string()),
            (
                std::borrow::Cow::Borrowed("cache_misses"),
                snap.cache_misses.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("blocked_queries"),
                blocked.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("resolved_total"),
                snap.resolved_total.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("upstream_errors"),
                snap.upstream_errors.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("cache_entries"),
                snap.cache_entries.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("cache_hit_rate"),
                format!("{hit_rate:.1}%"),
            ),
        ];

        #[cfg(feature = "dot")]
        {
            let status = if let Some(addr) = self.cfg.dot_listen {
                if self.cfg.tls_cert.is_some() && self.cfg.tls_key.is_some() {
                    format!("tls://{addr}")
                } else {
                    "dormant (tls cert missing)".to_string()
                }
            } else {
                "disabled".to_string()
            };
            stats.push((std::borrow::Cow::Borrowed("dot"), status));
        }

        #[cfg(feature = "doq")]
        {
            let status = if let Some(addr) = self.cfg.doq_listen {
                if self.cfg.tls_cert.is_some() && self.cfg.tls_key.is_some() {
                    format!("quic://{addr}")
                } else {
                    "dormant (tls cert missing)".to_string()
                }
            } else {
                "disabled".to_string()
            };
            stats.push((std::borrow::Cow::Borrowed("doq"), status));
        }

        stats
    }

    async fn serve(&mut self, ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        if !self.cfg.enabled {
            info!("DNS Service disabled in config");
            h.dormant(DormantReason::disabled("dns.enabled"));
            return Ok(());
        }

        let dns_ctx = self.init_dns_context().await?;
        ctx.provide_shared(Arc::clone(&dns_ctx));

        let (tx, mut mpsc_rx) = tokio::sync::mpsc::channel(100);
        let dns_handle = lanforge_core::context::DnsHandle::new(tx);
        ctx.set_dns_handle(dns_handle);

        let is_inert = self.custom_transport.as_ref().is_some_and(|t| t.is_inert());
        let parallelism = if is_inert {
            1
        } else {
            std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
        };
        info!(handlers = parallelism, is_inert, "Starting service");

        let mut workers = Vec::new();
        if let Some(ref transport) = self.custom_transport {
            info!("Custom/inert UDP transport active");
            for _ in 0..parallelism {
                workers.push(crate::server::worker::udp::spawn_udp_worker(
                    Arc::clone(&dns_ctx),
                    transport.clone(),
                ));
            }
        } else {
            let addrs = self.cfg.listen.addrs();
            if addrs.is_empty() {
                return Err(CoreError::Generic(
                    "No DNS listen addresses configured".to_string(),
                ));
            }

            for addr in &addrs {
                let transport =
                    crate::server::transport::net::bind_udp(*addr).map_err(CoreError::Io)?;
                if self.custom_transport.is_none() {
                    self.custom_transport = Some(transport.clone());
                }
                info!(%addr, "UDP listening");
                for _ in 0..parallelism {
                    workers.push(crate::server::worker::udp::spawn_udp_worker(
                        Arc::clone(&dns_ctx),
                        transport.clone(),
                    ));
                }
            }
        }

        let tcp_worker = if !is_inert {
            Some(crate::server::worker::tcp::spawn_tcp_worker(Arc::clone(
                &dns_ctx,
            )))
        } else {
            None
        };

        #[cfg(feature = "adblock")]
        info!("Adblock feature compiled in");
        #[cfg(not(feature = "adblock"))]
        info!("Adblock feature not compiled in");

        #[cfg(feature = "adblock")]
        let adblock_worker = if dns_ctx.filter.is_some() {
            Some(crate::server::worker::spawn_adblock_manager(Arc::clone(
                &dns_ctx,
            )))
        } else {
            None
        };

        let cache_worker = crate::server::worker::spawn_cache_handler(Arc::clone(&dns_ctx));

        #[cfg(feature = "dot")]
        let dot_worker = if let Some(addr) = self.cfg.dot_listen {
            if let (Some(cert), Some(key)) = (&self.cfg.tls_cert, &self.cfg.tls_key) {
                let cert = cert.clone();
                let key = key.clone();
                let ctx_dot = ctx.clone();
                Some(tokio::spawn(async move {
                    if let Err(e) =
                        crate::server::transport::dot::run_dot_worker(addr, &cert, &key, ctx_dot)
                            .await
                    {
                        tracing::error!("DoT worker error: {e}");
                    }
                }))
            } else {
                tracing::warn!(
                    "DoT is enabled on {addr} but tls_cert/tls_key is missing; DoT listener dormant"
                );
                None
            }
        } else {
            None
        };

        #[cfg(feature = "doq")]
        let doq_worker = if let Some(addr) = self.cfg.doq_listen {
            if let (Some(cert), Some(key)) = (&self.cfg.tls_cert, &self.cfg.tls_key) {
                let cert = cert.clone();
                let key = key.clone();
                let ctx_doq = ctx.clone();
                Some(tokio::spawn(async move {
                    if let Err(e) =
                        crate::server::transport::doq::run_doq_worker(addr, &cert, &key, ctx_doq)
                            .await
                    {
                        tracing::error!("DoQ worker error: {e}");
                    }
                }))
            } else {
                tracing::warn!(
                    "DoQ is enabled on {addr} but tls_cert/tls_key is missing; DoQ listener dormant"
                );
                None
            }
        } else {
            None
        };

        let mut bus_rx = ctx.bus().subscribe_dns();
        let mut sys_rx = ctx.bus().subscribe_system();
        let mut pppoe_rx = ctx.bus().subscribe_pppoe();
        let mut wan_rx = ctx.watch_wan();
        let mut upstreams_sub = ctx.config_subscription::<Vec<UpstreamTarget>>();
        let mut mode_sub = ctx.config_subscription::<UpstreamMode>();
        let mut rewrites_sub = ctx.config_subscription::<Vec<RewriteRule>>();
        let mut filter_subs = FilterSubscriptions::new(ctx);

        let mpsc_worker = {
            let dns_ctx = Arc::clone(&dns_ctx);
            tokio::spawn(async move {
                while let Some((req, resp_tx)) = mpsc_rx.recv().await {
                    let resp = handle_dns_request(req, Arc::clone(&dns_ctx)).await;
                    let _ = resp_tx.send(resp);
                }
            })
        };

        h.ready();

        loop {
            if !ctx.is_running() {
                break;
            }
            tokio::select! {
                Ok(()) = wan_rx.changed() => {
                    let snap = wan_rx.borrow().clone();
                    if snap.is_up() {
                        h.recovered();
                    } else {
                        h.degraded(lanforge_types::system::DegradedReason::UpstreamUnreachable);
                    }
                }

                cmd = h.next_command() => {
                    match cmd {
                        ServiceCommand::Stop | ServiceCommand::Shutdown => {
                            info!("DNS service received stop/shutdown command, terminating event loop");
                            break;
                        }
                        ServiceCommand::Restart => {
                            info!("DNS service received restart command, restarting");
                            h.request_restart();
                            break;
                        }
                        _ => {}
                    }
                }
                event_res = sys_rx.recv() => match event_res {
                    Ok(event) => {
                        if let lanforge_core::bus::LanforgeEvent::System(lanforge_core::bus::SystemEvent::Shutdown) = event.event {
                            info!("DNS service received shutdown signal, terminating event loop");
                            break;
                        }
                    }
                    Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => break,
                },
                // The ISP resolvers come from the live PPPoE status, not from the event payload: a
                // lagged topic loses nothing, it just resyncs.
                event_res = pppoe_rx.recv() => match event_res {
                    Ok(event) => {
                        if matches!(
                            event.event,
                            lanforge_core::bus::LanforgeEvent::Pppoe(
                                lanforge_core::bus::PppoeEvent::SessionUp(_)
                                    | lanforge_core::bus::PppoeEvent::SessionDown { .. }
                            )
                        ) {
                            resync_upstreams(ctx, &dns_ctx, false).await;
                        }
                    }
                    Err(RecvError::Lagged(_)) => resync_upstreams(ctx, &dns_ctx, false).await,
                    Err(RecvError::Closed) => break,
                },
                // Live config sections: applied in place, sockets untouched (D-9).
                Some(_) = upstreams_sub.next() => {
                    info!("Reloading upstreams");
                    resync_upstreams(ctx, &dns_ctx, true).await;
                }
                Some(delta) = mode_sub.next() => {
                    info!(mode = ?*delta.new, "Upstream resolution mode changed");
                    dns_ctx.recursive.set_mode(*delta.new);
                }
                Some(delta) = rewrites_sub.next() => {
                    info!("Reloading rewrites");
                    dns_ctx.rewrites.replace_rules((*delta.new).clone());
                    info!("Rewrites reloaded");
                }
                change = filter_subs.next() => {
                    apply_filter_change(&dns_ctx, &self.ctx, change);
                }
                msg = bus_rx.recv() => {
                    match msg {
                        Ok(timed_event) => match timed_event.event {
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::CacheFlush) => {
                                info!("Flushing cache");
                                dns_ctx.cache.invalidate_all();
                                info!("Cache flushed");
                            }
                            #[cfg(feature = "adblock")]
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::AdblockBlock(domain)) => {
                                if let Some(filter) = &dns_ctx.filter {
                                    filter.add_block(&domain);
                                    dns_ctx.cache.invalidate_all();
                                }
                            }
                            #[cfg(feature = "adblock")]
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::AdblockAllow(domain)) => {
                                if let Some(filter) = &dns_ctx.filter {
                                    filter.add_allow(&domain);
                                    dns_ctx.cache.invalidate_all();
                                }
                            }
                            #[cfg(feature = "adblock")]
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::AdblockToggle { enabled, duration_secs }) => {
                                if let Some(filter) = &dns_ctx.filter {
                                    // Arm the pause deadline *before* disabling: the adblock worker
                                    // treats "disabled with no deadline" as a permanent state.
                                    if !enabled && let Some(secs) = duration_secs {
                                        let until = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs() + secs;
                                        filter.timer.disabled_until.store(until, std::sync::atomic::Ordering::Relaxed);
                                        filter.set_enabled(false);
                                        info!(duration_secs = secs, "Adblocker disabled temporarily");
                                    } else {
                                        filter.set_enabled(enabled);
                                        info!(enabled = enabled, "Adblocker toggle updated");
                                    }
                                    dns_ctx.cache.invalidate_all();
                                }
                            }
                            _ => {}
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(_) => break,
                    }
                }
            }
        }

        // Abort *and* await every worker: an aborted JoinHandle resolves only once its future
        // (and the sockets it owns) has been dropped, so a restart can rebind port 53 at once.
        let mut tasks = workers;
        tasks.extend(tcp_worker);
        tasks.push(cache_worker);
        tasks.push(mpsc_worker);
        #[cfg(feature = "dot")]
        tasks.extend(dot_worker);
        #[cfg(feature = "doq")]
        tasks.extend(doq_worker);
        #[cfg(feature = "adblock")]
        tasks.extend(adblock_worker);
        for task in &tasks {
            task.abort();
        }
        join_all(tasks).await;
        ctx.set_service_state(Self::SERVICE_ID, ServiceState::Inactive);

        Ok(())
    }
}

/// Upstreams DNS forwards to: the configured ones or, when none is configured, the resolvers the
/// ISP announced on the live PPPoE session. Derived from current state, never from an event
/// payload, so a restart with the session up or a lagged bus cannot leave the LAN without one.
fn effective_upstream_targets(ctx: &LanforgeContext) -> Vec<UpstreamTarget> {
    let configured = ctx.get_dns_upstreams();
    if !configured.is_empty() {
        return configured;
    }
    ctx.pppoe_status()
        .filter(|s| s.state == PppoeSessionState::Connected)
        .map(|s| {
            s.dns_servers
                .iter()
                .map(|ip| UpstreamTarget {
                    addr: SocketAddr::new(*ip, 53),
                    protocol: UpstreamProtocol::Udp,
                    hostname: None,
                    domain: None,
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn build_upstreams(
    targets: &[UpstreamTarget],
    cache: &Arc<DnsCache>,
) -> Vec<Arc<UpstreamManager>> {
    let mut upstreams = Vec::with_capacity(targets.len());
    for target in targets {
        match UpstreamManager::new(target, Arc::clone(cache)).await {
            Ok(mgr) => upstreams.push(mgr),
            Err(e) => error!(addr = %target.addr, error = %e, "Failed to initialize upstream"),
        }
    }
    upstreams
}

/// Points the resolver at [`effective_upstream_targets`]. `force` rebuilds even an unchanged set
/// (an explicit config change); otherwise an unchanged set is left alone, cache included.
async fn resync_upstreams(ctx: &LanforgeContext, dns_ctx: &DnsContext, force: bool) {
    let targets = effective_upstream_targets(ctx);
    let current: Vec<(SocketAddr, UpstreamProtocol)> = dns_ctx
        .recursive
        .snapshots()
        .iter()
        .map(|s| (s.target, s.protocol))
        .collect();
    let wanted: Vec<(SocketAddr, UpstreamProtocol)> =
        targets.iter().map(|t| (t.addr, t.protocol)).collect();
    if !force && current == wanted {
        return;
    }
    info!(upstreams = ?wanted, "DNS upstreams updated");
    dns_ctx
        .recursive
        .replace_upstreams(build_upstreams(&targets, &dns_ctx.cache).await);
    if !dns_ctx.recursive.is_empty() {
        dns_ctx.cache.invalidate_all();
    }
}

async fn handle_dns_request(req: DnsRequest, dns_ctx: Arc<DnsContext>) -> DnsResponse {
    match req {
        DnsRequest::Stats => {
            let stats = &dns_ctx.stats;
            DnsResponse::Stats(DnsStatsResponse {
                total_requests: stats.requests_total.load(Ordering::Relaxed),
                cache_hits: stats.cache_hits.load(Ordering::Relaxed),
                cache_misses: stats.cache_misses.load(Ordering::Relaxed),
                upstream_errors: stats.upstream_errors.load(Ordering::Relaxed),
                auth_queries: stats.auth_queries.load(Ordering::Relaxed),
                recursions: stats.recursions.load(Ordering::Relaxed),
                #[cfg(feature = "adblock")]
                blocked_queries: stats.blocked_queries.load(Ordering::Relaxed),
                #[cfg(not(feature = "adblock"))]
                blocked_queries: 0,
                resolved_total: stats.resolved_total.load(Ordering::Relaxed),
                failed_total: stats.failed_total.load(Ordering::Relaxed),
                cache_entries: stats.cache_entries.load(Ordering::Relaxed),
                cache_capacity: stats.cache_capacity.load(Ordering::Relaxed),
                cache_evictions: stats.cache_evictions.load(Ordering::Relaxed),
            })
        }
        DnsRequest::LifetimeStats => DnsResponse::LifetimeStats(dns_ctx.stats.lifetime_snapshot()),
        DnsRequest::Upstreams => DnsResponse::Upstreams(dns_ctx.recursive.snapshots()),
        DnsRequest::UpstreamAdd { .. } => {
            DnsResponse::UpstreamAdd(Err("Mutations handled via context/api dispatcher".into()))
        }
        DnsRequest::UpstreamRemove { .. } => {
            DnsResponse::UpstreamRemove(Err("Mutations handled via context/api dispatcher".into()))
        }
        DnsRequest::CacheDump {
            limit,
            offset,
            q,
            kind,
        } => {
            let q_lower = q.as_deref().map(|s| s.to_lowercase());
            let mut entries = Vec::new();
            for (name, k, data, expires_in_secs) in dns_ctx.cache.dump() {
                if let Some(target_kind) = kind
                    && k != target_kind
                {
                    continue;
                }
                if let Some(query) = &q_lower
                    && !name.to_lowercase().contains(query)
                    && !data.to_lowercase().contains(query)
                {
                    continue;
                }
                entries.push(DnsCacheEntry {
                    name,
                    kind: k,
                    data,
                    expires_in_secs,
                });
            }
            let total = entries.len();
            let start = offset.unwrap_or(0).min(total);
            let end = (start + limit.unwrap_or(total)).min(total);
            let paginated = entries[start..end].to_vec();

            DnsResponse::CacheDump(DnsCacheResponse {
                entries: paginated,
                total,
            })
        }
        DnsRequest::CacheStatsExt => {
            let (total_entries, entries_by_type, memory_usage_bytes, average_ttl_secs) =
                dns_ctx.cache.get_stats_ext();
            DnsResponse::CacheStatsExt(DnsCacheStatsExtResponse {
                total_entries,
                entries_by_type,
                memory_usage_bytes,
                average_ttl_secs,
                min_ttl: dns_ctx.cache.min_ttl(),
                evictions: dns_ctx.stats.cache_evictions.load(Ordering::Relaxed),
                capacity: dns_ctx.cache.capacity(),
            })
        }
        DnsRequest::AdblockStatus => {
            #[cfg(feature = "adblock")]
            {
                if let Some(adblocker) = &dns_ctx.filter {
                    let runtime_cfg = adblocker.config.read();
                    let cache_dir = dns_ctx
                        .cfg
                        .adblock_cache_dir
                        .as_deref()
                        .unwrap_or("/var/lib/lanforge");
                    let manifest_path = std::path::Path::new(cache_dir)
                        .join("adblock")
                        .join("manifest.json");
                    let manifest =
                        crate::resolver::filter::manifest::AdblockManifest::load_or_default(
                            &manifest_path,
                        );
                    let last_update = if manifest.last_merge == 0 {
                        None
                    } else {
                        Some(manifest.last_merge)
                    };
                    let mut sources_ok = 0;
                    let mut sources_failing = 0;
                    for s in manifest.sources.values() {
                        if s.consecutive_failures > 0 {
                            sources_failing += 1;
                        } else if s.last_success > 0 {
                            sources_ok += 1;
                        }
                    }

                    let adblock_cfg = dns_ctx.ctx.get_dns_adblock();
                    let next_update = if adblock_cfg.enabled {
                        let target = crate::server::worker::compute_next_refresh_target(
                            chrono::Local::now(),
                            adblock_cfg.refresh_time,
                        );
                        Some(target.timestamp() as u64)
                    } else {
                        None
                    };

                    DnsResponse::AdblockStatus(
                        lanforge_types::network::dns::DnsAdblockStatusResponse {
                            enabled: adblocker.is_enabled(),
                            disabled_until: {
                                let until = adblocker.timer.disabled_until.load(Ordering::Relaxed);
                                if until == 0 { None } else { Some(until) }
                            },
                            remaining_secs: adblocker.timer.remaining_secs(),
                            blocklist_size: adblocker.blocklist_size(),
                            allowlist_size: adblocker.allowlist_size(),
                            blocking_mode: runtime_cfg.mode,
                            blocking_ip_v4: runtime_cfg.ipv4,
                            blocking_ip_v6: runtime_cfg.ipv6,
                            exceptions_size: adblocker.exceptions_size(),
                            last_update,
                            next_update,
                            sources_ok,
                            sources_failing,
                        },
                    )
                } else {
                    use lanforge_types::network::dns::DnsAdblockStatusResponse;

                    DnsResponse::AdblockStatus(DnsAdblockStatusResponse::default())
                }
            }
            #[cfg(not(feature = "adblock"))]
            {
                DnsResponse::AdblockStatus(
                    lanforge_types::network::dns::DnsAdblockStatusResponse::default(),
                )
            }
        }
        DnsRequest::AdblockSources => {
            #[cfg(feature = "adblock")]
            {
                let urls = dns_ctx.ctx.get_dns_adblock_urls();
                let cache_dir = dns_ctx
                    .cfg
                    .adblock_cache_dir
                    .as_deref()
                    .unwrap_or("/var/lib/lanforge");
                let manifest_path = std::path::Path::new(cache_dir)
                    .join("adblock")
                    .join("manifest.json");
                let manifest = crate::resolver::filter::manifest::AdblockManifest::load_or_default(
                    &manifest_path,
                );

                let sources = urls
                    .into_iter()
                    .map(|u| {
                        let id = u.source_id();
                        if let Some(sm) = manifest.sources.get(&id) {
                            AdblockSourceStatus {
                                id,
                                name: u.name.clone(),
                                url: u.url,
                                format: u.format,
                                format_detected: Some(sm.format_detected),
                                blocks: sm.stats.blocks as usize,
                                exceptions: sm.stats.exceptions as usize,
                                unsupported: sm.stats.unsupported as usize,
                                last_attempt: sm.last_attempt,
                                last_success: if sm.last_success == 0 {
                                    None
                                } else {
                                    Some(sm.last_success)
                                },
                                consecutive_failures: sm.consecutive_failures,
                                last_error: sm.last_error.clone(),
                                sample_unsupported: sm.unsupported_samples.clone(),
                            }
                        } else {
                            AdblockSourceStatus {
                                id,
                                name: u.name.clone(),
                                url: u.url,
                                format: u.format,
                                format_detected: None,
                                blocks: 0,
                                exceptions: 0,
                                unsupported: 0,
                                last_attempt: 0,
                                last_success: None,
                                consecutive_failures: 0,
                                last_error: None,
                                sample_unsupported: Vec::new(),
                            }
                        }
                    })
                    .collect();

                DnsResponse::AdblockSources(DnsAdblockSourcesResponse { sources })
            }
            #[cfg(not(feature = "adblock"))]
            {
                DnsResponse::AdblockSources(DnsAdblockSourcesResponse {
                    sources: Vec::new(),
                })
            }
        }
        DnsRequest::AdblockCheck { domain } => {
            #[cfg(feature = "adblock")]
            {
                if let Some(filter) = &dns_ctx.filter {
                    let cleaned = domain.trim_end_matches('.').to_ascii_lowercase();
                    let matched_filter = filter.check_domain(&cleaned);
                    let mut source_matches = Vec::new();
                    if let Some(FilterMatch {
                        origin: FilterOrigin::List { source_id },
                        action,
                        ref rule,
                        important,
                    }) = matched_filter
                    {
                        let urls = dns_ctx.ctx.get_dns_adblock_urls();
                        let url = urls
                            .iter()
                            .find(|u| u.source_id() == source_id)
                            .map(|u| u.url.clone())
                            .unwrap_or_else(|| format!("source#{source_id}"));

                        source_matches.push(AdblockSourceMatch {
                            source_id,
                            url,
                            action,
                            rule: rule.as_deref().map(ToString::to_string),
                            important,
                        });
                    }
                    DnsResponse::AdblockCheck(AdblockCheckResponse {
                        domain,
                        matched: matched_filter.is_some(),
                        filter: matched_filter,
                        source_matches,
                    })
                } else {
                    DnsResponse::AdblockCheck(AdblockCheckResponse {
                        domain,
                        matched: false,
                        filter: None,
                        source_matches: Vec::new(),
                    })
                }
            }
            #[cfg(not(feature = "adblock"))]
            {
                DnsResponse::AdblockCheck(AdblockCheckResponse {
                    domain,
                    matched: false,
                    filter: None,
                    source_matches: Vec::new(),
                })
            }
        }
        DnsRequest::AdblockSet { .. } => {
            DnsResponse::AdblockSet(Err("Mutations handled via context/api dispatcher".into()))
        }
        DnsRequest::AdblockConfigSet { .. } => DnsResponse::AdblockConfigSet(Err(
            "Mutations handled via context/api dispatcher".into(),
        )),
        DnsRequest::AdblockReload => {
            #[cfg(feature = "adblock")]
            {
                use lanforge_core::bus::LanforgeEvent;

                let _ = dns_ctx.bus.publish(LanforgeEvent::Dns(
                    lanforge_core::bus::DnsEvent::AdblockReload,
                ));
                DnsResponse::AdblockReload(Ok(()))
            }
            #[cfg(not(feature = "adblock"))]
            {
                DnsResponse::AdblockReload(Err("Adblock not enabled".into()))
            }
        }
        DnsRequest::AdblockUrlList => {
            #[cfg(feature = "adblock")]
            {
                DnsResponse::AdblockUrlList(dns_ctx.ctx.get_dns_adblock_urls())
            }
            #[cfg(not(feature = "adblock"))]
            {
                DnsResponse::AdblockUrlList(Vec::new())
            }
        }
        DnsRequest::AdblockUrlAdd { .. } => {
            DnsResponse::AdblockUrlAdd(Err("Mutations handled via context/api dispatcher".into()))
        }
        DnsRequest::AdblockUrlRemove { .. } => DnsResponse::AdblockUrlRemove(Err(
            "Mutations handled via context/api dispatcher".into(),
        )),
        DnsRequest::Query { name, qtype } => {
            DnsResponse::Query(resolve_diagnostic_internal(&dns_ctx, &name, qtype).await)
        }
    }
}

async fn resolve_diagnostic_internal(
    dns_ctx: &DnsContext,
    name: &str,
    qtype: DnsRecordType,
) -> Result<(Vec<DnsRecordEntry>, bool, String), String> {
    let mut query = DnsMessage::new();
    query.header.rd = true;
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from(name),
        qtype,
        qclass: DnsClass::IN,
    });

    let mut encoder = WireEncoder::new();
    let wire_query = encoder.encode_message(&query);

    let mut resp_buf = Vec::new();
    let Some(header) = WireHeader::parse(&wire_query) else {
        return Err("Failed to parse query header".into());
    };
    let Some(question) = WireQuestion::parse(&wire_query) else {
        return Err("Failed to parse query question".into());
    };

    let req = DnsPipelineRequest::new(
        &wire_query,
        &header,
        &question,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        TransportProtocol::Udp,
    );

    if let Err(e) = dns_ctx.pipeline.run(dns_ctx, req, &mut resp_buf).await {
        return Err(format!("Pipeline error: {e}"));
    }

    let mut decoder = WireDecoder::new(&resp_buf);
    let Some(msg) = decoder.decode_message() else {
        return Err("Failed to decode pipeline response".into());
    };

    let auth = msg.header.aa;
    let records = msg
        .answers
        .into_iter()
        .map(|r| DnsRecordEntry {
            name: r.name.to_string(),
            kind: r.rtype,
            data: r.rdata.to_string(),
            ttl: r.ttl,
        })
        .collect();

    let result_str = if let Some(ring) = &dns_ctx.query_log
        && let Some(last) = ring.get_recent(1).into_iter().next()
        && last.domain.as_ref() == name
    {
        format!("{:?}", last.result)
    } else {
        let key = CacheKey::from_question(&question);

        if let Some(entry) = dns_ctx.cache.cache.get(&key) {
            if entry.is_block {
                "CachedBlock".to_string()
            } else {
                "Cached".to_string()
            }
        } else if dns_ctx.rewrites.resolve_rewrite(name).is_some() {
            "Rewritten".to_string()
        } else if dns_ctx.local.resolve_local(name, qtype).is_some()
            || (qtype == DnsRecordType::PTR
                && dns_ctx
                    .local
                    .resolve_ptr(name)
                    .is_ok_and(|res| res.is_some()))
        {
            "Local".to_string()
        } else {
            #[cfg(feature = "adblock")]
            let is_blocked = dns_ctx
                .filter
                .as_ref()
                .is_some_and(|f| f.should_block(name));
            #[cfg(not(feature = "adblock"))]
            let is_blocked = false;

            if is_blocked {
                "Blocked".to_string()
            } else {
                "Forwarded".to_string()
            }
        }
    };

    Ok((records, auth, result_str))
}

/// Change of a filter-related config section observed by the DNS service loop.
enum FilterChange {
    /// Allowlist or custom block rules changed: resync the in-memory filter.
    #[cfg_attr(not(feature = "adblock"), allow(dead_code))]
    Rules,
    /// Adblock settings changed (mode, blocking IPs, enabled).
    #[cfg_attr(not(feature = "adblock"), allow(dead_code))]
    Adblock(Arc<AdblockDbConfig>),
}

/// Filter config subscriptions. `tokio::select!` arms cannot be `#[cfg]`-gated, so without the
/// `adblock` feature this type exists but never yields.
#[cfg(feature = "adblock")]
struct FilterSubscriptions {
    allowlist: ConfigSubscription<DnsAllowlist>,
    rules: ConfigSubscription<Vec<AdblockRuleEntry>>,
    adblock: ConfigSubscription<AdblockDbConfig>,
}

#[cfg(feature = "adblock")]
impl FilterSubscriptions {
    fn new(ctx: &LanforgeContext) -> Self {
        Self {
            allowlist: ctx.config_subscription(),
            rules: ctx.config_subscription(),
            adblock: ctx.config_subscription(),
        }
    }

    async fn next(&mut self) -> FilterChange {
        tokio::select! {
            Some(_) = self.allowlist.next() => FilterChange::Rules,
            Some(_) = self.rules.next() => FilterChange::Rules,
            Some(delta) = self.adblock.next() => FilterChange::Adblock(delta.new),
            else => std::future::pending().await,
        }
    }
}

#[cfg(not(feature = "adblock"))]
struct FilterSubscriptions;

#[cfg(not(feature = "adblock"))]
impl FilterSubscriptions {
    const fn new(_ctx: &LanforgeContext) -> Self {
        Self
    }

    async fn next(&mut self) -> FilterChange {
        std::future::pending().await
    }
}

#[cfg(feature = "adblock")]
fn apply_filter_change(dns_ctx: &DnsContext, ctx: &LanforgeContext, change: FilterChange) {
    let Some(filter) = &dns_ctx.filter else {
        return;
    };
    match change {
        FilterChange::Rules => {
            info!("Reloading allowlist and custom adblock rules");
            filter.sync_from_context(ctx);
        }
        FilterChange::Adblock(cfg) => {
            info!("Reloading adblock config");
            filter.replace_config(cfg.blocking_mode, cfg.blocking_ip_v4, cfg.blocking_ip_v6);
            filter.set_enabled(cfg.enabled);
        }
    }
    dns_ctx.cache.invalidate_all();
}

#[cfg(not(feature = "adblock"))]
fn apply_filter_change(_dns_ctx: &DnsContext, _ctx: &LanforgeContext, _change: FilterChange) {}
