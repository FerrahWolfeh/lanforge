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
use crate::server::DnsContext;
use crate::telemetry::{DnsStats, DnsStatsSnapshot, QueryRing};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceControl};
use lanforge_db::engine::LanforgeDb;
use lanforge_dns_wire::{WireDecoder, WireEncoder, WireHeader, WireQuestion};
use lanforge_types::network::dns::{
    DnsCacheStatsExtResponse, DnsClass, DnsMessage, DnsQuestion, DnsRecordEntry, DnsRecordType,
    DnsRequest, DnsResponse, DnsStatsResponse, TransportProtocol,
};
use lanforge_types::system::ServiceBanner;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tracing::{error, info};

#[lanforge_macros::lanforge_service(
    id = "dns",
    name = "DNS Server",
    critical = true,
    retries = 0,
    base_backoff = 2,
    max_backoff = 30,
    multi_threaded = true,
    describe = format!(
        "DNS on {}",
        self.cfg.listen
    )
)]
#[derive(Clone)]
pub struct DnsService {
    cfg: Arc<DnsConfig>,
    stats: Arc<DnsStats>,
    ctx: LanforgeContext,
    db: Arc<LanforgeDb>,
}

impl DnsService {
    #[must_use]
    pub fn new(cfg: DnsConfig, ctx: LanforgeContext, db: Arc<LanforgeDb>) -> Self {
        let stats = Arc::new(DnsStats::new());
        ctx.register_service_state("dns::stats", Arc::clone(&stats));
        let service = Self {
            cfg: Arc::new(cfg),
            stats,
            ctx: ctx.clone(),
            db,
        };
        ctx.register_status_provider(Arc::new(service.clone()));
        service
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
        let mut upstreams = Vec::new();
        if let Ok(rows) = self.db.load_dns_upstreams().await {
            for row in rows {
                let proto_lower = row.protocol.to_lowercase();
                let prefix = match row.domain {
                    Some(ref d) => format!("{}://{}@", proto_lower, d),
                    None => format!("{}://", proto_lower),
                };
                let full_str = format!("{}{}", prefix, row.addr);
                if let Ok(target) =
                    lanforge_types::network::dns::upstream::UpstreamTarget::from_str(&full_str)
                {
                    match UpstreamManager::new(&target, Arc::clone(&cache)).await {
                        Ok(mgr) => upstreams.push(mgr),
                        Err(e) => error!(
                            "❌ DNS: Failed to initialize upstream {}: {}",
                            target.addr, e
                        ),
                    }
                }
            }
        }

        if upstreams.is_empty() && self.cfg.enabled && !self.cfg.search_domains.is_empty() {
            tracing::warn!("⚠️ DNS: No upstreams configured. Only local resolution will work.");
        }
        #[cfg(feature = "adblock")]
        let db_adblock = self.db.load_adblock_config().await.unwrap_or_default();
        let db_rewrites = self.db.load_dns_rewrites().await.unwrap_or_default();
        #[cfg(feature = "adblock")]
        let db_allowlist = self.db.load_dns_allowlist().await.unwrap_or_default();

        let rewrites = Arc::new(RewriteStore::new());
        rewrites.replace_rules(db_rewrites);

        #[cfg(feature = "adblock")]
        let filter = {
            let adblock_enabled = db_adblock.enabled;
            info!(
                "🛡️ DNS: Adblock feature is initializing (Adblock: {})",
                adblock_enabled,
            );
            let blocker = AdBlocker::new(adblock_enabled);
            blocker.replace_allowlist(db_allowlist.into_iter().map(|(_, d)| d).collect());
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

        let recursive = Arc::new(UpstreamStrategy::new(self.cfg.upstream_mode, upstreams));

        let query_log = if self.cfg.query_log.enabled {
            Some(Arc::new(QueryRing::new(self.cfg.query_log.ring_size)))
        } else {
            None
        };

        let mut pipeline = Pipeline::new();
        pipeline.push(RewriteMiddleware::new());
        pipeline.push(LocalResolverMiddleware::new());
        pipeline.push(CacheMiddleware::new());
        #[cfg(feature = "adblock")]
        pipeline.push(AdblockMiddleware::new());
        pipeline.push(UpstreamMiddleware::new());

        let dns_ctx = DnsContext {
            cfg: Arc::clone(&self.cfg),
            stats: Arc::clone(&self.stats),
            bus: self.ctx.bus(),
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
            db: Arc::clone(&self.db),
            reverse_managers: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            resolving_ips: Arc::new(parking_lot::Mutex::new(HashSet::new())),
        };

        let dns_ctx = Arc::new(dns_ctx);
        Ok(dns_ctx)
    }
}

impl AsyncService for DnsService {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        if !self.cfg.enabled {
            info!("DNS Service disabled in config");
            return Ok(());
        }

        self.ctx.wait_for_db().await?;
        let dns_ctx = self.init_dns_context().await?;
        self.ctx
            .register_service_state("dns::context", Arc::clone(&dns_ctx));

        let (tx, mut mpsc_rx) = tokio::sync::mpsc::channel(100);
        let dns_handle = lanforge_core::context::DnsHandle::new(tx);
        self.ctx.set_dns_handle(dns_handle);

        let parallelism = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        info!("Starting DNS service with {} UDP handlers", parallelism);

        let mut workers = Vec::new();
        let socket = Arc::new(
            tokio::net::UdpSocket::bind(self.cfg.listen)
                .await
                .map_err(CoreError::Io)?,
        );

        ctrl.signal_ready();

        for _ in 0..parallelism {
            workers.push(crate::server::worker::udp::spawn_udp_worker(
                Arc::clone(&dns_ctx),
                Arc::clone(&socket),
            ));
        }

        let tcp_worker = crate::server::worker::tcp::spawn_tcp_worker(Arc::clone(&dns_ctx));

        #[cfg(feature = "adblock")]
        info!("🛡️ DNS: Adblock feature is compiled in.");
        #[cfg(not(feature = "adblock"))]
        info!("🛡️ DNS: Adblock feature is NOT compiled in.");

        #[cfg(feature = "adblock")]
        let adblock_worker = if dns_ctx.filter.is_some() {
            Some(crate::server::worker::spawn_adblock_manager(Arc::clone(
                &dns_ctx,
            )))
        } else {
            None
        };

        let cache_worker = crate::server::worker::spawn_cache_handler(Arc::clone(&dns_ctx));

        let mut bus_rx = self.ctx.bus().subscribe();

        let mpsc_worker = {
            let dns_ctx = Arc::clone(&dns_ctx);
            let db = Arc::clone(&self.db);
            tokio::spawn(async move {
                while let Some((req, resp_tx)) = mpsc_rx.recv().await {
                    let resp = handle_dns_request(req, Arc::clone(&dns_ctx), Arc::clone(&db)).await;
                    let _ = resp_tx.send(resp);
                }
            })
        };

        loop {
            if !self.ctx.is_running() {
                break;
            }
            tokio::select! {
                msg = bus_rx.recv() => {
                    match msg {
                        Ok(timed_event) => match timed_event.event {
                            lanforge_core::bus::LanforgeEvent::System(lanforge_core::bus::SystemEvent::Shutdown) => break,
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::ConfigUpstreamsChanged) => {
                                info!("🔄 DNS: Reloading upstreams from DB...");
                                let mut upstreams = Vec::new();
                                if let Ok(rows) = self.db.load_dns_upstreams().await {
                                    for row in rows {
                                        let proto_lower = row.protocol.to_lowercase();
                                        let prefix = match row.domain {
                                            Some(ref d) => format!("{}://{}@", proto_lower, d),
                                            None => format!("{}://", proto_lower),
                                        };
                                        let full_str = format!("{}{}", prefix, row.addr);
                                        if let Ok(target) = lanforge_types::network::dns::upstream::UpstreamTarget::from_str(&full_str) {
                                            match UpstreamManager::new(&target, Arc::clone(&dns_ctx.cache)).await {
                                                Ok(mgr) => upstreams.push(mgr),
                                                Err(e) => error!("❌ DNS: Failed to initialize upstream {}: {}", target.addr, e),
                                            }
                                        }
                                    }
                                }
                                dns_ctx.recursive.replace_upstreams(upstreams);
                                info!("✅ DNS: Upstreams reloaded.");
                                if !dns_ctx.recursive.is_empty() {
                                    dns_ctx.cache.invalidate_all();
                                    info!("✅ DNS: Cache invalidated after upstream reload.");
                                }
                            }
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::CacheFlush) => {
                                info!("🔄 DNS: Flushing cache...");
                                dns_ctx.cache.invalidate_all();
                                info!("✅ DNS: Cache flushed.");
                            }
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::ConfigRewritesChanged) => {
                                info!("🔄 DNS: Reloading rewrites from DB...");
                                match self.db.load_dns_rewrites().await {
                                    Ok(rewrites) => {
                                        dns_ctx.rewrites.replace_rules(rewrites);
                                        info!("✅ DNS: Rewrites reloaded.");
                                    }
                                    Err(e) => error!("❌ DNS: Failed to load rewrites: {}", e),
                                }
                            }
                            #[cfg(feature = "adblock")]
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::ConfigAllowlistChanged) => {
                                info!("🔄 DNS: Reloading allowlist from DB...");
                                if let Some(filter) = &dns_ctx.filter {
                                    match self.db.load_dns_allowlist().await {
                                        Ok(allow) => {
                                            filter.replace_allowlist(allow.into_iter().map(|(_, d)| d).collect());
                                            info!("✅ DNS: Allowlist reloaded.");
                                        }
                                        Err(e) => error!("❌ DNS: Failed to load allowlist: {}", e),
                                    }
                                }
                            }
                            #[cfg(feature = "adblock")]
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::ConfigAdblockChanged) => {
                                info!("🔄 DNS: Reloading adblock config from DB...");
                                if let Some(filter) = &dns_ctx.filter {
                                    match self.db.load_adblock_config().await {
                                        Ok(cfg) => {
                                            filter.replace_config(cfg.blocking_mode, cfg.blocking_ip_v4, cfg.blocking_ip_v6);
                                            filter.set_enabled(cfg.enabled);
                                            info!("✅ DNS: Adblock config reloaded.");
                                        }
                                        Err(e) => error!("❌ DNS: Failed to load adblock config: {}", e),
                                    }
                                }
                            }
                            #[cfg(feature = "adblock")]
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::AdblockToggle { enabled, duration_secs }) => {
                                if let Some(filter) = &dns_ctx.filter {
                                    filter.set_enabled(enabled);
                                    if !enabled && let Some(secs) = duration_secs {
                                        let until = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs() + secs;
                                        filter.timer.disabled_until.store(until, std::sync::atomic::Ordering::Relaxed);
                                        info!("🛡️ DNS: Adblocker disabled for {} seconds", secs);
                                    } else {
                                        info!("🛡️ DNS: Adblocker {}", if enabled { "enabled" } else { "disabled indefinitely" });
                                    }
                                }
                            }
                            _ => {}
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(_) => break,
                    }
                }
                () = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                    if !self.ctx.is_running() { break; }
                }
            }
        }

        for w in workers {
            w.abort();
        }
        tcp_worker.abort();
        cache_worker.abort();
        mpsc_worker.abort();
        #[cfg(feature = "adblock")]
        if let Some(w) = adblock_worker {
            w.abort();
        }

        Ok(())
    }
}

impl lanforge_core::service::StatusProvider for DnsService {
    fn banner(&self) -> ServiceBanner {
        let stats = vec![
            (
                std::borrow::Cow::Borrowed("cache_hits"),
                self.stats.cache_hits.load(Ordering::Relaxed).to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("requests_total"),
                self.stats
                    .requests_total
                    .load(Ordering::Relaxed)
                    .to_string(),
            ),
        ];

        ServiceBanner {
            id: "dns".to_string(),
            name: "DNS Server".to_string(),
            state: self.ctx.get_service_state("dns"),
            uptime_secs: self.ctx.get_service_uptime("dns"),
            stats,
        }
    }
}

async fn handle_dns_request(
    req: DnsRequest,
    dns_ctx: Arc<DnsContext>,
    db: Arc<LanforgeDb>,
) -> DnsResponse {
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
        DnsRequest::Upstreams => DnsResponse::Upstreams(dns_ctx.recursive.snapshots()),
        DnsRequest::UpstreamAdd {
            addr,
            protocol,
            domain,
        } => {
            let addr_str = addr.to_string();
            let proto_str = format!("{:?}", protocol);
            match db
                .add_dns_upstream(&addr_str, &proto_str, domain.as_deref())
                .await
            {
                Ok(_) => {
                    let _ = dns_ctx.bus.publish(lanforge_core::bus::LanforgeEvent::Dns(
                        lanforge_core::bus::DnsEvent::ConfigUpstreamsChanged,
                    ));
                    DnsResponse::UpstreamAdd(Ok(()))
                }
                Err(e) => DnsResponse::UpstreamAdd(Err(e.to_string())),
            }
        }
        DnsRequest::UpstreamRemove { addr, protocol } => {
            let addr_str = addr.to_string();
            let proto_str = format!("{:?}", protocol);
            match db.remove_dns_upstream(&addr_str, &proto_str).await {
                Ok(_) => {
                    let _ = dns_ctx.bus.publish(lanforge_core::bus::LanforgeEvent::Dns(
                        lanforge_core::bus::DnsEvent::ConfigUpstreamsChanged,
                    ));
                    DnsResponse::UpstreamRemove(Ok(()))
                }
                Err(e) => DnsResponse::UpstreamRemove(Err(e.to_string())),
            }
        }
        DnsRequest::CacheDump { limit, offset } => {
            let mut entries = Vec::new();
            for (name, kind, data, expires_in_secs) in dns_ctx.cache.dump() {
                entries.push(lanforge_types::network::dns::DnsCacheEntry {
                    name,
                    kind,
                    data,
                    expires_in_secs,
                });
            }
            let total = entries.len();
            let start = offset.unwrap_or(0).min(total);
            let end = (start + limit.unwrap_or(total)).min(total);
            let paginated = entries[start..end].to_vec();

            DnsResponse::CacheDump(lanforge_types::network::dns::DnsCacheResponse {
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
                        },
                    )
                } else {
                    DnsResponse::AdblockStatus(
                        lanforge_types::network::dns::DnsAdblockStatusResponse::default(),
                    )
                }
            }
            #[cfg(not(feature = "adblock"))]
            {
                DnsResponse::AdblockStatus(
                    lanforge_types::network::dns::DnsAdblockStatusResponse::default(),
                )
            }
        }
        DnsRequest::AdblockSet {
            enabled,
            duration_secs,
        } => {
            #[cfg(feature = "adblock")]
            {
                if duration_secs.is_none() {
                    let val = if enabled { "true" } else { "false" };
                    let _ = db.set_adblock_config_value("enabled", val).await;
                    let _ = dns_ctx.bus.publish(lanforge_core::bus::LanforgeEvent::Dns(
                        lanforge_core::bus::DnsEvent::ConfigAdblockChanged,
                    ));
                }
                let _ = dns_ctx.bus.publish(lanforge_core::bus::LanforgeEvent::Dns(
                    lanforge_core::bus::DnsEvent::AdblockToggle {
                        enabled,
                        duration_secs,
                    },
                ));
                DnsResponse::AdblockSet(Ok(()))
            }
            #[cfg(not(feature = "adblock"))]
            {
                let _ = enabled;
                let _ = duration_secs;
                DnsResponse::AdblockSet(Err("Adblock not enabled".into()))
            }
        }
        DnsRequest::AdblockConfigSet {
            blocking_mode,
            blocking_ip_v4,
            blocking_ip_v6,
        } => {
            #[cfg(feature = "adblock")]
            {
                if let Some(mode) = blocking_mode {
                    let _ = db
                        .set_adblock_config_value("blocking_mode", &mode.to_string())
                        .await;
                }
                if let Some(ip) = blocking_ip_v4 {
                    let _ = db
                        .set_adblock_config_value("blocking_ip_v4", &ip.to_string())
                        .await;
                }
                if let Some(ip) = blocking_ip_v6 {
                    let _ = db
                        .set_adblock_config_value("blocking_ip_v6", &ip.to_string())
                        .await;
                }
                let _ = dns_ctx.bus.publish(lanforge_core::bus::LanforgeEvent::Dns(
                    lanforge_core::bus::DnsEvent::ConfigAdblockChanged,
                ));
                DnsResponse::AdblockConfigSet(Ok(()))
            }
            #[cfg(not(feature = "adblock"))]
            {
                let _ = blocking_mode;
                let _ = blocking_ip_v4;
                let _ = blocking_ip_v6;
                DnsResponse::AdblockConfigSet(Err("Adblock not enabled".into()))
            }
        }
        DnsRequest::AdblockReload => {
            #[cfg(feature = "adblock")]
            {
                let _ = dns_ctx.bus.publish(lanforge_core::bus::LanforgeEvent::Dns(
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
                match db.load_adblock_urls().await {
                    Ok(urls) => DnsResponse::AdblockUrlList(
                        urls.into_iter()
                            .map(
                                |(id, url, kind)| lanforge_types::network::dns::AdblockUrlEntry {
                                    id: Some(id),
                                    url,
                                    kind,
                                },
                            )
                            .collect(),
                    ),
                    Err(_e) => DnsResponse::AdblockUrlList(Vec::new()),
                }
            }
            #[cfg(not(feature = "adblock"))]
            {
                DnsResponse::AdblockUrlList(Vec::new())
            }
        }
        DnsRequest::AdblockUrlAdd { url, kind } => {
            #[cfg(feature = "adblock")]
            {
                match db.add_adblock_url(&url, kind).await {
                    Ok(()) => {
                        let _ = dns_ctx.bus.publish(lanforge_core::bus::LanforgeEvent::Dns(
                            lanforge_core::bus::DnsEvent::ConfigAdblockChanged,
                        ));
                        DnsResponse::AdblockUrlAdd(Ok(()))
                    }
                    Err(e) => DnsResponse::AdblockUrlAdd(Err(e.to_string())),
                }
            }
            #[cfg(not(feature = "adblock"))]
            {
                let _ = url;
                let _ = kind;
                DnsResponse::AdblockUrlAdd(Err("Adblock not enabled".into()))
            }
        }
        DnsRequest::AdblockUrlRemove { url } => {
            #[cfg(feature = "adblock")]
            {
                match db.remove_adblock_url(&url).await {
                    Ok(()) => {
                        let _ = dns_ctx.bus.publish(lanforge_core::bus::LanforgeEvent::Dns(
                            lanforge_core::bus::DnsEvent::ConfigAdblockChanged,
                        ));
                        DnsResponse::AdblockUrlRemove(Ok(()))
                    }
                    Err(e) => DnsResponse::AdblockUrlRemove(Err(e.to_string())),
                }
            }
            #[cfg(not(feature = "adblock"))]
            {
                let _ = url;
                DnsResponse::AdblockUrlRemove(Err("Adblock not enabled".into()))
            }
        }
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
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
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
        // Fallback logic matching pipeline order
        #[cfg(feature = "adblock")]
        let is_blocked = dns_ctx
            .filter
            .as_ref()
            .is_some_and(|f| f.should_block(name));
        #[cfg(not(feature = "adblock"))]
        let is_blocked = false;

        if is_blocked {
            "Blocked".to_string()
        } else if dns_ctx.rewrites.resolve_rewrite(name).is_some() {
            "Rewritten".to_string()
        } else {
            let mut qname = name.as_bytes().to_vec();
            qname.make_ascii_lowercase();
            let key = CacheKey {
                qname,
                qtype: u16::from(qtype),
                qclass: 1, // IN
            };
            if dns_ctx.cache.cache.get(&key).is_some() {
                "Cached".to_string()
            } else if dns_ctx.local.resolve_local(name, qtype).is_some()
                || (qtype == DnsRecordType::PTR
                    && dns_ctx
                        .local
                        .resolve_ptr(name)
                        .is_ok_and(|res| res.is_some()))
            {
                "Local".to_string()
            } else {
                "Forwarded".to_string()
            }
        }
    };

    Ok((records, auth, result_str))
}
