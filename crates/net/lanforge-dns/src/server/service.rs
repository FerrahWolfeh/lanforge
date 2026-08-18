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
use lanforge_core::service::{AsyncService, ServiceDependency};
use lanforge_dns_wire::{WireDecoder, WireEncoder, WireHeader, WireQuestion};
use lanforge_types::network::dns::{
    DnsCacheEntry, DnsCacheResponse, DnsCacheStatsExtResponse, DnsClass, DnsMessage, DnsQuestion,
    DnsRecordEntry, DnsRecordType, DnsRequest, DnsResponse, DnsStatsResponse, TransportProtocol,
    upstream::{UpstreamProtocol, UpstreamTarget},
};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tracing::{debug, error, info};

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
}

impl DnsService {
    #[must_use]
    pub fn new(cfg: DnsConfig, ctx: LanforgeContext) -> Self {
        let stats = Arc::new(DnsStats::new());
        ctx.register_service_state("dns::stats", Arc::clone(&stats));
        Self {
            cfg: Arc::new(cfg),
            stats,
            ctx,
        }
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
        let ctx_upstreams = self.ctx.get_dns_upstreams();
        for target in ctx_upstreams {
            match UpstreamManager::new(&target, Arc::clone(&cache)).await {
                Ok(mgr) => upstreams.push(mgr),
                Err(e) => error!(
                    "DNS: Failed to initialize upstream {}: {}",
                    target.addr, e
                ),
            }
        }

        if upstreams.is_empty() && self.cfg.enabled && !self.cfg.search_domains.is_empty() {
            tracing::warn!("DNS: No upstreams configured — only local resolution active");
        }
        #[cfg(feature = "adblock")]
        let db_adblock = self.ctx.get_dns_adblock();
        let db_rewrites = self.ctx.get_dns_rewrites();
        #[cfg(feature = "adblock")]
        let db_allowlist = self.ctx.get_dns_allowlist();

        let rewrites = Arc::new(RewriteStore::new());
        rewrites.replace_rules(db_rewrites);

        #[cfg(feature = "adblock")]
        let filter = {
            let adblock_enabled = db_adblock.enabled;
            debug!(
                "DNS: Adblock filter initializing (enabled: {})",
                adblock_enabled,
            );
            let blocker = AdBlocker::new(adblock_enabled);
            blocker.replace_allowlist(db_allowlist.into_iter().collect());
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
        };

        let dns_ctx = Arc::new(dns_ctx);
        Ok(dns_ctx)
    }
}

impl AsyncService for DnsService {
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[ServiceDependency::Database]
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

        vec![
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
            (
                std::borrow::Cow::Borrowed("cache_hits"),
                hits.to_string(),
            ),
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
        ]
    }

    async fn serve(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        if !self.cfg.enabled {
            info!("DNS Service disabled in config");
            return Ok(());
        }

        let dns_ctx = self.init_dns_context().await?;
        ctx.register_service_state("dns::context", Arc::clone(&dns_ctx));

        let (tx, mut mpsc_rx) = tokio::sync::mpsc::channel(100);
        let dns_handle = lanforge_core::context::DnsHandle::new(tx);
        ctx.set_dns_handle(dns_handle);

        let parallelism = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        info!(handlers = parallelism, "DNS: Starting service");

        let mut workers = Vec::new();
        let socket = Arc::new(
            tokio::net::UdpSocket::bind(self.cfg.listen)
                .await
                .map_err(CoreError::Io)?,
        );

        for _ in 0..parallelism {
            workers.push(crate::server::worker::udp::spawn_udp_worker(
                Arc::clone(&dns_ctx),
                Arc::clone(&socket),
            ));
        }

        let tcp_worker = crate::server::worker::tcp::spawn_tcp_worker(Arc::clone(&dns_ctx));

        #[cfg(feature = "adblock")]
        info!("DNS: Adblock feature compiled in");
        #[cfg(not(feature = "adblock"))]
        info!("DNS: Adblock feature not compiled in");

        #[cfg(feature = "adblock")]
        let adblock_worker = if dns_ctx.filter.is_some() {
            Some(crate::server::worker::spawn_adblock_manager(Arc::clone(
                &dns_ctx,
            )))
        } else {
            None
        };

        let cache_worker = crate::server::worker::spawn_cache_handler(Arc::clone(&dns_ctx));

        let mut bus_rx = ctx.bus().subscribe_dns();

        let mpsc_worker = {
            let dns_ctx = Arc::clone(&dns_ctx);
            tokio::spawn(async move {
                while let Some((req, resp_tx)) = mpsc_rx.recv().await {
                    let resp = handle_dns_request(req, Arc::clone(&dns_ctx)).await;
                    let _ = resp_tx.send(resp);
                }
            })
        };

        loop {
            if !ctx.is_running() {
                break;
            }
            tokio::select! {
                msg = bus_rx.recv() => {
                    match msg {
                        Ok(timed_event) => match timed_event.event {
                            lanforge_core::bus::LanforgeEvent::System(lanforge_core::bus::SystemEvent::Shutdown) => break,
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::ConfigUpstreamsChanged) => {
                                info!("DNS: Reloading upstreams");
                                let mut upstreams = Vec::new();
                                let ctx_upstreams = ctx.get_dns_upstreams();
                                for target in ctx_upstreams {
                                    match UpstreamManager::new(&target, Arc::clone(&dns_ctx.cache)).await {
                                        Ok(mgr) => upstreams.push(mgr),
                                        Err(e) => error!(addr = %target.addr, error = %e, "DNS: Failed to initialize upstream"),
                                    }
                                }
                                dns_ctx.recursive.replace_upstreams(upstreams);
                                info!("DNS: Upstreams reloaded");
                                if !dns_ctx.recursive.is_empty() {
                                    dns_ctx.cache.invalidate_all();
                                    info!("DNS: Cache invalidated after upstream reload");
                                }
                            }
                            lanforge_core::bus::LanforgeEvent::Pppoe(lanforge_core::bus::PppoeEvent::SessionUp { dns, .. }) => {
                                // Auto-adopt ISP DNS upstreams if user has not configured custom static upstreams
                                if ctx.get_dns_upstreams().is_empty() && !dns.is_empty() {
                                    info!(count = dns.len(), "DNS: Auto-adopting ISP DNS upstreams from PPPoE WAN session");
                                    let mut upstreams = Vec::new();
                                    for ip in dns {
                                        let target = UpstreamTarget {
                                            addr: SocketAddr::new(ip, 53),
                                            protocol: UpstreamProtocol::Udp,
                                            hostname: None,
                                        };
                                        match UpstreamManager::new(&target, Arc::clone(&dns_ctx.cache)).await {
                                            Ok(mgr) => upstreams.push(mgr),
                                            Err(e) => error!(addr = %target.addr, error = %e, "DNS: Failed to initialize ISP upstream"),
                                        }
                                    }
                                    dns_ctx.recursive.replace_upstreams(upstreams);
                                    if !dns_ctx.recursive.is_empty() {
                                        dns_ctx.cache.invalidate_all();
                                        info!("DNS: ISP upstreams activated and cache cleared");
                                    }
                                }
                            }
                            lanforge_core::bus::LanforgeEvent::Pppoe(lanforge_core::bus::PppoeEvent::SessionDown { reason }) => {
                                if ctx.get_dns_upstreams().is_empty() {
                                    info!(reason = %reason, "DNS: PPPoE session down, clearing ISP upstreams");
                                    dns_ctx.recursive.replace_upstreams(Vec::new());
                                }
                            }
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::CacheFlush) => {
                                info!("DNS: Flushing cache");
                                dns_ctx.cache.invalidate_all();
                                info!("DNS: Cache flushed");
                            }
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::ConfigRewritesChanged) => {
                                info!("DNS: Reloading rewrites");
                                let rewrites = self.ctx.get_dns_rewrites();
                                dns_ctx.rewrites.replace_rules(rewrites);
                                info!("DNS: Rewrites reloaded");
                            }
                            #[cfg(feature = "adblock")]
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::ConfigAllowlistChanged) => {
                                info!("DNS: Reloading allowlist");
                                if let Some(filter) = &dns_ctx.filter {
                                    let allow = self.ctx.get_dns_allowlist();
                                    filter.replace_allowlist(allow.into_iter().collect());
                                    info!("DNS: Allowlist reloaded");
                                }
                            }
                            #[cfg(feature = "adblock")]
                            lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::ConfigAdblockChanged) => {
                                info!("DNS: Reloading adblock config");
                                if let Some(filter) = &dns_ctx.filter {
                                    let cfg = self.ctx.get_dns_adblock();
                                    filter.replace_config(cfg.blocking_mode, cfg.blocking_ip_v4, cfg.blocking_ip_v6);
                                    filter.set_enabled(cfg.enabled);
                                    info!("DNS: Adblock config reloaded");
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
                                        info!(duration_secs = secs, "DNS: Adblocker disabled temporarily");
                                    } else {
                                        info!(enabled = enabled, "DNS: Adblocker toggle updated");
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
