use crate::config::DnsConfig;
use crate::pipeline::{Pipeline, middleware::*};
use crate::resolver::{
    LocalResolver,
    filter::AdBlocker,
    recursive::{DnsCache, UpstreamManager, UpstreamStrategy},
};
use crate::server::DnsContext;
use crate::telemetry::{DnsStats, DnsStatsSnapshot, QueryRing};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceControl};
use lanforge_db::engine::LeaseDb;
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
        "DNS on {} ({} upstreams)",
        self.cfg.listen, self.cfg.upstreams.len()
    )
)]
pub struct DnsService {
    cfg: Arc<DnsConfig>,
    stats: Arc<DnsStats>,
    ctx: LanforgeContext,
    db: Arc<LeaseDb>,
}

impl DnsService {
    #[must_use]
    pub fn new(cfg: DnsConfig, ctx: LanforgeContext, db: Arc<LeaseDb>) -> Self {
        let stats = Arc::new(DnsStats::new());
        ctx.set_dns_stats(Arc::clone(&stats));
        Self {
            cfg: Arc::new(cfg),
            stats,
            ctx,
            db,
        }
    }

    #[must_use]
    pub fn stats_snapshot(&self) -> DnsStatsSnapshot {
        self.stats.snapshot()
    }

    pub async fn init_dns_context(&self) -> Result<Arc<DnsContext>, CoreError> {
        let cache = Arc::new(DnsCache::new(self.cfg.cache_size, self.cfg.cache_min_ttl));
        self.stats
            .cache_capacity
            .store(self.cfg.cache_size, Ordering::Relaxed);
        let mut upstreams = Vec::new();
        for entry in &self.cfg.upstreams {
            match UpstreamManager::new(&entry.target, Arc::clone(&cache)).await {
                Ok(mgr) => upstreams.push(mgr),
                Err(e) => error!(
                    "❌ DNS: Failed to initialize upstream {}: {}",
                    entry.target.addr, e
                ),
            }
        }

        if upstreams.is_empty() && self.cfg.enabled && !self.cfg.search_domains.is_empty() {
            tracing::warn!("⚠️ DNS: No upstreams configured. Only local resolution will work.");
        }
        let db_adblock = self.db.load_adblock_config().await.unwrap_or_default();
        let db_rewrites = self.db.load_dns_rewrites().await.unwrap_or_default();
        let db_allowlist = self.db.load_dns_allowlist().await.unwrap_or_default();

        let adblock_enabled = self.cfg.adblock_enabled || db_adblock.enabled;
        info!(
            "🛡️ DNS: Adblock feature is initializing (Adblock: {}, Rewrites: {})",
            adblock_enabled,
            !db_rewrites.is_empty()
        );
        let blocker = AdBlocker::new(adblock_enabled);

        // Populate from DB
        blocker.replace_rewrites(db_rewrites);
        blocker.replace_allowlist(db_allowlist.into_iter().collect());
        blocker.replace_config(
            db_adblock.blocking_mode,
            db_adblock.blocking_ip_v4,
            db_adblock.blocking_ip_v6,
        );

        let filter = Some(Arc::new(blocker));

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
        pipeline.push(AdblockMiddleware::new());
        pipeline.push(UpstreamMiddleware::new());

        // Create a static-lifetime local resolver by leaking (or just ensuring it only ever points to self.ctx)
        // Actually, DnsContext will hold a LocalResolver with 'static but it's okay because LanforgeContext is Arc-wrapped.
        // We'll just transmute or find a better way. For now, let's use a simpler approach.
        // Since DnsContext is Arc-wrapped and stays alive, we can safely hold references.

        let dns_ctx = DnsContext {
            cfg: Arc::clone(&self.cfg),
            stats: Arc::clone(&self.stats),
            bus: self.ctx.bus(),
            query_log,
            pipeline,
            local: LocalResolver::new(Arc::clone(&self.cfg), self.ctx.clone()),
            recursive,
            cache: Arc::clone(&cache),
            filter,
            soa_zone,
            soa_master_ns,
            soa_mailbox,
            db: Arc::clone(&self.db),
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
        self.ctx.set_dns_context(Arc::clone(&dns_ctx));

        let parallelism = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        info!("Starting DNS service with {} UDP handlers", parallelism);

        let mut workers = Vec::new();
        let socket = Arc::new(
            tokio::net::UdpSocket::bind(self.cfg.listen)
                .await
                .map_err(|e| CoreError::ServiceError(format!("Failed to bind UDP socket: {e}")))?,
        );

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

        ctrl.signal_ready();

        // Shutdown handling
        let mut rx = self.ctx.bus().subscribe();
        loop {
            tokio::select! {
                Ok(evt) = rx.recv() => {
                    match evt.event {
                        lanforge_core::bus::LanforgeEvent::System(lanforge_core::bus::SystemEvent::Shutdown) => {
                            break;
                        }
                        lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::ConfigRewritesChanged) => {
                            info!("🔄 DNS: Reloading rewrites from DB...");
                            if let Some(filter) = &dns_ctx.filter {
                                match self.db.load_dns_rewrites().await {
                                    Ok(rewrites) => {
                                        filter.replace_rewrites(rewrites);
                                        info!("✅ DNS: Rewrites reloaded.");
                                    }
                                    Err(e) => error!("❌ DNS: Failed to load rewrites: {}", e),
                                }
                            }
                        }
                        lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::ConfigAllowlistChanged) => {
                            info!("🔄 DNS: Reloading allowlist from DB...");
                            if let Some(filter) = &dns_ctx.filter {
                                match self.db.load_dns_allowlist().await {
                                    Ok(allow) => {
                                        filter.replace_allowlist(allow.into_iter().collect());
                                        info!("✅ DNS: Allowlist reloaded.");
                                    }
                                    Err(e) => error!("❌ DNS: Failed to load allowlist: {}", e),
                                }
                            }
                        }
                        lanforge_core::bus::LanforgeEvent::Dns(lanforge_core::bus::DnsEvent::ConfigAdblockChanged) => {
                            info!("🔄 DNS: Reloading adblock config from DB...");
                            if let Some(filter) = &dns_ctx.filter {
                                match self.db.load_adblock_config().await {
                                    Ok(cfg) => {
                                        filter.replace_config(cfg.blocking_mode, cfg.blocking_ip_v4, cfg.blocking_ip_v6);
                                        filter.set_enabled(self.cfg.adblock_enabled || cfg.enabled);
                                        info!("✅ DNS: Adblock config reloaded.");
                                    }
                                    Err(e) => error!("❌ DNS: Failed to load adblock config: {}", e),
                                }
                            }
                        }
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
        #[cfg(feature = "adblock")]
        if let Some(w) = adblock_worker {
            w.abort();
        }

        Ok(())
    }
}
