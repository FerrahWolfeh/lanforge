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
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tracing::info;

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
}

impl DnsService {
    #[must_use]
    pub fn new(cfg: DnsConfig, ctx: LanforgeContext) -> Self {
        let stats = Arc::new(DnsStats::new());
        ctx.set_dns_stats(Arc::clone(&stats));
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
        let cache = Arc::new(DnsCache::new(self.cfg.cache_size, self.cfg.cache_min_ttl));
        self.stats
            .cache_capacity
            .store(self.cfg.cache_size, Ordering::Relaxed);
        let mut upstreams = Vec::new();
        for prioritized in &self.cfg.upstreams {
            if let Ok(mgr) = UpstreamManager::new(&prioritized.target, Arc::clone(&cache)).await {
                upstreams.push(mgr);
            }
        }

        let filter = if self.cfg.adblock_enabled && !upstreams.is_empty() {
            Some(Arc::new(AdBlocker::new(self.cfg.adblock_enabled)))
        } else {
            None
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
        pipeline.push(AdblockMiddleware::new());
        pipeline.push(UpstreamMiddleware::new());

        // Create a static-lifetime local resolver by leaking (or just ensuring it only ever points to self.ctx)
        // Actually, DnsContext will hold a LocalResolver with 'static but it's okay because LanforgeContext is Arc-wrapped.
        // We'll just transmute or find a better way. For now, let's use a simpler approach.
        // Since DnsContext is Arc-wrapped and stays alive, we can safely hold references.

        let dns_ctx = Arc::new(DnsContext {
            cfg: Arc::clone(&self.cfg),
            stats: Arc::clone(&self.stats),
            bus: self.ctx.bus(),
            query_log,
            pipeline,
            local: LocalResolver::new(Arc::clone(&self.cfg), self.ctx.clone()),
            recursive,
            filter,
            soa_zone,
            soa_master_ns,
            soa_mailbox,
        });

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
                    if matches!(evt.event, lanforge_core::bus::LanforgeEvent::System(lanforge_core::bus::SystemEvent::Shutdown)) {
                        break;
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
