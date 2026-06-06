use lanforge_core::bus::EventBus;
use lanforge_core::context::state::State;
use lanforge_db::config::DatabaseConfig;
use lanforge_db::engine::LanforgeDb;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::TransportProtocol;
use lanforge_types::update::DeviceUpdate;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use lanforge_core::context::LanforgeContext;
use lanforge_dns::config::DnsConfig;
use lanforge_dns::error::DnsError;
use lanforge_dns::pipeline::{DnsPipelineRequest, Pipeline, middleware::*};
#[cfg(feature = "adblock")]
use lanforge_dns::resolver::AdBlocker;
use lanforge_dns::resolver::LocalResolver;
use lanforge_dns::resolver::RewriteStore;
use lanforge_dns::resolver::recursive::DnsCache;
use lanforge_dns::resolver::recursive::UpstreamStrategy;
use lanforge_dns::server::DnsContext;
use lanforge_dns::telemetry::QueryRing;
use lanforge_dns::telemetry::stats::DnsStats;
use lanforge_dns_wire::{WireHeader, WireQuestion};

#[allow(dead_code)]
pub fn init_test_context() -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    LanforgeContext::new(bus, table, None)
}

#[allow(dead_code)]
pub fn mock_config() -> DnsConfig {
    DnsConfig {
        search_domains: vec!["lan".to_string()],
        multi_search_labels: vec![vec![b"lan".to_vec()]],
        ..Default::default()
    }
}

#[allow(dead_code)]
pub async fn mock_dns_context(ctx: LanforgeContext, cfg: DnsConfig) -> DnsContext {
    let domain_base = cfg
        .search_domains
        .first()
        .map_or_else(|| "lan".to_string(), Clone::clone);

    let soa_zone: Arc<str> = Arc::from(domain_base.as_str());
    let soa_master_ns: Arc<str> = Arc::from(format!("ns.{domain_base}"));
    let soa_mailbox: Arc<str> = Arc::from(format!("hostmaster.{domain_base}"));

    let cfg_arc = Arc::new(cfg);
    let cache = Arc::new(DnsCache::new(cfg_arc.cache_size, 30, None));
    let recursive = Arc::new(UpstreamStrategy::new(cfg_arc.upstream_mode, Vec::new()));

    let rewrites = Arc::new(RewriteStore::new());
    if !cfg_arc.rewrites.is_empty() {
        rewrites.replace_rules(cfg_arc.rewrites.clone());
    }

    #[cfg(feature = "adblock")]
    let filter = {
        let adblocker = AdBlocker::new(cfg_arc.adblock_enabled);
        adblocker.replace_config(
            cfg_arc.blocking_mode,
            cfg_arc.blocking_ip_v4,
            cfg_arc.blocking_ip_v6,
        );
        Some(Arc::new(adblocker))
    };

    let mut pipeline = Pipeline::new();
    pipeline.push(RewriteMiddleware::new());
    pipeline.push(LocalResolverMiddleware::new());
    pipeline.push(CacheMiddleware::new());
    #[cfg(feature = "adblock")]
    pipeline.push(AdblockMiddleware::new());
    pipeline.push(UpstreamMiddleware::new());

    let db = Arc::new(
        LanforgeDb::open(&DatabaseConfig {
            url: "sqlite::memory:".to_string(),
            ..Default::default()
        })
        .await
        .unwrap(),
    );

    DnsContext {
        cfg: cfg_arc.clone(),
        stats: Arc::new(DnsStats::new()),
        bus: ctx.bus(),
        query_log: Some(Arc::new(QueryRing::new(100))),
        pipeline,
        db,
        local: LocalResolver::new(cfg_arc, ctx),
        recursive,
        cache,
        rewrites,
        #[cfg(feature = "adblock")]
        filter,
        soa_zone,
        soa_master_ns,
        soa_mailbox,
        reverse_managers: Arc::new(RwLock::new(HashMap::new())),
        resolving_ips: Arc::new(Mutex::new(HashSet::new())),
    }
}

#[allow(dead_code)]
pub fn register_test_device(ctx: &LanforgeContext, hostname: &str, mac: MacAddr, ip: Ipv4Addr) {
    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip,
        expires: SystemTime::now() + Duration::from_secs(3600),
    });
    if !hostname.is_empty() {
        let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
            mac,
            hostname: hostname.to_string(),
        });
    }
}

#[allow(dead_code)]
pub async fn process_query_test(
    data: &[u8],
    ctx: &DnsContext,
    src_ip: IpAddr,
    resp: &mut Vec<u8>,
) -> Result<bool, DnsError> {
    let header = WireHeader::parse(data).ok_or(DnsError::WireParseError)?;
    let question = WireQuestion::parse(data).ok_or(DnsError::WireParseError)?;
    ctx.pipeline
        .run(
            ctx,
            DnsPipelineRequest::new(data, &header, &question, src_ip, TransportProtocol::Udp),
            resp,
        )
        .await?;
    Ok(!resp.is_empty())
}
