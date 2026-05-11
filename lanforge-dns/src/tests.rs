use hickory_proto::op::{Edns, Message, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use lanforge_core::bus::EventBus;
use lanforge_core::context::state::State;
use lanforge_core::types::{
    CliHostUpdate, Device, DeviceUpdate, Duid, FieldUpdate, Ipv6AddrOrSuffix, MacAddr, Origin,
};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::*;
use crate::error::DnsError;
use crate::filter::AdBlocker;
use crate::health::{UpstreamHealth, UpstreamStatus};
use crate::resolver::LocalResolver;
use crate::response::ResponseBuilder;
use crate::server::DnsContext;
use crate::stats::DnsStats;
use crate::strategy::UpstreamMode;
use crate::upstream::UpstreamManager;
use crate::utils::extract_local_hostname;
use lanforge_core::context::LanforgeContext;
use lanforge_core::types::network::{QueryLogEntry, QueryResult};

fn init_test_context() -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    LanforgeContext::new(bus, table, None)
}

// Helper para gerar um DnsConfig pronto para os testes do Fast Path
fn mock_config() -> DnsConfig {
    DnsConfig {
        search_domains: vec!["lan".to_string()],
        multi_search_labels: vec![vec![b"lan".to_vec()]],
        ..Default::default()
    }
}

// Helpers para testes que operam diretamente no DeviceTable (sem async)
fn mock_dns_context(ctx: LanforgeContext, cfg: DnsConfig) -> DnsContext {
    let domain_base = cfg
        .search_domains
        .first()
        .map_or_else(|| "lan".to_string(), Clone::clone);

    let soa_zone = Name::from_str(&format!("{domain_base}.")).unwrap_or_else(|_| Name::root());
    let soa_master_ns =
        Name::from_str(&format!("ns.{domain_base}.")).unwrap_or_else(|_| Name::root());
    let soa_mailbox =
        Name::from_str(&format!("hostmaster.{domain_base}.")).unwrap_or_else(|_| Name::root());

    let upstream_strategy = Arc::new(crate::strategy::UpstreamStrategy::new(
        cfg.upstream_mode,
        Vec::new(),
    ));

    DnsContext {
        cfg,
        upstreams: Vec::new(),
        upstream_strategy,
        stats: Arc::new(DnsStats::default()),
        ctx,
        #[cfg(feature = "adblock")]
        adblocker: None,
        soa_zone,
        soa_master_ns,
        soa_mailbox,
        query_log: None,
    }
}

fn register_test_device(ctx: &LanforgeContext, hostname: &str, mac: MacAddr, ip: Ipv4Addr) {
    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip,
        expires: SystemTime::now() + Duration::from_hours(1),
    });
    if !hostname.is_empty() {
        let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
            mac,
            hostname: hostname.to_string(),
        });
    }
}

// Legacy functions for tests only
pub fn resolve_local(
    query: &Message,
    _device: &Device,
    qtype: RecordType,
    cfg: &DnsConfig,
    ctx: &LanforgeContext,
) -> Result<Option<Vec<u8>>, DnsError> {
    let dns_ctx = mock_dns_context(ctx.clone(), cfg.clone());
    let resolver = LocalResolver::new(cfg, ctx);
    let rb = ResponseBuilder::new(query, &dns_ctx);
    if let Some(records) = resolver.resolve_local(rb.qname(), qtype) {
        Ok(Some(rb.success(records)?))
    } else {
        Ok(Some(rb.empty_noerror()?))
    }
}

#[test]
fn test_extract_local_hostname_matches_domain() {
    let labels = vec![b"lan".to_vec()];
    let name = Name::from_str("archie.lan.").unwrap();
    assert_eq!(extract_local_hostname(&name, &[labels]), Some("archie"));
}

#[test]
fn resolve_local_matches_question_name_exactly() {
    let ctx = init_test_context();
    let cfg = mock_config();
    let mac = MacAddr([1, 2, 3, 4, 5, 0x11]);
    register_test_device(&ctx, "solarium", mac, Ipv4Addr::new(192, 168, 0, 2));

    let mut query = Message::query();
    let name = Name::from_str("solarium.lan.").unwrap();
    query.add_query(Query::query(name.clone(), RecordType::A));

    let device = ctx.get_device(&mac).unwrap();
    let result = resolve_local(&query, &device, RecordType::A, &cfg, &ctx).unwrap();
    let resp_bytes = result.unwrap();
    let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

    assert_eq!(resp_msg.answers[0].name, name);
}

#[test]
fn test_resolve_local_v6_suffix_merging() {
    let ctx = init_test_context();
    let ula = "fd00::".parse::<Ipv6Addr>().unwrap();
    let gua = "2001:db8::".parse::<Ipv6Addr>().unwrap();
    let mut cfg = mock_config();
    cfg.ula_prefix = Some(ula);
    cfg.gua_prefix = Some(gua);

    let mac = MacAddr([1, 2, 3, 4, 5, 6]);

    let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "test".to_string(),
    });

    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: "2001:db8::1".parse().unwrap(),
        is_active: true,
    });

    // Directly setup static device via apply to ensure consistency
    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: CliHostUpdate {
            hostname: FieldUpdate::Set("test".to_string()),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::Set(Ipv6AddrOrSuffix::parse("::beef").unwrap()),
            origin: Origin::Cli,
            boot_file: FieldUpdate::NoChange,
        },
    });

    let mut query = Message::query();
    let name = Name::from_str("test.lan.").unwrap();
    query.add_query(Query::query(name, RecordType::AAAA));

    let device_arc = ctx.get_device(&mac).expect("Should resolve locally");
    let res_bytes = resolve_local(&query, &device_arc, RecordType::AAAA, &cfg, &ctx)
        .unwrap()
        .expect("Should resolve locally");

    let res = Message::from_bytes(&res_bytes).unwrap();
    let answers = &res.answers;

    assert!(answers.len() >= 2);
    let ips: HashSet<Ipv6Addr> = answers
        .iter()
        .filter_map(|r| {
            if let RData::AAAA(ip) = &r.data {
                Some((*ip).into())
            } else {
                None
            }
        })
        .collect();

    assert!(ips.contains(&"fd00::beef".parse().unwrap()));
    assert!(ips.contains(&"2001:db8::1".parse().unwrap()));
}

#[test]
fn test_resolve_local_priority_ordering() {
    let ctx = init_test_context();
    let mut cfg = mock_config();
    cfg.ula_prefix = Some("fd00::".parse().unwrap());

    let mac = MacAddr([1, 2, 3, 4, 5, 0x22]);

    let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "priority-test".to_string(),
    });
    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip: "192.168.1.1".parse().unwrap(),
        expires: SystemTime::now() + Duration::from_hours(1),
    });
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: "2001:db8::1".parse().unwrap(),
        is_active: true,
    });
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: "fd00::1".parse().unwrap(),
        is_active: true,
    });

    let mut query = Message::query();
    let name = Name::from_str("priority-test.lan.").unwrap();
    query.add_query(Query::query(name, RecordType::ANY));

    let device_arc = ctx.get_device(&mac).unwrap();
    let res_bytes = resolve_local(&query, &device_arc, RecordType::ANY, &cfg, &ctx)
        .unwrap()
        .expect("Should resolve locally");

    let res = Message::from_bytes(&res_bytes).unwrap();
    let answers = &res.answers;

    assert!(answers.len() >= 3);
}

#[tokio::test]
async fn test_nxdomain_leak_prevention_and_soa() {
    let ctx_instance = init_test_context();
    let cfg = mock_config();
    let mut query = Message::query();
    let name = Name::from_str("fantasma.lan.").unwrap();
    query.add_query(Query::query(name, RecordType::A));
    let data = query.to_bytes().unwrap();
    let ctx = mock_dns_context(ctx_instance, cfg);
    let mut resp_buf = Vec::new();
    let has_resp =
        crate::handler::process_query(&data, &ctx, "127.0.0.1".parse().unwrap(), &mut resp_buf)
            .await
            .unwrap();
    assert!(has_resp);
    let resp = Message::from_bytes(&resp_buf).unwrap();
    assert_eq!(resp.response_code, ResponseCode::NXDomain);
}

#[tokio::test]
#[cfg(feature = "adblock")]
async fn test_adblock_integration() {
    use crate::filter::AdBlocker;
    use crate::strategy::UpstreamStrategy;
    let ctx_instance = init_test_context();
    let mut cfg = mock_config();
    cfg.adblock_enabled = true;
    cfg.upstreams = vec![PrioritizedUpstream {
        target: crate::config::UpstreamTarget {
            addr: "8.8.8.8:53".parse().unwrap(),
            protocol: crate::config::UpstreamProtocol::Udp,
            hostname: None,
        },
        priority: 10,
    }];

    let adblocker = Arc::new(AdBlocker::new());
    let mut list = std::collections::HashSet::new();
    list.insert("malware.com".to_string());
    adblocker.replace_blocklist(list);
    adblocker.set_enabled(true);

    let soa_zone = Name::from_str("lan.").unwrap();
    let soa_master_ns = Name::from_str("ns.lan.").unwrap();
    let soa_mailbox = Name::from_str("hostmaster.lan.").unwrap();

    let ctx = DnsContext {
        cfg,
        upstreams: Vec::new(),
        stats: Arc::new(DnsStats::default()),
        ctx: ctx_instance,
        adblocker: Some(adblocker),
        upstream_strategy: Arc::new(UpstreamStrategy::new(UpstreamMode::Sequential, vec![])),
        soa_zone,
        soa_master_ns,
        soa_mailbox,
        query_log: None,
    };

    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_str("malware.com.").unwrap(),
        RecordType::A,
    ));
    let data = query.to_bytes().unwrap();

    let mut resp_buf = Vec::new();
    let has_resp =
        crate::handler::process_query(&data, &ctx, "192.168.1.1".parse().unwrap(), &mut resp_buf)
            .await
            .unwrap();
    assert!(has_resp);

    let resp = Message::from_bytes(&resp_buf).unwrap();
    assert_eq!(resp.response_code, ResponseCode::NXDomain);
    assert_eq!(
        ctx.stats
            .blocked_queries
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[test]
fn test_edns0_is_preserved() {
    let cfg = mock_config();
    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_str("localhost.").unwrap(),
        RecordType::A,
    ));
    let mut extensions = Edns::new();
    extensions
        .options_mut()
        .insert(EdnsOption::Unknown(123, vec![1, 2, 3]));
    query.set_edns(extensions);
    let dns_ctx = mock_dns_context(init_test_context(), cfg);
    let resp = ResponseBuilder::new(&query, &dns_ctx).base();
    assert!(resp.edns.is_some());
}

#[test]
fn test_local_resolver_direct_api() {
    let ctx = init_test_context();
    let cfg = mock_config();
    let mac = MacAddr([1, 2, 3, 4, 5, 0x33]);
    register_test_device(&ctx, "direct", mac, Ipv4Addr::new(10, 10, 10, 10));
    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_str("direct.lan.").unwrap(),
        RecordType::A,
    ));
    let resolver = LocalResolver::new(&cfg, &ctx);
    let ips = resolver
        .resolve_ip("direct", RecordType::A)
        .expect("Should resolve host 'direct'");
    assert_eq!(ips.as_slice(), &[IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10))]);
}

#[test]
fn test_dhcp_registration_creates_dns_record() {
    let ctx = init_test_context();
    let cfg = mock_config();
    let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ip = Ipv4Addr::new(192, 168, 1, 50);

    // 1. Simulate DHCPv4 Lease
    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip,
        expires: SystemTime::now() + Duration::from_hours(1),
    });

    // 2. Simulate Hostname Hint from DHCP
    let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "my-device".to_string(),
    });

    let mut query = Message::query();
    let name = Name::from_str("my-device.lan.").unwrap();
    query.add_query(Query::query(name, RecordType::A));

    let ips = {
        LocalResolver::new(&cfg, &ctx)
            .resolve_ip("my-device", RecordType::A)
            .expect("Should resolve host 'my-device'")
    };

    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0], IpAddr::V4(ip));
}

#[test]
fn test_dns_response_contract() {
    let ctx = init_test_context();
    let ula = "fd00::".parse::<Ipv6Addr>().unwrap();
    let gua = "2001:db8::".parse::<Ipv6Addr>().unwrap();
    let mut cfg = mock_config();
    cfg.ula_prefix = Some(ula);
    cfg.gua_prefix = Some(gua);

    let mac = MacAddr([1, 2, 3, 4, 5, 0x99]);

    // 1. Static Suffix
    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: CliHostUpdate {
            hostname: FieldUpdate::Set("contract-test".to_string()),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::NoChange,
            v6_suffix: FieldUpdate::Set(Ipv6AddrOrSuffix::parse("::1057:cafe").unwrap()),
            origin: Origin::Cli,
            boot_file: FieldUpdate::NoChange,
        },
    });

    // 2. SLAAC addresses
    let slaac_ula = "fd00::7c5a:23c3:41dc:7d9e".parse().unwrap();
    let slaac_gua = "2001:db8::c8a2:cbd3:9d9e:89c7".parse().unwrap();
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: slaac_ula,
        is_active: true,
    });
    let _ = ctx.apply(DeviceUpdate::SlaacObserved {
        mac,
        addr: slaac_gua,
        is_active: true,
    });

    // 3. DHCPv6 Dynamic Lease
    let dynamic_ula = "fd00::33c".parse().unwrap();
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted {
        mac: Some(mac),
        duid: Duid::generate_ll_from_mac(mac.0),
        iaid: 1,
        ip: dynamic_ula,
        expires: SystemTime::now() + Duration::from_hours(1),
    });

    let mut query = Message::query();
    let name = Name::from_str("contract-test.lan.").unwrap();
    query.add_query(Query::query(name, RecordType::AAAA));

    let device_arc = ctx.get_device(&mac).unwrap();
    let res_bytes = resolve_local(&query, &device_arc, RecordType::AAAA, &cfg, &ctx)
        .unwrap()
        .expect("Should resolve locally");

    let res = Message::from_bytes(&res_bytes).unwrap();
    let ips: HashSet<Ipv6Addr> = res
        .answers
        .iter()
        .filter_map(|r| {
            if let RData::AAAA(ip) = &r.data {
                Some((*ip).into())
            } else {
                None
            }
        })
        .collect();

    // Assert ALL expected addresses are present
    assert!(
        ips.contains(&"fd00::1057:cafe".parse().unwrap()),
        "Missing Custom ULA"
    );
    assert!(
        ips.contains(&"2001:db8::1057:cafe".parse().unwrap()),
        "Missing Custom GUA"
    );
    assert!(ips.contains(&slaac_ula), "Missing SLAAC ULA");
    assert!(ips.contains(&slaac_gua), "Missing SLAAC GUA");
    assert!(ips.contains(&dynamic_ula), "Missing DHCPv6 Dynamic");

    assert_eq!(ips.len(), 5);
}

#[test]
fn test_upstream_health_ewma() {
    let health = UpstreamHealth::new();

    // First success sets EWMA to exact value
    health.record_success(1000);
    assert_eq!(health.rtt_ewma_us.load(Ordering::Relaxed), 1000);

    // Second success: alpha=0.3 -> 0.3*500 + 0.7*1000 = 150 + 700 = 850
    health.record_success(500);
    assert_eq!(health.rtt_ewma_us.load(Ordering::Relaxed), 850);
}

#[test]
fn test_upstream_health_consecutive_failures() {
    let health = UpstreamHealth::new();

    health.record_failure();
    assert_eq!(health.consecutive_failures.load(Ordering::Relaxed), 1);
    assert_eq!(health.total_failures.load(Ordering::Relaxed), 1);

    health.record_success(50);
    assert_eq!(health.consecutive_failures.load(Ordering::Relaxed), 0);
    assert_eq!(health.total_successes.load(Ordering::Relaxed), 1);
}

#[test]
fn test_upstream_health_status_timing() {
    let health = UpstreamHealth::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for _ in 0..5 {
        health.record_failure();
    }

    // At T=0, should be degraded
    health.last_failure_ts.store(now, Ordering::Relaxed);
    assert_eq!(health.status(), UpstreamStatus::Degraded);

    // At T=29, still degraded
    health.last_failure_ts.store(now - 29, Ordering::Relaxed);
    assert_eq!(health.status(), UpstreamStatus::Degraded);

    // At T=30, should recover
    health.last_failure_ts.store(now - 30, Ordering::Relaxed);
    assert_eq!(health.status(), UpstreamStatus::Healthy);
}

#[test]
fn test_upstream_health_snapshot_labels() {
    let health = UpstreamHealth::new();
    health.record_success(1234);

    let snap = health.snapshot("8.8.8.8:53".into(), "udp".into());
    assert_eq!(snap.target, "8.8.8.8:53");
    assert_eq!(snap.protocol, "udp");
    assert_eq!(snap.rtt_ewma_us, 1234);
    assert_eq!(snap.status, "Healthy");
}

#[tokio::test]
async fn test_strategy_sequential_ordering() {
    use crate::config::UpstreamTarget;
    use crate::strategy::{UpstreamMode, UpstreamStrategy};

    let t1: UpstreamTarget = "127.0.0.1:5301".parse().unwrap();
    let t2: UpstreamTarget = "127.0.0.1:5302".parse().unwrap();

    let m1 = UpstreamManager::new(&t1).await.unwrap();
    let m2 = UpstreamManager::new(&t2).await.unwrap();

    let strategy = UpstreamStrategy::new(UpstreamMode::Sequential, vec![m1.clone(), m2.clone()]);

    // Mock failure for m1
    for _ in 0..5 {
        m1.health.record_failure();
    }
    assert_eq!(m1.health.status(), UpstreamStatus::Degraded);

    // Strategy should skip m1 and try m2 (which will fail because nothing is listening)
    let mut msg = Message::query();
    msg.add_query(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::A,
    ));
    let query = msg.to_bytes().unwrap();
    let res = strategy.resolve(&query).await;
    assert!(res.is_err());

    // Total queries on m1 should still be 5
    assert_eq!(m1.health.total_queries.load(Ordering::Relaxed), 5);
    // m2 should have been tried once
    assert_eq!(m2.health.total_queries.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn test_strategy_fastest_selection() {
    use crate::config::UpstreamTarget;
    use crate::strategy::{UpstreamMode, UpstreamStrategy};

    let t1: UpstreamTarget = "1.1.1.1:53".parse().unwrap();
    let t2: UpstreamTarget = "8.8.8.8:53".parse().unwrap();

    let m1 = UpstreamManager::new(&t1).await.unwrap();
    let m2 = UpstreamManager::new(&t2).await.unwrap();

    // m2 is faster
    m1.health.record_success(2000);
    m2.health.record_success(500);

    let strategy = UpstreamStrategy::new(UpstreamMode::Fastest, vec![m1.clone(), m2]);

    let snapshots = strategy.snapshots();
    assert_eq!(snapshots[0].target, "1.1.1.1:53");
    assert_eq!(snapshots[1].target, "8.8.8.8:53");
}

#[tokio::test]
async fn test_strategy_parallel_all_degraded() {
    use crate::config::UpstreamTarget;
    use crate::strategy::{UpstreamMode, UpstreamStrategy};

    let t1: UpstreamTarget = "127.0.0.1:5303".parse().unwrap();
    let m1 = UpstreamManager::new(&t1).await.unwrap();

    for _ in 0..5 {
        m1.health.record_failure();
    }

    let strategy = UpstreamStrategy::new(UpstreamMode::Parallel, vec![m1.clone()]);

    // Even if degraded, if it's the only one, parallel should still try it (fallback)
    let mut msg = Message::query();
    msg.add_query(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::A,
    ));
    let query = msg.to_bytes().unwrap();
    let _ = strategy.resolve(&query).await;
    assert_eq!(m1.health.total_queries.load(Ordering::Relaxed), 6);
}

#[tokio::test]
async fn test_query_ring() {
    use crate::query_log::QueryRing;
    let ring = QueryRing::new(5);

    for i in 0u64..10 {
        ring.push(QueryLogEntry {
            timestamp: i,
            src_ip: "127.0.0.1".parse().unwrap(),
            domain: format!("host{i}.lan"),
            qtype: 1,
            result: QueryResult::Local,
            upstream_us: 0,
            cached: false,
        });
    }

    let entries = ring.get_recent(10);
    assert_eq!(entries.len(), 5);
    // Should contain the last 5 entries (5 to 9)
    assert_eq!(entries[0].domain, "host9.lan");
    assert_eq!(entries[4].domain, "host5.lan");
}

#[tokio::test]
#[cfg(feature = "adblock")]
async fn test_dns_rewrites_fallback() {
    let ctx_instance = init_test_context();
    let mut cfg = mock_config();
    cfg.adblock_enabled = true;
    cfg.rewrites = vec![
        crate::config::RewriteRule {
            domain: "vault.lan".to_string(),
            answer: "10.0.0.1".to_string(),
        },
        crate::config::RewriteRule {
            domain: "alias.lan".to_string(),
            answer: "target.lan".to_string(),
        },
    ];

    let adblocker = Arc::new(AdBlocker::new());
    adblocker.rewrites.write().clone_from(&cfg.rewrites);
    adblocker.set_enabled(true);

    let ctx = DnsContext {
        cfg: cfg.clone(),
        upstreams: Vec::new(),
        stats: Arc::new(DnsStats::default()),
        ctx: ctx_instance,
        adblocker: Some(adblocker),
        upstream_strategy: Arc::new(crate::strategy::UpstreamStrategy::new(
            UpstreamMode::Sequential,
            vec![],
        )),
        soa_zone: Name::from_str("lan.").unwrap(),
        soa_master_ns: Name::from_str("ns.lan.").unwrap(),
        soa_mailbox: Name::from_str("hostmaster.lan.").unwrap(),
        query_log: None,
    };

    // Use a query that triggers fallback (e.g., with a pointer or just calling handle_query_fallback)
    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_str("vault.lan.").unwrap(),
        RecordType::A,
    ));
    let data = query.to_bytes().unwrap();
    let mut resp_buf = Vec::new();

    // Test direct IP rewrite
    let res =
        crate::handler::process_query(&data, &ctx, "127.0.0.1".parse().unwrap(), &mut resp_buf)
            .await
            .unwrap();
    assert!(res);
    let resp = Message::from_bytes(&resp_buf).unwrap();
    assert_eq!(resp.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 1);
    if let RData::A(ip) = &resp.answers[0].data {
        assert_eq!(Into::<Ipv4Addr>::into(*ip), Ipv4Addr::new(10, 0, 0, 1));
    } else {
        panic!("Wrong record type");
    }

    // Test CNAME rewrite
    query = Message::query();
    query.add_query(Query::query(
        Name::from_str("alias.lan.").unwrap(),
        RecordType::A,
    ));
    let data = query.to_bytes().unwrap();
    resp_buf.clear();
    let res =
        crate::handler::process_query(&data, &ctx, "127.0.0.1".parse().unwrap(), &mut resp_buf)
            .await
            .unwrap();
    assert!(res);
    let resp = Message::from_bytes(&resp_buf).unwrap();
    assert_eq!(resp.answers.len(), 1);
    if let RData::CNAME(name) = &resp.answers[0].data {
        assert_eq!(name.to_string(), "target.lan.");
    } else {
        panic!("Wrong record type");
    }
}

#[tokio::test]
#[cfg(feature = "adblock")]
async fn test_dns_blocking_modes_fallback() {
    let ctx_instance = init_test_context();
    let mut cfg = mock_config();
    cfg.adblock_enabled = true;
    cfg.blocking_mode = crate::config::BlockingMode::NullIp;

    let adblocker = Arc::new(AdBlocker::new());
    let mut list = HashSet::new();
    list.insert("evil.com".to_string());
    adblocker.replace_blocklist(list);
    adblocker.set_enabled(true);

    let ctx = DnsContext {
        cfg: cfg.clone(),
        upstreams: vec![
            UpstreamManager::new(&"8.8.8.8:53".parse().unwrap())
                .await
                .unwrap(),
        ],
        stats: Arc::new(DnsStats::default()),
        ctx: ctx_instance,
        adblocker: Some(adblocker),
        upstream_strategy: Arc::new(crate::strategy::UpstreamStrategy::new(
            UpstreamMode::Sequential,
            vec![],
        )),
        soa_zone: Name::from_str("lan.").unwrap(),
        soa_master_ns: Name::from_str("ns.lan.").unwrap(),
        soa_mailbox: Name::from_str("hostmaster.lan.").unwrap(),
        query_log: None,
    };

    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_str("evil.com.").unwrap(),
        RecordType::A,
    ));
    let data = query.to_bytes().unwrap();
    let mut resp_buf = Vec::new();

    // Test NullIp mode
    let _ = crate::handler::process_query(&data, &ctx, "127.0.0.1".parse().unwrap(), &mut resp_buf)
        .await
        .unwrap();
    let resp = Message::from_bytes(&resp_buf).unwrap();
    assert_eq!(resp.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 1);
    if let RData::A(ip) = &resp.answers[0].data {
        assert_eq!(Into::<Ipv4Addr>::into(*ip), Ipv4Addr::UNSPECIFIED);
    }

    // Test Refused mode
    let mut cfg_refused = ctx.cfg.clone();
    cfg_refused.blocking_mode = crate::config::BlockingMode::Refused;
    let ctx_refused = DnsContext {
        cfg: cfg_refused,
        ..ctx
    };
    resp_buf.clear();
    let _ = crate::handler::process_query(
        &data,
        &ctx_refused,
        "127.0.0.1".parse().unwrap(),
        &mut resp_buf,
    )
    .await
    .unwrap();
    let resp = Message::from_bytes(&resp_buf).unwrap();
    assert_eq!(resp.response_code, ResponseCode::Refused);
}
