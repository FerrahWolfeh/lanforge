use hickory_proto::op::{Edns, Message, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use lanforge_core::bus::EventBus;
use lanforge_core::context::state::State;
use lanforge_types::{
    CliHostUpdate, Device, DeviceUpdate, Duid, FieldUpdate, Ipv6AddrOrSuffix, MacAddr, Origin,
};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use super::*;
use crate::error::DnsError;
use crate::resolver::LocalResolver;
use crate::response::ResponseBuilder;
use crate::server::{DnsContext, handle_query};
use crate::stats::DnsStats;
use crate::utils::extract_local_hostname;
use lanforge_core::context::LanforgeContext;

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

    DnsContext {
        cfg,
        upstreams: Vec::new(),
        stats: Arc::new(DnsStats::default()),
        ctx,
        #[cfg(feature = "adblock")]
        adblocker: None,
        soa_zone,
        soa_master_ns,
        soa_mailbox,
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
    let has_resp = handle_query(&data, &ctx, "127.0.0.1".parse().unwrap(), &mut resp_buf)
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
        soa_zone,
        soa_master_ns,
        soa_mailbox,
    };

    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_str("malware.com.").unwrap(),
        RecordType::A,
    ));
    let data = query.to_bytes().unwrap();

    let mut resp_buf = Vec::new();
    let has_resp = handle_query(&data, &ctx, "192.168.1.1".parse().unwrap(), &mut resp_buf)
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
