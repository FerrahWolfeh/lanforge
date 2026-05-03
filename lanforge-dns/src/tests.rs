use hickory_proto::op::{Edns, Message, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use lanforge_core::bus::EventBus;
use lanforge_core::context::state::{CliHostUpdate, DeviceUpdate, FieldUpdate, State};
use lanforge_core::device::{Device, Ipv6AddrOrSuffix, Origin};
use lanforge_core::identifiers::{Duid, MacAddr};
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
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
        search_domain: "lan".to_string(),
        multi_search_labels: vec![vec![b"lan".to_vec()]],
        ..Default::default()
    }
}

// Helpers para testes que operam diretamente no DeviceTable (sem async)
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
    device: &Device,
    qtype: RecordType,
    cfg: &DnsConfig,
    ctx: LanforgeContext,
) -> Result<Option<Vec<u8>>, DnsError> {
    let resolver = LocalResolver::new(cfg, ctx);
    if let Some(records) = resolver.resolve_local(query, device, qtype) {
        Ok(Some(ResponseBuilder::new(query, cfg).success(records)?))
    } else {
        Ok(Some(ResponseBuilder::new(query, cfg).empty_noerror()?))
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
    query.add_query(hickory_proto::op::Query::query(name.clone(), RecordType::A));

    let device = ctx.get_device(&mac).unwrap();
    let result = resolve_local(&query, &device, RecordType::A, &cfg, ctx).unwrap();
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
    let res_bytes = resolve_local(&query, &device_arc, RecordType::AAAA, &cfg, ctx)
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
    let res_bytes = resolve_local(&query, &device_arc, RecordType::ANY, &cfg, ctx)
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
    let ctx = DnsContext {
        cfg,
        upstream_mgr: None,
        stats: Arc::new(DnsStats::default()),
        ctx: ctx_instance,
        #[cfg(feature = "adblock")]
        adblocker: None,
    };
    let resp_bytes = handle_query(&data, &ctx, "127.0.0.1".parse().unwrap())
        .await
        .unwrap()
        .expect("Deve retornar uma resposta DNS");
    let resp = Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp.response_code, ResponseCode::NXDomain);
}

#[tokio::test]
#[cfg(feature = "adblock")]
async fn test_adblock_integration() {
    use crate::filter::AdBlocker;
    let ctx_instance = init_test_context();
    let mut cfg = mock_config();
    cfg.adblock_enabled = true;
    cfg.upstream = Some(crate::config::UpstreamTarget {
        addr: "8.8.8.8:53".parse().unwrap(),
        protocol: crate::config::UpstreamProtocol::Udp,
        hostname: None,
    });

    let adblocker = Arc::new(AdBlocker::new());
    let mut list = std::collections::HashSet::new();
    list.insert("malware.com".to_string());
    adblocker.replace_blocklist(list);
    adblocker.set_enabled(true);

    let ctx = DnsContext {
        cfg,
        upstream_mgr: None,
        stats: Arc::new(DnsStats::default()),
        ctx: ctx_instance,
        adblocker: Some(adblocker),
    };

    let mut query = Message::query();
    query.add_query(Query::query(
        Name::from_str("malware.com.").unwrap(),
        RecordType::A,
    ));
    let data = query.to_bytes().unwrap();

    let resp_bytes = handle_query(&data, &ctx, "192.168.1.1".parse().unwrap())
        .await
        .unwrap()
        .expect("Should return a response");

    let resp = Message::from_bytes(&resp_bytes).unwrap();
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
    let resp = ResponseBuilder::new(&query, &cfg).base();
    assert!(resp.edns.is_some());
}

#[test]
fn test_local_resolver_direct_api() {
    let ctx = init_test_context();
    let cfg = mock_config();
    let mac = MacAddr([1, 2, 3, 4, 5, 0x33]);
    register_test_device(&ctx, "direct", mac, Ipv4Addr::new(10, 10, 10, 10));
    let resolver = crate::resolver::LocalResolver::new(&cfg, ctx);
    let mut query = Message::query();
    query.add_query(hickory_proto::op::Query::query(
        Name::from_str("direct.lan.").unwrap(),
        RecordType::A,
    ));
    let resp_bytes = resolver
        .resolve_ip(&query, "direct", RecordType::A)
        .unwrap();
    let resp = Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp.response_code, ResponseCode::NoError);
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

    let resp_bytes = {
        LocalResolver::new(&cfg, ctx)
            .resolve_ip(&query, "my-device", RecordType::A)
            .unwrap()
    };
    let resp = Message::from_bytes(&resp_bytes).unwrap();

    assert_eq!(resp.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 1);
    if let RData::A(resolved_ip) = &resp.answers[0].data {
        assert_eq!(**resolved_ip, ip);
    } else {
        panic!("Wrong RData type");
    }
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
    let res_bytes = resolve_local(&query, &device_arc, RecordType::AAAA, &cfg, ctx)
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
