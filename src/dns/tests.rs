use hickory_proto::op::{Edns, Query};
use hickory_proto::rr::rdata::opt::EdnsOption;

use super::*;
use crate::bus::EventBus;
use crate::state::{Device, DeviceTable, MacAddr, Origin, V4Lease};
use std::{net::Ipv4Addr, time::SystemTime};

// Helpers para testes que precisam de ManagedTable
fn empty_table() -> Arc<ManagedTable> {
    Arc::new(ManagedTable::new(Arc::new(EventBus::new())))
}

// Helper para gerar um device mock
fn mock_device(mac_bytes: [u8; 6], host: &str) -> Device {
    let mac = crate::state::MacAddr(mac_bytes);
    Device {
        hostname: host.to_string(),
        mac,
        origin: Origin::Dynamic,
        managed_at: None,
        v4_static: None,
        v6_suffix: None,
        is_static: false,
        duid: None,
        v4: None,
        v6: None,
        v6_prefix: None,
        slaac: vec![],
        seen_v4: vec![],
        last_seen: SystemTime::now(),
    }
}

// Helpers para testes que operam diretamente no DeviceTable (sem async)
fn table_with_device(hostname: &str, mac: MacAddr, ip: Ipv4Addr) -> DeviceTable {
    let mut table = DeviceTable::new();
    table.devices.insert(
        mac,
        Device {
            hostname: hostname.into(),
            mac,
            origin: crate::state::Origin::Dynamic,
            managed_at: None,
            v4_static: None,
            v6_suffix: None,
            is_static: false,
            duid: None,
            v4: Some(V4Lease {
                ip,
                expires: SystemTime::now() + std::time::Duration::from_secs(3600),
            }),
            v6: None,
            v6_prefix: None,
            slaac: vec![],
            seen_v4: vec![],
            last_seen: SystemTime::now(),
        },
    );
    table
}

// --- normalize_name ---

#[test]
fn normalize_strips_domain_and_dot() {
    assert_eq!(normalize_name("archie.lan.", "lan"), "archie");
    assert_eq!(normalize_name("archie.lan", "lan"), "archie");
    assert_eq!(normalize_name("archie.", "lan"), "archie");
}

#[test]
fn normalize_keeps_bare_hostname() {
    assert_eq!(normalize_name("archie", "lan"), "archie");
    assert_eq!(normalize_name("NAS", "lan"), "nas");
}

#[test]
fn normalize_keeps_external_domains() {
    assert_eq!(normalize_name("foo.bar.com.", "lan"), "foo.bar.com");
    assert_eq!(normalize_name("google.com", "lan"), "google.com");
}

#[test]
fn normalize_handles_mismatched_search_domain() {
    assert_eq!(normalize_name("archie.local.", "lan"), "archie.local");
}

// --- resolve_local ---

#[test]
fn resolve_local_matches_question_name_exactly() {
    use hickory_proto::rr::Name;

    let cfg = DnsConfig::default();
    let mac = MacAddr::from_slice(&[0u8; 6]).unwrap();
    let table = table_with_device("solarium", mac, Ipv4Addr::new(192, 168, 0, 2));

    let mut query = Message::new();
    let name = Name::from_str("solarium.").unwrap();
    query.add_query(hickory_proto::op::Query::query(name.clone(), RecordType::A));

    let result = resolve_local(&query, "solarium", RecordType::A, &cfg, &table).unwrap();
    let resp_bytes = result.unwrap();
    let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

    assert_eq!(resp_msg.answers()[0].name(), &name);
}

// --- parse_arpa_name ---

#[test]
fn parses_ipv4_arpa_correctly() {
    let ip = parse_arpa_name("50.1.168.192.in-addr.arpa.").unwrap();
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
}

#[test]
fn parses_ipv6_arpa_correctly() {
    let arpa = "4.3.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa";
    let ip = parse_arpa_name(arpa).unwrap();
    assert_eq!(ip, "fd00::1234".parse::<IpAddr>().unwrap());
}

#[test]
fn invalid_arpa_returns_none() {
    assert_eq!(parse_arpa_name("invalid.in-addr.arpa"), None);
    assert_eq!(parse_arpa_name("999.1.1.1.in-addr.arpa"), None);
    assert_eq!(parse_arpa_name("google.com"), None);
}

// --- resolve_ptr ---

#[test]
fn resolve_ptr_returns_correct_hostname() {
    use hickory_proto::rr::Name;

    let cfg = DnsConfig::default();
    let mac = MacAddr::from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).unwrap();
    let table = table_with_device("solarium", mac, Ipv4Addr::new(192, 168, 0, 50));

    let mut query = Message::new();
    let qname = Name::from_str("50.0.168.192.in-addr.arpa.").unwrap();
    query.add_query(hickory_proto::op::Query::query(qname, RecordType::PTR));

    let result = resolve_ptr(&query, "50.0.168.192.in-addr.arpa", &cfg, &table).unwrap();
    let resp_bytes = result.expect("Deveria ter encontrado o dispositivo");
    let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

    assert_eq!(resp_msg.answers().len(), 1);
    if let Some(ptr_name) = resp_msg.answers()[0].data().as_ptr() {
        assert_eq!(ptr_name.to_utf8(), "solarium.lan.");
    } else {
        panic!("RData não é PTR");
    }
}

#[test]
fn resolve_ptr_uses_mac_fallback_if_no_hostname() {
    use hickory_proto::rr::Name;

    let cfg = DnsConfig::default();
    let mac = MacAddr::from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]).unwrap();
    let table = table_with_device("", mac, Ipv4Addr::new(10, 0, 0, 5));

    let mut query = Message::new();
    let qname = Name::from_str("5.0.0.10.in-addr.arpa.").unwrap();
    query.add_query(hickory_proto::op::Query::query(qname, RecordType::PTR));

    let result = resolve_ptr(&query, "5.0.0.10.in-addr.arpa", &cfg, &table).unwrap();
    let resp_bytes = result.expect("Deveria ter retornado uma resposta");
    let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

    if let Some(ptr_name) = resp_msg.answers()[0].data().as_ptr() {
        assert_eq!(ptr_name.to_utf8(), "host-112233445566.lan.");
    } else {
        panic!("RData não é PTR");
    }
}

// --- handle_query async ---

#[tokio::test]
async fn handle_query_refused_when_no_upstream() {
    let cfg = DnsConfig {
        upstream: None,
        ..Default::default()
    };
    let table = empty_table();

    let mut query = Message::new();
    let name = Name::from_str("google.com.").unwrap();
    query.add_query(hickory_proto::op::Query::query(name, RecordType::A));
    let query_bytes = query.to_bytes().unwrap();

    let src = "127.0.0.1:12345".parse().unwrap();
    let resp_bytes = if let Some(resp) = handle_query(&query_bytes, src, &cfg, &table, None)
        .await
        .unwrap()
    {
        resp
    } else {
        panic!("Deveria ter retornado uma resposta");
    };
    let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

    assert_eq!(resp_msg.response_code(), ResponseCode::Refused);
}

#[tokio::test]
async fn handle_query_forwards_when_upstream_present() {
    let cfg = DnsConfig {
        upstream: Some("1.2.3.4:53".parse().unwrap()),
        ..Default::default()
    };
    let table = empty_table();

    let mut query = Message::new();
    let name = Name::from_str("google.com.").unwrap();
    query.add_query(hickory_proto::op::Query::query(name, RecordType::A));
    let query_bytes = query.to_bytes().unwrap();

    let src = "127.0.0.1:12345".parse().unwrap();
    let mgr = UpstreamManager::new(cfg.upstream.unwrap()).await.unwrap();
    let result = handle_query(&query_bytes, src, &cfg, &table, Some(&mgr)).await;

    match result {
        Err(e) => {
            let err_str = format!("{e:#}");
            assert!(err_str.contains("timeout") || err_str.contains("upstream"));
        }
        Ok(resp_bytes) => {
            if let Some(resp) = resp_bytes {
                let resp_msg = Message::from_bytes(&resp).unwrap();
                assert_ne!(resp_msg.response_code(), ResponseCode::Refused);
            } else {
                panic!("Deveria ter retornado uma resposta");
            }
        }
    }
}

#[test]
fn test_resolve_local_v6_suffix_merging() {
    let ula = "fd00::".parse::<Ipv6Addr>().unwrap();
    let cfg = DnsConfig {
        ula_prefix: Some(ula),
        ..Default::default()
    };

    let mut table = DeviceTable::new();
    let mut dev = mock_device([1, 2, 3, 4, 5, 6], "test");
    dev.v6_suffix = Some("::beef".to_string());
    dev.slaac = vec!["2001:db8::1".parse().unwrap()];
    table.devices.insert(dev.mac, dev);

    let mut query = Message::new();
    let name = Name::from_str("test.lan.").unwrap();
    query.add_query(Query::query(name, RecordType::AAAA));

    let res_bytes = resolve_local(&query, "test", RecordType::AAAA, &cfg, &table)
        .unwrap()
        .expect("Should resolve locally");

    let res = Message::from_bytes(&res_bytes).unwrap();
    let answers = res.answers();

    // Agora deve passar, pois o suffix será corretamente misturado e não tratado como um IP estático.
    assert!(
        answers.len() >= 2,
        "Deveria retornar o ULA combinado e o GUA combinado"
    );

    let ips: HashSet<Ipv6Addr> = answers
        .iter()
        .filter_map(|r| {
            if let RData::AAAA(ip) = r.data() {
                Some((*ip).into())
            } else {
                None
            }
        })
        .collect();

    assert!(ips.contains(&"fd00::beef".parse().unwrap()));
    assert!(ips.contains(&"2001:db8::beef".parse().unwrap()));
}

#[tokio::test]
async fn test_nxdomain_leak_prevention_and_soa() {
    // Configuramos um upstream falso para testar se ele vai ignorar o forward e mandar NXDomain
    let cfg = DnsConfig {
        upstream: Some("127.0.0.1:9999".parse().unwrap()),
        search_domain: "lan".into(),
        ..Default::default()
    };
    let table_arc = Arc::new(ManagedTable::new(Arc::new(crate::bus::EventBus::new())));

    let mut query = Message::new();
    let name = Name::from_str("fantasma.lan.").unwrap();
    query.add_query(Query::query(name, RecordType::A));
    let data = query.to_bytes().unwrap();

    let resp_bytes = handle_query(
        &data,
        "127.0.0.1:12345".parse().unwrap(),
        &cfg,
        &table_arc,
        None,
    )
    .await
    .unwrap()
    .expect("Deve retornar uma resposta DNS");

    let resp = Message::from_bytes(&resp_bytes).unwrap();

    // DEVE ser NXDomain e não Forward/Refused
    assert_eq!(resp.response_code(), ResponseCode::NXDomain);

    // DEVE conter um SOA na seção de Autoridade para o Cache Negativo (RFC 2308)
    let soa_found = resp
        .name_servers()
        .iter()
        .any(|r| matches!(r.data(), RData::SOA(_)));
    assert!(soa_found, "Resposta NXDOMAIN precisa conter registro SOA");
}

#[test]
fn test_edns0_is_preserved() {
    let cfg = DnsConfig::default();
    let mut query = Message::new();
    query.add_query(Query::query(
        Name::from_str("localhost.").unwrap(),
        RecordType::A,
    ));

    // Adiciona um header EDNS simulado
    let mut extensions = Edns::new();
    extensions
        .options_mut()
        .insert(EdnsOption::Unknown(123, vec![1, 2, 3]));
    // Se usar versão nova, o Hickory pode expor: query.set_extensions(extensions);
    // Assumindo que a gambiarra do mut funciona na build:

    let query_ext = query.extensions_mut();

    if let Some(ext) = query_ext {
        *ext = extensions;
    } else {
        // If for whatever reason query_ext is None, we just put things in there
        *query_ext = Some(extensions);
    }

    // Gera a base response pra ver se reflete
    let resp = base_response(&query, &cfg);

    // O Response TEM que carregar as extensões que vieram na query
    assert!(
        resp.extensions().is_some(),
        "A resposta deve refletir o bloco EDNS0 do cliente"
    );
}
