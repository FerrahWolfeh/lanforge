use hickory_proto::op::{Edns, Message, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::bus::{EventBus, ManagedTable};
use crate::device::{Device, IPv4State, IPv6State, Ipv6AddrOrSuffix, MacAddr, Origin, V4Lease};
use crate::dns::resolver::{resolve_local, resolve_ptr};
use crate::dns::response::base_response;
use crate::dns::server::handle_query;
use crate::dns::upstream::UpstreamManager;
use crate::dns::utils::{extract_local_hostname, parse_arpa};
use crate::state::DeviceTable;
use std::{net::Ipv4Addr, time::SystemTime};

// Helpers para testes que precisam de ManagedTable
fn empty_table() -> Arc<ManagedTable> {
    Arc::new(ManagedTable::new(Arc::new(EventBus::new())))
}

// Helper para gerar um device mock
fn mock_device(mac_bytes: [u8; 6], host: &str) -> Device {
    let mac = MacAddr(mac_bytes);
    Device {
        hostname: host.to_string(),
        mac,
        origin: Origin::Dynamic,
        managed_at: None,
        duid: None,
        v4: IPv4State::None,
        v6: Vec::new(),
        v6_prefixes: Vec::new(),
        seen_v4: Vec::new(),
        last_seen: SystemTime::now(),
    }
}

// Helper para gerar um DnsConfig pronto para os testes do Fast Path
fn mock_config() -> DnsConfig {
    DnsConfig {
        search_domain: "lan".to_string(),
        search_labels: vec![b"lan".to_vec()],
        ..Default::default()
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
            origin: Origin::Dynamic,
            managed_at: None,
            duid: None,
            v4: IPv4State::Dynamic(V4Lease {
                ip,
                expires: SystemTime::now() + std::time::Duration::from_secs(3600),
            }),
            v6: Vec::new(),
            v6_prefixes: Vec::new(),
            seen_v4: Vec::new(),
            last_seen: SystemTime::now(),
        },
    );
    // CRÍTICO: Constrói os índices O(1) para o mock, senão os testes do resolve_ptr e name_index falham
    table.rebuild_dns_indices();
    table
}

// --- extração de hostnames (O novo normalize_name sem alocação) ---

#[test]
fn test_extract_local_hostname_matches_domain() {
    let labels = vec![b"lan".to_vec()];

    // Sucesso
    let name = Name::from_str("archie.lan.").unwrap();
    assert_eq!(extract_local_hostname(&name, &labels), Some("archie"));

    // Falha: subdomínio não deve ser capturado como host local simples
    let name_sub = Name::from_str("sub.archie.lan.").unwrap();
    assert_eq!(extract_local_hostname(&name_sub, &labels), None);

    // Falha: Domínio externo
    let name_ext = Name::from_str("google.com.").unwrap();
    assert_eq!(extract_local_hostname(&name_ext, &labels), None);
}

// --- resolve_local ---

#[test]
fn resolve_local_matches_question_name_exactly() {
    let cfg = mock_config();
    let mac = MacAddr::from_slice(&[0u8; 6]).unwrap();
    let table = table_with_device("solarium", mac, Ipv4Addr::new(192, 168, 0, 2));

    let mut query = Message::new();
    let name = Name::from_str("solarium.lan.").unwrap();
    query.add_query(hickory_proto::op::Query::query(name.clone(), RecordType::A));

    // Agora passamos a referência do device diretamente (simulando a saída do fast path)
    let device = table.devices.get(&mac).unwrap();
    let result = resolve_local(&query, device, RecordType::A, &cfg).unwrap();
    let resp_bytes = result.unwrap();
    let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

    assert_eq!(resp_msg.answers()[0].name(), &name);
}

// --- parse_arpa ---

#[test]
fn parses_ipv4_arpa_correctly() {
    let ip = parse_arpa("50.1.168.192.in-addr.arpa.").unwrap();
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
}

#[test]
fn parses_ipv6_arpa_correctly() {
    let arpa = "4.3.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa";
    let ip = parse_arpa(arpa).unwrap();
    assert_eq!(ip, "fd00::1234".parse::<IpAddr>().unwrap());
}

#[test]
fn invalid_arpa_returns_none() {
    assert_eq!(parse_arpa("invalid.in-addr.arpa"), None);
    assert_eq!(parse_arpa("999.1.1.1.in-addr.arpa"), None);
    assert_eq!(parse_arpa("google.com"), None);
}

// --- resolve_ptr ---

#[test]
fn resolve_ptr_returns_correct_hostname() {
    let cfg = mock_config();
    let mac = MacAddr::from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).unwrap();
    let table = table_with_device("solarium", mac, Ipv4Addr::new(192, 168, 0, 50));

    let mut query = Message::new();
    let qname = Name::from_str("50.0.168.192.in-addr.arpa.").unwrap();
    query.add_query(hickory_proto::op::Query::query(qname, RecordType::PTR));

    let result = resolve_ptr(&query, "50.0.168.192.in-addr.arpa", &cfg, &table).unwrap();
    let resp_bytes = result.expect("Deveria ter encontrado o dispositivo via ip_index O(1)");
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
    let cfg = mock_config();
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
    let mut cfg = mock_config();
    cfg.upstream = None;
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
    let mut cfg = mock_config();
    cfg.upstream = Some("1.2.3.4:53".parse().unwrap());
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
    let mut cfg = mock_config();
    cfg.ula_prefix = Some(ula);

    let mut table = DeviceTable::new();
    let mut dev = mock_device([1, 2, 3, 4, 5, 6], "test");
    dev.v6.push(IPv6State::Static(
        Ipv6AddrOrSuffix::parse("::beef").unwrap(),
    ));
    dev.v6
        .push(IPv6State::Slaac("2001:db8::1".parse().unwrap()));
    table.devices.insert(dev.mac, dev.clone());

    // CRÍTICO: Atualiza os índices do mock
    table.rebuild_dns_indices();

    let mut query = Message::new();
    let name = Name::from_str("test.lan.").unwrap();
    query.add_query(Query::query(name, RecordType::AAAA));

    let device_ref = table.devices.get(&dev.mac).unwrap();
    let res_bytes = resolve_local(&query, device_ref, RecordType::AAAA, &cfg)
        .unwrap()
        .expect("Should resolve locally");

    let res = Message::from_bytes(&res_bytes).unwrap();
    let answers = res.answers();

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
    let mut cfg = mock_config();
    cfg.upstream = Some("127.0.0.1:9999".parse().unwrap());

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
    let cfg = mock_config();
    let mut query = Message::new();
    query.add_query(Query::query(
        Name::from_str("localhost.").unwrap(),
        RecordType::A,
    ));

    let mut extensions = Edns::new();
    extensions
        .options_mut()
        .insert(EdnsOption::Unknown(123, vec![1, 2, 3]));

    let query_ext = query.extensions_mut();

    if let Some(ext) = query_ext {
        *ext = extensions;
    } else {
        *query_ext = Some(extensions);
    }

    let resp = base_response(&query, &cfg);

    assert!(
        resp.extensions().is_some(),
        "A resposta deve refletir o bloco EDNS0 do cliente"
    );
}

#[tokio::test]
async fn test_dns_cache_hit() {
    let mut cfg = mock_config();
    cfg.upstream = Some("1.2.3.4:53".parse().unwrap());

    let mut query = Message::new();
    let name = Name::from_str("example.com.").unwrap();
    query.add_query(hickory_proto::op::Query::query(name, RecordType::A));
    let query_bytes = query.to_bytes().unwrap();

    let mgr = UpstreamManager::new(cfg.upstream.unwrap()).await.unwrap();

    // Simular uma resposta no cache
    let mut resp = Message::new();
    resp.set_id(query.id());
    resp.add_answer(Record::from_rdata(
        query.queries()[0].name().clone(),
        60,
        RData::A(Ipv4Addr::new(9, 9, 9, 9).into()),
    ));
    let resp_bytes = resp.to_bytes().unwrap();

    mgr.cache.insert(&query, &resp, resp_bytes.clone());

    // A chamada ao forward deve retornar do cache sem tentar o upstream (que daria timeout)
    let result = mgr
        .forward(&query_bytes, cfg.upstream.unwrap())
        .await
        .unwrap();
    let resp_msg = Message::from_bytes(&result).unwrap();

    assert_eq!(
        resp_msg.answers()[0].data().as_a().unwrap(),
        &Ipv4Addr::new(9, 9, 9, 9).into()
    );
}

#[tokio::test]
async fn test_tcp_fallback_trigger() {
    let mut cfg = mock_config();
    let upstream_addr = "127.0.0.1:5353".parse().unwrap();
    cfg.upstream = Some(upstream_addr);

    let mgr = UpstreamManager::new(upstream_addr).await.unwrap();

    let mut query = Message::new();
    query.add_query(hickory_proto::op::Query::query(
        Name::from_str("large.zone.").unwrap(),
        RecordType::A,
    ));
    let query_bytes = query.to_bytes().unwrap();

    // Spawn a task to call forward
    let mgr_clone = Arc::new(mgr); // Clone Arc for the spawned task
    let mgr_for_spawn = Arc::clone(&mgr_clone);
    let handle =
        tokio::spawn(async move { mgr_for_spawn.forward(&query_bytes, upstream_addr).await });

    // Wait a bit for forward to insert into pending
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Injetar uma resposta truncada no canal de resposta UDP
    let mut truncated_resp = Message::new();
    truncated_resp.set_id(1); // O internal_id deve ser 1 na primeira query
    truncated_resp.set_truncated(true);
    let tr_bytes = truncated_resp.to_bytes().unwrap();

    let tx = {
        let mut pending = mgr_clone.pending.lock().unwrap(); // Use mgr_clone here
        pending
            .remove(&1)
            .expect("Deveria haver uma query pendente com ID 1")
    };

    let _ = tx.send(tr_bytes);

    // O forward deve perceber o TC e tentar o TCP, o que deve falhar com Connect Error
    let result = handle.await.unwrap();

    match result {
        Err(e) => {
            let err_str = format!("{e:#}").to_lowercase();
            // Deve ter tentado TCP e falhado (porque não há servidor)
            assert!(
                err_str.contains("tcp") || err_str.contains("connect"),
                "Deveria ter tentado TCP: {err_str}"
            );
        }
        Ok(_) => panic!("Deveria ter falhado ao tentar TCP num servidor inexistente"),
    }
}

#[test]
fn test_resolve_local_priority_ordering() {
    let mut cfg = mock_config();
    cfg.ula_prefix = Some("fd00::".parse().unwrap());

    let mut table = DeviceTable::new();
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);
    let mut dev = mock_device(mac.0, "priority-test");
    dev.v4 = IPv4State::Static("192.168.1.1".parse().unwrap());
    dev.v6 = vec![
        IPv6State::Slaac("2001:db8::1".parse().unwrap()),
        IPv6State::Slaac("fd00::1".parse().unwrap()),
    ];
    table.devices.insert(mac, dev);
    table.rebuild_dns_indices();

    let mut query = Message::new();
    let name = Name::from_str("priority-test.lan.").unwrap();
    query.add_query(Query::query(name, RecordType::ANY));

    let device_ref = table.devices.get(&mac).unwrap();
    let res_bytes = resolve_local(&query, device_ref, RecordType::ANY, &cfg)
        .unwrap()
        .expect("Should resolve locally");

    let res = Message::from_bytes(&res_bytes).unwrap();
    let answers = res.answers();

    // Order should be: ULA (AAAA fd00::1) > IPv4 (A 192.168.1.1) > GUA (AAAA 2001:db8::1)
    assert!(answers.len() >= 3);

    // Check first answer is ULA
    if let RData::AAAA(ip) = answers[0].data() {
        assert_eq!(Ipv6Addr::from(*ip), "fd00::1".parse::<Ipv6Addr>().unwrap());
    } else {
        panic!(
            "First answer should be ULA (AAAA), got {:?}",
            answers[0].data()
        );
    }

    // Check second answer is IPv4
    if let RData::A(ip) = answers[1].data() {
        assert_eq!(
            Ipv4Addr::from(*ip),
            "192.168.1.1".parse::<Ipv4Addr>().unwrap()
        );
    } else {
        panic!(
            "Second answer should be IPv4 (A), got {:?}",
            answers[1].data()
        );
    }

    // Check third answer is GUA
    if let RData::AAAA(ip) = answers[2].data() {
        assert_eq!(
            Ipv6Addr::from(*ip),
            "2001:db8::1".parse::<Ipv6Addr>().unwrap()
        );
    } else {
        panic!(
            "Third answer should be GUA (AAAA), got {:?}",
            answers[2].data()
        );
    }
}
