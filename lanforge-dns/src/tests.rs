use hickory_proto::op::{Edns, Message, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use lanforge_core::bus::{EventBus, ManagedTable};
use lanforge_core::device::{Device, IPv6State, Ipv6AddrOrSuffix};
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::DeviceTable;
use lanforge_core::state::update::DeviceUpdate;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::error::DnsError;
use crate::resolver::LocalResolver;
use crate::response::ResponseBuilder;
use crate::server::{DnsContext, handle_query};
use crate::upstream::UpstreamManager;
use crate::utils::{extract_local_hostname, parse_arpa};
use std::{net::Ipv4Addr, time::SystemTime};

// Helpers para testes que precisam de ManagedTable
fn empty_table() -> Arc<ManagedTable> {
    Arc::new(ManagedTable::new(Arc::new(EventBus::new())))
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
    table.apply_update(DeviceUpdate::V4LeaseGranted {
        mac,
        ip,
        expires: SystemTime::now() + std::time::Duration::from_secs(3600),
    });
    if !hostname.is_empty() {
        table.apply_update(DeviceUpdate::DhcpHostnameHint {
            mac,
            hostname: hostname.to_string(),
        });
    }
    table
}

// Legacy functions for tests only
// Funções legadas mantidas temporariamente para compatibilidade com testes e server.rs pré-migração.
pub fn resolve_local(
    query: &Message,
    device: &Device,
    qtype: RecordType,
    cfg: &DnsConfig,
) -> Result<Option<Vec<u8>>, DnsError> {
    // Esta função simulada é ligeiramente diferente pois o resolve_ip agora encapsula o lookup.
    // Mas para manter a assinatura antiga, criamos uma tabela fake ou apenas usamos a lógica interna.
    let table = DeviceTable::new(); // Dummy
    let resolver = LocalResolver::new(cfg, &table);
    if let Some(records) = resolver.resolve_local_with_device(query, device, qtype) {
        Ok(Some(ResponseBuilder::new(query, cfg).success(records)?))
    } else {
        Ok(Some(ResponseBuilder::new(query, cfg).empty_noerror()?))
    }
}

pub fn resolve_ptr(
    query: &Message,
    qname_str: &str,
    cfg: &DnsConfig,
    table: &DeviceTable,
) -> Result<Option<Vec<u8>>, DnsError> {
    let resolver = LocalResolver::new(cfg, table);
    let qname = Name::from_str(qname_str).unwrap_or_else(|_| Name::root());
    resolver.resolve_ptr(query, &qname)
}

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
    let device = table.get_device(&mac).unwrap();
    let result = resolve_local(&query, device, RecordType::A, &cfg).unwrap();
    let resp_bytes = result.unwrap();
    let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

    assert_eq!(resp_msg.answers()[0].name(), &name);
}

// --- parse_arpa ---

#[test]
fn parses_ipv4_arpa_correctly() {
    let ip = parse_arpa(&Name::from_str("50.1.168.192.in-addr.arpa.").unwrap()).unwrap();
    assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
}

#[test]
fn parses_ipv6_arpa_correctly() {
    let arpa =
        Name::from_str("4.3.2.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa")
            .unwrap();
    let ip = parse_arpa(&arpa).unwrap();
    assert_eq!(ip, "fd00::1234".parse::<IpAddr>().unwrap());
}

#[test]
fn invalid_arpa_returns_none() {
    assert_eq!(
        parse_arpa(&Name::from_str("invalid.in-addr.arpa").unwrap()),
        None
    );
    assert_eq!(
        parse_arpa(&Name::from_str("999.1.1.1.in-addr.arpa").unwrap()),
        None
    );
    assert_eq!(parse_arpa(&Name::from_str("google.com").unwrap()), None);
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

    let ctx = DnsContext {
        cfg,
        table,
        upstream_mgr: None,
    };
    let resp_bytes = if let Some(resp) = handle_query(&query_bytes, &ctx).await.unwrap() {
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

    let mgr = UpstreamManager::new(cfg.upstream.unwrap()).await.unwrap();
    let ctx = DnsContext {
        cfg,
        table,
        upstream_mgr: Some(mgr),
    };
    let result = handle_query(&query_bytes, &ctx).await;

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
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);

    table.apply_update(DeviceUpdate::SlaacObserved {
        mac,
        addr: "2001:db8::1".parse().unwrap(),
    });
    // Simula o sufixo estático
    let dev = table.get_device_mut(&mac).unwrap();
    dev.hostname = "test".into();
    dev.v6.push(IPv6State::Static(
        Ipv6AddrOrSuffix::parse("::beef").unwrap(),
    ));

    // CRÍTICO: Agora invocamos explicitamente o rebuild via update do bus (através do DeviceUpdate)
    // No DeviceTable "cru" de um teste unitário, chamamos rebuild_dns_indices internamente via apply_update
    // Mas aqui como mudamos o dev diretamente, precisamos rodar o rebuild
    table.apply_update(DeviceUpdate::RebuildDnsIndices);

    let mut query = Message::new();
    let name = Name::from_str("test.lan.").unwrap();
    query.add_query(Query::query(name, RecordType::AAAA));

    let device_ref = table.get_device(&mac).expect("Should resolve locally");
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

    let table_arc = Arc::new(ManagedTable::new(Arc::new(EventBus::new())));

    let mut query = Message::new();
    let name = Name::from_str("fantasma.lan.").unwrap();
    query.add_query(Query::query(name, RecordType::A));
    let data = query.to_bytes().unwrap();

    let ctx = DnsContext {
        cfg,
        table: table_arc,
        upstream_mgr: None,
    };

    let resp_bytes = handle_query(&data, &ctx)
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

    let resp = ResponseBuilder::new(&query, &cfg).base();

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
    table.apply_update(DeviceUpdate::V4LeaseGranted {
        mac,
        ip: "192.168.1.1".parse().unwrap(),
        expires: SystemTime::now() + Duration::from_secs(3600),
    });
    table.apply_update(DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: "priority-test".into(),
    });

    let dev = table.get_device_mut(&mac).unwrap();
    dev.v6
        .push(IPv6State::Slaac("2001:db8::1".parse().unwrap()));
    dev.v6.push(IPv6State::Slaac("fd00::1".parse().unwrap()));

    table.apply_update(DeviceUpdate::RebuildDnsIndices);

    let mut query = Message::new();
    let name = Name::from_str("priority-test.lan.").unwrap();
    query.add_query(Query::query(name, RecordType::ANY));

    let device_ref = table.get_device(&mac).unwrap();
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

#[test]
fn test_local_resolver_direct_api() {
    let cfg = mock_config();
    let mac = MacAddr([1, 2, 3, 4, 5, 6]);
    let table = table_with_device("direct", mac, Ipv4Addr::new(10, 10, 10, 10));

    let resolver = crate::resolver::LocalResolver::new(&cfg, &table);

    let mut query = Message::new();
    query.add_query(hickory_proto::op::Query::query(
        Name::from_str("direct.lan.").unwrap(),
        RecordType::A,
    ));

    // Test resolve_ip
    let resp_bytes = resolver
        .resolve_ip(&query, "direct", RecordType::A)
        .unwrap();
    let resp = Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp.response_code(), ResponseCode::NoError);
    assert_eq!(resp.answers().len(), 1);

    // Test resolve_ip for NXDOMAIN
    let resp_bytes = resolver
        .resolve_ip(&query, "nonexistent", RecordType::A)
        .unwrap();
    let resp = Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp.response_code(), ResponseCode::NXDomain);

    // Test resolve_ptr with Name directly
    let qname = Name::from_str("10.10.10.10.in-addr.arpa.").unwrap();
    let resp_bytes = resolver.resolve_ptr(&query, &qname).unwrap().unwrap();
    let resp = Message::from_bytes(&resp_bytes).unwrap();
    assert_eq!(resp.response_code(), ResponseCode::NoError);
}
