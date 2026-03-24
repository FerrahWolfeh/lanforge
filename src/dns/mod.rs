//! src/dns/mod.rs — Servidor DNS autoritativo da LAN
//!
//! Responde A/AAAA/PTR para dispositivos conhecidos pelo Manager e encaminha
//! todo o resto para o Unbound (ou outro resolver upstream).
//!
//! ## Papel no modelo device-first
//!
//! O DNS é um **consumidor puro** do `ManagedTable` — nunca escreve estado.
//! Ele é a voz do Manager para o resto da rede: se o Manager conhece um
//! device, o DNS sabe resolver o hostname. Se não conhece, encaminha.
//!
//! Isso significa que o Pi-hole (ou qualquer outro cliente) que perguntar
//! "quem é `solarium.lan`?" receberá a resposta imediatamente após o
//! Manager aprender o device via DHCP ou NDP — sem reload, sem arquivo
//! de hosts, sem latência de propagação.
//!
//! ## Fluxo por query
//!
//! ```text
//! Query UDP recebida
//!     └─► normalize_name()         remove sufixo do search_domain
//!               │
//!               ▼
//!     ManagedTable::read()         snapshot de leitura do Manager
//!               │
//!       ┌───────┴───────┐
//!       ▼               ▼
//!   A/AAAA/ANY        PTR
//!   resolve_local()   resolve_ptr()
//!       │               │
//!       └───────┬───────┘
//!               │ encontrou?
//!            sim│         não
//!               ▼         ▼
//!          responde    forward_to_upstream()
//! ```

use anyhow::{Context, Result};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{Name, RData, Record, RecordType},
    serialize::binary::{BinDecodable, BinEncodable},
};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::bus::ManagedTable;
use crate::state::DeviceTable;

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    /// Upstream resolver (ex: Unbound em 127.0.0.1:5335).
    /// Se `None`, queries não-locais retornam REFUSED.
    pub upstream: Option<SocketAddr>,
    pub search_domain: String,
    pub ula_prefix: Option<Ipv6Addr>,
    pub ttl: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "0.0.0.0:53".parse().unwrap(),
            upstream: None,
            search_domain: "lan".into(),
            ula_prefix: None,
            ttl: 60,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point da task
// ---------------------------------------------------------------------------

/// Inicia o serviço DNS. Invocar via `tokio::spawn` + supervisor.
///
/// Recebe `Arc<ManagedTable>` — acesso read-only ao estado do Manager.
/// Não publica eventos, não escreve estado.
pub async fn dns_service(cfg: DnsConfig, table: Arc<ManagedTable>) -> Result<()> {
    if !cfg.enabled {
        info!("Serviço DNS desabilitado na config");
        return std::future::pending().await;
    }

    let sock = Arc::new(
        UdpSocket::bind(cfg.listen)
            .await
            .with_context(|| format!("falha ao bindar DNS em {}", cfg.listen))?,
    );

    info!(
        "Escutando em {} (upstream: {:?}, domínio: .{})",
        cfg.listen, cfg.upstream, cfg.search_domain
    );

    let mut buf = vec![0u8; 4096];

    loop {
        match sock.recv_from(&mut buf).await {
            Ok((len, src)) => {
                let data = buf[..len].to_vec();
                let sock = Arc::clone(&sock);
                let table = Arc::clone(&table);
                let cfg = cfg.clone();

                tokio::spawn(async move {
                    match handle_query(&data, src, &cfg, &table).await {
                        Ok(response) => {
                            if let Err(e) = sock.send_to(&response, src).await {
                                warn!("Erro ao enviar resposta para {src}: {e}");
                            }
                        }
                        Err(e) => warn!("Erro ao processar query de {src}: {e:#}"),
                    }
                });
            }
            Err(e) => warn!("Erro de recv: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Processamento de query
// ---------------------------------------------------------------------------

async fn handle_query(
    data: &[u8],
    src: SocketAddr,
    cfg: &DnsConfig,
    table: &ManagedTable,
) -> Result<Vec<u8>> {
    let query = Message::from_bytes(data).context("falha ao parsear query DNS")?;

    let Some(question) = query.queries().first() else {
        return nxdomain_response(&query);
    };

    let qname = question.name().to_string();
    let qtype = question.query_type();

    debug!("Query de {src}: {qname} {qtype:?}");

    let hostname = normalize_name(&qname, &cfg.search_domain);

    // Snapshot de leitura — libera o lock antes de qualquer I/O de rede
    let t = table.read().await;

    if matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
        if let Some(response) = resolve_local(&query, &hostname, qtype, cfg, &t)? {
            debug!("Respondido localmente (A/AAAA): {hostname}");
            return Ok(response);
        }
    } else if qtype == RecordType::PTR
        && let Some(response) = resolve_ptr(&query, &qname, cfg, &t)?
    {
        debug!("Respondido localmente (PTR): {qname}");
        return Ok(response);
    }

    drop(t); // Libera o lock antes do forward

    if let Some(upstream) = cfg.upstream {
        forward_to_upstream(data, upstream).await
    } else {
        debug!("Upstream não configurado e query não é local: {qname}. Retornando REFUSED.");
        refused_response(&query)
    }
}

// ---------------------------------------------------------------------------
// Resolução local — Forward (Nome → IP)
// ---------------------------------------------------------------------------

fn resolve_local(
    query: &Message,
    hostname: &str,
    qtype: RecordType,
    cfg: &DnsConfig,
    table: &DeviceTable,
) -> Result<Option<Vec<u8>>> {
    let device = table.devices.values().find(|d| {
        let has_name = !d.hostname.is_empty() && d.hostname.eq_ignore_ascii_case(hostname);
        let fallback = format!("host-{}", d.mac.to_string().replace(':', ""));
        has_name || fallback.eq_ignore_ascii_case(hostname)
    });

    let Some(device) = device else {
        return Ok(None);
    };

    let question = query.queries().first().expect("Query validada");
    let name = question.name().clone();
    let mut records: Vec<Record> = Vec::new();

    let static_entry = table.static_entries.get(&device.mac);

    if matches!(qtype, RecordType::A | RecordType::ANY) {
        // Estático tem precedência sobre lease dinâmico
        let v4_ip = static_entry
            .and_then(|e| e.v4_ip)
            .or(device.v4_static)
            .or_else(|| device.v4.as_ref().map(|l| l.ip));

        if let Some(ip) = v4_ip {
            records.push(Record::from_rdata(
                name.clone(),
                cfg.ttl,
                RData::A(ip.into()),
            ));
        }
    }

    if matches!(qtype, RecordType::AAAA | RecordType::ANY) {
        let mut ulas = Vec::new();
        let mut others = Vec::new();

        let mut classify_ip = |ip: Ipv6Addr| {
            if (ip.segments()[0] & 0xfe00) == 0xfc00 {
                ulas.push(ip);
            } else {
                others.push(ip);
            }
        };

        if let Some(v6) = &device.v6 {
            classify_ip(v6.ip);
        }

        // Se houver sufixo estático, ele gera um endereço ULA que tem precedência
        let v6_suffix = static_entry
            .and_then(|e| e.v6_suffix.as_ref())
            .or(device.v6_suffix.as_ref());

        if let Some(suffix) = v6_suffix {
            // Se o sufixo for um IP completo, usamos ele diretamente
            if let Ok(ip) = suffix.parse::<Ipv6Addr>() {
                classify_ip(ip);
            } else if suffix.starts_with("::") {
                // Se for um sufixo (ex: ::1234), tentamos combinar com os prefixos conhecidos
                let mut applied_prefixes = HashSet::<[u16; 4]>::new();

                // 1. Prefixo ULA da configuração (mais estável)
                if let Some(ula) = cfg.ula_prefix {
                    let segments = ula.segments();
                    let ula_prefix = [segments[0], segments[1], segments[2], segments[3]];
                    if applied_prefixes.insert(ula_prefix)
                        && let Some(ip) = combine_prefix_suffix(&ula_prefix, suffix)
                    {
                        classify_ip(ip);
                    }
                }

                // 2. Prefixos GUA/ULA aprendidos via SLAAC (dinâmicos)
                for slaac_ip in &device.slaac {
                    let segments = slaac_ip.segments();
                    let prefix = [segments[0], segments[1], segments[2], segments[3]];
                    if applied_prefixes.insert(prefix)
                        && let Some(ip) = combine_prefix_suffix(&prefix, suffix)
                    {
                        classify_ip(ip);
                    }
                }
            }
        }

        for ip in &device.slaac {
            classify_ip(*ip);
        }

        let best_ips = if ulas.is_empty() { others } else { ulas };

        for ip in best_ips {
            records.push(Record::from_rdata(
                name.clone(),
                cfg.ttl,
                RData::AAAA(ip.into()),
            ));
        }
    }

    if records.is_empty() {
        return Ok(Some(empty_noerror_response(query)?));
    }

    let mut resp = Message::new();
    resp.set_id(query.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_authoritative(true)
        .set_response_code(ResponseCode::NoError)
        .add_queries(query.queries().to_vec())
        .add_answers(records);

    Ok(Some(
        resp.to_bytes().context("falha serializar resposta local")?,
    ))
}

// ---------------------------------------------------------------------------
// Resolução local — Reversa (IP → Nome)
// ---------------------------------------------------------------------------

fn resolve_ptr(
    query: &Message,
    qname: &str,
    cfg: &DnsConfig,
    table: &DeviceTable,
) -> Result<Option<Vec<u8>>> {
    let Some(target_ip) = parse_arpa_name(qname) else {
        return Ok(None);
    };

    let device = table.devices.values().find(|d| {
        if let Some(v4) = &d.v4
            && target_ip == v4.ip
        {
            return true;
        }
        if let Some(stat) = table.static_entries.get(&d.mac)
            && let Some(stat_v4) = stat.v4_ip
            && target_ip == stat_v4
        {
            return true;
        }
        if let Some(v4_static) = d.v4_static
            && IpAddr::V4(v4_static) == target_ip
        {
            return true;
        }
        if let Some(v6) = &d.v6
            && target_ip == v6.ip
        {
            return true;
        }
        if d.slaac.iter().any(|&ip| IpAddr::V6(ip) == target_ip) {
            return true;
        }
        false
    });

    let Some(device) = device else {
        return Ok(None);
    };

    let question = query.queries().first().expect("Query validada");
    let name = question.name().clone();

    let host = if device.hostname.is_empty() {
        format!("host-{}", device.mac.to_string().replace(':', ""))
    } else {
        device.hostname.clone()
    };

    let fqdn = format!("{}.{}.", host, cfg.search_domain);
    let ptr_name =
        Name::from_str(&fqdn).unwrap_or_else(|_| Name::from_str("invalid.lan.").unwrap());

    let record = Record::from_rdata(
        name,
        cfg.ttl,
        RData::PTR(hickory_proto::rr::rdata::PTR(ptr_name)),
    );

    let mut resp = Message::new();
    resp.set_id(query.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_authoritative(true)
        .set_response_code(ResponseCode::NoError)
        .add_queries(query.queries().to_vec())
        .add_answers(vec![record]);

    Ok(Some(
        resp.to_bytes()
            .context("falha serializar resposta PTR local")?,
    ))
}

// ---------------------------------------------------------------------------
// Forward pro upstream
// ---------------------------------------------------------------------------

async fn forward_to_upstream(data: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let out = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("bind socket upstream")?;

    out.send_to(data, upstream)
        .await
        .context("send para upstream")?;

    let mut buf = vec![0u8; 4096];
    let (len, _) = timeout(Duration::from_secs(3), out.recv_from(&mut buf))
        .await
        .context("timeout esperando resposta do upstream")?
        .context("recv do upstream")?;

    Ok(buf[..len].to_vec())
}

// ---------------------------------------------------------------------------
// Helpers de resposta
// ---------------------------------------------------------------------------

fn nxdomain_response(query: &Message) -> Result<Vec<u8>> {
    let mut resp = Message::new();
    resp.set_id(query.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_response_code(ResponseCode::NXDomain)
        .add_queries(query.queries().to_vec());
    resp.to_bytes().context("serializar NXDOMAIN")
}

fn refused_response(query: &Message) -> Result<Vec<u8>> {
    let mut resp = Message::new();
    resp.set_id(query.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_response_code(ResponseCode::Refused)
        .add_queries(query.queries().to_vec());
    resp.to_bytes().context("serializar REFUSED")
}

fn empty_noerror_response(query: &Message) -> Result<Vec<u8>> {
    let mut resp = Message::new();
    resp.set_id(query.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_response_code(ResponseCode::NoError)
        .add_queries(query.queries().to_vec());
    resp.to_bytes().context("serializar NOERROR vazio")
}

fn normalize_name(name: &str, search_domain: &str) -> String {
    let s = name.trim_end_matches('.');
    let suffix = format!(".{search_domain}");
    s.strip_suffix(&suffix).unwrap_or(s).to_lowercase()
}

fn parse_arpa_name(name: &str) -> Option<IpAddr> {
    let name = name.trim_end_matches('.').to_lowercase();

    if let Some(v4_part) = name.strip_suffix(".in-addr.arpa") {
        let parts: Vec<&str> = v4_part.split('.').collect();
        if parts.len() == 4
            && let (Ok(a), Ok(b), Ok(c), Ok(d)) = (
                parts[3].parse::<u8>(),
                parts[2].parse::<u8>(),
                parts[1].parse::<u8>(),
                parts[0].parse::<u8>(),
            )
        {
            return Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
        }
    } else if let Some(v6_part) = name.strip_suffix(".ip6.arpa") {
        let parts: Vec<&str> = v6_part.split('.').collect();
        if parts.len() == 32 {
            let mut hex = String::with_capacity(39);
            for (i, p) in parts.into_iter().rev().enumerate() {
                hex.push_str(p);
                if i % 4 == 3 && i != 31 {
                    hex.push(':');
                }
            }
            if let Ok(ipv6) = hex.parse::<Ipv6Addr>() {
                return Some(IpAddr::V6(ipv6));
            }
        }
    }
    None
}

fn combine_prefix_suffix(prefix_segs: &[u16], suffix: &str) -> Option<Ipv6Addr> {
    let clean_suffix = suffix.strip_prefix("::").unwrap_or(suffix);
    let suffix_ip: Ipv6Addr = format!("::{clean_suffix}").parse().ok()?;
    let suf_segs = suffix_ip.segments();

    Some(Ipv6Addr::new(
        prefix_segs[0],
        prefix_segs[1],
        prefix_segs[2],
        prefix_segs[3],
        suf_segs[4],
        suf_segs[5],
        suf_segs[6],
        suf_segs[7],
    ))
}

// ---------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::EventBus;
    use crate::state::{Device, DeviceTable, MacAddr, V4Lease};
    use std::{net::Ipv4Addr, time::SystemTime};

    // Helpers para testes que precisam de ManagedTable
    fn empty_table() -> Arc<ManagedTable> {
        Arc::new(ManagedTable::new(Arc::new(EventBus::new())))
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
                slaac: vec![],
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
        let resp_bytes = handle_query(&query_bytes, src, &cfg, &table).await.unwrap();
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
        let result = handle_query(&query_bytes, src, &cfg, &table).await;

        match result {
            Err(e) => {
                let err_str = format!("{e:#}");
                assert!(err_str.contains("timeout") || err_str.contains("upstream"));
            }
            Ok(resp_bytes) => {
                let resp_msg = Message::from_bytes(&resp_bytes).unwrap();
                assert_ne!(resp_msg.response_code(), ResponseCode::Refused);
            }
        }
    }

    #[tokio::test]
    async fn test_resolve_local_v6_suffix_merging() {
        let ula = "fd00::".parse::<Ipv6Addr>().unwrap();
        let cfg = DnsConfig {
            ula_prefix: Some(ula),
            ..Default::default()
        };
        let mut table = DeviceTable::new();
        let mac = MacAddr([1, 2, 3, 4, 5, 6]);
        let dev = table.get_or_insert(mac);
        dev.hostname = "test".to_string();
        dev.v6_suffix = Some("::beef".to_string());
        dev.slaac = vec!["2001:db8::1".parse().unwrap()];

        let mut query = Message::new();
        let name = Name::from_str("test.lan.").unwrap();
        query.add_query(hickory_proto::op::Query::query(name, RecordType::AAAA));

        let res_bytes = resolve_local(&query, "test", RecordType::AAAA, &cfg, &table)
            .unwrap()
            .expect("Should resolve");

        let res = Message::from_bytes(&res_bytes).expect("Should parse message");
        let answers = res.answers();
        assert!(answers.len() >= 2);

        let ips: HashSet<Ipv6Addr> = answers
            .iter()
            .filter_map(|r: &Record| {
                let data = r.data();
                if let RData::AAAA(ip) = data {
                    Some((*ip).into())
                } else {
                    None
                }
            })
            .collect();

        assert!(ips.contains(&"fd00::beef".parse().unwrap()));
        assert!(ips.contains(&"2001:db8::beef".parse().unwrap()));
    }
}
