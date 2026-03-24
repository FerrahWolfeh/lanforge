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
    rr::{Name, RData, Record, RecordType, rdata::SOA},
    serialize::binary::{BinDecodable, BinEncodable},
};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tokio::{
    io::AsyncReadExt,
    io::AsyncWriteExt,
    net::{TcpListener, UdpSocket},
};
use tracing::{debug, info};

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

pub async fn dns_service(cfg: DnsConfig, table: Arc<ManagedTable>) -> Result<()> {
    if !cfg.enabled {
        info!("Serviço DNS desabilitado na config");
        return std::future::pending().await;
    }

    let udp_sock = Arc::new(UdpSocket::bind(cfg.listen).await.context("bind UDP")?);
    let tcp_listener = TcpListener::bind(cfg.listen).await.context("bind TCP")?;

    info!(
        "Escutando DNS (UDP/TCP) em {} (upstream: {:?}, domínio: .{})",
        cfg.listen, cfg.upstream, cfg.search_domain
    );

    let cfg_arc = Arc::new(cfg);

    // Task UDP
    let udp_cfg = Arc::clone(&cfg_arc);
    let udp_table = Arc::clone(&table);
    let udp_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            if let Ok((len, src)) = udp_sock.recv_from(&mut buf).await {
                let data = buf[..len].to_vec();
                let sock = Arc::clone(&udp_sock);
                let t = Arc::clone(&udp_table);
                let c = Arc::clone(&udp_cfg);

                tokio::spawn(async move {
                    if let Ok(Some(response)) = handle_query(&data, src, &c, &t).await {
                        let _ = sock.send_to(&response, src).await;
                    }
                });
            }
        }
    });

    // Task TCP (RFC 5966)
    let tcp_cfg = Arc::clone(&cfg_arc);
    let tcp_table = Arc::clone(&table);
    let tcp_task = tokio::spawn(async move {
        loop {
            if let Ok((mut stream, src)) = tcp_listener.accept().await {
                let t = Arc::clone(&tcp_table);
                let c = Arc::clone(&tcp_cfg);

                tokio::spawn(async move {
                    let mut len_buf = [0u8; 2];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut buf = vec![0u8; len];
                    if stream.read_exact(&mut buf).await.is_err() {
                        return;
                    }

                    if let Ok(Some(response)) = handle_query(&buf, src, &c, &t).await {
                        let resp_len = (response.len() as u16).to_be_bytes();
                        let _ = stream.write_all(&resp_len).await;
                        let _ = stream.write_all(&response).await;
                    }
                });
            }
        }
    });

    let _ = tokio::join!(udp_task, tcp_task);
    Ok(())
}

// ---------------------------------------------------------------------------
// Processamento de query
// ---------------------------------------------------------------------------

async fn handle_query(
    data: &[u8],
    src: SocketAddr,
    cfg: &DnsConfig,
    table: &ManagedTable,
) -> Result<Option<Vec<u8>>> {
    let Ok(query) = Message::from_bytes(data) else {
        return Ok(None); // Dropa lixo silently
    };

    // Ignora pacotes que já são respostas (QR = 1)
    if query.message_type() != MessageType::Query {
        return Ok(None);
    }

    // RFC 1035: Query vazia -> FORMERR
    let Some(question) = query.queries().first() else {
        return Ok(Some(formerr_response(&query, cfg)?));
    };

    let qname = question.name().to_string();
    let qtype = question.query_type();

    debug!("Query de {src}: {qname} {qtype:?}");

    let hostname = normalize_name(&qname, &cfg.search_domain);

    let t = table.read().await;

    if matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
        if let Some(response) = resolve_local(&query, &hostname, qtype, cfg, &t)? {
            return Ok(Some(response));
        }
    } else if qtype == RecordType::PTR
        && let Some(response) = resolve_ptr(&query, &qname, cfg, &t)?
    {
        return Ok(Some(response));
    }

    drop(t);

    // Prevenção de Leak: Se for pro nosso domínio, mas não achou, responde NXDOMAIN.
    let is_local_domain = qname.trim_end_matches('.').ends_with(&cfg.search_domain);
    if is_local_domain {
        return Ok(Some(nxdomain_response(&query, cfg)?));
    }

    // Encaminha se tiver upstream, senão REFUSED
    if let Some(upstream) = cfg.upstream {
        forward_to_upstream(data, upstream, query.id())
            .await
            .map(Some)
    } else {
        Ok(Some(refused_response(&query, cfg)?))
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

        let v6_suffix = static_entry
            .and_then(|e| e.v6_suffix.as_ref())
            .or(device.v6_suffix.as_ref());

        if let Some(suffix) = v6_suffix {
            // CORREÇÃO AQUI: Se começa com "::", é sufixo e deve ser combinado.
            if suffix.starts_with("::") {
                let mut applied_prefixes = HashSet::<[u16; 4]>::new();

                if let Some(ula) = cfg.ula_prefix {
                    let segments = ula.segments();
                    let ula_prefix = [segments[0], segments[1], segments[2], segments[3]];
                    if applied_prefixes.insert(ula_prefix)
                        && let Some(ip) = combine_prefix_suffix(&ula_prefix, suffix)
                    {
                        classify_ip(ip);
                    }
                }

                for slaac_ip in &device.slaac {
                    let segments = slaac_ip.segments();
                    let prefix = [segments[0], segments[1], segments[2], segments[3]];
                    if applied_prefixes.insert(prefix)
                        && let Some(ip) = combine_prefix_suffix(&prefix, suffix)
                    {
                        classify_ip(ip);
                    }
                }
            } else if let Ok(ip) = suffix.parse::<Ipv6Addr>() {
                // Se não for sufixo puro, tenta ler como IP completo (ex: v6_suffix = "2001:db8::10")
                classify_ip(ip);
            }
        }

        for ip in &device.slaac {
            classify_ip(*ip);
        }

        // Correção do Bug IPv6: Retorna todos os IPs sintetizados (ULAs e GUAs)
        for ip in ulas.into_iter().chain(others.into_iter()) {
            records.push(Record::from_rdata(
                name.clone(),
                cfg.ttl,
                RData::AAAA(ip.into()),
            ));
        }
    }

    if records.is_empty() {
        return Ok(Some(empty_noerror_response(query, cfg)?));
    }

    let mut resp = base_response(query, cfg);
    resp.set_response_code(ResponseCode::NoError)
        .add_answers(records);

    Ok(Some(resp.to_bytes()?))
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

        // Correção PTR: Checa se o IP reverso corresponde a um sufixo sintetizado
        if let IpAddr::V6(target_v6) = target_ip {
            let target_segs = target_v6.segments();
            let mut prefixes = Vec::new();
            if let Some(ula) = cfg.ula_prefix {
                prefixes.push(ula.segments());
            }
            for ip in &d.slaac {
                prefixes.push(ip.segments());
            }

            let v6_suffix = table
                .static_entries
                .get(&d.mac)
                .and_then(|e| e.v6_suffix.as_ref())
                .or(d.v6_suffix.as_ref());
            if let Some(suffix) = v6_suffix
                && suffix.starts_with("::")
            {
                let clean = suffix.strip_prefix("::").unwrap_or(suffix);
                if let Ok(suf_ip) = format!("::{clean}").parse::<Ipv6Addr>() {
                    let suf_segs = suf_ip.segments();
                    if target_segs[4..] == suf_segs[4..] {
                        let t_pref = [
                            target_segs[0],
                            target_segs[1],
                            target_segs[2],
                            target_segs[3],
                        ];
                        if prefixes.iter().any(|p| p[0..4] == t_pref) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    });

    let Some(device) = device else {
        return Ok(None);
    };

    let question = query.queries().first().unwrap();
    let name = question.name().clone();

    let host = if device.hostname.is_empty() {
        format!("host-{}", device.mac.to_string().replace(':', ""))
    } else {
        device.hostname.clone()
    };

    let fqdn = format!("{}.{}.", host, cfg.search_domain);
    let ptr_name = Name::from_str(&fqdn).unwrap_or_else(|_| Name::root());

    let record = Record::from_rdata(
        name,
        cfg.ttl,
        RData::PTR(hickory_proto::rr::rdata::PTR(ptr_name)),
    );

    let mut resp = base_response(query, cfg);
    resp.set_response_code(ResponseCode::NoError)
        .add_answers(vec![record]);

    Ok(Some(resp.to_bytes()?))
}

// ---------------------------------------------------------------------------
// Forward pro upstream
// ---------------------------------------------------------------------------

async fn forward_to_upstream(data: &[u8], upstream: SocketAddr, orig_id: u16) -> Result<Vec<u8>> {
    let out = UdpSocket::bind("0.0.0.0:0").await?;
    out.send_to(data, upstream).await?;

    let mut buf = vec![0u8; 4096];
    let to = Duration::from_secs(3);
    let start = tokio::time::Instant::now();

    // Validação de segurança: Loop até bater o timeout ignorando pacotes lixo/spoofing
    while start.elapsed() < to {
        let left = to - start.elapsed();
        if let Ok(Ok((len, src))) = timeout(left, out.recv_from(&mut buf)).await
            && src == upstream
            && let Ok(resp) = Message::from_bytes(&buf[..len])
            && resp.id() == orig_id
        {
            return Ok(buf[..len].to_vec());
        }
    }
    anyhow::bail!("Timeout ou sem resposta válida do upstream")
}

// ---------------------------------------------------------------------------
// Helpers de resposta (com suporte a SOA e EDNS0)
// ---------------------------------------------------------------------------

fn base_response(query: &Message, cfg: &DnsConfig) -> Message {
    let mut resp = Message::new();
    resp.set_id(query.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_authoritative(true)
        .set_recursion_available(cfg.upstream.is_some())
        .add_queries(query.queries().to_vec());

    if let Some(edns) = query.extensions() {
        if let Some(ext) = resp.extensions_mut() {
            *ext = edns.clone(); // Your casual mem copy of death
        } else {
            let ext = resp.extensions_mut();
            *ext = Some(edns.clone()); // and make it double
        }
    }
    resp
}

fn add_soa(resp: &mut Message, cfg: &DnsConfig) {
    let name = Name::from_str(&format!("{}.", cfg.search_domain)).unwrap_or_else(|_| Name::root());
    let mname =
        Name::from_str(&format!("ns.{}.", cfg.search_domain)).unwrap_or_else(|_| Name::root());
    let rname = Name::from_str(&format!("hostmaster.{}.", cfg.search_domain))
        .unwrap_or_else(|_| Name::root());
    let soa = SOA::new(mname, rname, 1, 7200, 3600, 1209600, 3600);
    resp.add_name_server(Record::from_rdata(name, 3600, RData::SOA(soa)));
}

fn nxdomain_response(query: &Message, cfg: &DnsConfig) -> Result<Vec<u8>> {
    let mut resp = base_response(query, cfg);
    resp.set_response_code(ResponseCode::NXDomain);
    add_soa(&mut resp, cfg);
    Ok(resp.to_bytes()?)
}

fn refused_response(query: &Message, cfg: &DnsConfig) -> Result<Vec<u8>> {
    let mut resp = base_response(query, cfg);
    resp.set_response_code(ResponseCode::Refused);
    Ok(resp.to_bytes()?)
}

fn empty_noerror_response(query: &Message, cfg: &DnsConfig) -> Result<Vec<u8>> {
    let mut resp = base_response(query, cfg);
    resp.set_response_code(ResponseCode::NoError);
    add_soa(&mut resp, cfg);
    Ok(resp.to_bytes()?)
}

fn formerr_response(query: &Message, cfg: &DnsConfig) -> Result<Vec<u8>> {
    let mut resp = base_response(query, cfg);
    resp.set_response_code(ResponseCode::FormErr);
    Ok(resp.to_bytes()?)
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
        let resp_bytes =
            if let Some(resp) = handle_query(&query_bytes, src, &cfg, &table).await.unwrap() {
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
        let result = handle_query(&query_bytes, src, &cfg, &table).await;

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
            slaac: vec![],
            last_seen: SystemTime::now(),
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

        let resp_bytes = handle_query(&data, "127.0.0.1:12345".parse().unwrap(), &cfg, &table_arc)
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
}
