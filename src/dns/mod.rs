//! src/dns/mod.rs — Servidor DNS mínimo da LAN
//!
//! Responde A/AAAA/PTR para dispositivos da DeviceTable e encaminha
//! todo o resto para o Unbound (ou outro resolver upstream).
//!
//! Fluxo por query:
//!   1. Parse da query
//!   2. Normaliza o nome (remove sufixo do search_domain se presente)
//!   3. Busca na DeviceTable — se achar, responde direto
//!   4. Se não achar, encaminha pro upstream e devolve a resposta intacta

use anyhow::{Context, Result};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{Name, RData, Record, RecordType},
    serialize::binary::{BinDecodable, BinEncodable},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::state::DeviceTable;

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub enabled: bool,
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
    pub search_domain: String,
    pub ttl: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            enabled: true,
            listen: "0.0.0.0:53".parse().unwrap(),
            upstream: "127.0.0.1:5335".parse().unwrap(),
            search_domain: "lan".into(),
            ttl: 60,
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point da task
// ---------------------------------------------------------------------------

pub async fn dns_service(cfg: DnsConfig, table: Arc<RwLock<DeviceTable>>) -> Result<()> {
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
        "Escutando em {} (upstream: {}, domínio: .{})",
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
    table: &Arc<RwLock<DeviceTable>>,
) -> Result<Vec<u8>> {
    let query = Message::from_bytes(data).context("falha ao parsear query DNS")?;

    let Some(question) = query.queries().first() else {
        return nxdomain_response(&query);
    };

    let qname = question.name().to_string();
    let qtype = question.query_type();

    debug!("Query de {src}: {qname} {qtype:?}");

    let hostname = normalize_name(&qname, &cfg.search_domain);

    let t = table.read().await;

    // Intercepta A, AAAA ou ANY (Resolução Direta)
    if matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
        if let Some(response) = resolve_local(&query, &hostname, qtype, cfg, &t)? {
            debug!("Respondido localmente (A/AAAA): {hostname}");
            return Ok(response);
        }
    }
    // Intercepta PTR (Resolução Reversa)
    else if qtype == RecordType::PTR
        && let Some(response) = resolve_ptr(&query, &qname, cfg, &t)?
    {
        debug!("Respondido localmente (PTR): {qname}");
        return Ok(response);
    }

    drop(t); // Libera o lock de leitura da tabela antes do forward

    forward_to_upstream(data, cfg.upstream).await
}

// ---------------------------------------------------------------------------
// Resolução local (Nome -> IP)
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
        let v4_ip = device
            .v4
            .as_ref()
            .map(|l| l.ip)
            .or_else(|| static_entry.and_then(|e| e.v4_ip));

        if let Some(ip) = v4_ip {
            records.push(Record::from_rdata(
                name.clone(),
                cfg.ttl,
                RData::A(ip.into()),
            ));
        }
    }

    if matches!(qtype, RecordType::AAAA | RecordType::ANY) {
        if let Some(v6) = &device.v6 {
            records.push(Record::from_rdata(
                name.clone(),
                cfg.ttl,
                RData::AAAA(v6.ip.into()),
            ));
        }
        for slaac_ip in &device.slaac {
            records.push(Record::from_rdata(
                name.clone(),
                cfg.ttl,
                RData::AAAA((*slaac_ip).into()),
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
// Resolução local Reversa (IP -> Nome)
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
        // Checa lease dinâmico v4
        if let Some(v4) = &d.v4
            && target_ip == v4.ip
        {
            return true;
        }
        // Checa entrada estática v4
        if let Some(stat) = table.static_entries.get(&d.mac)
            && let Some(stat_v4) = stat.v4_ip
            && target_ip == stat_v4
        {
            return true;
        }
        // Checa lease dinâmico v6
        if let Some(v6) = &d.v6
            && target_ip == v6.ip
        {
            return true;
        }
        // Checa SLAAC
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

    // Constrói o nome que será devolvido (usando a mesma lógica de fallback)
    let host = if !device.hostname.is_empty() {
        device.hostname.clone()
    } else {
        format!("host-{}", device.mac.to_string().replace(':', ""))
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
    let suffix = format!(".{}", search_domain);
    s.strip_suffix(&suffix).unwrap_or(s).to_lowercase()
}

// ---------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Device, MacAddr, V4Lease};
    use std::{net::Ipv4Addr, time::SystemTime};

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

    #[test]
    fn resolve_local_matches_question_name_exactly() {
        use hickory_proto::rr::Name;
        use std::str::FromStr;

        let cfg = DnsConfig::default();
        let mut table = DeviceTable::new();
        let mac = MacAddr::from_slice(&[0u8; 6]).unwrap();
        table.devices.insert(
            mac,
            Device {
                hostname: "solarium".into(),
                mac,
                is_static: false,
                duid: None,
                v4: Some(V4Lease {
                    ip: Ipv4Addr::new(192, 168, 0, 2),
                    expires: SystemTime::now(),
                }),
                v6: None,
                slaac: vec![],
                last_seen: SystemTime::now(),
            },
        );

        let mut query = Message::new();
        let name = Name::from_str("solarium.").unwrap();
        query.add_query(hickory_proto::op::Query::query(name.clone(), RecordType::A));

        let result = resolve_local(&query, "solarium", RecordType::A, &cfg, &table).unwrap();
        let resp_bytes = result.unwrap();
        let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

        assert_eq!(resp_msg.answers()[0].name(), &name);
    }

    #[test]
    fn parses_ipv4_arpa_correctly() {
        let ip = parse_arpa_name("50.1.168.192.in-addr.arpa.").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)));
    }

    #[test]
    fn parses_ipv6_arpa_correctly() {
        // fd00::1234
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
    #[test]
    fn resolve_ptr_returns_correct_hostname() {
        use hickory_proto::rr::Name;
        use std::str::FromStr;

        let cfg = DnsConfig::default();
        let mut table = DeviceTable::new();
        let mac = MacAddr::from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).unwrap();

        // Cadastra o solarium com IP 192.168.0.50
        table.devices.insert(
            mac,
            Device {
                hostname: "solarium".into(),
                mac,
                is_static: false,
                duid: None,
                v4: Some(V4Lease {
                    ip: Ipv4Addr::new(192, 168, 0, 50),
                    expires: SystemTime::now(),
                }),
                v6: None,
                slaac: vec![],
                last_seen: SystemTime::now(),
            },
        );

        // Finge que o Pi-hole mandou um "dig -x 192.168.0.50"
        let mut query = Message::new();
        let arpa_string = "50.0.168.192.in-addr.arpa.";
        let qname = Name::from_str(arpa_string).unwrap();
        query.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::PTR,
        ));

        // Roda a resolução
        let result = resolve_ptr(&query, "50.0.168.192.in-addr.arpa", &cfg, &table).unwrap();

        let resp_bytes = result.expect("Deveria ter encontrado o dispositivo na tabela");
        let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

        // Valida se a resposta aponta para "solarium.lan."
        assert_eq!(resp_msg.answers().len(), 1);

        let rdata = resp_msg.answers()[0].data();

        if let Some(ptr_name) = rdata.as_ptr() {
            // O fallback tira os dois pontos do MAC e anexa o search_domain
            assert_eq!(ptr_name.to_utf8(), "solarium.lan.");
        } else {
            panic!("O RData retornado não é do tipo PTR");
        }
    }

    #[test]
    fn resolve_ptr_uses_mac_fallback_if_no_hostname() {
        use hickory_proto::rr::Name;
        use std::str::FromStr;

        let cfg = DnsConfig::default();
        let mut table = DeviceTable::new();
        // Um MAC fácil de mapear visualmente
        let mac = MacAddr::from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]).unwrap();

        table.devices.insert(
            mac,
            Device {
                hostname: "".into(), // Hostname vazio para forçar o fallback
                mac,
                is_static: false,
                duid: None,
                v4: Some(V4Lease {
                    ip: Ipv4Addr::new(10, 0, 0, 5),
                    expires: SystemTime::now(),
                }),
                v6: None,
                slaac: vec![],
                last_seen: SystemTime::now(),
            },
        );

        let mut query = Message::new();
        let qname = Name::from_str("5.0.0.10.in-addr.arpa.").unwrap();
        query.add_query(hickory_proto::op::Query::query(
            qname.clone(),
            RecordType::PTR,
        ));

        let result = resolve_ptr(&query, "5.0.0.10.in-addr.arpa", &cfg, &table).unwrap();

        let resp_bytes = result.expect("Deveria ter retornado uma resposta");
        let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

        let rdata = resp_msg.answers()[0].data();

        if let Some(ptr_name) = rdata.as_ptr() {
            // O fallback tira os dois pontos do MAC e anexa o search_domain
            assert_eq!(ptr_name.to_utf8(), "host-112233445566.lan.");
        } else {
            panic!("O RData retornado não é do tipo PTR");
        }
    }
}
