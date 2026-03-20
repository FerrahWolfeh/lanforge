//! src/dns/mod.rs — Servidor DNS mínimo da LAN
//!
//! Responde A/AAAA para dispositivos da DeviceTable e encaminha
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
    rr::{RData, Record, RecordType},
    serialize::binary::{BinDecodable, BinEncodable},
};
use std::net::SocketAddr;
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

    // Buffer aumentado para 4096 para suportar respostas EDNS0 maiores que 512 bytes
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

    if matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
        let t = table.read().await;
        if let Some(response) = resolve_local(&query, &hostname, qtype, cfg, &t)? {
            debug!("Respondido localmente: {hostname}");
            return Ok(response);
        }
    }

    forward_to_upstream(data, cfg.upstream).await
}

// ---------------------------------------------------------------------------
// Resolução local
// ---------------------------------------------------------------------------

fn resolve_local(
    query: &Message,
    hostname: &str,
    qtype: RecordType,
    cfg: &DnsConfig,
    table: &DeviceTable,
) -> Result<Option<Vec<u8>>> {
    let device = table
        .devices
        .values()
        .find(|d| d.hostname.eq_ignore_ascii_case(hostname));

    let Some(device) = device else {
        return Ok(None);
    };

    // CORREÇÃO: Usar o Name exato que veio na query para evitar que o client
    // rejeite a resposta por "mismatched question/answer".
    let question = query
        .queries()
        .first()
        .expect("Query validada anteriormente");
    let name = question.name().clone();
    let mut records: Vec<Record> = Vec::new();

    if matches!(qtype, RecordType::A | RecordType::ANY)
        && let Some(v4) = &device.v4
    {
        let r = RData::A(v4.ip.into());
        let record = Record::from_rdata(name.clone(), cfg.ttl, r);
        records.push(record);
    }

    if matches!(qtype, RecordType::AAAA | RecordType::ANY) {
        if let Some(v6) = &device.v6 {
            let r = RData::AAAA(v6.ip.into());
            let record = Record::from_rdata(name.clone(), cfg.ttl, r);
            records.push(record);
        }
        for slaac_ip in &device.slaac {
            let r = RData::AAAA((*slaac_ip).into());
            let record = Record::from_rdata(name.clone(), cfg.ttl, r);
            records.push(record);
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
        resp.to_bytes()
            .context("falha ao serializar resposta DNS local")?,
    ))
}

// ---------------------------------------------------------------------------
// Forward pro upstream
// ---------------------------------------------------------------------------

async fn forward_to_upstream(data: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    // Nota: Bindar em porta efêmera por query é aceitável para uso doméstico,
    // mas pode causar "port exhaustion" em cenários de altíssimo tráfego.
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
    use std::{net::Ipv4Addr, time::SystemTime};

    use crate::state::{Device, MacAddr, V4Lease};

    use super::*;

    #[test]
    fn normalize_strips_domain_and_dot() {
        assert_eq!(normalize_name("archie.lan.", "lan"), "archie");
        assert_eq!(normalize_name("archie.lan", "lan"), "archie");
        assert_eq!(normalize_name("archie.", "lan"), "archie");
    }

    #[test]
    fn normalize_keeps_bare_hostname() {
        assert_eq!(normalize_name("archie", "lan"), "archie");
        assert_eq!(normalize_name("NAS", "lan"), "nas"); // garante lowercase
    }

    #[test]
    fn normalize_keeps_external_domains() {
        assert_eq!(normalize_name("foo.bar.com.", "lan"), "foo.bar.com");
        assert_eq!(normalize_name("google.com", "lan"), "google.com");
    }

    #[test]
    fn normalize_handles_mismatched_search_domain() {
        // Se o cliente perguntar com um domínio diferente, não deve cortar
        assert_eq!(normalize_name("archie.local.", "lan"), "archie.local");
    }

    // Nota para os próximos testes:
    // Você precisará importar e construir um `Device` do seu crate::state
    // Estou usando um pseudo-código comentado aqui para ilustrar o formato
    // ideal de teste para a função `resolve_local`.

    #[test]
    fn resolve_local_matches_question_name_exactly() {
        use hickory_proto::rr::Name;
        use std::str::FromStr;

        // 1. Setup da config e tabela com um device "solarium"
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

        // 2. Criar uma query simulando um "dig solarium A"
        let mut query = Message::new();
        let name = Name::from_str("solarium.").unwrap();
        query.add_query(hickory_proto::op::Query::query(name.clone(), RecordType::A));

        // 3. Chamar a resolução
        let result = resolve_local(&query, "solarium", RecordType::A, &cfg, &table).unwrap();

        // 4. Garantir que o nome devolvido na resposta é "solarium." e não "solarium.lan."
        let resp_bytes = result.unwrap();
        let resp_msg = Message::from_bytes(&resp_bytes).unwrap();

        assert_eq!(resp_msg.answers()[0].name(), &name);
    }
}
