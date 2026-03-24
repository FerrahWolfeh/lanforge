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
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot::{self, Sender};
use tokio::time::timeout;
use tokio::{
    io::AsyncReadExt,
    io::AsyncWriteExt,
    net::{TcpListener, UdpSocket},
};
use tracing::{debug, info};

use crate::bus::ManagedTable;
use crate::state::DeviceTable;

#[cfg(test)]
mod tests;

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

    // Gerenciador de upstream (reutiliza socket para economia de recursos)
    let upstream_mgr = if let Some(upstream) = cfg_arc.upstream {
        Some(UpstreamManager::new(upstream).await?)
    } else {
        None
    };

    // Task UDP
    let udp_cfg = Arc::clone(&cfg_arc);
    let udp_table = Arc::clone(&table);
    let udp_mgr = upstream_mgr.clone();
    let udp_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            if let Ok((len, src)) = udp_sock.recv_from(&mut buf).await {
                let data = buf[..len].to_vec();
                let sock = Arc::clone(&udp_sock);
                let t = Arc::clone(&udp_table);
                let c = Arc::clone(&udp_cfg);
                let m = udp_mgr.clone();

                tokio::spawn(async move {
                    if let Ok(Some(response)) = handle_query(&data, src, &c, &t, m.as_deref()).await
                    {
                        let _ = sock.send_to(&response, src).await;
                    }
                });
            }
        }
    });

    // Task TCP (RFC 5966)
    let tcp_cfg = Arc::clone(&cfg_arc);
    let tcp_table = Arc::clone(&table);
    let tcp_mgr = upstream_mgr.clone();
    let tcp_task = tokio::spawn(async move {
        loop {
            if let Ok((mut stream, src)) = tcp_listener.accept().await {
                let t = Arc::clone(&tcp_table);
                let c = Arc::clone(&tcp_cfg);
                let m = tcp_mgr.clone();

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

                    if let Ok(Some(response)) = handle_query(&buf, src, &c, &t, m.as_deref()).await
                    {
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
    upstream_mgr: Option<&UpstreamManager>,
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
    if let (Some(upstream), Some(mgr)) = (cfg.upstream, upstream_mgr) {
        forward_to_upstream(data, upstream, mgr).await.map(Some)
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
// Forward pro upstream (Versão otimizada com socket persistente)
// ---------------------------------------------------------------------------

struct UpstreamManager {
    socket: Arc<UdpSocket>,
    pending: Arc<Mutex<HashMap<u16, Sender<Vec<u8>>>>>,
    next_id: AtomicU16,
}

impl UpstreamManager {
    async fn new(upstream: SocketAddr) -> Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let pending = Arc::new(Mutex::new(HashMap::<u16, Sender<Vec<u8>>>::new()));

        let s = Arc::clone(&socket);
        let p = Arc::clone(&pending);

        // Task de escuta centralizada para o upstream
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                if let Ok((len, src)) = s.recv_from(&mut buf).await {
                    if src != upstream {
                        continue;
                    }
                    if let Ok(msg) = Message::from_bytes(&buf[..len]) {
                        let id = msg.id();
                        let tx = {
                            let mut map = p.lock().unwrap();
                            map.remove(&id)
                        };
                        if let Some(tx) = tx {
                            let _ = tx.send(buf[..len].to_vec());
                        }
                    }
                }
            }
        });

        Ok(Arc::new(Self {
            socket,
            pending,
            next_id: AtomicU16::new(1),
        }))
    }

    async fn forward(&self, data: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
        let mut query = Message::from_bytes(data)?;
        let orig_id = query.id();

        // Mapeia para um ID interno único para evitar colisões entre clientes LAN
        let internal_id = self.next_id.fetch_add(1, Ordering::SeqCst);
        query.set_id(internal_id);

        let data_to_send = query.to_bytes()?;
        let (tx, rx) = oneshot::channel();

        {
            let mut map = self.pending.lock().unwrap();
            map.insert(internal_id, tx);
        }

        self.socket.send_to(&data_to_send, upstream).await?;

        match timeout(Duration::from_secs(3), rx).await {
            Ok(Ok(resp_bytes)) => {
                // Restaura o ID original antes de devolver ao cliente
                if let Ok(mut resp) = Message::from_bytes(&resp_bytes) {
                    resp.set_id(orig_id);
                    return Ok(resp.to_bytes()?);
                }
                anyhow::bail!("Resposta corrompida do upstream")
            }
            Ok(Err(_)) => anyhow::bail!("Canal de resposta fechado prematuramente"),
            Err(_) => {
                // Cleanup em caso de timeout
                let mut map = self.pending.lock().unwrap();
                map.remove(&internal_id);
                anyhow::bail!("Timeout esperando resposta do upstream")
            }
        }
    }
}

async fn forward_to_upstream(
    data: &[u8],
    upstream: SocketAddr,
    manager: &UpstreamManager,
) -> Result<Vec<u8>> {
    manager.forward(data, upstream).await
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
