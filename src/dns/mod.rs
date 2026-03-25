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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};
use tokio::sync::oneshot::{self, Sender};
use tokio::time::timeout;
use tokio::{
    io::AsyncReadExt,
    io::AsyncWriteExt,
    net::{TcpListener, UdpSocket},
};
use tracing::{info, trace};

use crate::state::DeviceTable;
use crate::{bus::ManagedTable, state::Device};

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
    pub search_labels: Vec<Vec<u8>>,
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
            search_labels: vec!["lan".into()],
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
        return Ok(None);
    };

    if query.message_type() != MessageType::Query {
        return Ok(None);
    }

    let Some(question) = query.queries().first() else {
        return Ok(Some(formerr_response(&query, cfg)?));
    };

    let qname = question.name();
    let qtype = question.query_type();

    // DICA: Use trace! em vez de debug! para que ele seja compilado e ignorado
    // em produção (RUST_LOG=info), evitando as alocações de IP no hot path.
    trace!(%src, %qname, ?qtype, "Query recebida");

    // -----------------------------------------------------------------------
    // Fast Path: Zonas Locais (A, AAAA, ANY)
    // -----------------------------------------------------------------------
    if matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
        // Se extraiu com sucesso, a query PERTENCE à nossa zona autoritativa.
        if let Some(hostname_slice) = extract_local_hostname(qname, &cfg.search_labels) {
            let safe_hostname = fast_lowercase(hostname_slice);

            let t = table.read().await;

            // Busca O(1)
            if let Some(&mac_addr) = t.name_index.get(safe_hostname.as_ref())
                && let Some(device) = t.devices.get(&mac_addr)
                && let Some(response) = resolve_local(&query, device, qtype, cfg, &t)?
            {
                return Ok(Some(response));
            }

            // Se é da nossa zona mas o dispositivo não existe -> NXDOMAIN imediato
            return Ok(Some(nxdomain_response(&query, cfg)?));
        }
    }
    // -----------------------------------------------------------------------
    // Tratamento de PTR (Resolução Reversa)
    // -----------------------------------------------------------------------
    else if qtype == RecordType::PTR {
        // Para o PTR, ainda alocamos uma String por enquanto para não quebrar a sua resolve_ptr
        let qname_str = qname.to_string();
        if qname_str.ends_with(".arpa.") {
            let t = table.read().await;
            if let Some(response) = resolve_ptr(&query, &qname_str, cfg, &t)? {
                return Ok(Some(response));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Fallback: Encaminha para o Upstream ou RECUSA
    // -----------------------------------------------------------------------
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
    device: &Device, // Recebe a referência do dispositivo em O(1)
    qtype: RecordType,
    cfg: &DnsConfig,
    table: &DeviceTable,
) -> Result<Option<Vec<u8>>> {
    let question = query.queries().first().expect("Query validada");

    // Hickory exige que o Name de resposta seja 'owned', então 1 clone aqui é aceitável
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
                classify_ip(ip);
            }
        }

        for ip in &device.slaac {
            classify_ip(*ip);
        }

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
    qname: &str, // Assumindo que você passou a string da query
    cfg: &DnsConfig,
    table: &DeviceTable,
) -> Result<Option<Vec<u8>>> {
    // 1. Extrai o IP diretamente da string .arpa sem alocações pesadas
    let Some(target_ip) = parse_arpa(qname) else {
        return Ok(None);
    };

    // 2. Busca O(1) absoluta no novo índice
    let Some(&mac) = table.ip_index.get(&target_ip) else {
        return Ok(None);
    };

    let device = table
        .devices
        .get(&mac)
        .expect("Índice corrompido: MAC não encontrado");

    let question = query.queries().first().unwrap();
    let name = question.name().clone();

    // 3. Usa o mesmo fallback se o hostname estiver vazio
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

/// Parseador de ARPA otimizado sem alocação de Vec ou manipulação reversa pesada.
fn parse_arpa(name: &str) -> Option<IpAddr> {
    let name = name.trim_end_matches('.');

    if let Some(v4_part) = name.strip_suffix(".in-addr.arpa") {
        let mut parts = v4_part.split('.');
        // Lendo do fim para o começo diretamente do iterador
        let d: u8 = parts.next()?.parse().ok()?;
        let c: u8 = parts.next()?.parse().ok()?;
        let b: u8 = parts.next()?.parse().ok()?;
        let a: u8 = parts.next()?.parse().ok()?;
        return Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)));
    }

    // (Mantenha sua lógica de IPv6 atual aqui se ela já funciona bem,
    // ou otimize para ler os nibbles diretamente do slice sem o with_capacity)
    if let Some(v6_part) = name.strip_suffix(".ip6.arpa") {
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

/// Extrai o hostname local diretamente dos labels do pacote DNS bruto.
/// Custo de alocação: 0 bytes.
fn extract_local_hostname<'a>(qname: &'a Name, search_labels: &[Vec<u8>]) -> Option<&'a str> {
    let mut iter = qname.iter();

    // 1. O primeiro label é sempre o alvo (ex: "node-12" de "node-12.lanforge.local")
    let host_bytes = iter.next()?;

    // 2. Valida se o resto da query bate exatamente com o seu domínio de busca
    for expected_label in search_labels {
        let actual_label = iter.next()?;

        // Comparação de bytes ignorando case (muito mais rápido que mexer com UTF-8 strings)
        if !actual_label.eq_ignore_ascii_case(expected_label) {
            return None;
        }
    }

    // 3. Se a query tiver mais labels (ex: sub.node-12.lanforge.local), rejeita
    if iter.next().is_some() {
        return None;
    }

    // 4. Tudo certo. Converte os bytes do hostname para &str e devolve
    std::str::from_utf8(host_bytes).ok()
}

/// Verifica se a string já é minúscula.
/// Em 99% das queries LAN, não fazemos NENHUMA alocação (retorna Borrowed).
/// Só aloca memória no heap (Owned) se algum dispositivo maluco mandar letras maiúsculas.
fn fast_lowercase(s: &str) -> Cow<'_, str> {
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(s.to_ascii_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}

// ---------------------------------------------------------------------------
// Testes
// ---------------------------------------------------------------------------
