use anyhow::{Context, Result};
use hickory_proto::{op::Message, rr::RecordType, serialize::binary::BinDecodable};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tracing::info;

use crate::dns::{config::DnsConfig, resolver::LocalResolver, utils::extract_local_hostname_wire};
use crate::dns::{
    upstream::{UpstreamManager, forward_to_upstream},
    utils::parse_arpa_wire,
};
use crate::dns::{
    utils::{extract_local_hostname, fast_lowercase},
    wire::WireResponseWriter,
};
use crate::{bus::ManagedTable, dns::wire::qtypes::QType};

/// Shared, immutable service state for the DNS hot path.
/// A single Arc<DnsContext> replaces 3 separate Arc clones per query.
pub(crate) struct DnsContext {
    pub cfg: DnsConfig,
    pub table: Arc<ManagedTable>,
    pub upstream_mgr: Option<Arc<UpstreamManager>>,
}

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
    let upstream_mgr = if let Some(upstream) = cfg.upstream {
        Some(UpstreamManager::new(upstream).await?)
    } else {
        None
    };

    let ctx = Arc::new(DnsContext {
        cfg,
        table: Arc::clone(&table),
        upstream_mgr,
    });

    let udp_ctx = Arc::clone(&ctx);
    let udp_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            if let Ok((len, src)) = udp_sock.recv_from(&mut buf).await {
                let data = buf[..len].to_vec();
                let sock = Arc::clone(&udp_sock);
                let c = Arc::clone(&udp_ctx);

                tokio::spawn(async move {
                    if let Ok(Some(response)) = handle_query(&data, &c).await {
                        let _ = sock.send_to(&response, src).await;
                    }
                });
            }
        }
    });

    let tcp_ctx = Arc::clone(&ctx);
    let tcp_task = tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = tcp_listener.accept().await {
                let c = Arc::clone(&tcp_ctx);

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

                    if let Ok(Some(response)) = handle_query(&buf, &c).await {
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

// Extra-hot path
pub(crate) async fn handle_query(data: &[u8], ctx: &DnsContext) -> Result<Option<Vec<u8>>> {
    // Phase 1: Zero-Alloc Wire Parsing
    let Some(header) = crate::dns::wire::WireHeader::parse(data) else {
        return Ok(None);
    };

    if !header.is_query() {
        return Ok(None);
    }

    let Some(question) = crate::dns::wire::WireQuestion::parse(data) else {
        // Fallback para Hickory se o wire-parser falhar (ex: pointers na question)
        return handle_query_fallback(data, ctx).await;
    };

    let raw_qtype = question.qtype(); // u16 — antes de converter
    let qtype = QType::from(raw_qtype);
    let edns = crate::dns::wire::WireOptScanner::scan(data, &header, &question);
    let ra = ctx.cfg.upstream.is_some();

    // Phase 2: Zero-Alloc Routing Decisions

    // Phase 2: Local Resolution Attempt
    let local_response: Option<Vec<u8>> = match qtype {
        QType::A | QType::AAAA | QType::Any => {
            let mut labels = question.labels();
            if let Some(hostname_slice) =
                extract_local_hostname_wire(&mut labels, &ctx.cfg.search_labels)
            {
                let safe_hostname = fast_lowercase(hostname_slice);
                let Ok(query) = Message::from_bytes(data) else {
                    return Ok(None);
                };
                let t = ctx.table.read();
                Some(
                    LocalResolver::new(&ctx.cfg, &t).resolve_ip(
                        &query,
                        &safe_hostname,
                        RecordType::from(raw_qtype),
                    )?, // u16 direto pro hickory
                )
            } else {
                None
            }
        }

        QType::PTR => {
            if let Some(target_ip) = parse_arpa_wire(question.labels()) {
                let t = ctx.table.read();
                if t.ip_index.contains_key(&target_ip) {
                    let Ok(query) = Message::from_bytes(data) else {
                        return Ok(None);
                    };
                    LocalResolver::new(&ctx.cfg, &t)
                        .resolve_ptr(&query, query.queries()[0].name())?
                } else {
                    None
                }
            } else {
                None
            }
        }

        _ => None, // qualquer outro tipo vai direto pro upstream
    };

    if let Some(response) = local_response {
        return Ok(Some(response));
    }

    // Phase 3: Upstream or Refused — único lugar onde essa decisão é tomada
    match (ctx.cfg.upstream, &ctx.upstream_mgr) {
        (Some(upstream), Some(mgr)) => forward_to_upstream(data, upstream, mgr).await.map(Some),
        _ => Ok(Some(WireResponseWriter::write_error_response(
            data,
            &question,
            5, // REFUSED
            edns.as_ref(),
            ra,
        ))),
    }

    // Phase 3: Zero-Copy Upstream Forwarding
}

/// Fallback para o comportamento original caso o wire-parser encontre algo complexo.
async fn handle_query_fallback(data: &[u8], ctx: &DnsContext) -> Result<Option<Vec<u8>>> {
    let Ok(query) = Message::from_bytes(data) else {
        return Ok(None);
    };
    let rb = crate::dns::response::ResponseBuilder::new(&query, &ctx.cfg);
    let Some(question) = query.queries().first() else {
        // Mesmo no fallback, se falhar a question, tentamos um FormErr wire-level se possível,
        // mas aqui já falhamos no wire-parser original, então usamos o rb.
        return Ok(Some(rb.formerr()?));
    };
    let qname = question.name();
    let qtype = question.query_type();

    if matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
        if let Some(hostname_slice) = extract_local_hostname(qname, &ctx.cfg.search_labels) {
            let safe_hostname = fast_lowercase(hostname_slice);
            let t = ctx.table.read();
            let resolver = crate::dns::resolver::LocalResolver::new(&ctx.cfg, &t);
            return Ok(Some(resolver.resolve_ip(&query, &safe_hostname, qtype)?));
        }
    } else if qtype == RecordType::PTR {
        let t = ctx.table.read();
        let resolver = crate::dns::resolver::LocalResolver::new(&ctx.cfg, &t);
        if let Some(response) = resolver.resolve_ptr(&query, qname)? {
            return Ok(Some(response));
        }
    }

    if let (Some(upstream), Some(mgr)) = (ctx.cfg.upstream, &ctx.upstream_mgr) {
        forward_to_upstream(data, upstream, mgr).await.map(Some)
    } else {
        Ok(Some(rb.refused()?))
    }
}
