use anyhow::{Context, Result};
use hickory_proto::{
    op::{Message, MessageType},
    rr::RecordType,
    serialize::binary::BinDecodable,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tracing::{info, trace};

use crate::bus::ManagedTable;
use crate::dns::config::DnsConfig;
use crate::dns::upstream::{UpstreamManager, forward_to_upstream};
use crate::dns::utils::{extract_local_hostname, fast_lowercase};

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

    let upstream_mgr = if let Some(upstream) = cfg_arc.upstream {
        Some(UpstreamManager::new(upstream).await?)
    } else {
        None
    };

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

// Extra-hot path
pub(crate) async fn handle_query(
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

    let rb = crate::dns::response::ResponseBuilder::new(&query, cfg);

    let Some(question) = query.queries().first() else {
        return Ok(Some(rb.formerr()?));
    };

    let qname = question.name();
    let qtype = question.query_type();

    trace!(%src, %qname, ?qtype, "Query recebida");

    // Fast Path para Redução de Latência e Prevenção de Leaks
    if matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
        if let Some(hostname_slice) = extract_local_hostname(qname, &cfg.search_labels) {
            let safe_hostname = fast_lowercase(hostname_slice);

            // Somente após confirmar que a query é para o domínio local, bloqueamos a tabela
            let t = table.read();
            let resolver = crate::dns::resolver::LocalResolver::new(cfg, &t);
            return Ok(Some(resolver.resolve_ip(&query, &safe_hostname, qtype)?));
        }
    } else if qtype == RecordType::PTR {
        // PTR Optimization: O resolver agora recebe &Name e faz parse interno via labels
        let t = table.read();
        let resolver = crate::dns::resolver::LocalResolver::new(cfg, &t);
        if let Some(response) = resolver.resolve_ptr(&query, qname)? {
            return Ok(Some(response));
        }
    }

    // Encaminhamento para Upstream (Internet)
    if let (Some(upstream), Some(mgr)) = (cfg.upstream, upstream_mgr) {
        forward_to_upstream(data, upstream, mgr).await.map(Some)
    } else {
        Ok(Some(rb.refused()?))
    }
}
