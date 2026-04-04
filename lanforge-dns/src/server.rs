use crate::error::DnsError;
use hickory_proto::{op::Message, rr::RecordType, serialize::binary::BinDecodable};
use lanforge_core::bus::ManagedTable;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tracing::info;

use crate::{
    config::DnsConfig, resolver::LocalResolver, utils::extract_local_hostname_wire,
    wire::qtypes::QType,
};
use crate::{
    upstream::{UpstreamManager, forward_to_upstream},
    utils::parse_arpa_wire,
};
use crate::{
    utils::{extract_local_hostname, fast_lowercase},
    wire::WireResponseWriter,
};
use lanforge_core::bus::LanforgeEvent;

/// Shared, immutable service state for the DNS hot path.
///
/// A single `Arc<DnsContext>` replaces several individual `Arc` clones per query,
/// reducing atomic reference counting overhead in the fast path.
pub(crate) struct DnsContext {
    pub cfg: DnsConfig,
    pub table: Arc<ManagedTable>,
    pub upstream_mgr: Option<Arc<UpstreamManager>>,
}

use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, LanforgeService};

pub struct DnsService {
    cfg: DnsConfig,
}

impl DnsService {
    #[must_use]
    pub fn new(cfg: DnsConfig) -> Self {
        Self { cfg }
    }
}

impl LanforgeService for DnsService {
    fn name(&self) -> &str {
        "DnsService"
    }
}

impl AsyncService for DnsService {
    async fn run(&mut self) -> std::result::Result<(), CoreError> {
        use lanforge_core::context::LanforgeContext;

        if !self.cfg.enabled {
            info!("DNS Service disabled in config");
            return Ok(());
        }

        let table = LanforgeContext::table();
        let bus = LanforgeContext::bus();

        // 1. Wait for DB Ready (Parallel optimization)
        info!("DNS: Waiting for database engine...");
        let mut ready_rx = bus.subscribe();
        while let Ok(event) = ready_rx.recv().await {
            if matches!(event, LanforgeEvent::DbReady) {
                break;
            }
            if matches!(event, LanforgeEvent::Shutdown) {
                return Ok(());
            }
        }

        let udp_sock = Arc::new(
            UdpSocket::bind(self.cfg.listen)
                .await
                .map_err(|e| CoreError::Generic(format!("UDP Bind Error: {e}")))?,
        );
        let tcp_listener = TcpListener::bind(self.cfg.listen)
            .await
            .map_err(|e| CoreError::Generic(format!("TCP Bind Error: {e}")))?;

        info!(
            "DNS Service listening (UDP/TCP) on {} (upstream: {:?}, domain: .{})",
            self.cfg.listen, self.cfg.upstream, self.cfg.search_domain
        );

        let upstream_mgr = if let Some(upstream) = self.cfg.upstream {
            Some(
                UpstreamManager::new(upstream)
                    .await
                    .map_err(|e| CoreError::Generic(e.to_string()))?,
            )
        } else {
            None
        };

        let ctx = Arc::new(DnsContext {
            cfg: self.cfg.clone(),
            table: Arc::clone(&table),
            upstream_mgr,
        });

        // Signal readiness
        let _ = bus.publish(LanforgeEvent::ServiceReady {
            name: "dns".to_string(),
        });

        let udp_ctx = Arc::clone(&ctx);
        let mut udp_rx = bus.subscribe();
        let udp_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                tokio::select! {
                    res = udp_sock.recv_from(&mut buf) => {
                        let Ok((len, src)) = res else {
                            continue;
                        };

                        if let Ok(Some(response)) = handle_query(&buf[..len], &udp_ctx).await {
                            let _ = udp_sock.send_to(&response, src).await;
                        }
                    }
                    Ok(LanforgeEvent::Shutdown) = udp_rx.recv() => {
                        info!("DNS UDP service: shutdown received");
                        break;
                    }
                }
            }
        });

        let tcp_ctx = Arc::clone(&ctx);
        let mut tcp_rx = bus.subscribe();
        let tcp_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    res = tcp_listener.accept() => {
                        if let Ok((mut stream, _)) = res {
                            let c = Arc::clone(&tcp_ctx);

                            tokio::spawn(async move {
                                let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
                                }).await;
                            });
                        }
                    }
                    Ok(LanforgeEvent::Shutdown) = tcp_rx.recv() => {
                        info!("DNS TCP service: shutdown received");
                        break;
                    }
                }
            }
        });

        let _ = tokio::join!(udp_task, tcp_task);
        Ok(())
    }
}

/// The extra-hot path: Initial query triage and routing.
///
/// This function uses the zero-allocation wire parser to decide how to handle
/// the query before performing a full parse.
///
/// ```mermaid
/// flowchart TD
///     Start[Inbound Query] --> WireHeader[WireHeader::parse]
///     WireHeader -->|Valid Query| WireQuestion[WireQuestion::parse]
///     WireQuestion -->|Simple Name| Local{Local Resolution?}
///     Local -->|Found| Return[Local Response]
///     Local -->|Not Found| Upstream[forward_to_upstream]
///     WireQuestion -->|Complex Name/Pointers| Fallback[handle_query_fallback]
///     Fallback --> Local2{Local Resolution?}
///     Local2 -->|Found| Return
///     Local2 -->|Not Found| Upstream
/// ```
pub(crate) async fn handle_query(
    data: &[u8],
    ctx: &DnsContext,
) -> Result<Option<Vec<u8>>, DnsError> {
    // Phase 1: Zero-Alloc Wire Parsing
    let Some(header) = crate::wire::WireHeader::parse(data) else {
        return Ok(None);
    };

    if !header.is_query() {
        return Ok(None);
    }

    let Some(question) = crate::wire::WireQuestion::parse(data) else {
        // Fallback to Hickory-DNS if the wire-parser finds something complex (e.g., pointers in the question)
        return handle_query_fallback(data, ctx).await;
    };

    let raw_qtype = question.qtype(); // u16 — before conversion
    let qtype = QType::from(raw_qtype);
    let edns = crate::wire::WireOptScanner::scan(data, &header, &question);
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
                    )?, // raw u16 passed directly to hickory-dns
                )
            } else {
                None
            }
        }

        QType::PTR => {
            if let Some(target_ip) = parse_arpa_wire(question.labels()) {
                let t = ctx.table.read();
                if t.get_by_ip(&target_ip).is_some() {
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

        _ => None, // Any other type goes directly to upstream
    };

    if let Some(response) = local_response {
        return Ok(Some(response));
    }

    // Phase 3: Upstream or Refused — The single point for this decision
    match (ctx.cfg.upstream, &ctx.upstream_mgr) {
        (Some(upstream), Some(mgr)) => forward_to_upstream(data, upstream, mgr).await.map(Some),
        _ => Ok(Some(WireResponseWriter::write_error_response(
            data,
            &question,
            3, // NXDOMAIN (Changed from 5 REFUSED for authoritative conditional forwarding)
            edns.as_ref(),
            ra,
        ))),
    }

    // Phase 3: Zero-Copy Upstream Forwarding
}

/// Fallback logic for queries that are too complex for the zero-alloc wire parser.
async fn handle_query_fallback(data: &[u8], ctx: &DnsContext) -> Result<Option<Vec<u8>>, DnsError> {
    let Ok(query) = Message::from_bytes(data) else {
        return Ok(None);
    };
    let rb = crate::response::ResponseBuilder::new(&query, &ctx.cfg);
    let Some(question) = query.queries().first() else {
        // Even in fallback, if the question is missing, we try a wire-level FormErr if possible.
        // However, if we reached here, the wire-parser already failed, so we use the ResponseBuilder.
        return Ok(Some(rb.formerr()?));
    };
    let qname = question.name();
    let qtype = question.query_type();

    if matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
        if let Some(hostname_slice) = extract_local_hostname(qname, &ctx.cfg.search_labels) {
            let safe_hostname = fast_lowercase(hostname_slice);
            let t = ctx.table.read();
            let resolver = crate::resolver::LocalResolver::new(&ctx.cfg, &t);
            return Ok(Some(resolver.resolve_ip(&query, &safe_hostname, qtype)?));
        }
    } else if qtype == RecordType::PTR {
        let t = ctx.table.read();
        let resolver = crate::resolver::LocalResolver::new(&ctx.cfg, &t);
        if let Some(response) = resolver.resolve_ptr(&query, qname)? {
            return Ok(Some(response));
        }
    }

    if let (Some(upstream), Some(mgr)) = (ctx.cfg.upstream, &ctx.upstream_mgr) {
        forward_to_upstream(data, upstream, mgr).await.map(Some)
    } else {
        Ok(Some(rb.nxdomain()?))
    }
}
