use crate::error::DnsError;
use hickory_proto::{op::Message, rr::RecordType, serialize::binary::BinDecodable};
use lanforge_core::bus::TimedEvent;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use tracing::info;

use crate::{
    config::DnsConfig, resolver::LocalResolver, stats::DnsStats, utils::extract_local_hostname_wire,
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
    pub upstream_mgr: Option<Arc<UpstreamManager>>,
    pub stats: Arc<DnsStats>,
    pub ctx: lanforge_core::context::LanforgeContext,
}

use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, LanforgeService};

pub struct DnsService {
    cfg: DnsConfig,
    stats: Arc<DnsStats>,
    ctx: lanforge_core::context::LanforgeContext,
}

impl DnsService {
    #[must_use]
    pub fn new(cfg: DnsConfig, ctx: lanforge_core::context::LanforgeContext) -> Self {
        let stats = Arc::new(DnsStats::new());
        ctx.set_dns_stats_opt(Arc::clone(&stats));
        Self { cfg, stats, ctx }
    }

    /// Returns a snapshot of the current DNS statistics.
    #[must_use]
    pub fn stats_snapshot(&self) -> crate::stats::DnsStatsSnapshot {
        self.stats.snapshot()
    }
}

impl LanforgeService for DnsService {
    fn meta(&self) -> lanforge_core::service::ServiceMeta {
        lanforge_core::service::ServiceMeta {
            id: "dns",
            display_name: "DNS Server",
            critical: true,
            max_retries: 0,
            base_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(30),
            stack_kb: 384,
        }
    }

    fn describe(&self) -> String {
        format!(
            "DNS on {} (upstream: {:?}, domain: .{})",
            self.cfg.listen, self.cfg.upstream, self.cfg.search_domain
        )
    }
}

impl AsyncService for DnsService {
    async fn run(&mut self) -> std::result::Result<(), CoreError> {
        if !self.cfg.enabled {
            info!("DNS Service disabled in config");
            return Ok(());
        }

        let bus = self.ctx.bus_opt();

        // 1. Wait for DB Ready (Parallel optimization)
        info!("DNS: Waiting for database engine...");
        self.ctx.wait_for_db_opt().await?;

        let udp_sock = Arc::new(
            UdpSocket::bind(self.cfg.listen)
                .await
                .map_err(|e| CoreError::Generic(format!("UDP Bind Error: {e}")))?,
        );
        let tcp_listener = TcpListener::bind(self.cfg.listen)
            .await
            .map_err(|e| CoreError::Generic(format!("TCP Bind Error: {e}")))?;

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
            upstream_mgr,
            stats: Arc::clone(&self.stats),
            ctx: self.ctx.clone(),
        });

        // Signal readiness
        let _ = bus.publish(LanforgeEvent::ServiceReady {
            name: "dns".to_string(),
        });

        let mut rx = bus.subscribe();

        // UDP Task
        let udp_ctx = Arc::clone(&ctx);
        let udp_sock_inner = Arc::clone(&udp_sock);
        let ctx_udp = self.ctx.clone();
        let udp_task = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                tokio::select! {
                    res = udp_sock_inner.recv_from(&mut buf) => {
                        let Ok((len, src)) = res else { continue; };
                        if let Ok(Some(response)) = handle_query(&buf[..len], &udp_ctx).await {
                            let _ = udp_sock_inner.send_to(&response, src).await;
                        }
                    }
                    () = tokio::time::sleep(Duration::from_millis(100)) => {
                         if !ctx_udp.is_running_opt() { break; }
                    }
                }
            }
        });

        // TCP Task
        let tcp_ctx = Arc::clone(&ctx);
        let ctx_tcp = self.ctx.clone();
        let tcp_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    res = tcp_listener.accept() => {
                        if let Ok((mut stream, _)) = res {
                            let c = Arc::clone(&tcp_ctx);
                            tokio::spawn(async move {
                                let _ = tokio::time::timeout(Duration::from_secs(5), async {
                                    let mut len_buf = [0u8; 2];
                                    stream.read_exact(&mut len_buf).await?;
                                    let len = u16::from_be_bytes(len_buf) as usize;
                                    let mut query_buf = vec![0u8; len];
                                    stream.read_exact(&mut query_buf).await?;

                                    if let Ok(Some(response)) = handle_query(&query_buf, &c).await {
                                        let resp_len = u16::try_from(response.len()).unwrap_or(u16::MAX).to_be_bytes();
                                        stream.write_all(&resp_len).await?;
                                        stream.write_all(&response).await?;
                                    }
                                    Ok::<(), std::io::Error>(())
                                }).await;
                            });
                        }
                    }
                    () = tokio::time::sleep(Duration::from_millis(100)) => {
                        if !ctx_tcp.is_running_opt() { break; }
                    }
                }
            }
        });

        // Wait for shutdown or tasks
        let ctx_main = self.ctx.clone();
        loop {
            tokio::select! {
                Ok(TimedEvent { event: LanforgeEvent::Shutdown, .. }) = rx.recv() => {
                    info!("DNS service: shutdown received");
                    break;
                }
                () = tokio::time::sleep(Duration::from_millis(500)) => {
                    if !ctx_main.is_running_opt() { break; }
                }
            }
        }

        // Cancel tasks and exit
        udp_task.abort();
        tcp_task.abort();
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
    ctx.stats.inc_requests();

    // PHASE 1: Zero-Alloc Triage
    let Some(header) = crate::wire::WireHeader::parse(data) else {
        return Ok(None);
    };
    if !header.is_query() {
        return Ok(None);
    }

    let Some(question) = crate::wire::WireQuestion::parse(data) else {
        return handle_query_fallback(data, ctx).await;
    };

    // PHASE 2: Local Resolution Attempt
    if let Some(resp) = resolve_local_wire(data, &question, ctx)? {
        ctx.stats.inc_auth();
        ctx.stats.inc_cache_hit();
        return Ok(Some(resp));
    }

    ctx.stats.inc_cache_miss();

    // PHASE 3: Recursive Forwarding
    if let (Some(upstream), Some(mgr)) = (ctx.cfg.upstream, &ctx.upstream_mgr) {
        ctx.stats.inc_recursive();
        forward_to_upstream(data, upstream, mgr).await.map(Some)
    } else {
        let edns = crate::wire::WireOptScanner::scan(data, &header, &question);
        let ra = ctx.cfg.upstream.is_some();
        Ok(Some(WireResponseWriter::write_error_response(
            data,
            &question,
            3,
            edns.as_ref(),
            ra,
        )))
    }
}

/// Helper function for local resolution using wire-parsed data.
fn resolve_local_wire(
    data: &[u8],
    question: &crate::wire::WireQuestion<'_>,
    ctx: &DnsContext,
) -> Result<Option<Vec<u8>>, DnsError> {
    use crate::wire::qtypes::QType;
    let raw_qtype = question.qtype();
    let qtype = QType::from(raw_qtype);

    match qtype {
        QType::A | QType::AAAA | QType::Any => {
            let mut labels = question.labels();
            if let Some(hostname_slice) =
                extract_local_hostname_wire(&mut labels, &ctx.cfg.multi_search_labels)
            {
                let safe_hostname = fast_lowercase(hostname_slice);
                let query = Message::from_bytes(data)?;
                let resp = LocalResolver::new(&ctx.cfg, ctx.ctx.clone()).resolve_ip(
                    &query,
                    &safe_hostname,
                    RecordType::from(raw_qtype),
                )?;
                return Ok(Some(resp));
            }
        }
        QType::PTR => {
            if let Some(_target_ip) = parse_arpa_wire(question.labels()) {
                let query = Message::from_bytes(data)?;
                let resp = LocalResolver::new(&ctx.cfg, ctx.ctx.clone())
                    .resolve_ptr(&query, query.queries()[0].name())?;
                if let Some(r) = resp {
                    return Ok(Some(r));
                }
            }
        }
        _ => {}
    }
    Ok(None)
}

/// Fallback logic for queries that are too complex for the zero-alloc wire parser.
async fn handle_query_fallback(data: &[u8], ctx: &DnsContext) -> Result<Option<Vec<u8>>, DnsError> {
    let Ok(query) = Message::from_bytes(data) else {
        return Ok(None);
    };
    let rb = crate::response::ResponseBuilder::new(&query, &ctx.cfg);
    let question = query
        .queries()
        .first()
        .ok_or(crate::error::DnsError::WireParseError)?;
    let qname = question.name();
    let qtype = question.query_type();

    if matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
        if let Some(hostname_slice) = extract_local_hostname(qname, &ctx.cfg.multi_search_labels) {
            let safe_hostname = fast_lowercase(hostname_slice);
            ctx.stats.inc_auth();
            ctx.stats.inc_cache_hit();
            let resp = LocalResolver::new(&ctx.cfg, ctx.ctx.clone()).resolve_ip(
                &query,
                &safe_hostname,
                qtype,
            )?;
            return Ok(Some(resp));
        }
    } else if qtype == RecordType::PTR {
        let resp = LocalResolver::new(&ctx.cfg, ctx.ctx.clone()).resolve_ptr(&query, qname)?;
        if let Some(response) = resp {
            ctx.stats.inc_auth();
            ctx.stats.inc_cache_hit();
            return Ok(Some(response));
        }
    }

    ctx.stats.inc_cache_miss();

    if let (Some(upstream), Some(mgr)) = (ctx.cfg.upstream, &ctx.upstream_mgr) {
        ctx.stats.inc_recursive();
        forward_to_upstream(data, upstream, mgr).await.map(Some)
    } else {
        Ok(Some(rb.nxdomain()?))
    }
}
