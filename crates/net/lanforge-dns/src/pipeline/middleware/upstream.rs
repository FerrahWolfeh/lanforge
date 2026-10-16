use lanforge_types::network::dns::{DnsRecordType, QueryResult};

use crate::error::DnsError;
use crate::pipeline::{DnsPipelineRequest, Middleware};
use crate::server::{DnsContext, DnsLogEvent};
use crate::utils::extract_first_answer_summary;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::time::Instant;

#[derive(Default)]
pub struct UpstreamMiddleware;

impl UpstreamMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl Middleware for UpstreamMiddleware {
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn run<'a>(
        &'a self,
        ctx: &'a DnsContext,
        req: DnsPipelineRequest<'a>,
        resp: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DnsError>> + Send + 'a>> {
        Box::pin(async move {
            let start = Instant::now();
            match ctx
                .recursive
                .resolve_with_parsed(req.data, req.header, req.question)
                .await
            {
                Ok(r) => {
                    let elapsed = start.elapsed().as_micros() as u32;

                    ctx.stats.inc_resolved();
                    if r.cached {
                        ctx.stats.inc_cache_hit();
                    } else if !r.coalesced {
                        ctx.stats.inc_cache_miss();
                        ctx.stats.inc_recursive();
                    }

                    let result = if r.is_block {
                        #[cfg(feature = "adblock")]
                        ctx.stats.inc_blocked();
                        QueryResult::CachedBlock
                    } else if r.cached {
                        QueryResult::Cached
                    } else {
                        QueryResult::Forwarded
                    };

                    *resp = r.data;

                    let answer = if ctx.query_log.is_some() {
                        extract_first_answer_summary(resp, req.question.wire_len())
                    } else {
                        None
                    };

                    ctx.record_log(DnsLogEvent {
                        src_ip: req.src_ip,
                        src_mac: None,
                        domain: req.domain.clone(),
                        qtype: DnsRecordType::from(req.question.qtype()),
                        result,
                        upstream_us: elapsed,
                        cached: r.cached,
                        answer,
                        protocol: req.protocol,
                        filter: req.filter_match.lock().clone(),
                    });

                    // Update cache size counter in real-time
                    if !r.cached && !r.coalesced && let Some(mgr) = ctx.recursive.all_upstreams().next() {
                        ctx.stats
                            .cache_entries
                            .store(mgr.cache.cache.len() as u64, Ordering::Relaxed);
                    }

                    Ok(true)
                }
                Err(e) => {
                    let elapsed = start.elapsed().as_micros() as u32;
                    ctx.stats.inc_failed();
                    ctx.stats.inc_upstream_error();

                    ctx.record_log(DnsLogEvent {
                        src_ip: req.src_ip,
                        src_mac: None,
                        domain: req.domain.clone(),
                        qtype: DnsRecordType::from(req.question.qtype()),
                        result: QueryResult::Error,
                        upstream_us: elapsed,
                        cached: false,
                        answer: Some(format!("SERVFAIL: {e}")),
                        protocol: req.protocol,
                        filter: req.filter_match.lock().clone(),
                    });

                    Err(e)
                }
            }
        })
    }
}
