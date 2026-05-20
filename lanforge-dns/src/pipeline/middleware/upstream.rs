use lanforge_types::network::dns::{DnsRecordType, DnsResponseCode, QueryResult};

use crate::error::DnsError;
use crate::pipeline::{DnsPipelineRequest, Middleware};
use crate::resolver::labels_to_domain;
use crate::server::{DnsContext, DnsLogEvent};
use lanforge_dns_wire::WireDecoder;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
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
            match ctx.recursive.resolve(req.data).await {
                Ok((upstream_resp, cached, is_block)) => {
                    let elapsed = start.elapsed().as_micros() as u32;

                    ctx.stats.inc_resolved();
                    if cached {
                        ctx.stats.inc_cache_hit();
                    } else {
                        ctx.stats.inc_cache_miss();
                    }

                    let result = if is_block {
                        #[cfg(feature = "adblock")]
                        ctx.stats.inc_blocked();
                        QueryResult::CachedBlock
                    } else if cached {
                        QueryResult::Cached
                    } else {
                        QueryResult::Forwarded
                    };

                    let domain = labels_to_domain(req.question.labels());
                    let src_mac = ctx.local.ctx.get_mac_by_ip(req.src_ip);

                    *resp = upstream_resp;

                    let mut answer = None;
                    let mut decoder = WireDecoder::new(resp);
                    if let Some(msg) = decoder.decode_message() {
                        if let Some(first) = msg.answers.first() {
                            answer = Some(format!("{}", first.rdata));
                        } else if msg.header.rcode != DnsResponseCode::NoError {
                            answer = Some(format!("{:?}", msg.header.rcode));
                        }
                    }

                    ctx.record_log(DnsLogEvent {
                        src_ip: req.src_ip,
                        src_mac,
                        domain: Arc::from(domain),
                        qtype: DnsRecordType::from(req.question.qtype()),
                        result,
                        upstream_us: elapsed,
                        cached,
                        answer,
                        protocol: req.protocol,
                    });

                    // Update cache size counter in real-time
                    if !cached && let Some(mgr) = ctx.recursive.all_upstreams().next() {
                        ctx.stats
                            .cache_entries
                            .store(mgr.cache.cache.len() as u64, Ordering::Relaxed);
                    }

                    Ok(true)
                }
                Err(e) => {
                    ctx.stats.inc_failed();
                    Err(e)
                }
            }
        })
    }
}
