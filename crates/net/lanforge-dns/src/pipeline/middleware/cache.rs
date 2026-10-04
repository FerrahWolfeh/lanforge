use lanforge_types::network::dns::{DnsRecordType, QueryResult};

use crate::error::DnsError;
use crate::pipeline::{DnsPipelineRequest, Middleware};
use crate::server::{DnsContext, DnsLogEvent};
use crate::utils::extract_first_answer_summary;
use std::future::Future;
use std::pin::Pin;

#[derive(Default)]
pub struct CacheMiddleware;

impl CacheMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl Middleware for CacheMiddleware {
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    fn run<'a>(
        &'a self,
        ctx: &'a DnsContext,
        req: DnsPipelineRequest<'a>,
        resp: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DnsError>> + Send + 'a>> {
        Box::pin(async move {
            if let Some((cached_resp, is_block)) = ctx.cache.get_wire(req.data, req.question) {
                *resp = cached_resp;

                ctx.stats.inc_cache_hit();

                let result = if is_block {
                    #[cfg(feature = "adblock")]
                    ctx.stats.inc_blocked();
                    QueryResult::CachedBlock
                } else {
                    QueryResult::Cached
                };

                let src_mac = ctx.local.ctx.get_mac_by_ip(req.src_ip);
                let answer = if ctx.query_log.is_some() {
                    extract_first_answer_summary(resp, req.question.wire_len())
                } else {
                    None
                };

                ctx.record_log(DnsLogEvent {
                    src_ip: req.src_ip,
                    src_mac,
                    domain: req.domain.clone(),
                    qtype: DnsRecordType::from(req.question.qtype()),
                    result,
                    upstream_us: 0,
                    cached: true,
                    answer,
                    protocol: req.protocol,
                    filter: req.filter_match.lock().clone(),
                });

                return Ok(true);
            }

            Ok(false)
        })
    }
}
