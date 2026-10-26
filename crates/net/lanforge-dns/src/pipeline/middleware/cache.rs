use lanforge_types::network::dns::{DnsRecordType, QueryResult};

use crate::error::DnsError;
use crate::pipeline::{DnsPipelineRequest, Middleware};
use crate::server::{DnsContext, DnsLogEvent};
use crate::utils::extract_first_answer_summary;

#[derive(Default)]
pub struct CacheMiddleware;

impl CacheMiddleware {
    pub fn new() -> Self {
        Self
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn run_sync(
        &self,
        ctx: &DnsContext,
        req: &DnsPipelineRequest<'_>,
        resp: &mut Vec<u8>,
    ) -> Result<bool, DnsError> {
        if let Some(is_block) = ctx.cache.get_wire_into(req.data, req.question, resp) {
            ctx.stats.inc_cache_hit();

            let result = if is_block {
                #[cfg(feature = "adblock")]
                ctx.stats.inc_blocked();
                QueryResult::CachedBlock
            } else {
                QueryResult::Cached
            };

            let answer = if ctx.query_log.is_some() {
                extract_first_answer_summary(resp, req.question.wire_len())
            } else {
                None
            };

            ctx.record_log(DnsLogEvent {
                src_ip: req.src_ip,
                src_mac: None,
                domain: &req.domain,
                qtype: DnsRecordType::from(req.question.qtype()),
                result,
                upstream_us: 0,
                cached: true,
                answer,
                protocol: req.protocol,
                filter: req.filter_match.clone(),
                coalesce_id: None,
            });

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl Middleware for CacheMiddleware {
    fn run_sync(
        &self,
        ctx: &DnsContext,
        req: &mut DnsPipelineRequest<'_>,
        resp: &mut Vec<u8>,
    ) -> Result<bool, DnsError> {
        CacheMiddleware::run_sync(self, ctx, req, resp)
    }
}
