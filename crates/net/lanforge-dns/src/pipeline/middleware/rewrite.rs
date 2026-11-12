use lanforge_types::network::dns::{DnsRecordType, QueryResult};

use crate::error::DnsError;
use crate::pipeline::{DnsPipelineRequest, Middleware};
use crate::server::{DnsContext, DnsLogEvent};
use crate::utils::extract_first_answer_summary;

#[derive(Default)]
pub struct RewriteMiddleware;

impl RewriteMiddleware {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn run_sync(
        &self,
        ctx: &DnsContext,
        req: &DnsPipelineRequest<'_>,
        resp: &mut Vec<u8>,
    ) -> Result<bool, DnsError> {
        if ctx.rewrites.try_resolve_rewrite_wire(
            req.data,
            req.header,
            req.question,
            ctx,
            &req.domain,
            resp,
        ) {
            ctx.stats.inc_auth();

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
                result: QueryResult::Rewritten,
                upstream_us: 0,
                cached: false,
                answer,
                protocol: req.protocol,
                filter: None,
                coalesce_id: None,
                upstream: None,
            });

            return Ok(true);
        }
        Ok(false)
    }
}

impl Middleware for RewriteMiddleware {
    fn run_sync(
        &self,
        ctx: &DnsContext,
        req: &mut DnsPipelineRequest<'_>,
        resp: &mut Vec<u8>,
    ) -> Result<bool, DnsError> {
        RewriteMiddleware::run_sync(self, ctx, req, resp)
    }
}
