use lanforge_types::network::dns::{DnsRecordType, QueryResult};

use crate::error::DnsError;
use crate::pipeline::Middleware;
use crate::server::{DnsContext, DnsLogEvent};
use crate::utils::extract_first_answer_summary;

#[derive(Default)]
pub struct RewriteMiddleware;

impl RewriteMiddleware {
    pub fn new() -> Self {
        Self
    }

    pub fn run_sync(
        &self,
        ctx: &DnsContext,
        req: &crate::pipeline::DnsPipelineRequest<'_>,
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
        req: &mut crate::pipeline::DnsPipelineRequest<'_>,
        resp: &mut Vec<u8>,
    ) -> Result<bool, DnsError> {
        RewriteMiddleware::run_sync(self, ctx, req, resp)
    }
}

