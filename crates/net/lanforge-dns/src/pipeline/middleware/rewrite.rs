use lanforge_types::network::dns::{DnsRecordType, QueryResult};

use crate::error::DnsError;
use crate::pipeline::Middleware;
use crate::server::{DnsContext, DnsLogEvent};
use crate::utils::extract_first_answer_summary;
use std::future::Future;
use std::pin::Pin;

#[derive(Default)]
pub struct RewriteMiddleware;

impl RewriteMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl Middleware for RewriteMiddleware {
    fn run<'a>(
        &'a self,
        ctx: &'a DnsContext,
        req: crate::pipeline::DnsPipelineRequest<'a>,
        resp: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DnsError>> + Send + 'a>> {
        Box::pin(async move {
            if ctx.rewrites.try_resolve_rewrite_wire(
                req.data,
                req.header,
                req.question,
                ctx,
                &req.domain,
                resp,
            ) {
                ctx.stats.inc_auth();

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
                    result: QueryResult::Rewritten,
                    upstream_us: 0,
                    cached: false,
                    answer,
                    protocol: req.protocol,
                    filter: None,
                });

                return Ok(true);
            }
            Ok(false)
        })
    }
}
