use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::QueryResult;

use crate::error::DnsError;
use crate::pipeline::{DnsPipelineRequest, Middleware};
use crate::server::{DnsContext, DnsLogEvent};
use crate::utils::extract_first_answer_summary;
use std::future::Future;
use std::pin::Pin;

#[derive(Default)]
pub struct LocalResolverMiddleware;

impl LocalResolverMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl Middleware for LocalResolverMiddleware {
    fn run_sync(
        &self,
        ctx: &DnsContext,
        req: &DnsPipelineRequest<'_>,
        resp: &mut Vec<u8>,
    ) -> Option<Result<bool, DnsError>> {
        let has_upstreams = !ctx.recursive.is_empty();
        if ctx
            .local
            .resolve_local_wire(req.data, req.header, req.question, has_upstreams, resp)
        {
            ctx.stats.inc_auth();

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
                result: QueryResult::Local,
                upstream_us: 0,
                cached: false,
                answer,
                protocol: req.protocol,
                filter: None,
                coalesce_id: None,
            });

            return Some(Ok(true));
        }
        Some(Ok(false))
    }

    fn run<'a>(
        &'a self,
        ctx: &'a DnsContext,
        req: DnsPipelineRequest<'a>,
        resp: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DnsError>> + Send + 'a>> {
        Box::pin(std::future::ready(
            self.run_sync(ctx, &req, resp).unwrap_or(Ok(false)),
        ))
    }
}
