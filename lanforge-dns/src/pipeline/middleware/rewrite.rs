use lanforge_core::types::{DnsRecordType, QueryResult};

use crate::error::DnsError;
use crate::pipeline::Middleware;
use crate::resolver::filter::labels_to_domain;
use crate::server::{DnsContext, DnsLogEvent};
use crate::wire::WireDecoder;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

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
            if let Some(filter) = &ctx.filter {
                let domain = labels_to_domain(req.question.labels());
                if filter.try_resolve_rewrite_wire(
                    req.data,
                    req.header,
                    req.question,
                    ctx,
                    &domain,
                    resp,
                ) {
                    ctx.stats.inc_auth();

                    let src_mac = ctx.local.ctx.get_mac_by_ip(req.src_ip);

                    let mut answer = None;
                    let mut decoder = WireDecoder::new(resp);
                    if let Some(msg) = decoder.decode_message()
                        && let Some(first) = msg.answers.first()
                    {
                        answer = Some(format!("{}", first.rdata));
                    }

                    ctx.record_log(DnsLogEvent {
                        src_ip: req.src_ip,
                        src_mac,
                        domain: Arc::from(domain),
                        qtype: DnsRecordType::from(req.question.qtype()),
                        result: QueryResult::Rewritten,
                        upstream_us: 0,
                        cached: false,
                        answer,
                        protocol: req.protocol,
                    });

                    return Ok(true);
                }
            }
            Ok(false)
        })
    }
}
