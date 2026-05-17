use lanforge_dns_wire::WireDecoder;
use lanforge_types::network::dns::{DnsRecordType, DnsResponseCode, QueryResult};

use crate::error::DnsError;
use crate::pipeline::{DnsPipelineRequest, Middleware};
use crate::resolver::filter::labels_to_domain;
use crate::server::{DnsContext, DnsLogEvent};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

#[derive(Default)]
pub struct LocalResolverMiddleware;

impl LocalResolverMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl Middleware for LocalResolverMiddleware {
    fn run<'a>(
        &'a self,
        ctx: &'a DnsContext,
        req: DnsPipelineRequest<'a>,
        resp: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DnsError>> + Send + 'a>> {
        Box::pin(async move {
            let has_upstreams = !ctx.recursive.is_empty();
            if ctx
                .local
                .resolve_local_wire(req.data, req.header, req.question, has_upstreams, resp)
            {
                ctx.stats.inc_auth();

                let domain = labels_to_domain(req.question.labels());
                let src_mac = ctx.local.ctx.get_mac_by_ip(req.src_ip);

                // Try to extract answer from the response we just built
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
                    result: QueryResult::Local,
                    upstream_us: 0,
                    cached: false,
                    answer,
                    protocol: req.protocol,
                });

                return Ok(true);
            }
            Ok(false)
        })
    }
}
