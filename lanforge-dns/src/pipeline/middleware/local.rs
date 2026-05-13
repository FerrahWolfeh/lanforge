use lanforge_core::types::{DnsRecordType, DnsResponseCode, QueryResult};

use crate::error::DnsError;
use crate::pipeline::Middleware;
use crate::resolver::filter::labels_to_domain;
use crate::server::{DnsContext, DnsLogEvent};
use crate::wire::{WireDecoder, WireHeader, WireQuestion};
use std::future::Future;
use std::net::IpAddr;
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
        data: &'a [u8],
        header: &'a WireHeader,
        question: &'a WireQuestion<'a>,
        _src_ip: IpAddr,
        resp: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DnsError>> + Send + 'a>> {
        Box::pin(async move {
            let has_upstreams = !ctx.recursive.is_empty();
            if ctx
                .local
                .resolve_local_wire(data, header, question, has_upstreams, resp)
            {
                ctx.stats.inc_auth();

                let domain = labels_to_domain(question.labels());
                let src_mac = ctx.local.ctx.get_mac_by_ip(_src_ip);

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
                    src_ip: _src_ip,
                    src_mac,
                    domain: Arc::from(domain),
                    qtype: DnsRecordType::from(question.qtype()),
                    result: QueryResult::Local,
                    upstream_us: 0,
                    cached: false,
                    answer,
                });

                return Ok(true);
            }
            Ok(false)
        })
    }
}
