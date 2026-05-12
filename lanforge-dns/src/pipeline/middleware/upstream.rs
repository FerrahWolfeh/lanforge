use lanforge_core::types::DnsResponseCode;
use lanforge_core::types::ndp::QueryResult;
use lanforge_core::types::ndp::dns::DnsRecordType;

use crate::error::DnsError;
use crate::pipeline::Middleware;
use crate::resolver::filter::labels_to_domain;
use crate::server::DnsContext;
use crate::wire::{WireDecoder, WireHeader, WireQuestion};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

#[derive(Default)]
pub struct UpstreamMiddleware;

impl UpstreamMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl Middleware for UpstreamMiddleware {
    fn run<'a>(
        &'a self,
        ctx: &'a DnsContext,
        data: &'a [u8],
        _header: &'a WireHeader,
        question: &'a WireQuestion<'a>,
        src_ip: IpAddr,
        resp: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DnsError>> + Send + 'a>> {
        Box::pin(async move {
            let start = std::time::Instant::now();
            match ctx.recursive.resolve(data).await {
                Ok((upstream_resp, cached)) => {
                    let elapsed = start.elapsed().as_micros() as u32;

                    ctx.stats.inc_resolved();
                    if cached {
                        ctx.stats.inc_cache_hit();
                    } else {
                        ctx.stats.inc_cache_miss();
                    }

                    let result = if cached {
                        QueryResult::Cached
                    } else {
                        QueryResult::Forwarded
                    };

                    let domain = labels_to_domain(question.labels());
                    let src_mac = ctx.local.ctx.get_mac_by_ip(src_ip);

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

                    ctx.record_log(crate::server::DnsLogEvent {
                        src_ip,
                        src_mac,
                        domain: Arc::from(domain),
                        qtype: DnsRecordType::from(question.qtype()),
                        result,
                        upstream_us: elapsed,
                        cached,
                        answer,
                    });
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
