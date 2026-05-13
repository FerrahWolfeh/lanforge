use lanforge_core::types::network::dns::{DnsRecordType, QueryResult};

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
pub struct CacheMiddleware;

impl CacheMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl Middleware for CacheMiddleware {
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
            if let Some((cached_resp, is_block)) = ctx.cache.get_wire(data, question) {
                *resp = cached_resp;

                ctx.stats.inc_cache_hit();

                let result = if is_block {
                    QueryResult::CachedBlock
                } else {
                    QueryResult::Cached
                };

                let domain = labels_to_domain(question.labels());
                let src_mac = ctx.local.ctx.get_mac_by_ip(src_ip);

                let mut answer = None;
                let mut decoder = WireDecoder::new(resp);
                if let Some(msg) = decoder.decode_message()
                    && let Some(first) = msg.answers.first()
                {
                    answer = Some(format!("{}", first.rdata));
                }

                ctx.record_log(DnsLogEvent {
                    src_ip,
                    src_mac,
                    domain: Arc::from(domain),
                    qtype: DnsRecordType::from(question.qtype()),
                    result,
                    upstream_us: 0,
                    cached: true,
                    answer,
                });

                return Ok(true);
            }

            Ok(false)
        })
    }
}
