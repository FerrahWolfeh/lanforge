use lanforge_core::types::network::dns::{DnsRecordType, QueryResult};

use crate::error::DnsError;
use crate::pipeline::Middleware;
use crate::resolver::filter::labels_to_domain;
use crate::server::{DnsContext, DnsLogEvent};
use crate::wire::{WireHeader, WireQuestion};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

#[derive(Default)]
pub struct AdblockMiddleware;

impl AdblockMiddleware {
    pub fn new() -> Self {
        Self
    }
}

impl Middleware for AdblockMiddleware {
    fn run<'a>(
        &'a self,
        ctx: &'a DnsContext,
        data: &'a [u8],
        header: &'a WireHeader,
        question: &'a WireQuestion<'a>,
        src_ip: IpAddr,
        resp: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DnsError>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(filter) = &ctx.filter {
                let domain = labels_to_domain(question.labels());
                if filter.should_block(&domain) {
                    filter.apply_adblock_wire(data, header, question, ctx, resp);
                    filter.inc_ip_stats(src_ip);
                    ctx.stats.inc_blocked();

                    // Cache the block
                    let scanner = crate::wire::WireResponseScanner::new(resp);
                    let (offsets, min_ttl) = scanner.scan_ttls();
                    let key = crate::resolver::recursive::cache::CacheKey {
                        qname: question.qname_raw().to_vec(),
                        qtype: question.qtype(),
                        qclass: question.qclass(),
                    };
                    ctx.cache.insert(key, resp.clone(), offsets, min_ttl, true);

                    let src_mac = ctx.local.ctx.get_mac_by_ip(src_ip);
                    ctx.record_log(DnsLogEvent {
                        src_ip,
                        src_mac,
                        domain: Arc::from(domain),
                        qtype: DnsRecordType::from(question.qtype()),
                        result: QueryResult::Blocked,
                        upstream_us: 0,
                        cached: false,
                        answer: Some("BLOCKED".to_string()),
                    });
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }
}
