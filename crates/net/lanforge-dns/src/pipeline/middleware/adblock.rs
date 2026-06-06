#![cfg(feature = "adblock")]

use lanforge_dns_wire::WireResponseScanner;
use lanforge_types::network::dns::{DnsRecordType, QueryResult};

use crate::error::DnsError;
use crate::pipeline::{DnsPipelineRequest, Middleware};
use crate::resolver::labels_to_domain;
use crate::resolver::recursive::cache::CacheKey;
use crate::server::{DnsContext, DnsLogEvent};
use std::future::Future;
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
        req: DnsPipelineRequest<'a>,
        resp: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, DnsError>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(filter) = &ctx.filter {
                let domain = labels_to_domain(req.question.labels());
                if filter.should_block(&domain) {
                    filter.apply_adblock_wire(req.data, req.header, req.question, ctx, resp);
                    filter.inc_ip_stats(req.src_ip);
                    ctx.stats.inc_blocked();

                    // Cache the block
                    let scanner = WireResponseScanner::new(resp);
                    let (offsets, min_ttl) = scanner.scan_ttls();
                    let key = CacheKey {
                        qname: req.question.qname_raw().to_vec(),
                        qtype: req.question.qtype(),
                        qclass: req.question.qclass(),
                    };
                    ctx.cache.insert(key, resp.clone(), offsets, min_ttl, true);

                    let src_mac = ctx.local.ctx.get_mac_by_ip(req.src_ip);
                    ctx.record_log(DnsLogEvent {
                        src_ip: req.src_ip,
                        src_mac,
                        domain: Arc::from(domain),
                        qtype: DnsRecordType::from(req.question.qtype()),
                        result: QueryResult::Blocked,
                        upstream_us: 0,
                        cached: false,
                        answer: Some("BLOCKED".to_string()),
                        protocol: req.protocol,
                    });
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }
}
