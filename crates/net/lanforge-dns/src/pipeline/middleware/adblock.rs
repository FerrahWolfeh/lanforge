#![cfg(feature = "adblock")]

use lanforge_types::network::dns::{DnsRecordType, FilterAction, QueryResult};

use crate::error::DnsError;
use crate::pipeline::{DnsPipelineRequest, Middleware};
use crate::server::{DnsContext, DnsLogEvent};
use std::future::Future;
use std::pin::Pin;

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
                let Some(m) = filter.check_domain(&req.domain) else {
                    return Ok(false);
                };
                if m.action == FilterAction::Block {
                    filter.apply_adblock_wire(req.data, req.header, req.question, ctx, resp);
                    filter.inc_ip_stats(req.src_ip);
                    ctx.stats.inc_blocked();

                    let src_mac = ctx.local.ctx.get_mac_by_ip(req.src_ip);
                    ctx.record_log(DnsLogEvent {
                        src_ip: req.src_ip,
                        src_mac,
                        domain: req.domain.clone(),
                        qtype: DnsRecordType::from(req.question.qtype()),
                        result: QueryResult::Blocked,
                        upstream_us: 0,
                        cached: false,
                        answer: Some("BLOCKED".to_string()),
                        protocol: req.protocol,
                        filter: Some(Box::new(m)),
                    });
                    return Ok(true);
                }
                // Action is Allow (e.g. @@ exception rule or user allowlist)
                *req.filter_match.lock() = Some(Box::new(m));
            }
            Ok(false)
        })
    }
}
