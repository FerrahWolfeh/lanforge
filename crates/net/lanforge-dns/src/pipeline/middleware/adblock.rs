#![cfg(feature = "adblock")]

use lanforge_types::network::dns::{DnsRecordType, FilterAction, QueryResult};

use crate::error::DnsError;
use crate::pipeline::{DnsPipelineRequest, Middleware};
use crate::server::{DnsContext, DnsLogEvent};

#[derive(Default)]
pub struct AdblockMiddleware;

impl AdblockMiddleware {
    pub fn new() -> Self {
        Self
    }

    pub fn run_sync(
        &self,
        ctx: &DnsContext,
        req: &mut DnsPipelineRequest<'_>,
        resp: &mut Vec<u8>,
    ) -> Result<bool, DnsError> {
        if let Some(filter) = &ctx.filter {
            let Some(m) = filter.check_domain(&req.domain) else {
                return Ok(false);
            };
            if m.action == FilterAction::Block {
                filter.apply_adblock_wire(req.data, req.header, req.question, ctx, resp);
                filter.inc_ip_stats(req.src_ip);
                ctx.stats.inc_blocked();

                let answer = if ctx.query_log.is_some() {
                    Some("BLOCKED".to_string())
                } else {
                    None
                };

                ctx.record_log(DnsLogEvent {
                    src_ip: req.src_ip,
                    src_mac: None,
                    domain: &req.domain,
                    qtype: DnsRecordType::from(req.question.qtype()),
                    result: QueryResult::Blocked,
                    upstream_us: 0,
                    cached: false,
                    answer,
                    protocol: req.protocol,
                    filter: Some(Box::new(m)),
                    coalesce_id: None,
                });
                return Ok(true);
            }
            // Action is Allow (e.g. @@ exception rule or user allowlist)
            req.filter_match = Some(Box::new(m));
        }
        Ok(false)
    }
}

impl Middleware for AdblockMiddleware {
    fn run_sync(
        &self,
        ctx: &DnsContext,
        req: &mut DnsPipelineRequest<'_>,
        resp: &mut Vec<u8>,
    ) -> Result<bool, DnsError> {
        AdblockMiddleware::run_sync(self, ctx, req, resp)
    }
}
