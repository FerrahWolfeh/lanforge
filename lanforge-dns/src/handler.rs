use crate::error::DnsError;
use crate::resolver::LocalResolver;
use crate::response::ResponseBuilder;
use crate::server::DnsContext;
use crate::wire::{WireHeader, WireOptScanner, WireQuestion, WireResponseWriter};
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use lanforge_core::types::network::QueryResult;
use std::net::IpAddr;
use std::time::Instant;

#[cfg(feature = "adblock")]
use crate::filter::labels_to_domain;

/// The extra-hot path: Initial query triage and routing.
///
/// This function uses the zero-allocation wire parser to decide how to handle
/// the query before performing a full parse into the provided buffer.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub async fn process_query(
    data: &[u8],
    ctx: &DnsContext,
    src_addr: IpAddr,
    resp: &mut Vec<u8>,
) -> Result<bool, DnsError> {
    let start_instant = Instant::now();
    ctx.stats.inc_requests();

    // PHASE 1: Zero-Alloc Triage
    let Some(header) = WireHeader::parse(data) else {
        return Ok(false);
    };
    if !header.is_query() {
        return Ok(false);
    }

    let Some(question) = WireQuestion::parse(data) else {
        return process_query_fallback(data, ctx, src_addr, resp, start_instant).await;
    };

    #[cfg(feature = "adblock")]
    let domain = labels_to_domain(question.labels());
    #[cfg(not(feature = "adblock"))]
    let domain = String::new(); // Not fully extracted if adblock is disabled, but could be for logging.

    // PHASE 2: Local Resolution Attempt
    let resolver = LocalResolver::new(&ctx.cfg, &ctx.ctx);
    if resolver.resolve_local_wire(data, &header, &question, !ctx.upstreams.is_empty(), resp) {
        ctx.stats.inc_auth();
        ctx.stats.inc_cache_hit();
        ctx.record_log(
            src_addr,
            domain,
            question.qtype(),
            QueryResult::Local,
            0,
            false,
        );
        return Ok(true);
    }

    // PHASE 2.2: DNS Rewrites
    #[cfg(feature = "adblock")]
    if let Some(adblocker) = &ctx.adblocker
        && adblocker.try_resolve_rewrite_wire(data, &header, &question, ctx, &domain, resp)
    {
        ctx.stats.inc_auth();
        ctx.record_log(
            src_addr,
            domain,
            question.qtype(),
            QueryResult::Rewritten,
            0,
            false,
        );
        return Ok(true);
    }

    ctx.stats.inc_cache_miss();

    // PHASE 2.5: Adblock Filtering
    #[cfg(feature = "adblock")]
    if let Some(adblocker) = &ctx.adblocker
        && adblocker.is_enabled()
        && adblocker.should_block(&domain)
    {
        ctx.stats.inc_blocked();
        ctx.ctx.inc_dns_blocked();
        adblocker.inc_ip_stats(src_addr);
        adblocker.apply_adblock_wire(data, &header, &question, ctx, resp);
        ctx.record_log(
            src_addr,
            domain,
            question.qtype(),
            QueryResult::Blocked,
            0,
            false,
        );
        return Ok(true);
    }

    // PHASE 3: Recursive Forwarding
    if resolve_recursive(
        data,
        ctx,
        src_addr,
        domain.clone(),
        question.qtype(),
        start_instant,
        resp,
    )
    .await
    {
        return Ok(true);
    }

    let edns = WireOptScanner::scan(data, &header, &question);
    let ra = !ctx.upstreams.is_empty();
    WireResponseWriter::write_error_response(data, &question, 3, edns, ra, resp);
    let elapsed = u32::try_from(start_instant.elapsed().as_micros()).unwrap_or(u32::MAX);
    ctx.record_log(
        src_addr,
        domain,
        question.qtype(),
        QueryResult::NxDomain,
        elapsed,
        false,
    );
    Ok(true)
}

/// Fallback logic for queries that are too complex for the zero-alloc wire parser.
#[cfg_attr(feature = "hotpath", hotpath::measure)]
pub async fn process_query_fallback(
    data: &[u8],
    ctx: &DnsContext,
    src_addr: IpAddr,
    resp: &mut Vec<u8>,
    start_instant: Instant,
) -> Result<bool, DnsError> {
    let Ok(query) = Message::from_bytes(data) else {
        return Ok(false);
    };
    let rb = ResponseBuilder::new(&query, ctx);
    let question = query.queries.first().ok_or(DnsError::WireParseError)?;
    let qname = question.name();
    let qtype = question.query_type();

    // PHASE 2: Local Resolution Attempt (Fallback path)
    let resolver = LocalResolver::new(&ctx.cfg, &ctx.ctx);
    if resolver.resolve_local_fallback(&rb, qname, qtype, resp)? {
        ctx.stats.inc_auth();
        ctx.stats.inc_cache_hit();
        ctx.record_log(
            src_addr,
            qname.to_string(),
            qtype.into(),
            QueryResult::Local,
            0,
            false,
        );
        return Ok(true);
    }

    // PHASE 2.2: DNS Rewrites (Fallback path)
    #[cfg(feature = "adblock")]
    if let Some(adblocker) = &ctx.adblocker
        && adblocker.try_resolve_rewrite_fallback(ctx, &rb, qname, qtype, src_addr, resp)?
    {
        return Ok(true);
    }

    ctx.stats.inc_cache_miss();

    // PHASE 2.5: Adblock Filtering (Fallback path)
    #[cfg(feature = "adblock")]
    if let Some(adblocker) = &ctx.adblocker
        && adblocker.apply_adblock_fallback(ctx, &rb, qname, qtype, src_addr, resp)?
    {
        return Ok(true);
    }

    // PHASE 3: Recursive Forwarding
    if resolve_recursive(
        data,
        ctx,
        src_addr,
        qname.to_string(),
        qtype.into(),
        start_instant,
        resp,
    )
    .await
    {
        return Ok(true);
    }

    resp.clear();
    resp.extend_from_slice(&rb.nxdomain()?);
    let elapsed = u32::try_from(start_instant.elapsed().as_micros()).unwrap_or(u32::MAX);
    ctx.record_log(
        src_addr,
        qname.to_string(),
        qtype.into(),
        QueryResult::NxDomain,
        elapsed,
        false,
    );
    Ok(true)
}

async fn resolve_recursive(
    data: &[u8],
    ctx: &DnsContext,
    src_addr: IpAddr,
    domain: String,
    qtype: u16,
    start_instant: Instant,
    resp: &mut Vec<u8>,
) -> bool {
    match ctx.upstream_strategy.resolve(data).await {
        Ok((upstream_resp, from_cache)) => {
            ctx.stats.inc_recursive();
            resp.clear();
            resp.extend_from_slice(&upstream_resp);
            let result = if from_cache {
                QueryResult::Cached
            } else {
                QueryResult::Forwarded
            };
            let elapsed = u32::try_from(start_instant.elapsed().as_micros()).unwrap_or(u32::MAX);
            ctx.record_log(src_addr, domain, qtype, result, elapsed, from_cache);
            true
        }
        Err(e) => {
            if !matches!(e, DnsError::Refused) {
                ctx.stats.inc_upstream_error();
            }
            false
        }
    }
}
