use super::common::*;
use lanforge_types::network::dns::{
    DnsRData, DnsRecordType, DnsResponseCode, adblock::RewriteRule,
};

#[tokio::test]
async fn pipeline_nxdomain_basic() {
    let ctx_instance = init_test_context();
    let cfg = mock_config();
    let ctx = mock_dns_context(ctx_instance, cfg).await;

    let data = DnsPacketBuilder::query("nonexistent.lan", DnsRecordType::A)
        .with_id(0x1234)
        .build_bytes();
    let mut resp_buf = Vec::new();

    let has_resp = process_query_test(&data, &ctx, "127.0.0.1".parse().unwrap(), &mut resp_buf)
        .await
        .unwrap();

    assert!(has_resp);
    let resp = parse_response(&resp_buf).expect("Valid response");
    assert_eq!(resp.header.rcode, DnsResponseCode::NXDomain);
}

#[tokio::test]
#[cfg(feature = "adblock")]
async fn pipeline_adblocking() {
    use std::collections::HashSet;

    use crate::resolver::filter::DiskBlocklist;

    let ctx_instance = init_test_context();
    let mut cfg = mock_config();
    cfg.adblock_enabled = true;

    let dns_ctx = mock_dns_context(ctx_instance, cfg).await;
    let filter = dns_ctx
        .filter
        .as_ref()
        .expect("Filter should be initialized");

    let mut domains = HashSet::new();
    domains.insert("doubleclick.net".to_string());
    let dir = tempfile::tempdir().unwrap();
    let temp_path = dir.path().join("blocklist.rkyv");
    let bl =
        DiskBlocklist::build(domains, &temp_path, 100).expect("Failed to build test blocklist");

    filter.replace_blocklist(bl);
    filter.set_enabled(true);

    let data = DnsPacketBuilder::query("doubleclick.net", DnsRecordType::A)
        .with_id(0x1234)
        .build_bytes();
    let mut resp_buf = Vec::new();

    let has_resp = process_query_test(&data, &dns_ctx, "127.0.0.1".parse().unwrap(), &mut resp_buf)
        .await
        .unwrap();

    assert!(has_resp);
    let resp = parse_response(&resp_buf).expect("Valid response");

    assert_eq!(resp.header.rcode, DnsResponseCode::NXDomain);
    assert_eq!(dns_ctx.stats.snapshot().blocked_queries, 1);
}

#[tokio::test]
async fn pipeline_rewrite_rule() {
    let ctx_instance = init_test_context();
    let mut cfg = mock_config();
    cfg.rewrites.push(RewriteRule {
        id: None,
        domain: "portal.local".to_string(),
        answer: "10.10.10.10".parse().unwrap(),
        rtype: DnsRecordType::A,
    });

    let ctx = mock_dns_context(ctx_instance, cfg).await;

    let data = DnsPacketBuilder::query("portal.local", DnsRecordType::A)
        .with_id(0x5678)
        .build_bytes();
    let mut resp_buf = Vec::new();

    let has_resp = process_query_test(&data, &ctx, "127.0.0.1".parse().unwrap(), &mut resp_buf)
        .await
        .unwrap();

    assert!(has_resp, "Should have a response for rewrite");
    let resp = parse_response(&resp_buf).expect("Valid response");
    assert_eq!(resp.header.rcode, DnsResponseCode::NoError);
    assert_eq!(resp.answers.len(), 1);
    if let DnsRData::A(ip) = &resp.answers[0].rdata {
        assert_eq!(ip.to_string(), "10.10.10.10");
    } else {
        panic!("Wrong RData type: {:?}", resp.answers[0].rdata);
    }
}

#[tokio::test]
#[cfg(feature = "adblock")]
async fn pipeline_cached_block() {
    use crate::resolver::filter::DiskBlocklist;
    use lanforge_types::network::dns::QueryResult;
    use std::collections::HashSet;

    let ctx_instance = init_test_context();
    let mut cfg = mock_config();
    cfg.adblock_enabled = true;

    let dns_ctx = mock_dns_context(ctx_instance, cfg).await;
    let filter = dns_ctx.filter.as_ref().unwrap();

    let mut domains = HashSet::new();
    domains.insert("ads.com".to_string());
    let dir = tempfile::tempdir().unwrap();
    let temp_path = dir.path().join("blocklist.rkyv");
    let bl = DiskBlocklist::build(domains, &temp_path, 100).unwrap();
    filter.replace_blocklist(bl);
    filter.set_enabled(true);

    let data = DnsPacketBuilder::query("ads.com", DnsRecordType::A)
        .with_id(0x1111)
        .build_bytes();
    let mut resp_buf = Vec::new();

    // 1. First query -> Should be Blocked
    let has_resp = process_query_test(&data, &dns_ctx, "127.0.0.1".parse().unwrap(), &mut resp_buf)
        .await
        .unwrap();
    assert!(has_resp);
    assert_eq!(dns_ctx.stats.snapshot().blocked_queries, 1);

    // 2. Second query (same) -> Per D9, blocked queries are NOT cached.
    let mut resp_buf2 = Vec::new();
    let has_resp2 = process_query_test(
        &data,
        &dns_ctx,
        "127.0.0.1".parse().unwrap(),
        &mut resp_buf2,
    )
    .await
    .unwrap();
    assert!(has_resp2);

    let recent = dns_ctx.query_log.as_ref().unwrap().get_recent(2);
    assert_eq!(recent[0].result, QueryResult::Blocked);
    assert_eq!(dns_ctx.stats.snapshot().blocked_queries, 2);
    assert_eq!(dns_ctx.stats.snapshot().cache_hits, 0);

    // 3. Immediately unblock: query should not be served from a stale block cache
    filter.set_enabled(false);
    let mut resp_buf3 = Vec::new();
    let res3 = process_query_test(
        &data,
        &dns_ctx,
        "127.0.0.1".parse().unwrap(),
        &mut resp_buf3,
    )
    .await;
    assert!(res3.is_err());
}
