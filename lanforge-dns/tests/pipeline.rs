mod common;
use common::*;
use lanforge_core::types::{
    DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecordType, DnsResponseCode,
};
use lanforge_dns::{
    config::RewriteRule,
    wire::{WireDecoder, WireEncoder},
};
use std::sync::Arc;

#[tokio::test]
async fn pipeline_nxdomain_basic() {
    let ctx_instance = init_test_context();
    let cfg = mock_config();
    let ctx = mock_dns_context(ctx_instance, cfg).await;

    let mut query = DnsMessage::new();
    query.header.id = 0x1234;
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from("nonexistent.lan"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });

    let mut encoder = WireEncoder::new();
    let data = encoder.encode_message(&query);
    let mut resp_buf = Vec::new();

    let has_resp = process_query_test(&data, &ctx, "127.0.0.1".parse().unwrap(), &mut resp_buf)
        .await
        .unwrap();

    assert!(has_resp);
    let mut decoder = WireDecoder::new(&resp_buf);
    let resp = decoder.decode_message().unwrap();
    assert_eq!(resp.header.rcode, DnsResponseCode::NXDomain);
}

#[tokio::test]
#[cfg(feature = "adblock")]
async fn pipeline_adblocking() {
    use std::collections::HashSet;

    use lanforge_dns::resolver::filter::DiskBlocklist;

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
    let temp_path = std::env::temp_dir().join("test_blocklist.rkyv");
    let bl =
        DiskBlocklist::build(domains, &temp_path, 100).expect("Failed to build test blocklist");

    filter.replace_blocklist(bl);
    filter.set_enabled(true);

    let mut query = DnsMessage::new();
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from("doubleclick.net"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });

    let mut encoder = WireEncoder::new();
    let data = encoder.encode_message(&query);
    let mut resp_buf = Vec::new();

    let has_resp = process_query_test(&data, &dns_ctx, "127.0.0.1".parse().unwrap(), &mut resp_buf)
        .await
        .unwrap();

    assert!(has_resp);
    let mut decoder = WireDecoder::new(&resp_buf);
    let resp = decoder.decode_message().unwrap();

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
        answer: "10.10.10.10".to_string(),
        rtype: DnsRecordType::A,
    });

    let ctx = mock_dns_context(ctx_instance, cfg).await;

    let mut query = DnsMessage::new();
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from("portal.local"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });

    let mut encoder = WireEncoder::new();
    let data = encoder.encode_message(&query);
    let mut resp_buf = Vec::new();

    let has_resp = process_query_test(&data, &ctx, "127.0.0.1".parse().unwrap(), &mut resp_buf)
        .await
        .unwrap();

    assert!(has_resp, "Should have a response for rewrite");
    let mut decoder = WireDecoder::new(&resp_buf);
    let resp = decoder.decode_message().unwrap();
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
    use lanforge_core::types::network::dns::QueryResult;
    use lanforge_dns::resolver::filter::DiskBlocklist;
    use std::collections::HashSet;

    let ctx_instance = init_test_context();
    let mut cfg = mock_config();
    cfg.adblock_enabled = true;

    let dns_ctx = mock_dns_context(ctx_instance, cfg).await;
    let filter = dns_ctx.filter.as_ref().unwrap();

    let mut domains = HashSet::new();
    domains.insert("ads.com".to_string());
    let temp_path = std::env::temp_dir().join("test_cache_block.rkyv");
    let bl = DiskBlocklist::build(domains, &temp_path, 100).unwrap();
    filter.replace_blocklist(bl);
    filter.set_enabled(true);

    let mut query = DnsMessage::new();
    query.header.id = 0x1111;
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from("ads.com"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });

    let mut encoder = WireEncoder::new();
    let data = encoder.encode_message(&query);
    let mut resp_buf = Vec::new();

    // 1. First query -> Should be Blocked
    let has_resp = process_query_test(&data, &dns_ctx, "127.0.0.1".parse().unwrap(), &mut resp_buf)
        .await
        .unwrap();
    assert!(has_resp);
    assert_eq!(dns_ctx.stats.snapshot().blocked_queries, 1);

    // 2. Second query (same) -> Should be CachedBlock
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

    // Check logs for the second query
    let recent = dns_ctx.query_log.as_ref().unwrap().get_recent(2);
    assert_eq!(recent[0].result, QueryResult::CachedBlock);
    assert_eq!(dns_ctx.stats.snapshot().cache_hits, 1);
}
