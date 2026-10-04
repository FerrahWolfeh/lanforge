mod common;
use common::*;
use lanforge_dns::resolver::recursive::cache::CacheKey;
use lanforge_dns_wire::{WireDecoder, WireEncoder, WireResponseScanner};
use lanforge_types::device::TransientOrigin;
use lanforge_types::network::dns::upstream::{UpstreamProtocol, UpstreamTarget};
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecord, DnsRecordType, DnsResponseCode,
    adblock::RewriteRule,
};
use lanforge_types::network::{DnsReverseResolver, IpSubnet};
use lanforge_types::update::DeviceUpdate;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

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
        answer: "10.10.10.10".parse().unwrap(),
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
    use lanforge_dns::resolver::filter::DiskBlocklist;
    use lanforge_types::network::dns::QueryResult;
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

    // 2. Second query (same) -> Per D9, blocked queries are NOT cached.
    // The query is evaluated fresh and blocked by the engine without polluting cache.
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

    // Check logs for the second query: still Blocked, no cache hit
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
    // Without an upstream configured, an unblocked query is not served from cache
    // (which would have returned Ok(true) with 0.0.0.0), but instead falls through to resolution.
    assert!(res3.is_err());
}

#[tokio::test]
async fn pipeline_transient_ip_reverse_dns_cached() {
    let ctx_instance = init_test_context();
    let cfg = mock_config();

    // 1. Setup a DnsReverseResolver rule for 100.64.0.0/10
    let resolver_target = UpstreamTarget {
        addr: "127.0.0.1:9999".parse().unwrap(),
        protocol: UpstreamProtocol::Udp,
        hostname: None,
        domain: None,
    };
    let subnet = IpSubnet::from_str("100.64.0.0/10").unwrap();
    let resolver_rule = DnsReverseResolver {
        subnet,
        resolver: resolver_target,
    };
    let _ = ctx_instance.apply(DeviceUpdate::AddReverseResolver {
        resolver: Box::new(resolver_rule),
    });

    let dns_ctx = mock_dns_context(ctx_instance, cfg).await;

    // 2. Mock query and PTR answer that we insert into cache
    let mut query = DnsMessage::new();
    query.header.rd = true;
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from("5.0.64.100.in-addr.arpa"),
        qtype: DnsRecordType::PTR,
        qclass: DnsClass::IN,
    });
    let query_bytes = WireEncoder::new().encode_message(&query);
    let question = lanforge_dns_wire::WireQuestion::parse(&query_bytes).unwrap();

    let mut resp_msg = DnsMessage::new();
    resp_msg.header.qr = true;
    resp_msg.header.qdcount = 1;
    resp_msg.header.ancount = 1;
    resp_msg.questions.push(query.questions[0].clone());
    resp_msg.answers.push(DnsRecord {
        name: query.questions[0].name.clone(),
        rtype: DnsRecordType::PTR,
        rclass: DnsClass::IN,
        ttl: 30,
        rdata: DnsRData::PTR(Arc::from("cached-transient.tailscale.")),
    });
    let resp_bytes = WireEncoder::new().encode_message(&resp_msg);

    let scanner = WireResponseScanner::new(&resp_bytes);
    let (offsets, min_ttl) = scanner.scan_ttls();

    let key = CacheKey::from_question(&question);
    dns_ctx
        .cache
        .insert(key, resp_bytes, offsets, min_ttl, false);

    // 3. Send a dummy query with source IP = 100.64.0.5
    let client_ip = "100.64.0.5".parse::<IpAddr>().unwrap();
    let mut dummy_query = DnsMessage::new();
    dummy_query.header.id = 0x1111;
    dummy_query.header.qdcount = 1;
    dummy_query.questions.push(DnsQuestion {
        name: Arc::from("nonexistent.lan"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    let dummy_bytes = WireEncoder::new().encode_message(&dummy_query);
    let mut resp_buf = Vec::new();

    // This should trigger handle_reverse_dns_trigger in the pipeline run
    let has_resp = process_query_test(&dummy_bytes, &dns_ctx, client_ip, &mut resp_buf)
        .await
        .unwrap();
    assert!(has_resp);

    // 4. Poll until the background task resolves the transient IP
    let mut resolved = false;
    for _ in 0..50 {
        if let Some(host) = dns_ctx.local.ctx.get_transient_host(&client_ip) {
            assert_eq!(host.hostname.name, "cached-transient.tailscale");
            assert_eq!(host.origin, TransientOrigin::Tailscale);
            resolved = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(resolved, "Transient host resolution in background failed");
}
