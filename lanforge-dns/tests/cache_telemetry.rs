mod common;
use common::*;
use lanforge_core::types::{
    DnsClass, DnsMessage, DnsQuestion, DnsRecordType, QueryLogEntry, QueryResult,
};
use lanforge_dns::resolver::recursive::cache::{CacheKey, DnsCache};
use lanforge_dns::wire::{WireEncoder, WireQuestion};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn cache_hit_and_ttl_scrubbing() {
    let cache = DnsCache::new(100, 30);

    // 1. Create a query
    let mut query = DnsMessage::new();
    query.header.id = 0xAAAA;
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from("example.com"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    let mut encoder = WireEncoder::new();
    let query_data = encoder.encode_message(&query);
    let question = WireQuestion::parse(&query_data).expect("Should parse query with qdcount=1");

    // 2. Create a mock response
    let mut resp_data = vec![0u8; 64];
    resp_data[0..2].copy_from_slice(&0xBBBBu16.to_be_bytes()); // Original ID
    // Add a TTL field at offset 40 (example)
    let ttl_offset = 40;
    let original_ttl: u32 = 60;
    resp_data[ttl_offset..ttl_offset + 4].copy_from_slice(&original_ttl.to_be_bytes());

    let key = CacheKey {
        qname: question.qname_raw().to_vec(),
        qtype: question.qtype(),
        qclass: question.qclass(),
    };

    // 3. Insert into cache
    cache.insert(
        key.clone(),
        resp_data.clone(),
        vec![ttl_offset],
        original_ttl,
        false,
    );

    let (hit, _is_block) = cache
        .get_wire(&query_data, &question)
        .expect("Should be a cache hit");
    assert_eq!(
        hit[0..2],
        0xAAAAu16.to_be_bytes(),
        "ID should be patched to match query"
    );

    // 5. Test TTL scrubbing by manually adjusting the entry
    {
        let mut entry = cache.cache.get_mut(&key).unwrap();
        // Move created_at 10 seconds into the past
        entry.created_at -= Duration::from_secs(10);
    }

    let (hit_scrubbed, _) = cache
        .get_wire(&query_data, &question)
        .expect("Should be a cache hit");
    let scrubbed_ttl = u32::from_be_bytes([
        hit_scrubbed[ttl_offset],
        hit_scrubbed[ttl_offset + 1],
        hit_scrubbed[ttl_offset + 2],
        hit_scrubbed[ttl_offset + 3],
    ]);
    assert_eq!(scrubbed_ttl, 50, "TTL should be decremented by 10 seconds");
}

#[tokio::test]
async fn stats_gathering() {
    let ctx = init_test_context();
    let cfg = mock_config();
    let dns_ctx = mock_dns_context(ctx, cfg);

    // Simulate some activity
    dns_ctx.stats.inc_requests();
    dns_ctx.stats.inc_cache_hit();
    dns_ctx.stats.inc_resolved();

    let snapshot = dns_ctx.stats.snapshot();
    assert_eq!(snapshot.requests_total, 1);
    assert_eq!(snapshot.cache_hits, 1);
    assert_eq!(snapshot.resolved_total, 1);
    assert_eq!(snapshot.cache_misses, 0);
}

#[tokio::test]
async fn query_logging_ring_buffer() {
    let ctx = init_test_context();
    let cfg = mock_config();
    let dns_ctx = mock_dns_context(ctx, cfg);

    let query_log = dns_ctx
        .query_log
        .as_ref()
        .expect("Query log should be enabled");

    // Log a few queries
    for i in 0..5 {
        query_log.push(QueryLogEntry {
            timestamp: 0,
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            domain: Arc::from(format!("query-{i}.lan")),
            upstream_us: 10,
            qtype: DnsRecordType::A,
            result: QueryResult::Local,
            cached: false,
            src_mac: None,
            answer: Some("1.1.1.1".to_string()),
        });
    }

    let logs = query_log.get_recent(10);
    assert_eq!(logs.len(), 5);
    assert_eq!(logs[0].domain.as_ref(), "query-4.lan"); // Most recent first
}

#[test]
fn cache_expiration() {
    let cache = DnsCache::new(10, 30);
    let key = CacheKey {
        qname: b"\x04test\x00".to_vec(),
        qtype: 1,
        qclass: 1,
    };

    // Insert with very short TTL
    cache.insert(key.clone(), vec![0; 64], vec![], 1, false);

    // Manually expire it
    {
        let mut entry = cache.cache.get_mut(&key).unwrap();
        entry.expires_at = Instant::now() - Duration::from_secs(1);
    }

    // Should be a miss now
    let mut data = vec![0u8; 12];
    data[5] = 1; // qdcount = 1
    data.extend_from_slice(b"\x04test\x00\x00\x01\x00\x01");
    let question = WireQuestion::parse(&data).expect("Should parse with qdcount=1");

    assert!(
        cache.get_wire(&data, &question).is_none(),
        "Should be a cache miss due to expiration"
    );
}
