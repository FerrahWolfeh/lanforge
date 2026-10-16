use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use lanforge_dns::resolver::recursive::{DnsCache, UpstreamManager, UpstreamMode, UpstreamStrategy};
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::dns::{DnsClass, DnsMessage, DnsQuestion, DnsRecordType};
use tokio::net::UdpSocket;

#[path = "common/mod.rs"]
mod common;

#[tokio::test]
async fn test_coalesced_queries_patch_transaction_id_and_deduplicate() {
    // 1. Bind a mock upstream UDP socket that delays response
    let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_sock.local_addr().unwrap();
    let packet_count = Arc::new(AtomicUsize::new(0));
    let pc_clone = Arc::clone(&packet_count);

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, client_addr)) = upstream_sock.recv_from(&mut buf).await {
            pc_clone.fetch_add(1, Ordering::SeqCst);
            let mut decoder = WireDecoder::new(&buf[..n]);
            if let Some(msg) = decoder.decode_message() {
                // Delay 150ms to allow concurrent followers to enter in_flight
                tokio::time::sleep(Duration::from_millis(150)).await;

                let mut resp_msg = DnsMessage::new();
                resp_msg.header.id = msg.header.id;
                resp_msg.header.qr = true;
                resp_msg.header.rd = msg.header.rd;
                resp_msg.header.ra = true;
                resp_msg.header.qdcount = 1;
                resp_msg.questions = msg.questions;

                let mut encoder = WireEncoder::new();
                let resp_bytes = encoder.encode_message(&resp_msg);
                let _ = upstream_sock.send_to(&resp_bytes, client_addr).await;
            }
        }
    });

    let target = format!("udp://{upstream_addr}").parse::<UpstreamTarget>().unwrap();
    let cache = Arc::new(DnsCache::new(100, 30, None));
    let mgr = UpstreamManager::new(&target, cache).await.unwrap();
    let strategy = UpstreamStrategy::new(UpstreamMode::Sequential, vec![mgr]);

    // Build 3 queries for the same domain with different transaction IDs
    let make_query = |id: u16| {
        let mut query = DnsMessage::new();
        query.header.id = id;
        query.header.rd = true;
        query.header.qdcount = 1;
        query.questions.push(DnsQuestion {
            name: Arc::from("coalesce-test.example.com"),
            qtype: DnsRecordType::A,
            qclass: DnsClass::IN,
        });
        let mut encoder = WireEncoder::new();
        encoder.encode_message(&query)
    };

    let q1 = make_query(1001);
    let q2 = make_query(1002);
    let q3 = make_query(1003);

    // Fire all 3 queries concurrently
    let (res1, res2, res3) = tokio::join!(
        strategy.resolve(&q1),
        strategy.resolve(&q2),
        strategy.resolve(&q3),
    );

    let res1 = res1.expect("q1 failed");
    let res2 = res2.expect("q2 failed");
    let res3 = res3.expect("q3 failed");

    // Verify IDs are preserved / patched correctly for each caller
    assert_eq!(&res1.data[..2], &1001u16.to_be_bytes());
    assert_eq!(&res2.data[..2], &1002u16.to_be_bytes());
    assert_eq!(&res3.data[..2], &1003u16.to_be_bytes());

    // Verify coalescing flags: exactly 1 leader (coalesced == false) and 2 followers (coalesced == true)
    let coalesced_count = [res1.coalesced, res2.coalesced, res3.coalesced]
        .iter()
        .filter(|&&c| c)
        .count();
    assert_eq!(coalesced_count, 2, "Expected exactly 2 coalesced responses");

    // Verify mock upstream received exactly 1 query packet
    assert_eq!(packet_count.load(Ordering::SeqCst), 1, "Expected exactly 1 packet to hit upstream");
}

#[tokio::test]
async fn test_coalesced_queries_pipeline_metrics() {
    let upstream_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_sock.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, client_addr)) = upstream_sock.recv_from(&mut buf).await {
            let mut decoder = WireDecoder::new(&buf[..n]);
            if let Some(msg) = decoder.decode_message() {
                tokio::time::sleep(Duration::from_millis(150)).await;

                let mut resp_msg = DnsMessage::new();
                resp_msg.header.id = msg.header.id;
                resp_msg.header.qr = true;
                resp_msg.header.rd = msg.header.rd;
                resp_msg.header.ra = true;
                resp_msg.header.qdcount = 1;
                resp_msg.questions = msg.questions;

                let mut encoder = WireEncoder::new();
                let resp_bytes = encoder.encode_message(&resp_msg);
                let _ = upstream_sock.send_to(&resp_bytes, client_addr).await;
            }
        }
    });

    let target = format!("udp://{upstream_addr}").parse::<UpstreamTarget>().unwrap();
    let lanforge_ctx = common::init_test_context();
    let dns_cfg = common::mock_config();
    let dns_ctx = common::mock_dns_context(lanforge_ctx, dns_cfg).await;

    let mgr = UpstreamManager::new(&target, Arc::clone(&dns_ctx.cache)).await.unwrap();
    dns_ctx.recursive.replace_upstreams(vec![mgr]);

    let make_query = |id: u16| {
        let mut query = DnsMessage::new();
        query.header.id = id;
        query.header.rd = true;
        query.header.qdcount = 1;
        query.questions.push(DnsQuestion {
            name: Arc::from("pipeline-coalesce.example.com"),
            qtype: DnsRecordType::A,
            qclass: DnsClass::IN,
        });
        let mut encoder = WireEncoder::new();
        encoder.encode_message(&query)
    };

    let q1 = make_query(2001);
    let q2 = make_query(2002);
    let q3 = make_query(2003);

    let src_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));

    let run_one = |query_bytes: Vec<u8>| {
        let ctx_ref = &dns_ctx;
        async move {
            let mut resp = Vec::new();
            let ok = common::process_query_test(&query_bytes, ctx_ref, src_ip, &mut resp).await;
            (ok, resp)
        }
    };

    let (r1, r2, r3) = tokio::join!(
        run_one(q1),
        run_one(q2),
        run_one(q3),
    );

    let (ok1, resp1) = r1;
    let (ok2, resp2) = r2;
    let (ok3, resp3) = r3;

    assert!(ok1.unwrap());
    assert!(ok2.unwrap());
    assert!(ok3.unwrap());

    assert_eq!(&resp1[..2], &2001u16.to_be_bytes());
    assert_eq!(&resp2[..2], &2002u16.to_be_bytes());
    assert_eq!(&resp3[..2], &2003u16.to_be_bytes());

    // Stats verification:
    // All 3 resolved
    assert_eq!(dns_ctx.stats.resolved_total.load(Ordering::Relaxed), 3);
    // Only 1 upstream miss and 1 recursive upstream query
    assert_eq!(dns_ctx.stats.cache_misses.load(Ordering::Relaxed), 1);
    assert_eq!(dns_ctx.stats.recursions.load(Ordering::Relaxed), 1);
    // None counted as cache hits (they are coalesced in-flight queries)
    assert_eq!(dns_ctx.stats.cache_hits.load(Ordering::Relaxed), 0);
}
