use std::sync::Arc;
use std::time::{Duration, Instant};

use lanforge_dns::resolver::recursive::{
    DnsCache, UpstreamManager, UpstreamMode, UpstreamStrategy,
};
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::dns::{DnsClass, DnsMessage, DnsQuestion, DnsRecordType};
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_sequential_hedging_recovers_from_unresponsive_upstream_in_under_1200ms() {
    // 1. Silent upstream (never responds to queries)
    let silent_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let silent_addr = silent_sock.local_addr().unwrap();

    // 2. Fast responsive upstream
    let fast_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fast_addr = fast_sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, client_addr)) = fast_sock.recv_from(&mut buf).await {
            let mut decoder = WireDecoder::new(&buf[..n]);
            if let Some(msg) = decoder.decode_message() {
                let mut resp_msg = DnsMessage::new();
                resp_msg.header.id = msg.header.id;
                resp_msg.header.qr = true;
                resp_msg.header.rd = msg.header.rd;
                resp_msg.header.ra = true;
                resp_msg.header.qdcount = 1;
                resp_msg.questions = msg.questions;

                let mut encoder = WireEncoder::new();
                let resp_bytes = encoder.encode_message(&resp_msg);
                let _ = fast_sock.send_to(&resp_bytes, client_addr).await;
            }
        }
    });

    let target_silent = format!("udp://{silent_addr}")
        .parse::<UpstreamTarget>()
        .unwrap();
    let target_fast = format!("udp://{fast_addr}")
        .parse::<UpstreamTarget>()
        .unwrap();

    let cache = Arc::new(DnsCache::new(100, 30, None));
    let mgr_silent = UpstreamManager::new(&target_silent, Arc::clone(&cache))
        .await
        .unwrap();
    let mgr_fast = UpstreamManager::new(&target_fast, Arc::clone(&cache))
        .await
        .unwrap();

    // In Sequential mode: silent upstream is tried first, then fast upstream
    let strategy = UpstreamStrategy::new(UpstreamMode::Sequential, vec![mgr_silent, mgr_fast]);

    let mut query = DnsMessage::new();
    query.header.id = 4321;
    query.header.rd = true;
    query.header.qdcount = 1;
    query.questions.push(DnsQuestion {
        name: Arc::from("hedging-test.example.com"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    let mut encoder = WireEncoder::new();
    let query_bytes = encoder.encode_message(&query);

    let start = Instant::now();
    let res = strategy.resolve(&query_bytes).await;
    let elapsed = start.elapsed();

    assert!(
        res.is_ok(),
        "Expected resolution to succeed via hedged upstream"
    );
    let resolved = res.unwrap();
    assert_eq!(&resolved.data[..2], &4321u16.to_be_bytes());

    // Since initial EWMA is 0, default hedge_delay is 400ms.
    // Resolution should finish in ~400-500ms, well below the previous 3000ms+ timeout!
    assert!(
        elapsed < Duration::from_millis(1200),
        "Expected elapsed < 1200ms with hedging, but took {:?}",
        elapsed
    );
    assert!(
        elapsed >= Duration::from_millis(350),
        "Expected elapsed >= 350ms (hedged request delay), took {:?}",
        elapsed
    );
}
