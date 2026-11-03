//! Per-upstream accounting under sequential hedging and parallel races.

use std::sync::Arc;
use std::time::{Duration, Instant};

use lanforge_dns::resolver::recursive::{
    DnsCache, UpstreamManager, UpstreamMode, UpstreamStrategy,
};
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsQuestion, DnsRecordType, UpstreamStatus,
};
use tokio::net::UdpSocket;

/// A local UDP upstream answering every query after `delay` (`None` = never answers).
async fn upstream(delay: Option<Duration>) -> Arc<UpstreamManager> {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap();
    if let Some(delay) = delay {
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, client)) = sock.recv_from(&mut buf).await {
                let Some(msg) = WireDecoder::new(&buf[..n]).decode_message() else {
                    continue;
                };
                let mut resp = DnsMessage::new();
                resp.header.id = msg.header.id;
                resp.header.qr = true;
                resp.header.rd = msg.header.rd;
                resp.header.ra = true;
                resp.header.qdcount = 1;
                resp.questions = msg.questions;
                let bytes = WireEncoder::new().encode_message(&resp).to_vec();
                let sock = Arc::clone(&sock);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = sock.send_to(&bytes, client).await;
                });
            }
        });
    } else {
        // Keep the socket open, never answer.
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while sock.recv_from(&mut buf).await.is_ok() {}
        });
    }
    let target = format!("udp://{addr}").parse::<UpstreamTarget>().unwrap();
    UpstreamManager::new(&target, Arc::new(DnsCache::new(100, 30, None)))
        .await
        .unwrap()
}

fn query(i: usize) -> Vec<u8> {
    let mut q = DnsMessage::new();
    q.header.id = u16::try_from(i % 60000).unwrap();
    q.header.rd = true;
    q.header.qdcount = 1;
    q.questions.push(DnsQuestion {
        name: Arc::from(format!("q{i}.example.com")),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });
    WireEncoder::new().encode_message(&q).to_vec()
}

/// A mute first upstream in sequential mode: each query waited the hedge delay (400 ms) and
/// went to the next one, the abandoned attempt was never counted, so the mute upstream stayed
/// "healthy" and first forever. Unanswered abandoned attempts now count as failures: it
/// degrades, drops out of the order, and queries stop paying the hedge delay.
#[tokio::test(flavor = "multi_thread")]
async fn a_mute_first_upstream_degrades_and_stops_costing_the_hedge_delay() {
    let mute = upstream(None).await;
    let fast = upstream(Some(Duration::from_millis(5))).await;
    let strategy = UpstreamStrategy::new(UpstreamMode::Sequential, vec![Arc::clone(&mute), fast]);

    for i in 0..6 {
        strategy.resolve(&query(i)).await.unwrap();
    }
    // The abandoned attempts expire; the next query that reaches the mute upstream counts them.
    tokio::time::sleep(Duration::from_millis(3200)).await;
    strategy.resolve(&query(6)).await.unwrap();

    let snaps = strategy.snapshots();
    let snap = snaps.iter().find(|s| s.target == mute.target.addr).unwrap();
    assert!(snap.total_failures >= 5, "{snap:?}");
    assert_eq!(snap.status, UpstreamStatus::Degraded, "{snap:?}");

    let start = Instant::now();
    strategy.resolve(&query(7)).await.unwrap();
    let took = start.elapsed();
    assert!(
        took < Duration::from_millis(200),
        "still waits for the mute upstream: {took:?}"
    );
}
