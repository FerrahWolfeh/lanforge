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

/// Sent / won / failed per upstream, `n` distinct queries through `mode`.
async fn counts(mode: UpstreamMode, delays: &[Option<Duration>], n: usize) -> Vec<(u64, u64, u64)> {
    let mut mgrs = Vec::new();
    for d in delays {
        mgrs.push(upstream(*d).await);
    }
    let strategy = UpstreamStrategy::new(mode, mgrs.clone());
    for i in 0..n {
        strategy.resolve(&query(i)).await.unwrap();
    }
    // Late answers of the losers arrive after the winner.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let snaps = strategy.snapshots();
    mgrs.iter()
        .map(|m| {
            let s = snaps.iter().find(|s| s.target == m.target.addr).unwrap();
            (s.total_queries, s.total_wins, s.total_failures)
        })
        .collect()
}

/// Each resolved query has exactly one winner, and "queries" counts what was sent: a late
/// answer from a race loser is an answer, not a query won. (Before, the counters only counted
/// answers: in parallel mode every upstream showed every query, in sequential a slow first
/// upstream looked like it answered them all.)
#[tokio::test(flavor = "multi_thread")]
async fn every_query_has_one_winner_and_queries_count_what_was_sent() {
    let fast = Some(Duration::from_millis(5));
    let slow = Some(Duration::from_millis(600));
    let wins = |c: &[(u64, u64, u64)]| c.iter().map(|x| x.1).sum::<u64>();

    let c = counts(UpstreamMode::Sequential, &[fast, fast, fast], 20).await;
    assert_eq!(
        c,
        vec![(20, 20, 0), (0, 0, 0), (0, 0, 0)],
        "sequential: all on the first"
    );

    // 600 ms > the first hedge delay (400 ms): the next upstream is asked too and wins until
    // the first one's RTT stretches the delay.
    let c = counts(UpstreamMode::Sequential, &[slow, fast], 6).await;
    assert_eq!(wins(&c), 6, "{c:?}");
    assert_eq!(c[0].0, 6, "every query was sent to the first: {c:?}");
    assert!(c[0].1 < 6, "the first lost some races: {c:?}");
    assert_eq!(
        c[1].0, c[1].1,
        "the second is only asked when it then wins: {c:?}"
    );

    let c = counts(UpstreamMode::Parallel, &[fast, fast, fast], 20).await;
    assert!(c.iter().all(|x| x.0 == 20), "parallel sends to all: {c:?}");
    assert_eq!(wins(&c), 20, "{c:?}");
}

/// A backup the sequential order never needed has no evidence: "untested", not "healthy"
/// (the owner's ::1001 showed 0 queries and "healthy").
#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_never_asked_is_untested_not_healthy() {
    let first = upstream(Some(Duration::from_millis(5))).await;
    let backup = upstream(Some(Duration::from_millis(5))).await;
    let strategy = UpstreamStrategy::new(
        UpstreamMode::Sequential,
        vec![Arc::clone(&first), Arc::clone(&backup)],
    );
    strategy.resolve(&query(0)).await.unwrap();
    let snaps = strategy.snapshots();
    let status = |m: &Arc<UpstreamManager>| {
        snaps
            .iter()
            .find(|s| s.target == m.target.addr)
            .unwrap()
            .status
    };
    assert_eq!(status(&first), UpstreamStatus::Healthy);
    assert_eq!(status(&backup), UpstreamStatus::Untested);
}
