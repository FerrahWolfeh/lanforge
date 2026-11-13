//! Off-path answers to plain UDP upstream queries (RFC 5452). The source port of an upstream
//! is fixed for its lifetime, so the query ID must be unpredictable (§4.3), and an answer is
//! accepted only when it repeats the question asked (§9.1). Sequential IDs made a spoofed
//! answer a matter of counting.

use crate::resolver::UpstreamManager;
use crate::resolver::recursive::DnsCache;
use crate::test_utils::DnsPacketBuilder;
use lanforge_dns_wire::{WireHeader, WireQuestion};
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::upstream::{UpstreamProtocol, UpstreamTarget};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

async fn manager(addr: SocketAddr) -> Arc<UpstreamManager> {
    let target = UpstreamTarget::at(addr, UpstreamProtocol::Udp, None);
    UpstreamManager::new(&target, addr, Arc::new(DnsCache::new(100, 30, None)))
        .await
        .expect("manager")
}

/// `query` turned into its (empty) answer.
fn answer(query: &[u8]) -> Vec<u8> {
    let mut resp = query.to_vec();
    resp[2] |= 0x80; // QR
    resp
}

fn query(name: &str) -> Vec<u8> {
    DnsPacketBuilder::query(name, DnsRecordType::A).build_bytes()
}

fn qname(msg: &[u8]) -> Vec<u8> {
    WireQuestion::parse(msg)
        .expect("question")
        .qname_raw()
        .to_vec()
}

#[tokio::test]
async fn upstream_query_ids_are_not_sequential() {
    const QUERIES: usize = 32;
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let addr = upstream.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let mut ids = Vec::with_capacity(QUERIES);
        for _ in 0..QUERIES {
            let (len, from) = upstream.recv_from(&mut buf).await.expect("recv");
            ids.push(WireHeader::parse(&buf[..len]).expect("header").id());
            upstream
                .send_to(&answer(&buf[..len]), from)
                .await
                .expect("send");
        }
        ids
    });

    let mgr = manager(addr).await;
    for i in 0..QUERIES {
        timeout(
            Duration::from_secs(5),
            mgr.forward(&query(&format!("q{i}.example"))),
        )
        .await
        .expect("answered in time")
        .expect("answered");
    }
    let ids = server.await.expect("server");
    let steps = ids
        .windows(2)
        .filter(|w| w[1].wrapping_sub(w[0]) == 1)
        .count();
    // Random IDs make a +1 step a 1-in-65536 event.
    assert!(steps < 2, "IDs follow each other: {ids:?}");
}

#[tokio::test]
async fn answer_to_another_question_is_ignored() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let addr = upstream.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (len, from) = upstream.recv_from(&mut buf).await.expect("recv");
        let real = &buf[..len];
        // An off-path guess that got port and ID right, for another name, arrives first.
        let mut forged = answer(&query("evil.example"));
        forged[..2].copy_from_slice(&real[..2]);
        upstream.send_to(&forged, from).await.expect("send forged");
        upstream
            .send_to(&answer(real), from)
            .await
            .expect("send real");
    });

    let mgr = manager(addr).await;
    let (resp, _, _) = timeout(Duration::from_secs(5), mgr.forward(&query("good.example")))
        .await
        .expect("answered in time")
        .expect("answered");
    assert_eq!(qname(&resp), qname(&query("good.example")));
}

#[tokio::test]
async fn answer_with_the_name_in_another_case_is_accepted() {
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let addr = upstream.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (len, from) = upstream.recv_from(&mut buf).await.expect("recv");
        let mut resp = answer(&buf[..len]);
        resp[13..17].make_ascii_uppercase(); // "good" → "GOOD"
        upstream.send_to(&resp, from).await.expect("send");
    });

    let mgr = manager(addr).await;
    timeout(Duration::from_secs(5), mgr.forward(&query("good.example")))
        .await
        .expect("answered in time")
        .expect("answered");
}
