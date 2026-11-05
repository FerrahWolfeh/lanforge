//! `DoQ` listener (RFC 9250): framed queries, owned connections.
//!
//! Regressions: queries and answers were sent without the 2-byte length prefix of RFC 9250
//! §4.2 (no standard client could talk to it), and connections/streams ran as detached tasks
//! that outlived a stop of the service and kept the UDP port.
#![cfg(feature = "doq")]

mod common;
#[path = "common/tls.rs"]
mod tls;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use common::{extract_a, parse_response};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Connection, Endpoint};
use tls::{NAS_IP, RunningDns, SelfSigned, client_config, nas_query, self_signed};
use tokio::time::timeout;

async fn connect(addr: SocketAddr, cert: &SelfSigned) -> (Endpoint, Connection) {
    let crypto = QuicClientConfig::try_from(client_config(cert, b"doq")).expect("quic crypto");
    let mut endpoint =
        Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("client endpoint");
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(crypto)));
    let conn = timeout(
        Duration::from_secs(2),
        endpoint.connect(addr, "localhost").expect("connect"),
    )
    .await
    .expect("handshake in time")
    .expect("handshake");
    (endpoint, conn)
}

/// Sends `bytes` on a new stream, then FIN; returns everything the server sent back.
async fn exchange(conn: &Connection, bytes: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = conn.open_bi().await.expect("stream");
    send.write_all(bytes).await.expect("write");
    send.finish().expect("finish");
    timeout(Duration::from_secs(2), recv.read_to_end(65_537))
        .await
        .expect("answer in time")
        .unwrap_or_default()
}

fn framed(message: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(message.len())
        .expect("small")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(message);
    out
}

#[tokio::test]
async fn doq_answers_length_prefixed_queries() {
    let cert = self_signed();
    let dns = RunningDns::start(&cert).await;
    let (_endpoint, conn) = connect(dns.doq, &cert).await;

    // RFC 9250 §4.2: Message ID 0, 2-byte length prefix, one query per stream.
    let resp = exchange(&conn, &framed(&nas_query(0))).await;
    let (prefix, message) = resp.split_first_chunk::<2>().expect("framed answer");
    assert_eq!(
        usize::from(u16::from_be_bytes(*prefix)),
        message.len(),
        "answer must carry its length prefix"
    );
    let msg = parse_response(message).expect("valid answer");
    assert_eq!(msg.header.id, 0);
    assert_eq!(extract_a(&msg), vec![NAS_IP]);

    // Several streams on the same connection, concurrently.
    let query = framed(&nas_query(0));
    let answers = futures::future::join_all((0..8).map(|_| exchange(&conn, &query))).await;
    assert!(
        answers.iter().all(|a| a.len() > 2),
        "every stream is answered"
    );

    dns.stop().await;
}

#[tokio::test]
async fn doq_rejects_unframed_and_mismatched_streams() {
    let cert = self_signed();
    let dns = RunningDns::start(&cert).await;
    let (_endpoint, conn) = connect(dns.doq, &cert).await;

    // A bare message (the old non-RFC form) and a prefix that lies about the length.
    assert!(exchange(&conn, &nas_query(0)).await.is_empty());
    let mut lying = framed(&nas_query(0));
    lying[1] += 1;
    assert!(exchange(&conn, &lying).await.is_empty());

    // The connection survives a bad stream.
    assert!(exchange(&conn, &framed(&nas_query(0))).await.len() > 2);

    dns.stop().await;
}

#[tokio::test]
async fn stop_closes_doq_connections_and_frees_the_port() {
    let cert = self_signed();
    let dns = RunningDns::start(&cert).await;
    let doq = dns.doq;
    let (_endpoint, conn) = connect(doq, &cert).await;
    assert!(exchange(&conn, &framed(&nas_query(0))).await.len() > 2);

    dns.stop().await;
    assert!(
        timeout(Duration::from_secs(1), conn.closed()).await.is_ok(),
        "a DoQ connection outlived the stopped service"
    );
    assert!(
        std::net::UdpSocket::bind(doq).is_ok(),
        "DoQ port {doq} still held after stop"
    );
}
