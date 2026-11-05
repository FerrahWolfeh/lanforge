#![allow(
    unused_crate_dependencies,
    reason = "integration test crates see every dev-dependency"
)]
//! `DoT` listener (RFC 7858): answers, owns its connections, closes silent clients.
//!
//! Regressions: connections ran as detached tasks (they outlived a stop of the service), the
//! TLS handshake and the query body had no timeout (a client that went quiet held a task and a
//! descriptor forever), and an accept error retried without a pause.
#![cfg(feature = "dot")]

mod common;
#[path = "common/tls.rs"]
mod tls;

use std::sync::Arc;
use std::time::Duration;

use common::{extract_a, parse_response};
use rustls::pki_types::ServerName;
use tls::{NAS_IP, RunningDns, client_config, nas_query, self_signed};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

async fn connect(dns: &RunningDns, cert: &tls::SelfSigned) -> TlsStream<TcpStream> {
    let connector = TlsConnector::from(Arc::new(client_config(cert, b"")));
    let tcp = TcpStream::connect(dns.dot).await.expect("DoT port open");
    connector
        .connect(ServerName::try_from("localhost").expect("name"), tcp)
        .await
        .expect("TLS handshake")
}

async fn ask(stream: &mut TlsStream<TcpStream>, query: &[u8]) -> Vec<u8> {
    let len = u16::try_from(query.len())
        .expect("small query")
        .to_be_bytes();
    stream.write_all(&len).await.expect("write");
    stream.write_all(query).await.expect("write");
    let mut len_buf = [0u8; 2];
    timeout(Duration::from_secs(2), stream.read_exact(&mut len_buf))
        .await
        .expect("answer in time")
        .expect("read");
    let mut resp = vec![0u8; usize::from(u16::from_be_bytes(len_buf))];
    stream.read_exact(&mut resp).await.expect("read");
    resp
}

/// `true` once the server closed the connection (EOF or reset) within `within`.
async fn closed_within<S: AsyncReadExt + Unpin>(stream: &mut S, within: Duration) -> bool {
    let mut byte = [0u8; 1];
    matches!(
        timeout(within, stream.read(&mut byte)).await,
        Ok(Ok(0) | Err(_))
    )
}

#[tokio::test]
async fn stop_closes_open_dot_sessions() {
    let cert = self_signed();
    let dns = RunningDns::start(&cert).await;

    let mut session = connect(&dns, &cert).await;
    let resp = ask(&mut session, &nas_query(0x4242)).await;
    let msg = parse_response(&resp).expect("valid answer");
    assert_eq!(msg.header.id, 0x4242);
    assert_eq!(extract_a(&msg), vec![NAS_IP]);

    // The session stays open; stopping DNS must end it now, not at the client's idle timeout.
    dns.stop().await;
    assert!(
        closed_within(&mut session, Duration::from_secs(1)).await,
        "a DoT session outlived the stopped service"
    );
}

#[tokio::test]
async fn dot_closes_clients_that_go_quiet() {
    let cert = self_signed();
    let dns = RunningDns::start(&cert).await;

    // Never starts the TLS handshake.
    let mut silent = TcpStream::connect(dns.dot).await.expect("DoT port open");
    // Sends a length prefix, then never the query.
    let mut stalled = connect(&dns, &cert).await;
    stalled.write_all(&[0, 40]).await.expect("write");
    stalled.flush().await.expect("flush");

    // Idle bound is 10 s; both checks run concurrently.
    let bound = Duration::from_secs(13);
    let (silent_closed, stalled_closed) = tokio::join!(
        closed_within(&mut silent, bound),
        closed_within(&mut stalled, bound)
    );
    assert!(
        silent_closed,
        "a client that never sent a ClientHello was kept open"
    );
    assert!(stalled_closed, "a client stuck mid-query was kept open");

    dns.stop().await;
}
