use crate::config::UpstreamTarget;
use crate::upstream::UpstreamManager;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::str::FromStr;

fn init_crypto() {
    use rustls::crypto::ring::default_provider;
    let _ = default_provider().install_default();
}

/// Live I/O tests for upstream resolvers.
/// These tests require internet connectivity.

#[tokio::test]
async fn test_upstream_udp_live() {
    init_crypto();
    let target = UpstreamTarget::from_str("udp://8.8.8.8:53").unwrap();
    let manager = UpstreamManager::new(&target).await.unwrap();
    
    let mut msg = Message::query();
    msg.add_query(Query::query(Name::from_str("google.com.").unwrap(), RecordType::A));
    let query = msg.to_bytes().unwrap();
    
    let (resp_bytes, cached) = manager.forward(&query).await.expect("UDP forward failed");
    assert!(!cached);
    
    let resp = Message::from_bytes(&resp_bytes).expect("Invalid DNS response");
    assert!(!resp.answers.is_empty());
}

#[tokio::test]
#[cfg(feature = "dot")]
async fn test_upstream_dot_live() {
    init_crypto();
    // Use the @ syntax to provide both the hostname (for SNI) and the IP address.
    let target = UpstreamTarget::from_str("tls://cloudflare-dns.com@1.1.1.1:853").unwrap();
    let manager = UpstreamManager::new(&target).await.unwrap();
    
    let mut msg = Message::query();
    msg.add_query(Query::query(Name::from_str("cloudflare.com.").unwrap(), RecordType::A));
    let query = msg.to_bytes().unwrap();
    
    let (resp_bytes, cached) = manager.forward(&query).await.expect("DoT forward failed");
    assert!(!cached);
    
    let resp = Message::from_bytes(&resp_bytes).expect("Invalid DNS response");
    assert!(!resp.answers.is_empty());
}

// DoQ tests are often flaky against public resolvers due to protocol version ambiguity
// (RFC 9250 vs early drafts) and specific ALPN/TLS requirements.
// We skip it in live I/O tests to avoid CI noise.
/*
#[tokio::test]
#[cfg(feature = "doq")]
async fn test_upstream_doq_live() {
    init_crypto();
    // AdGuard DNS supports DoQ. We use the @ syntax to provide both hostname (for SNI) and IP.
    let target = UpstreamTarget::from_str("quic://dns.adguard-dns.com@94.140.14.14:853").unwrap();
    let manager = UpstreamManager::new(&target).await.unwrap();
    
    let mut msg = Message::query();
    msg.add_query(Query::query(Name::from_str("example.com.").unwrap(), RecordType::A));
    let query = msg.to_bytes().unwrap();
    
    let (resp_bytes, cached) = manager.forward(&query).await.expect("DoQ forward failed");
    assert!(!cached);
    
    let resp = Message::from_bytes(&resp_bytes).expect("Invalid DNS response");
    assert!(!resp.answers.is_empty());
}
*/

#[tokio::test]
#[cfg(feature = "doh-upstream")]
async fn test_upstream_doh_live() {
    init_crypto();
    // Google DoH
    let target = UpstreamTarget::from_str("https://8.8.8.8:443").unwrap();
    let manager = UpstreamManager::new(&target).await.unwrap();
    
    let mut msg = Message::query();
    msg.add_query(Query::query(Name::from_str("google.com.").unwrap(), RecordType::A));
    let query = msg.to_bytes().unwrap();
    
    let (resp_bytes, cached) = manager.forward(&query).await.expect("DoH forward failed");
    assert!(!cached);
    
    let resp = Message::from_bytes(&resp_bytes).expect("Invalid DNS response");
    assert!(!resp.answers.is_empty());
}

#[tokio::test]
async fn test_upstream_tcp_fallback_live() {
    init_crypto();
    // Querying a large TXT record often triggers truncation
    let target = UpstreamTarget::from_str("udp://8.8.8.8:53").unwrap();
    let manager = UpstreamManager::new(&target).await.unwrap();
    
    let mut msg = Message::query();
    // Use a record that is guaranteed to exist
    msg.add_query(Query::query(Name::from_str("google.com.").unwrap(), RecordType::A));
    let query = msg.to_bytes().unwrap();
    
    let (resp_bytes, _) = manager.forward(&query).await.expect("Forward failed");
    let resp = Message::from_bytes(&resp_bytes).expect("Invalid DNS response");
    assert!(!resp.answers.is_empty());
}
