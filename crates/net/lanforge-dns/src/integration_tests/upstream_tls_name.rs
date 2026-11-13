//! The name an encrypted upstream is verified against. Without a TLS name
//! (`tls://1.1.1.1`) the certificate must be checked against the address itself (RFC 8310 §8.2,
//! an IP SAN) and no SNI sent (RFC 6066 §3: no IP literals); with one (`tls://name@ip`) that name
//! is the SNI. A built-in fallback name made every IP-only `DoT`/`DoQ` upstream fail its handshake.

use crate::resolver::UpstreamManager;
use crate::resolver::recursive::DnsCache;
use crate::test_utils::DnsPacketBuilder;
use lanforge_types::network::dns::DnsRecordType;
use lanforge_types::network::dns::upstream::UpstreamTarget;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::timeout;

/// Forwards one query to `target` (served at `addr`) and returns the SNI the server saw.
async fn forward_and_capture(
    target: &str,
    addr: SocketAddr,
    seen: oneshot::Receiver<Option<String>>,
) -> Option<String> {
    let target: UpstreamTarget = target.parse().expect("target");
    let cache = Arc::new(DnsCache::new(100, 30, None));
    let mgr = UpstreamManager::new(&target, addr, cache)
        .await
        .expect("manager");
    let query = DnsPacketBuilder::query("example.com", DnsRecordType::A).build_bytes();
    // The test server never completes the handshake: the query itself fails.
    let _ = timeout(Duration::from_secs(10), mgr.forward(&query)).await;
    timeout(Duration::from_secs(5), seen)
        .await
        .expect("the client reached the server")
        .expect("server reported")
}

#[cfg(feature = "dot")]
mod dot {
    use super::forward_and_capture;
    use rustls::server::Acceptor;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_rustls::LazyConfigAcceptor;

    /// A TCP listener that reads one `ClientHello` and reports its SNI.
    async fn hello_server() -> (SocketAddr, oneshot::Receiver<Option<String>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let start = LazyConfigAcceptor::new(Acceptor::default(), stream)
                .await
                .expect("client hello");
            let _ = tx.send(start.client_hello().server_name().map(str::to_string));
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn ip_only_target_sends_no_foreign_name() {
        let (addr, seen) = hello_server().await;
        let sni = forward_and_capture(&format!("tls://{addr}"), addr, seen).await;
        assert_eq!(sni, None, "verified against the address, no SNI");
    }

    #[tokio::test]
    async fn tls_name_is_the_sni() {
        let (addr, seen) = hello_server().await;
        let sni = forward_and_capture(&format!("tls://dot.example@{addr}"), addr, seen).await;
        assert_eq!(sni.as_deref(), Some("dot.example"));
    }
}

#[cfg(feature = "doq")]
mod doq {
    use super::forward_and_capture;
    use crate::integration_tests::common::tls::self_signed;
    use lanforge_crypto::tls::load_tls_config;
    use quinn::crypto::rustls::{HandshakeData, QuicServerConfig};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::sync::oneshot;

    /// A `DoQ` endpoint that reports the SNI of the first handshake.
    fn hello_server() -> (quinn::Endpoint, oneshot::Receiver<Option<String>>) {
        let cert = self_signed();
        let mut tls = load_tls_config(&cert.cert_pem, &cert.key_pem).expect("server tls");
        tls.alpn_protocols = vec![b"doq".to_vec()];
        let server = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(tls).expect("quic server"),
        ));
        let endpoint = quinn::Endpoint::server(server, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind");
        let accept = endpoint.clone();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let mut connecting = accept
                .accept()
                .await
                .expect("incoming")
                .accept()
                .expect("connecting");
            let data = connecting.handshake_data().await.expect("handshake data");
            let data = data.downcast::<HandshakeData>().expect("rustls data");
            let _ = tx.send(data.server_name);
        });
        (endpoint, rx)
    }

    #[tokio::test]
    async fn ip_only_target_sends_no_foreign_name() {
        let (server, seen) = hello_server();
        let addr = server.local_addr().expect("addr");
        let sni = forward_and_capture(&format!("quic://{addr}"), addr, seen).await;
        assert_eq!(sni, None, "verified against the address, no SNI");
    }

    #[tokio::test]
    async fn tls_name_is_the_sni() {
        let (server, seen) = hello_server();
        let addr = server.local_addr().expect("addr");
        let sni = forward_and_capture(&format!("quic://doq.example@{addr}"), addr, seen).await;
        assert_eq!(sni.as_deref(), Some("doq.example"));
    }
}
