use lanforge_transport::{
    DualTcpListener, Icmp6Transport, RateLimitConfig, RateLimiter, UdpTransport,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

#[tokio::test]
async fn test_udp_inert_pipeline() {
    let (handle, transport) = UdpTransport::inert();
    assert!(transport.is_inert());

    let client_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
    let query_payload = b"test query".to_vec();

    // 1. Inject packet
    handle.inject(query_payload.clone(), client_addr).await;

    // 2. Receive via transport
    let mut buf = [0u8; 1024];
    let (len, src) = timeout(Duration::from_millis(500), transport.recv(&mut buf))
        .await
        .expect("Timeout on recv")
        .expect("Recv error");

    assert_eq!(&buf[..len], query_payload.as_slice());
    assert_eq!(src, client_addr);

    // 3. Verify metrics
    assert_eq!(transport.metrics().rx_packets(), 1);
    assert_eq!(transport.metrics().rx_bytes(), query_payload.len() as u64);

    // 4. Send reply
    let reply_payload = b"test response";
    transport
        .send(reply_payload, &src)
        .await
        .expect("Send error");

    // 5. Inspect reply via handle
    let (out_packet, dst) = timeout(Duration::from_millis(500), handle.recv_reply())
        .await
        .expect("Timeout waiting for reply")
        .expect("No reply received");

    assert_eq!(out_packet, reply_payload);
    assert_eq!(dst, client_addr);

    assert_eq!(transport.metrics().tx_packets(), 1);
    assert_eq!(transport.metrics().tx_bytes(), reply_payload.len() as u64);
}

#[tokio::test]
async fn test_rate_limiter_bounded_behavior() {
    let config = RateLimitConfig {
        pps: 10,
        burst: 2,
        max_sources: 4,
    };
    let limiter = RateLimiter::new(config);

    let ip1: IpAddr = "10.0.0.1".parse().unwrap();
    let ip2: IpAddr = "10.0.0.2".parse().unwrap();

    // First 2 should be allowed (burst)
    assert!(limiter.check(&ip1));
    assert!(limiter.check(&ip1));

    // Third immediate packet should be dropped
    assert!(!limiter.check(&ip1));

    // ip2 should still have its burst available
    assert!(limiter.check(&ip2));
    assert!(limiter.check(&ip2));
    assert!(!limiter.check(&ip2));
}

#[tokio::test]
async fn test_icmp6_inert_pipeline() {
    let (handle, transport) = Icmp6Transport::inert();
    assert!(transport.is_inert());

    let src: SocketAddrV6 = "[fe80::1]:0".parse().unwrap();
    let rs_packet = vec![133, 0, 0, 0, 0, 0, 0, 0];

    handle.inject(rs_packet.clone(), src).await;

    let mut buf = [0u8; 512];
    let (len, from) = timeout(Duration::from_millis(500), transport.recv(&mut buf))
        .await
        .expect("Timeout on recv")
        .expect("Recv error");

    assert_eq!(&buf[..len], rs_packet.as_slice());
    assert_eq!(from, src);

    // Send RA response
    let ra_packet = vec![134, 0, 0, 0];
    transport.send(&ra_packet, &src).expect("Send error");

    let (out_packet, dst) = timeout(Duration::from_millis(500), handle.recv_reply())
        .await
        .expect("Timeout on reply")
        .expect("No reply");

    assert_eq!(out_packet, ra_packet);
    assert_eq!(dst, src);
}

#[tokio::test]
async fn test_udp_kernel_dual_loopback() {
    // Pick an ephemeral port by binding port 0
    let temp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = temp.local_addr().unwrap().port();
    drop(temp);

    // Try dual_stack on loopback port
    let transport = UdpTransport::dual_stack(port);
    if let Ok(transport) = transport {
        assert!(!transport.is_inert());
        let addrs = transport.local_addrs().unwrap();
        assert!(!addrs.is_empty());

        // Send a test packet to localhost IPv4
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = SocketAddr::from(([127, 0, 0, 1], port));
        client.send_to(b"ping", target).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, src) = timeout(Duration::from_millis(500), transport.recv(&mut buf))
            .await
            .expect("Timeout")
            .unwrap();

        assert_eq!(&buf[..n], b"ping");
        assert_eq!(src.ip(), Ipv4Addr::new(127, 0, 0, 1));

        // Reply back
        transport.send(b"pong", &src).await.unwrap();
        let (n, _) = timeout(Duration::from_millis(500), client.recv_from(&mut buf))
            .await
            .expect("Timeout on pong")
            .unwrap();
        assert_eq!(&buf[..n], b"pong");
    }
}

#[tokio::test]
async fn test_tcp_dual_loopback() {
    let temp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = temp.local_addr().unwrap().port();
    drop(temp);

    let listener = DualTcpListener::bind_dual_stack(port);
    if let Ok(listener) = listener {
        let addrs = listener.local_addrs().unwrap();
        assert!(!addrs.is_empty());

        // Connect via IPv4
        let connect_handle = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port)))
                .await
                .unwrap();
            stream.write_all(b"hello tcp").await.unwrap();
        });

        let (mut stream, src) = timeout(Duration::from_millis(500), listener.accept())
            .await
            .expect("Timeout on accept")
            .unwrap();

        assert_eq!(src.ip(), Ipv4Addr::new(127, 0, 0, 1));
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello tcp");

        connect_handle.await.unwrap();
    }
}
