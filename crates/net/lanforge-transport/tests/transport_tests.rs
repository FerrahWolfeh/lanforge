use lanforge_transport::{
    DualTcpListener, Icmp6Transport, RateLimitConfig, RateLimiter, UdpTransport,
};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_millis(1000);

#[tokio::test]
async fn test_udp_inert_full_duplex_pipeline() -> Result<(), Box<dyn Error>> {
    let (handle, transport) = UdpTransport::inert();
    assert!(transport.is_inert(), "Transport must operate in inert mode");

    let client_addr: SocketAddr = "192.168.1.100:12345".parse()?;
    let query_payload = b"LANFORGE_SYNTHETIC_QUERY".to_vec();

    // 1. Arrange & Inject synthetic packet from client
    handle.inject(query_payload.clone(), client_addr).await;

    // 2. Act: Receive on transport
    let mut buf = [0u8; 1024];
    let (len, src) = timeout(TEST_TIMEOUT, transport.recv(&mut buf)).await??;

    // 3. Assert ingress data & metrics
    assert_eq!(&buf[..len], query_payload.as_slice());
    assert_eq!(src, client_addr);
    assert_eq!(transport.metrics().rx_packets(), 1);
    assert_eq!(transport.metrics().rx_bytes(), query_payload.len() as u64);

    // 4. Act: Send reply from transport
    let reply_payload = b"LANFORGE_SYNTHETIC_REPLY";
    let sent = transport.send(reply_payload, &src).await?;
    assert_eq!(sent, reply_payload.len());

    // 5. Assert egress reply captured on handle
    let (out_packet, dst) = timeout(TEST_TIMEOUT, handle.recv_reply())
        .await?
        .ok_or("No reply packet captured on InertHandle")?;

    assert_eq!(out_packet, reply_payload);
    assert_eq!(dst, client_addr);
    assert_eq!(transport.metrics().tx_packets(), 1);
    assert_eq!(transport.metrics().tx_bytes(), reply_payload.len() as u64);

    Ok(())
}

#[tokio::test]
async fn test_icmp6_inert_router_solicitation_pipeline() -> Result<(), Box<dyn Error>> {
    let (handle, transport) = Icmp6Transport::inert();
    assert!(transport.is_inert(), "Transport must operate in inert mode");

    let src: SocketAddrV6 = "[fe80::cafe:babe]:0".parse()?;
    // RFC 4861: ICMPv6 Router Solicitation (Type 133, Code 0, Reserved 4 bytes)
    let rs_packet = vec![133, 0, 0, 0, 0, 0, 0, 0];

    // 1. Inject RS from synthetic host
    handle.inject(rs_packet.clone(), src).await;

    // 2. Transport receives RS
    let mut buf = [0u8; 512];
    let (len, from) = timeout(TEST_TIMEOUT, transport.recv(&mut buf)).await??;

    assert_eq!(&buf[..len], rs_packet.as_slice());
    assert_eq!(from, src);
    assert_eq!(transport.metrics().rx_packets(), 1);
    assert_eq!(transport.metrics().rx_bytes(), rs_packet.len() as u64);

    // 3. Service replies with Router Advertisement (Type 134)
    let ra_packet = vec![134, 0, 0, 0, 0, 0, 0, 64];
    let sent = transport.send(&ra_packet, &src)?;
    assert_eq!(sent, ra_packet.len());

    // 4. Inspect reply on InertHandle
    let (out_packet, dst) = timeout(TEST_TIMEOUT, handle.recv_reply())
        .await?
        .ok_or("No RA packet captured on InertHandle")?;

    assert_eq!(out_packet, ra_packet);
    assert_eq!(dst, src);
    assert_eq!(transport.metrics().tx_packets(), 1);
    assert_eq!(transport.metrics().tx_bytes(), ra_packet.len() as u64);

    Ok(())
}

#[tokio::test]
async fn test_udp_rate_limiter_integration_pipeline() -> Result<(), Box<dyn Error>> {
    let (handle, transport) = UdpTransport::inert();

    // Configure rate limiter: 0 pps replenish, burst of 2 packets per source
    let limiter = RateLimiter::new(RateLimitConfig {
        pps: 0,
        burst: 2,
        max_sources: 4,
    });
    transport.set_rate_limiter(limiter);

    let abuser: SocketAddr = "10.0.0.99:5000".parse()?;
    let legitimate: SocketAddr = "10.0.0.1:5000".parse()?;

    // Send 3 packets from abuser (2 allowed, 1 dropped)
    handle.inject(b"abuser-1".to_vec(), abuser).await;
    handle.inject(b"abuser-2".to_vec(), abuser).await;
    handle.inject(b"abuser-3".to_vec(), abuser).await;

    // Send 1 packet from legitimate user
    handle.inject(b"legit-1".to_vec(), legitimate).await;

    let mut buf = [0u8; 64];

    // Read 1st abuser packet
    let (n, src) = timeout(TEST_TIMEOUT, transport.recv(&mut buf)).await??;
    assert_eq!(&buf[..n], b"abuser-1");
    assert_eq!(src, abuser);

    // Read 2nd abuser packet
    let (n, src) = timeout(TEST_TIMEOUT, transport.recv(&mut buf)).await??;
    assert_eq!(&buf[..n], b"abuser-2");
    assert_eq!(src, abuser);

    // 3rd abuser packet is dropped internally by rate limiter!
    // Next packet delivered must be legitimate-1!
    let (n, src) = timeout(TEST_TIMEOUT, transport.recv(&mut buf)).await??;
    assert_eq!(&buf[..n], b"legit-1");
    assert_eq!(src, legitimate);

    assert_eq!(transport.metrics().dropped_packets(), 1);
    assert_eq!(transport.metrics().rx_packets(), 3);

    Ok(())
}

#[tokio::test]
async fn test_udp_kernel_loopback_bidirectional() -> Result<(), Box<dyn Error>> {
    // Ephemeral port assignment directly on bind: zero race conditions!
    let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
    let transport = UdpTransport::bind_single(loopback)?;
    let port = transport.local_addrs()?[0].port();
    assert_ne!(port, 0);

    // Independent client socket
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let target = SocketAddr::from(([127, 0, 0, 1], port));

    // Client -> Server
    client.send_to(b"kernel_ping", target).await?;

    let mut buf = [0u8; 64];
    let (n, src) = timeout(TEST_TIMEOUT, transport.recv(&mut buf)).await??;
    assert_eq!(&buf[..n], b"kernel_ping");
    assert_eq!(src.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

    // Server -> Client reply
    transport.send(b"kernel_pong", &src).await?;

    let (n, from) = timeout(TEST_TIMEOUT, client.recv_from(&mut buf)).await??;
    assert_eq!(&buf[..n], b"kernel_pong");
    assert_eq!(from.port(), port);

    Ok(())
}

#[tokio::test]
async fn test_tcp_kernel_loopback_connection_lifecycle() -> Result<(), Box<dyn Error>> {
    // Ephemeral port assignment directly on bind: zero race conditions!
    let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = DualTcpListener::bind_single(loopback)?;
    let server_addr = listener.local_addrs()?[0];
    assert_ne!(server_addr.port(), 0);

    let client_handle = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(server_addr).await?;
        stream.write_all(b"HELLO_TCP_SERVER").await?;

        let mut buf = [0u8; 16];
        stream.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"HELLO_TCP_CLIENT");
        Ok::<(), std::io::Error>(())
    });

    let (mut server_stream, client_addr) = timeout(TEST_TIMEOUT, listener.accept()).await??;
    assert_eq!(client_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

    let mut buf = [0u8; 16];
    server_stream.read_exact(&mut buf).await?;
    assert_eq!(&buf, b"HELLO_TCP_SERVER");

    server_stream.write_all(b"HELLO_TCP_CLIENT").await?;
    client_handle.await??;

    Ok(())
}
