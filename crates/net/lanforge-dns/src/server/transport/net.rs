use lanforge_transport::{DualTcpListener, UdpTransport};
use std::io;
use std::net::SocketAddr;

/// Binds a UDP transport with native dual-stack Y-transport support.
///
/// If `addr` is an unspecified IPv6 address (`[::]:port`), this creates a native
/// dual-socket Y-transport binding both `0.0.0.0:port` and `[::]:port` concurrently
/// with `IPV6_V6ONLY = true`. If IPv6 is unsupported on the host, it gracefully falls
/// back to IPv4 single-socket.
pub fn bind_udp(addr: SocketAddr) -> io::Result<UdpTransport> {
    match addr {
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => UdpTransport::dual_stack(v6.port()),
        _ => UdpTransport::bind_single(addr),
    }
}

/// Binds a TCP listener with native dual-stack Y-listener support.
///
/// If `addr` is an unspecified IPv6 address (`[::]:port`), this creates a native
/// dual-socket Y-listener binding both `0.0.0.0:port` and `[::]:port` concurrently
/// with `IPV6_V6ONLY = true`. If IPv6 is unsupported on the host, it gracefully falls
/// back to IPv4 single-listener.
pub fn bind_tcp(addr: SocketAddr) -> io::Result<DualTcpListener> {
    match addr {
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => DualTcpListener::bind_dual_stack(v6.port()),
        _ => DualTcpListener::bind_single(addr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[tokio::test]
    async fn should_bind_single_udp_to_ephemeral_port() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let transport = bind_udp(addr).expect("bind_udp should succeed");
        let local_addrs = transport.local_addrs().expect("local_addrs should succeed");
        assert_eq!(local_addrs.len(), 1);
        assert_ne!(local_addrs[0].port(), 0);
    }

    #[tokio::test]
    async fn should_bind_single_tcp_to_ephemeral_port() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let listener = bind_tcp(addr).expect("bind_tcp should succeed");
        let local_addrs = listener.local_addrs().expect("local_addrs should succeed");
        assert_eq!(local_addrs.len(), 1);
        assert_ne!(local_addrs[0].port(), 0);
    }

    #[tokio::test]
    async fn should_bind_dual_udp_on_unspecified_v6() {
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
        let transport = bind_udp(addr).expect("dual bind_udp should succeed");
        let local_addrs = transport.local_addrs().expect("local_addrs should succeed");
        assert!(!local_addrs.is_empty());
    }

    #[tokio::test]
    async fn should_bind_dual_tcp_on_unspecified_v6() {
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
        let listener = bind_tcp(addr).expect("dual bind_tcp should succeed");
        let local_addrs = listener.local_addrs().expect("local_addrs should succeed");
        assert!(!local_addrs.is_empty());
    }
}

