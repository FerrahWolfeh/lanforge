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
