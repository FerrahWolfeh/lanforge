use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, UdpSocket};
use tracing::warn;

/// Binds a UDP socket with dual-stack support and fallback to IPv4.
///
/// If `addr` is an unspecified IPv6 address (`[::]:port`), this creates an
/// `AF_INET6` socket with `IPV6_V6ONLY = false`. If IPv6 is unsupported on the
/// host (e.g. disabled in kernel), it falls back gracefully to `0.0.0.0:port`.
pub fn bind_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    match addr {
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
            let socket_res = (|| -> io::Result<socket2::Socket> {
                let s = socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )?;
                s.set_only_v6(false)?;
                s.set_nonblocking(true)?;
                s.bind(&socket2::SockAddr::from(addr))?;
                Ok(s)
            })();

            match socket_res {
                Ok(s) => {
                    let std_sock: std::net::UdpSocket = s.into();
                    UdpSocket::from_std(std_sock)
                }
                Err(e) => {
                    warn!(
                        "DNS: IPv6 dual-stack UDP bind to {} failed ({}), falling back to 0.0.0.0:{}",
                        addr,
                        e,
                        v6.port()
                    );
                    let v4_addr = SocketAddr::from(([0, 0, 0, 0], v6.port()));
                    let std_sock = std::net::UdpSocket::bind(v4_addr)?;
                    std_sock.set_nonblocking(true)?;
                    UdpSocket::from_std(std_sock)
                }
            }
        }
        SocketAddr::V6(_) => {
            let s = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            s.set_only_v6(true)?;
            s.set_nonblocking(true)?;
            s.bind(&socket2::SockAddr::from(addr))?;
            let std_sock: std::net::UdpSocket = s.into();
            UdpSocket::from_std(std_sock)
        }
        SocketAddr::V4(_) => {
            let std_sock = std::net::UdpSocket::bind(addr)?;
            std_sock.set_nonblocking(true)?;
            UdpSocket::from_std(std_sock)
        }
    }
}

/// Binds a TCP listener with dual-stack support and fallback to IPv4.
///
/// If `addr` is an unspecified IPv6 address (`[::]:port`), this creates an
/// `AF_INET6` socket with `IPV6_V6ONLY = false`. If IPv6 is unsupported on the
/// host, it falls back gracefully to `0.0.0.0:port`.
pub fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    match addr {
        SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
            let socket_res = (|| -> io::Result<socket2::Socket> {
                let s = socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::STREAM,
                    Some(socket2::Protocol::TCP),
                )?;
                s.set_only_v6(false)?;
                s.set_reuse_address(true)?;
                s.set_nonblocking(true)?;
                s.bind(&socket2::SockAddr::from(addr))?;
                s.listen(1024)?;
                Ok(s)
            })();

            match socket_res {
                Ok(s) => {
                    let std_listener: std::net::TcpListener = s.into();
                    TcpListener::from_std(std_listener)
                }
                Err(e) => {
                    warn!(
                        "DNS: IPv6 dual-stack TCP bind to {} failed ({}), falling back to 0.0.0.0:{}",
                        addr,
                        e,
                        v6.port()
                    );
                    let v4_addr = SocketAddr::from(([0, 0, 0, 0], v6.port()));
                    let s = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )?;
                    s.set_reuse_address(true)?;
                    s.set_nonblocking(true)?;
                    s.bind(&socket2::SockAddr::from(v4_addr))?;
                    s.listen(1024)?;
                    let std_listener: std::net::TcpListener = s.into();
                    TcpListener::from_std(std_listener)
                }
            }
        }
        SocketAddr::V6(_) => {
            let s = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            s.set_only_v6(true)?;
            s.set_reuse_address(true)?;
            s.set_nonblocking(true)?;
            s.bind(&socket2::SockAddr::from(addr))?;
            s.listen(1024)?;
            let std_listener: std::net::TcpListener = s.into();
            TcpListener::from_std(std_listener)
        }
        SocketAddr::V4(_) => {
            let s = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            s.set_reuse_address(true)?;
            s.set_nonblocking(true)?;
            s.bind(&socket2::SockAddr::from(addr))?;
            s.listen(1024)?;
            let std_listener: std::net::TcpListener = s.into();
            TcpListener::from_std(std_listener)
        }
    }
}
