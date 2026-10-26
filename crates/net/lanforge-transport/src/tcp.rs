use crate::metrics::TransportMetrics;
use std::io;
use std::net::{
    Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener as StdTcpListener,
};
use std::sync::Arc;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tracing::{debug, warn};

enum TcpBackend {
    KernelDual {
        v4: TokioTcpListener,
        v6: TokioTcpListener,
    },
    KernelSingle(TokioTcpListener),
}

struct TcpInner {
    backend: TcpBackend,
    metrics: TransportMetrics,
}

/// Y-Shaped Dual-Stack asynchronous TCP listener.
///
/// Binds native IPv4 and native IPv6 listeners concurrently, accepting incoming
/// connections through a single unified `accept().await` call.
#[derive(Clone)]
pub struct DualTcpListener {
    inner: Arc<TcpInner>,
}

impl DualTcpListener {
    /// Binds a dual-stack TCP listener to `0.0.0.0:port` and `[::]:port` (IPV6_V6ONLY=true).
    ///
    /// If IPv6 is unsupported on the host, it gracefully falls back to IPv4 single-listener.
    pub fn bind_dual_stack(port: u16) -> io::Result<Self> {
        let v4_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        let v6_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);

        Self::bind_dual(v4_addr, v6_addr)
    }

    /// Binds specific IPv4 and IPv6 addresses into a dual-listener.
    pub fn bind_dual(v4_addr: SocketAddrV4, v6_addr: SocketAddrV6) -> io::Result<Self> {
        let v4_res = (|| -> io::Result<TokioTcpListener> {
            let s = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            s.set_reuse_address(true)?;
            s.set_nonblocking(true)?;
            s.bind(&socket2::SockAddr::from(SocketAddr::V4(v4_addr)))?;
            s.listen(1024)?;
            let std_listener: StdTcpListener = s.into();
            TokioTcpListener::from_std(std_listener)
        })();

        let v6_res = (|| -> io::Result<TokioTcpListener> {
            let s = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            s.set_only_v6(true)?;
            s.set_reuse_address(true)?;
            s.set_nonblocking(true)?;
            s.bind(&socket2::SockAddr::from(SocketAddr::V6(v6_addr)))?;
            s.listen(1024)?;
            let std_listener: StdTcpListener = s.into();
            TokioTcpListener::from_std(std_listener)
        })();

        match (v4_res, v6_res) {
            (Ok(v4), Ok(v6)) => {
                debug!(%v4_addr, %v6_addr, "TCP: Dual-socket Y-listener active");
                Ok(Self {
                    inner: Arc::new(TcpInner {
                        backend: TcpBackend::KernelDual { v4, v6 },
                        metrics: TransportMetrics::new(),
                    }),
                })
            }
            (Ok(v4), Err(e)) => {
                warn!(%v6_addr, "TCP: IPv6 bind failed ({e}), falling back to IPv4 single-listener");
                Ok(Self {
                    inner: Arc::new(TcpInner {
                        backend: TcpBackend::KernelSingle(v4),
                        metrics: TransportMetrics::new(),
                    }),
                })
            }
            (Err(e), Ok(v6)) => {
                warn!(%v4_addr, "TCP: IPv4 bind failed ({e}), falling back to IPv6 single-listener");
                Ok(Self {
                    inner: Arc::new(TcpInner {
                        backend: TcpBackend::KernelSingle(v6),
                        metrics: TransportMetrics::new(),
                    }),
                })
            }
            (Err(e4), Err(e6)) => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("Failed to bind both IPv4 ({e4}) and IPv6 ({e6}) TCP listeners"),
            )),
        }
    }

    /// Binds a single TCP listener to the specified address.
    pub fn bind_single(addr: SocketAddr) -> io::Result<Self> {
        let std_listener = StdTcpListener::bind(addr)?;
        std_listener.set_nonblocking(true)?;
        let tokio_listener = TokioTcpListener::from_std(std_listener)?;
        Ok(Self {
            inner: Arc::new(TcpInner {
                backend: TcpBackend::KernelSingle(tokio_listener),
                metrics: TransportMetrics::new(),
            }),
        })
    }

    /// Accesses transparent traffic metrics.
    #[must_use]
    pub fn metrics(&self) -> &TransportMetrics {
        &self.inner.metrics
    }

    /// Accepts the next incoming TCP connection from either the IPv4 or IPv6 arm.
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let res = match &self.inner.backend {
            TcpBackend::KernelDual { v4, v6 } => {
                tokio::select! {
                    res = v4.accept() => res,
                    res = v6.accept() => res,
                }
            }
            TcpBackend::KernelSingle(listener) => listener.accept().await,
        };

        match &res {
            Ok(_) => {
                self.inner.metrics.record_rx(1);
            }
            Err(_) => {
                self.inner.metrics.record_error();
            }
        }
        res
    }

    /// Returns the local addresses of the bound listeners.
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        match &self.inner.backend {
            TcpBackend::KernelDual { v4, v6 } => Ok(vec![v4.local_addr()?, v6.local_addr()?]),
            TcpBackend::KernelSingle(listener) => Ok(vec![listener.local_addr()?]),
        }
    }
}

impl crate::metrics::TransportStats for DualTcpListener {
    fn snapshot(&self) -> lanforge_types::network::snapshot::TransportSnapshot {
        self.inner.metrics.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn should_bind_single_to_ephemeral_port_and_report_local_address() {
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = DualTcpListener::bind_single(loopback).expect("bind_single failed");

        let addrs = listener.local_addrs().expect("local_addrs failed");
        assert_eq!(addrs.len(), 1);
        assert_ne!(addrs[0].port(), 0, "OS must assign an ephemeral port");
        assert_eq!(addrs[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn should_accept_tcp_connections_and_transfer_data() {
        let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = DualTcpListener::bind_single(loopback).expect("bind_single failed");
        let server_addr = listener.local_addrs().unwrap()[0];

        let client_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(server_addr)
                .await
                .expect("Client failed to connect");
            client
                .write_all(b"ping tcp")
                .await
                .expect("Client write failed");

            let mut reply = [0u8; 8];
            client
                .read_exact(&mut reply)
                .await
                .expect("Client read failed");
            assert_eq!(&reply, b"pong tcp");
        });

        let (mut stream, client_addr) = timeout(Duration::from_millis(500), listener.accept())
            .await
            .expect("Accept timed out")
            .expect("Accept failed");

        assert_eq!(client_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        let mut buf = [0u8; 8];
        stream
            .read_exact(&mut buf)
            .await
            .expect("Server read failed");
        assert_eq!(&buf, b"ping tcp");

        stream
            .write_all(b"pong tcp")
            .await
            .expect("Server write failed");
        client_task.await.expect("Client task panicked");
    }

    #[tokio::test]
    async fn should_bind_dual_on_ephemeral_port_or_fallback() {
        let v4_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        let v6_addr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0);

        if let Ok(listener) = DualTcpListener::bind_dual(v4_addr, v6_addr) {
            let addrs = listener.local_addrs().expect("local_addrs failed");
            assert!(!addrs.is_empty(), "Must have at least one bound address");
            for addr in addrs {
                assert_ne!(addr.port(), 0, "Bound port must be non-zero");
            }
        }
    }
}
