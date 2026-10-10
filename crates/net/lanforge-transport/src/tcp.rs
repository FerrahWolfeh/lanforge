use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener as StdTcpListener};
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

/// Y-Shaped Dual-Stack asynchronous TCP listener.
///
/// Binds native IPv4 and native IPv6 listeners concurrently, accepting incoming
/// connections through a single unified `accept().await` call.
#[derive(Clone)]
pub struct DualTcpListener {
    inner: Arc<TcpBackend>,
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
                    inner: Arc::new(TcpBackend::KernelDual { v4, v6 }),
                })
            }
            (Ok(v4), Err(e)) => {
                warn!(%v6_addr, "TCP: IPv6 bind failed ({e}), falling back to IPv4 single-listener");
                Ok(Self {
                    inner: Arc::new(TcpBackend::KernelSingle(v4)),
                })
            }
            (Err(e), Ok(v6)) => {
                warn!(%v4_addr, "TCP: IPv4 bind failed ({e}), falling back to IPv6 single-listener");
                Ok(Self {
                    inner: Arc::new(TcpBackend::KernelSingle(v6)),
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
            inner: Arc::new(TcpBackend::KernelSingle(tokio_listener)),
        })
    }

    /// Accepts the next incoming TCP connection from either the IPv4 or IPv6 arm.
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        match &*self.inner {
            TcpBackend::KernelDual { v4, v6 } => {
                tokio::select! {
                    res = v4.accept() => res,
                    res = v6.accept() => res,
                }
            }
            TcpBackend::KernelSingle(listener) => listener.accept().await,
        }
    }

    /// Returns the local addresses of the bound listeners.
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        match &*self.inner {
            TcpBackend::KernelDual { v4, v6 } => {
                Ok(vec![v4.local_addr()?, v6.local_addr()?])
            }
            TcpBackend::KernelSingle(listener) => Ok(vec![listener.local_addr()?]),
        }
    }
}
