use crate::bind::{bind_error, dual_bind_error};
use crate::inert::{InertHandle, InertPort};
use crate::limiter::RateLimiter;
use crate::metrics::{TransportMetrics, TransportStats};
use lanforge_types::network::bind::BindError;
use lanforge_types::network::snapshot::TransportSnapshot;
use std::io;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket as StdUdpSocket,
};
use std::sync::Arc;
use tokio::net::UdpSocket as TokioUdpSocket;
use tracing::{debug, warn};

enum UdpBackend {
    /// Y-Transport dual-socket: native IPv4 and native IPv6 running concurrently.
    KernelDual {
        v4: TokioUdpSocket,
        v6: TokioUdpSocket,
    },
    /// Single socket (IPv4-only or IPv6-only).
    KernelSingle(TokioUdpSocket),
    /// In-memory inert transport for rootless testing and simulation.
    #[cfg(any(test, feature = "inert"))]
    Inert(InertPort<SocketAddr>),
}

struct UdpInner {
    backend: UdpBackend,
    metrics: Arc<TransportMetrics>,
    limiter: parking_lot::RwLock<Option<RateLimiter<IpAddr>>>,
}

/// Y-Shaped Dual-Stack asynchronous UDP transport.
///
/// Features:
/// - Native concurrent IPv4 and IPv6 sockets (never mangles addresses to `::ffff:`).
/// - Automatic outbound routing based on target IP family.
/// - Built-in transparent metrics and bounded rate limiting.
/// - In-memory inert mode for rootless integration and unit testing.
#[derive(Clone)]
pub struct UdpTransport {
    inner: Arc<UdpInner>,
}

impl UdpTransport {
    /// Creates a Y-shaped dual-stack transport bound to `0.0.0.0:port` and `[::]:port` (`IPV6_V6ONLY=true`).
    ///
    /// If IPv6 is not supported by the kernel, it gracefully falls back to IPv4 single-socket.
    ///
    /// # Errors
    /// Both families failed to bind.
    pub fn dual_stack(port: u16) -> Result<Self, BindError> {
        let v4_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        let v6_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);

        Self::bind_dual(v4_addr, v6_addr)
    }

    /// Binds specific IPv4 and IPv6 addresses into a dual-socket transport.
    ///
    /// If one protocol family fails to bind (e.g. IPv6 disabled on host), it falls back
    /// to the available protocol family if possible.
    ///
    /// # Errors
    /// Both families failed to bind.
    pub fn bind_dual(v4_addr: SocketAddrV4, v6_addr: SocketAddrV6) -> Result<Self, BindError> {
        let v4_res = (|| -> io::Result<TokioUdpSocket> {
            let std_sock = StdUdpSocket::bind(v4_addr)?;
            std_sock.set_nonblocking(true)?;
            TokioUdpSocket::from_std(std_sock)
        })();

        let v6_res = (|| -> io::Result<TokioUdpSocket> {
            let s = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            s.set_only_v6(true)?;
            s.set_nonblocking(true)?;
            s.bind(&socket2::SockAddr::from(SocketAddr::V6(v6_addr)))?;
            let std_sock: StdUdpSocket = s.into();
            TokioUdpSocket::from_std(std_sock)
        })();

        match (v4_res, v6_res) {
            (Ok(v4), Ok(v6)) => {
                debug!(%v4_addr, %v6_addr, "UDP: Dual-socket Y-transport bound");
                Ok(Self::from_backend(UdpBackend::KernelDual { v4, v6 }))
            }
            (Ok(v4), Err(e)) => {
                warn!(%v6_addr, "UDP: IPv6 bind failed ({e}), falling back to IPv4 single-socket");
                Ok(Self::from_backend(UdpBackend::KernelSingle(v4)))
            }
            (Err(e), Ok(v6)) => {
                warn!(%v4_addr, "UDP: IPv4 bind failed ({e}), falling back to IPv6 single-socket");
                Ok(Self::from_backend(UdpBackend::KernelSingle(v6)))
            }
            (Err(e4), Err(e6)) => Err(dual_bind_error(
                format!("{v4_addr} and {v6_addr}"),
                &e4,
                &e6,
            )),
        }
    }

    /// Binds a single UDP socket to the specified address.
    ///
    /// # Errors
    /// The address could not be bound.
    pub fn bind_single(addr: SocketAddr) -> Result<Self, BindError> {
        (|| -> io::Result<Self> {
            let std_sock = StdUdpSocket::bind(addr)?;
            std_sock.set_nonblocking(true)?;
            let tokio_sock = TokioUdpSocket::from_std(std_sock)?;
            Ok(Self::from_backend(UdpBackend::KernelSingle(tokio_sock)))
        })()
        .map_err(|e| bind_error(addr.to_string(), e))
    }

    /// Binds `addr` on `iface` only (`SO_BINDTODEVICE`, `SO_REUSEADDR`): a server that answers
    /// one link, like DHCP. An IPv4 socket may also send to the broadcast address.
    ///
    /// # Errors
    /// The interface does not exist ([`BindErrorKind::NoDevice`]) or the address could not be
    /// bound; a socket that would listen on every interface is never returned.
    ///
    /// [`BindErrorKind::NoDevice`]: crate::BindErrorKind::NoDevice
    pub fn bind_device(iface: &str, addr: SocketAddr) -> Result<Self, BindError> {
        let open = || -> io::Result<Self> {
            let domain = if addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            };
            let sock =
                socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
            sock.set_reuse_address(true)?;
            if addr.is_ipv4() {
                sock.set_broadcast(true)?;
            } else {
                sock.set_only_v6(true)?;
            }
            sock.bind_device(Some(iface.as_bytes()))?;
            sock.set_nonblocking(true)?;
            sock.bind(&socket2::SockAddr::from(addr))?;
            let std_socket: StdUdpSocket = sock.into();
            Ok(Self::from_backend(UdpBackend::KernelSingle(
                TokioUdpSocket::from_std(std_socket)?,
            )))
        };
        open().map_err(|e| bind_error(format!("{addr}%{iface}"), e))
    }

    /// Joins the IPv6 multicast `group` on the interface `ifindex` (a server listening to a
    /// link-scoped group, like `DHCPv6`'s `ff02::1:2`).
    ///
    /// # Errors
    /// The group could not be joined: the socket would never hear the group's packets.
    pub fn join_multicast_v6(&self, group: &Ipv6Addr, ifindex: u32) -> Result<(), BindError> {
        let res = match &self.inner.backend {
            UdpBackend::KernelSingle(sock) => sock.join_multicast_v6(group, ifindex),
            UdpBackend::KernelDual { v6, .. } => v6.join_multicast_v6(group, ifindex),
            #[cfg(any(test, feature = "inert"))]
            UdpBackend::Inert(_) => Ok(()),
        };
        res.map_err(|e| bind_error(format!("{group}%{ifindex}"), e))
    }

    fn from_backend(backend: UdpBackend) -> Self {
        Self {
            inner: Arc::new(UdpInner {
                backend,
                metrics: Arc::new(TransportMetrics::new()),
                limiter: parking_lot::RwLock::new(None),
            }),
        }
    }

    /// Creates an inert transport for rootless testing and simulation.
    #[must_use]
    #[cfg(any(test, feature = "inert"))]
    pub fn inert() -> (InertHandle<SocketAddr>, Self) {
        let (handle, port) = InertPort::pair(128);
        (handle, Self::from_backend(UdpBackend::Inert(port)))
    }

    /// Configures an optional token-bucket rate limiter.
    pub fn set_rate_limiter(&self, limiter: RateLimiter<IpAddr>) {
        *self.inner.limiter.write() = Some(limiter);
    }

    /// Accesses transparent traffic metrics.
    #[must_use]
    pub fn metrics(&self) -> &TransportMetrics {
        &self.inner.metrics
    }

    /// A handle on the traffic counters alone (no socket): what a status view may keep.
    #[must_use]
    pub fn metrics_handle(&self) -> Arc<TransportMetrics> {
        Arc::clone(&self.inner.metrics)
    }

    /// Returns `true` if operating in inert testing mode.
    #[must_use]
    pub fn is_inert(&self) -> bool {
        match &self.inner.backend {
            UdpBackend::KernelDual { .. } | UdpBackend::KernelSingle(_) => false,
            #[cfg(any(test, feature = "inert"))]
            UdpBackend::Inert(_) => true,
        }
    }

    /// Returns the local addresses of the bound sockets.
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        match &self.inner.backend {
            UdpBackend::KernelDual { v4, v6 } => Ok(vec![v4.local_addr()?, v6.local_addr()?]),
            UdpBackend::KernelSingle(sock) => Ok(vec![sock.local_addr()?]),
            #[cfg(any(test, feature = "inert"))]
            UdpBackend::Inert(_) => Ok(vec![SocketAddr::from(([127, 0, 0, 1], 0))]),
        }
    }

    /// Receives a datagram into the provided buffer.
    ///
    /// In dual-stack mode, fairly polls across IPv4 and IPv6 arms.
    /// Automatically applies rate-limiting and tracks packet/byte metrics.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            let (n, src) = match &self.inner.backend {
                UdpBackend::KernelDual { v4, v6 } => {
                    tokio::select! {
                        res = v4.readable() => {
                            res.map_err(|e| self.counted(e))?;
                            match v4.try_recv_from(buf) {
                                Ok(r) => r,
                                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                                Err(e) => return Err(self.counted(e)),
                            }
                        }
                        res = v6.readable() => {
                            res.map_err(|e| self.counted(e))?;
                            match v6.try_recv_from(buf) {
                                Ok(r) => r,
                                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                                Err(e) => return Err(self.counted(e)),
                            }
                        }
                    }
                }
                UdpBackend::KernelSingle(sock) => {
                    sock.recv_from(buf).await.map_err(|e| self.counted(e))?
                }
                #[cfg(any(test, feature = "inert"))]
                UdpBackend::Inert(port) => {
                    let mut rx = port.in_rx.lock().await;
                    match rx.recv().await {
                        Some((packet, addr)) => {
                            let len = packet.len().min(buf.len());
                            buf[..len].copy_from_slice(&packet[..len]);
                            (len, addr)
                        }
                        None => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Inert UDP transport channel closed",
                            ));
                        }
                    }
                }
            };

            // Rate-limiting check
            if let Some(ref limiter) = *self.inner.limiter.read()
                && !limiter.check(&src.ip())
            {
                self.inner.metrics.record_drop();
                continue; // Drop packet early without returning to caller
            }

            self.inner.metrics.record_rx(n);
            return Ok((n, src));
        }
    }

    /// Sends a datagram to the specified destination address.
    ///
    /// Automatically routes to the IPv4 or IPv6 socket based on the target address family.
    pub async fn send(&self, payload: &[u8], target: &SocketAddr) -> io::Result<usize> {
        let res = match &self.inner.backend {
            UdpBackend::KernelDual { v4, v6 } => match target {
                SocketAddr::V4(_) => v4.send_to(payload, target).await,
                SocketAddr::V6(_) => v6.send_to(payload, target).await,
            },
            UdpBackend::KernelSingle(sock) => sock.send_to(payload, target).await,
            #[cfg(any(test, feature = "inert"))]
            UdpBackend::Inert(port) => port
                .out_tx
                .send((payload.to_vec(), *target))
                .await
                .map(|_| payload.len())
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())),
        };

        match res {
            Ok(n) => {
                self.inner.metrics.record_tx(n);
                Ok(n)
            }
            Err(e) => Err(self.counted(e)),
        }
    }

    /// Sends a datagram to the specified destination address.
    pub async fn send_to(&self, payload: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.send(payload, &target).await
    }

    /// Receives a datagram into the provided buffer (alias to `recv`).
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv(buf).await
    }

    /// Attempts to send a datagram immediately without awaiting.
    pub fn try_send(&self, payload: &[u8], target: &SocketAddr) -> io::Result<usize> {
        let res = match &self.inner.backend {
            UdpBackend::KernelDual { v4, v6 } => match target {
                SocketAddr::V4(_) => v4.try_send_to(payload, *target),
                SocketAddr::V6(_) => v6.try_send_to(payload, *target),
            },
            UdpBackend::KernelSingle(sock) => sock.try_send_to(payload, *target),
            #[cfg(any(test, feature = "inert"))]
            UdpBackend::Inert(port) => port
                .out_tx
                .try_send((payload.to_vec(), *target))
                .map(|_| payload.len())
                .map_err(|e| io::Error::new(io::ErrorKind::WouldBlock, e.to_string())),
        };

        match res {
            Ok(n) => {
                self.inner.metrics.record_tx(n);
                Ok(n)
            }
            // A full send buffer is back-pressure, not a failing socket.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            Err(e) => Err(self.counted(e)),
        }
    }

    /// Counts a socket error (the health signal the supervisor degrades on) and passes it on.
    fn counted(&self, e: io::Error) -> io::Error {
        self.inner.metrics.record_error();
        e
    }
}

impl TransportStats for UdpTransport {
    fn snapshot(&self) -> TransportSnapshot {
        self.inner.metrics.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limiter::RateLimitConfig;
    use std::net::SocketAddr;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn a_taken_port_is_addr_in_use() {
        let first = UdpTransport::bind_single("127.0.0.1:0".parse().unwrap()).expect("bind");
        let taken = first.local_addrs().unwrap()[0];
        let Err(err) = UdpTransport::bind_single(taken) else {
            panic!("the port is taken");
        };
        assert_eq!(err.kind, crate::BindErrorKind::AddrInUse);
        assert_eq!(err.target, taken.to_string());
    }

    /// A device-bound socket on an interface that does not exist fails as `NoDevice`; it never
    /// falls back to listening on every interface.
    #[tokio::test]
    async fn a_missing_interface_is_no_device() {
        let Err(err) = UdpTransport::bind_device("lfnone0", "0.0.0.0:0".parse().unwrap()) else {
            panic!("no such interface");
        };
        assert_eq!(err.kind, crate::BindErrorKind::NoDevice);
    }

    /// A send the kernel refuses is counted as an error (broadcast without `SO_BROADCAST` is
    /// `EACCES`); a successful one is not.
    #[tokio::test]
    async fn should_count_kernel_send_errors() {
        let transport =
            UdpTransport::bind_single("127.0.0.1:0".parse().unwrap()).expect("bind loopback");
        let target: SocketAddr = "255.255.255.255:9".parse().unwrap();
        assert!(transport.send(b"x", &target).await.is_err());
        assert!(transport.try_send(b"x", &target).is_err());
        let own = transport.local_addrs().expect("bound")[0];
        transport.send(b"x", &own).await.expect("send to itself");
        let snap = transport.snapshot();
        assert_eq!(snap.errors, 2);
        assert_eq!(snap.tx_packets, 1);
    }

    #[test]
    fn should_report_inert_status_and_synthetic_addresses() {
        let (_handle, transport) = UdpTransport::inert();
        assert!(
            transport.is_inert(),
            "Inert transport must return true for is_inert()"
        );

        let addrs = transport.local_addrs().expect("local_addrs must succeed");
        assert_eq!(
            addrs,
            vec![SocketAddr::from(([127, 0, 0, 1], 0))],
            "Inert transport should report loopback placeholder address"
        );
    }

    #[tokio::test]
    async fn should_send_and_receive_in_inert_mode_updating_metrics() {
        let (handle, transport) = UdpTransport::inert();
        let client_addr: SocketAddr = "192.168.1.55:54321".parse().unwrap();
        let payload = b"hello inert udp".to_vec();

        // 1. Inject packet into transport
        handle.inject(payload.clone(), client_addr).await;

        let mut buf = [0u8; 128];
        let (len, src) = timeout(Duration::from_millis(500), transport.recv(&mut buf))
            .await
            .expect("Recv timeout")
            .expect("Recv failed");

        assert_eq!(src, client_addr);
        assert_eq!(&buf[..len], payload.as_slice());
        assert_eq!(transport.metrics().rx_packets(), 1);
        assert_eq!(transport.metrics().rx_bytes(), payload.len() as u64);

        // 2. Send reply from transport
        let reply = b"inert reply";
        let sent = transport.send(reply, &src).await.expect("Send failed");
        assert_eq!(sent, reply.len());
        assert_eq!(transport.metrics().tx_packets(), 1);
        assert_eq!(transport.metrics().tx_bytes(), reply.len() as u64);

        // 3. Inspect reply on handle
        let (out_packet, dst) = handle.recv_reply().await.expect("Expected reply on handle");
        assert_eq!(out_packet, reply);
        assert_eq!(dst, client_addr);
    }

    #[tokio::test]
    async fn should_truncate_payload_when_recv_buffer_is_smaller() {
        let (handle, transport) = UdpTransport::inert();
        let client_addr: SocketAddr = "10.0.0.1:9000".parse().unwrap();

        handle.inject(b"0123456789".to_vec(), client_addr).await;

        let mut small_buf = [0u8; 4];
        let (len, src) = transport.recv(&mut small_buf).await.expect("Recv failed");

        assert_eq!(len, 4);
        assert_eq!(&small_buf, b"0123");
        assert_eq!(src, client_addr);
    }

    #[tokio::test]
    async fn should_support_try_send_in_inert_mode() {
        let (handle, transport) = UdpTransport::inert();
        let dst: SocketAddr = "10.0.0.2:8000".parse().unwrap();

        let n = transport
            .try_send(b"immediate", &dst)
            .expect("try_send failed");
        assert_eq!(n, 9);
        assert_eq!(transport.metrics().tx_packets(), 1);

        let (reply, out_dst) = handle
            .try_recv_reply()
            .expect("Reply must be immediately available");
        assert_eq!(reply, b"immediate");
        assert_eq!(out_dst, dst);
    }

    #[tokio::test]
    async fn should_return_unexpected_eof_when_handle_channel_closed() {
        let (handle, transport) = UdpTransport::inert();
        drop(handle);

        let mut buf = [0u8; 64];
        let err = transport
            .recv(&mut buf)
            .await
            .expect_err("Expected EOF error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn should_apply_rate_limiter_and_record_drop_metrics_in_inert_mode() {
        let (handle, transport) = UdpTransport::inert();
        let client_addr: SocketAddr = "192.168.1.10:12345".parse().unwrap();

        let limiter = RateLimiter::new(RateLimitConfig {
            pps: 0,
            burst: 1,
            max_sources: 4,
        });
        transport.set_rate_limiter(limiter);

        // Inject 2 packets from same source
        handle.inject(b"pkt 1".to_vec(), client_addr).await;
        handle.inject(b"pkt 2".to_vec(), client_addr).await;

        // Also inject a 3rd packet from a different source so recv() doesn't hang
        // (the 2nd packet from client_addr will be dropped by the rate limiter)
        let other_client: SocketAddr = "192.168.1.20:12345".parse().unwrap();
        handle
            .inject(b"pkt 3 from other".to_vec(), other_client)
            .await;

        let mut buf = [0u8; 64];

        // 1st packet: client_addr (passes burst limit)
        let (len, src) = transport.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"pkt 1");
        assert_eq!(src, client_addr);

        // 2nd packet: client_addr (exceeds burst limit, silently dropped in recv() loop)
        // 3rd packet: other_client (passes its own burst limit)
        let (len, src) = transport.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"pkt 3 from other");
        assert_eq!(src, other_client);

        assert_eq!(transport.metrics().dropped_packets(), 1);
        assert_eq!(transport.metrics().rx_packets(), 2);
    }

    #[test]
    fn should_ignore_multicast_join_in_inert_mode() {
        let (_handle, transport) = UdpTransport::inert();
        let multiaddr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let res = transport.join_multicast_v6(&multiaddr, 0);
        assert!(
            res.is_ok(),
            "Multicast join in inert mode must succeed as no-op"
        );
    }
}
