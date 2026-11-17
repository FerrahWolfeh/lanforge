use crate::bind::bind_error;
use crate::inert::{InertHandle, InertPort};
use crate::metrics::{TransportMetrics, TransportStats};
use crate::sys;
use lanforge_types::network::bind::BindError;
use lanforge_types::network::snapshot::TransportSnapshot;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::AsFd;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tracing::info;

const ALL_ROUTERS_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
const ICMP6_FILTER: libc::c_int = 1;
const ICMPV6_TYPE_RS: u8 = 133;
const ICMPV6_TYPE_RA: u8 = 134;

enum Icmp6Backend {
    Kernel(AsyncFd<Socket>),
    #[cfg(any(test, feature = "inert"))]
    Inert(InertPort<SocketAddrV6>),
}

struct Icmp6Inner {
    backend: Icmp6Backend,
    metrics: Arc<TransportMetrics>,
}

/// Specialized asynchronous `ICMPv6` raw transport for Router Advertisements and NDP.
///
/// Configures kernel-level `ICMP6_FILTER` for zero-overhead filtering of non-RS packets,
/// hop limit 255 validation, and provides an inert mode for rootless testing.
#[derive(Clone)]
pub struct Icmp6Transport {
    inner: Arc<Icmp6Inner>,
}

impl Icmp6Transport {
    /// Creates and binds a raw `ICMPv6` socket to `iface`, joining `ff02::2` and filtering for RS (133).
    ///
    /// # Errors
    /// The socket could not be opened on `iface`.
    pub fn bind(iface: &str, iface_index: u32) -> Result<Self, BindError> {
        Self::open_rs_listener(iface, iface_index).map_err(|e| bind_error(iface.to_string(), e))
    }

    fn open_rs_listener(iface: &str, iface_index: u32) -> io::Result<Self> {
        let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;

        // Bind to LAN interface
        sock.bind_device(Some(iface.as_bytes()))?;

        // RFC 4861 §6.1.2: Hop limit must be 255
        sock.set_multicast_hops_v6(255)?;
        sys::set_sockopt_int(
            sock.as_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            255,
        )?;

        // Join ff02::2 (all-routers)
        sock.join_multicast_v6(&ALL_ROUTERS_MULTICAST, iface_index)?;

        // Kernel-level filter: accept only Router Solicitations (133)
        set_icmp6_filter_only(&sock, ICMPV6_TYPE_RS)?;

        sock.set_nonblocking(true)?;
        let async_fd = sys::register_socket(sock)?;

        info!("Raw socket bound on {iface} (index {iface_index}), listening for RS");
        Ok(Self {
            inner: Arc::new(Icmp6Inner {
                backend: Icmp6Backend::Kernel(async_fd),
                metrics: Arc::new(TransportMetrics::new()),
            }),
        })
    }

    /// A passive listener for the Router Advertisements another router sends on `iface` (an
    /// ISP's on the `PPPoE` link): only type 134 passes the kernel filter; the all-nodes group the
    /// RAs go to is joined by every IPv6 interface. Receives copies only: whoever configures
    /// the link (the kernel, networkd) still gets its own.
    ///
    /// # Errors
    /// The socket could not be opened on `iface`.
    pub fn bind_ra_listener(iface: &str) -> Result<Self, BindError> {
        Self::open_ra_listener(iface).map_err(|e| bind_error(iface.to_string(), e))
    }

    fn open_ra_listener(iface: &str) -> io::Result<Self> {
        let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        sock.bind_device(Some(iface.as_bytes()))?;
        set_icmp6_filter_only(&sock, ICMPV6_TYPE_RA)?;
        sock.set_nonblocking(true)?;
        let async_fd = sys::register_socket(sock)?;
        info!("Raw socket bound on {iface}, listening for RA");
        Ok(Self {
            inner: Arc::new(Icmp6Inner {
                backend: Icmp6Backend::Kernel(async_fd),
                metrics: Arc::new(TransportMetrics::new()),
            }),
        })
    }

    /// Creates an inert transport for rootless testing and simulation.
    #[must_use]
    #[cfg(any(test, feature = "inert"))]
    pub fn inert() -> (InertHandle<SocketAddrV6>, Self) {
        let (handle, port) = InertPort::pair(64);
        let transport = Self {
            inner: Arc::new(Icmp6Inner {
                backend: Icmp6Backend::Inert(port),
                metrics: Arc::new(TransportMetrics::new()),
            }),
        };
        (handle, transport)
    }

    /// Returns `true` if operating in inert testing mode.
    #[must_use]
    pub fn is_inert(&self) -> bool {
        match &self.inner.backend {
            Icmp6Backend::Kernel(_) => false,
            #[cfg(any(test, feature = "inert"))]
            Icmp6Backend::Inert(_) => true,
        }
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

    /// Receives an `ICMPv6` datagram into the provided buffer.
    ///
    /// # Errors
    /// Waiting for readiness or `recvfrom(2)` fails, or the inert channel is closed (`UnexpectedEof`).
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV6)> {
        match &self.inner.backend {
            Icmp6Backend::Kernel(async_fd) => loop {
                let mut guard = async_fd.readable().await.map_err(|e| self.counted(e))?;
                match sys::recv_from_v6(guard.get_inner().as_fd(), buf) {
                    // Readiness stays set until EAGAIN: the next call reads what is queued.
                    Ok((n, src)) => {
                        self.inner.metrics.record_rx(n);
                        return Ok((n, src));
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        guard.clear_ready();
                    }
                    Err(err) => return Err(self.counted(err)),
                }
            },
            #[cfg(any(test, feature = "inert"))]
            Icmp6Backend::Inert(port) => {
                let mut rx = port.in_rx.lock().await;
                match rx.recv().await {
                    Some((packet, addr)) => {
                        let len = packet.len().min(buf.len());
                        buf[..len].copy_from_slice(&packet[..len]);
                        self.inner.metrics.record_rx(len);
                        Ok((len, addr))
                    }
                    None => Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Inert ICMPv6 transport channel closed",
                    )),
                }
            }
        }
    }

    /// Sends an `ICMPv6` packet to the specified destination address.
    ///
    /// # Errors
    /// `send_to` fails on the underlying socket, or the inert channel is full or closed (`WouldBlock`).
    pub fn send(&self, payload: &[u8], target: &SocketAddrV6) -> io::Result<usize> {
        let res = match &self.inner.backend {
            Icmp6Backend::Kernel(async_fd) => {
                let sock = async_fd.get_ref();
                let sa = socket2::SockAddr::from(SocketAddr::V6(*target));
                sock.send_to(payload, &sa)
            }
            #[cfg(any(test, feature = "inert"))]
            Icmp6Backend::Inert(port) => port
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

impl TransportStats for Icmp6Transport {
    fn snapshot(&self) -> TransportSnapshot {
        self.inner.metrics.snapshot()
    }
}

/// Kernel `ICMP6_FILTER` passing only `icmp_type` (a set bit blocks that type).
fn set_icmp6_filter_only(sock: &Socket, icmp_type: u8) -> io::Result<()> {
    let mut filter = [0xFFu8; 32];
    let t = icmp_type as usize;
    filter[t / 8] &= !(1u8 << (t % 8));

    sys::set_sockopt_bytes(sock.as_fd(), libc::IPPROTO_ICMPV6, ICMP6_FILTER, &filter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV6;
    use std::time::Duration;
    use tokio::sync::Mutex;
    use tokio::time::timeout;

    /// Every RA listener on `lo` hears every RA sent there: the tests that send them take turns.
    static RAS_ON_LO: Mutex<()> = Mutex::const_new(());

    /// Real sockets: needs `CAP_NET_RAW`, so it is ignored by default. Rootless run:
    /// `unshare -rn sh -c 'ip link set lo up && cargo test -p lanforge-transport -- --ignored
    /// ra_listener'` (the build must already be done outside the namespace).
    #[tokio::test]
    #[ignore = "needs CAP_NET_RAW (run inside `unshare -rn`)"]
    async fn ra_listener_passes_ras_and_nothing_else() {
        let _lo = RAS_ON_LO.lock().await;
        let listener = Icmp6Transport::bind_ra_listener("lo").expect("bind on lo");
        let sender = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap();
        let to = socket2::SockAddr::from(SocketAddr::V6("[::1]:0".parse().unwrap()));
        let ns = [
            135u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let ra = [134u8, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        sender.send_to(&ns, &to).unwrap(); // filtered out by the kernel
        sender.send_to(&ra, &to).unwrap();
        let mut buf = [0u8; 64];
        let (n, src) = timeout(Duration::from_secs(2), listener.recv(&mut buf))
            .await
            .expect("an RA arrives")
            .expect("recv");
        // The kernel fills the checksum (bytes 2..4) on send.
        assert_eq!(n, ra.len());
        assert_eq!(buf[0], 134, "the NS sent first never reached the listener");
        assert_eq!(&buf[4..n], &ra[4..]);
        assert_eq!(*src.ip(), Ipv6Addr::LOCALHOST);
    }

    /// A send the kernel refuses (no route in an empty namespace) is counted as an error.
    #[tokio::test]
    #[ignore = "needs CAP_NET_RAW (run inside `unshare -rn`)"]
    async fn send_errors_are_counted() {
        let transport = Icmp6Transport::bind_ra_listener("lo").expect("bind on lo");
        let ra = [134u8, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let unroutable: SocketAddrV6 = "[2001:db8::1]:0".parse().unwrap();
        assert!(transport.send(&ra, &unroutable).is_err());
        assert_eq!(transport.snapshot().errors, 1);
    }

    #[test]
    fn should_report_inert_status() {
        let (_handle, transport) = Icmp6Transport::inert();
        assert!(
            transport.is_inert(),
            "Inert transport must return true for is_inert()"
        );
        assert_eq!(transport.metrics().rx_packets(), 0);
        assert_eq!(transport.metrics().tx_packets(), 0);
    }

    #[tokio::test]
    async fn should_send_and_receive_icmp6_in_inert_mode() {
        let (handle, transport) = Icmp6Transport::inert();
        let src: SocketAddrV6 = "[fe80::1]:0".parse().unwrap();
        let rs_packet = vec![133, 0, 0, 0, 0, 0, 0, 0];

        // 1. Inject RS packet
        handle.inject(rs_packet.clone(), src).await;

        let mut buf = [0u8; 512];
        let (len, from) = timeout(Duration::from_millis(500), transport.recv(&mut buf))
            .await
            .expect("Recv timeout")
            .expect("Recv failed");

        assert_eq!(&buf[..len], rs_packet.as_slice());
        assert_eq!(from, src);
        assert_eq!(transport.metrics().rx_packets(), 1);
        assert_eq!(transport.metrics().rx_bytes(), rs_packet.len() as u64);

        // 2. Send RA reply
        let ra_packet = vec![134, 0, 0, 0];
        let sent = transport.send(&ra_packet, &src).expect("Send failed");
        assert_eq!(sent, ra_packet.len());
        assert_eq!(transport.metrics().tx_packets(), 1);
        assert_eq!(transport.metrics().tx_bytes(), ra_packet.len() as u64);

        // 3. Inspect reply on handle
        let (out_packet, dst) = handle.recv_reply().await.expect("Expected reply");
        assert_eq!(out_packet, ra_packet);
        assert_eq!(dst, src);
    }

    #[tokio::test]
    async fn should_truncate_icmp6_payload_when_recv_buffer_is_smaller() {
        let (handle, transport) = Icmp6Transport::inert();
        let src: SocketAddrV6 = "[fe80::2]:0".parse().unwrap();
        let data = vec![1, 2, 3, 4, 5, 6, 7, 8];

        handle.inject(data, src).await;

        let mut small_buf = [0u8; 3];
        let (len, from) = transport.recv(&mut small_buf).await.expect("Recv failed");
        assert_eq!(len, 3);
        assert_eq!(&small_buf, &[1, 2, 3]);
        assert_eq!(from, src);
    }

    #[tokio::test]
    async fn should_return_unexpected_eof_when_handle_channel_closed() {
        let (handle, transport) = Icmp6Transport::inert();
        drop(handle);

        let mut buf = [0u8; 64];
        let err = transport
            .recv(&mut buf)
            .await
            .expect_err("Expected EOF error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn should_support_synchronous_send_in_inert_mode() {
        let (handle, transport) = Icmp6Transport::inert();
        let target: SocketAddrV6 = "[ff02::1]:0".parse().unwrap();
        let payload = vec![134, 0, 0, 0, 0, 0];

        let n = transport.send(&payload, &target).expect("send failed");
        assert_eq!(n, payload.len());
        assert_eq!(transport.metrics().tx_packets(), 1);

        let (reply, out_dst) = handle.try_recv_reply().expect("Expected immediate reply");
        assert_eq!(reply, payload);
        assert_eq!(out_dst, target);
    }

    #[test]
    fn should_calculate_icmp6_filter_rs_bit_correctly() {
        let mut filter = [0xFFu8; 32];
        let t = ICMPV6_TYPE_RS as usize;
        filter[t / 8] &= !(1u8 << (t % 8));

        // ICMPV6_TYPE_RS is 133
        // 133 / 8 = 16, 133 % 8 = 5
        assert_eq!(filter[16], !(1u8 << 5));
        // All other bytes must remain 0xFF (blocking all other ICMPv6 message types)
        for (i, byte) in filter.iter().enumerate() {
            if i != 16 {
                assert_eq!(
                    *byte, 0xFF,
                    "Byte {i} must be 0xFF to filter out other ICMPv6 types"
                );
            }
        }
    }

    /// Regression: a successful read cleared the readiness, so a second RA queued with the first
    /// waited for another arrival.
    #[tokio::test]
    #[ignore = "needs CAP_NET_RAW (run inside `unshare -rn`)"]
    async fn queued_ras_are_all_delivered() {
        let _lo = RAS_ON_LO.lock().await;
        let listener = Icmp6Transport::bind_ra_listener("lo").expect("bind on lo");
        let sender = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap();
        let to = socket2::SockAddr::from(SocketAddr::V6("[::1]:0".parse().unwrap()));
        for hop_limit in 1..=3u8 {
            let ra = [134u8, 0, 0, 0, hop_limit, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            sender.send_to(&ra, &to).unwrap();
        }
        let mut buf = [0u8; 64];
        for hop_limit in 1..=3u8 {
            timeout(Duration::from_secs(2), listener.recv(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("queued RA {hop_limit} not delivered"))
                .expect("recv");
            assert_eq!(buf[4], hop_limit);
        }
    }
}
