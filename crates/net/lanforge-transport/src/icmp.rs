use crate::inert::{InertHandle, InertPort};
use crate::metrics::{TransportMetrics, TransportStats};
use parking_lot::Mutex;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::sync::{oneshot, watch};
use tracing::{debug, warn};

static IDENT_COUNTER: AtomicU16 = AtomicU16::new(1000);

type PendingRegistry = Arc<Mutex<HashMap<(IpAddr, u16, u16), oneshot::Sender<()>>>>;

enum IcmpBackend {
    Kernel {
        socket_v4: Option<Arc<AsyncFd<Socket>>>,
        socket_v6: Option<Arc<AsyncFd<Socket>>>,
    },
    #[cfg(any(test, feature = "inert"))]
    Inert { port: InertPort<IpAddr> },
}

/// Decoupled dual-stack ICMP Ping helper for active reachability checks.
///
/// Supports IPv4 and IPv6 ICMP echo requests and replies with per-instance
/// unique identifier isolation, timeout handling, and inert simulation support.
#[derive(Clone)]
pub struct IcmpPinger {
    backend: Arc<IcmpBackend>,
    registry: PendingRegistry,
    ident: u16,
    metrics: Arc<TransportMetrics>,
    _shutdown_tx: Arc<watch::Sender<bool>>,
}

impl IcmpPinger {
    /// Creates and initializes a new `IcmpPinger`, binding raw ICMPv4/v6 sockets and
    /// spawning the background reader loop.
    pub fn new() -> io::Result<Self> {
        let socket_v4 = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
            Ok(s) => {
                let _ = s.set_nonblocking(true);
                Some(Arc::new(unsafe { AsyncFd::register(s)? }))
            }
            Err(e) => {
                warn!("Failed to create raw IPv4 ICMP socket: {e}");
                None
            }
        };

        let socket_v6 = match Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)) {
            Ok(s) => {
                let _ = s.set_nonblocking(true);
                let fd = s.as_raw_fd();
                let offset = 2i32;
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::IPPROTO_IPV6,
                        libc::IPV6_CHECKSUM,
                        std::ptr::from_ref(&offset).cast::<libc::c_void>(),
                        u32::try_from(std::mem::size_of::<libc::c_int>()).unwrap_or(4)
                            as libc::socklen_t,
                    );
                }
                Some(Arc::new(unsafe { AsyncFd::register(s)? }))
            }
            Err(e) => {
                warn!("Failed to create raw IPv6 ICMP socket: {e}");
                None
            }
        };

        if socket_v4.is_none() && socket_v6.is_none() {
            return Err(io::Error::other("No raw ICMP sockets available"));
        }

        let registry = Arc::new(Mutex::new(HashMap::new()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let ident = IDENT_COUNTER.fetch_add(1, Ordering::Relaxed);

        let pinger = Self {
            backend: Arc::new(IcmpBackend::Kernel {
                socket_v4,
                socket_v6,
            }),
            registry,
            ident,
            metrics: Arc::new(TransportMetrics::new()),
            _shutdown_tx: Arc::new(shutdown_tx),
        };

        pinger.spawn_kernel_read_loop(shutdown_rx);

        Ok(pinger)
    }

    /// Creates an inert `IcmpPinger` for rootless simulation and testing.
    #[must_use]
    #[cfg(any(test, feature = "inert"))]
    pub fn inert() -> (InertHandle<IpAddr>, Self) {
        let (handle, port) = InertPort::pair(64);
        let registry = Arc::new(Mutex::new(HashMap::new()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let ident = IDENT_COUNTER.fetch_add(1, Ordering::Relaxed);

        let pinger = Self {
            backend: Arc::new(IcmpBackend::Inert { port: port.clone() }),
            registry,
            ident,
            metrics: Arc::new(TransportMetrics::new()),
            _shutdown_tx: Arc::new(shutdown_tx),
        };

        pinger.spawn_inert_read_loop(port, shutdown_rx);

        (handle, pinger)
    }

    /// Returns the unique instance identifier used for ICMP echo packets.
    #[must_use]
    pub const fn ident(&self) -> u16 {
        self.ident
    }

    fn spawn_kernel_read_loop(&self, mut shutdown_rx: watch::Receiver<bool>) {
        let IcmpBackend::Kernel {
            socket_v4,
            socket_v6,
        } = self.backend.as_ref()
        else {
            return;
        };
        let registry = self.registry.clone();
        let s_v4 = socket_v4.clone();
        let s_v6 = socket_v6.clone();

        tokio::spawn(async move {
            let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
            loop {
                if *shutdown_rx.borrow() {
                    break;
                }

                let mut read_v4_failed = false;
                let mut read_v6_failed = false;

                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        break;
                    }
                    guard_res = async {
                        match s_v4.as_ref() {
                            Some(fd) => fd.readable().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        if let Ok(mut guard) = guard_res {
                            match guard.get_inner().recv_from(&mut buf) {
                                Ok((n, addr)) => {
                                    guard.clear_ready();
                                    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                                    if let Some(sock_addr) = addr.as_socket() {
                                        let ip = sock_addr.ip();
                                        if let Some((id, seq)) = parse_icmpv4_echo_reply(bytes) {
                                            let mut reg = registry.lock();
                                            if let Some(tx) = reg.remove(&(ip, id, seq)) {
                                                let _ = tx.send(());
                                            }
                                        }
                                    }
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    guard.clear_ready();
                                }
                                Err(_) => {
                                    read_v4_failed = true;
                                }
                            }
                        } else {
                            read_v4_failed = true;
                        }
                    }
                    guard_res = async {
                        match s_v6.as_ref() {
                            Some(fd) => fd.readable().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        if let Ok(mut guard) = guard_res {
                            match guard.get_inner().recv_from(&mut buf) {
                                Ok((n, addr)) => {
                                    guard.clear_ready();
                                    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                                    if let Some(sock_addr) = addr.as_socket() {
                                        let ip = sock_addr.ip();
                                        if let Some((id, seq)) = parse_icmpv6_echo_reply(bytes) {
                                            let mut reg = registry.lock();
                                            if let Some(tx) = reg.remove(&(ip, id, seq)) {
                                                let _ = tx.send(());
                                            }
                                        }
                                    }
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    guard.clear_ready();
                                }
                                Err(_) => {
                                    read_v6_failed = true;
                                }
                            }
                        } else {
                            read_v6_failed = true;
                        }
                    }
                }

                if read_v4_failed && read_v6_failed {
                    break;
                }
            }
        });
    }

    #[cfg(any(test, feature = "inert"))]
    fn spawn_inert_read_loop(
        &self,
        port: InertPort<IpAddr>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let registry = self.registry.clone();
        tokio::spawn(async move {
            loop {
                if *shutdown_rx.borrow() {
                    break;
                }
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        break;
                    }
                    recv_res = async {
                        let mut rx = port.in_rx.lock().await;
                        rx.recv().await
                    } => {
                        let Some((bytes, ip)) = recv_res else {
                            break;
                        };
                        let parsed = match ip {
                            IpAddr::V4(_) => parse_icmpv4_echo_reply(&bytes),
                            IpAddr::V6(_) => parse_icmpv6_echo_reply(&bytes),
                        };
                        if let Some((id, seq)) = parsed {
                            let mut reg = registry.lock();
                            if let Some(tx) = reg.remove(&(ip, id, seq)) {
                                let _ = tx.send(());
                            }
                        }
                    }
                }
            }
        });
    }

    /// Sends a targeted ICMP Echo Request and waits for an Echo Reply with a 1-second timeout.
    pub async fn ping(&self, ip: IpAddr, seq: u16) -> io::Result<bool> {
        self.ping_timeout(ip, seq, Duration::from_secs(1)).await
    }

    /// Sends a targeted ICMP Echo Request and waits for an Echo Reply with the specified timeout.
    pub async fn ping_timeout(&self, ip: IpAddr, seq: u16, timeout: Duration) -> io::Result<bool> {
        const PAYLOAD: &[u8] = b"LanforgeProberPingPayload";
        const PACKET_LEN: usize = 8 + PAYLOAD.len();

        let ident = self.ident;
        let (tx, rx) = oneshot::channel();

        // Register pending ping
        {
            let mut reg = self.registry.lock();
            reg.insert((ip, ident, seq), tx);
        }

        let sent = match self.backend.as_ref() {
            IcmpBackend::Kernel {
                socket_v4,
                socket_v6,
            } => match ip {
                IpAddr::V4(ip4) => socket_v4.as_ref().is_some_and(|s_v4| {
                    let mut packet = [0u8; PACKET_LEN];
                    packet[0] = 8; // Echo Request
                    packet[1] = 0;
                    packet[4..6].copy_from_slice(&ident.to_be_bytes());
                    packet[6..8].copy_from_slice(&seq.to_be_bytes());
                    packet[8..].copy_from_slice(PAYLOAD);
                    let cs = checksum(&packet);
                    packet[2..4].copy_from_slice(&cs.to_be_bytes());

                    let dest = SocketAddr::new(IpAddr::V4(ip4), 0);
                    s_v4.get_ref()
                        .send_to(&packet, &socket2::SockAddr::from(dest))
                        .is_ok()
                }),
                IpAddr::V6(ip6) => socket_v6.as_ref().is_some_and(|s_v6| {
                    let mut packet = [0u8; PACKET_LEN];
                    packet[0] = 128; // Echo Request
                    packet[1] = 0;
                    packet[4..6].copy_from_slice(&ident.to_be_bytes());
                    packet[6..8].copy_from_slice(&seq.to_be_bytes());
                    packet[8..].copy_from_slice(PAYLOAD);

                    let dest = SocketAddr::new(IpAddr::V6(ip6), 0);
                    s_v6.get_ref()
                        .send_to(&packet, &socket2::SockAddr::from(dest))
                        .is_ok()
                }),
            },
            #[cfg(any(test, feature = "inert"))]
            IcmpBackend::Inert { port } => {
                let mut packet = [0u8; PACKET_LEN];
                match ip {
                    IpAddr::V4(_) => {
                        packet[0] = 8;
                        packet[1] = 0;
                        packet[4..6].copy_from_slice(&ident.to_be_bytes());
                        packet[6..8].copy_from_slice(&seq.to_be_bytes());
                        packet[8..].copy_from_slice(PAYLOAD);
                        let cs = checksum(&packet);
                        packet[2..4].copy_from_slice(&cs.to_be_bytes());
                    }
                    IpAddr::V6(_) => {
                        packet[0] = 128;
                        packet[1] = 0;
                        packet[4..6].copy_from_slice(&ident.to_be_bytes());
                        packet[6..8].copy_from_slice(&seq.to_be_bytes());
                        packet[8..].copy_from_slice(PAYLOAD);
                    }
                }
                port.out_tx.try_send((packet.to_vec(), ip)).is_ok()
            }
        };

        if !sent {
            self.registry.lock().remove(&(ip, ident, seq));
            self.metrics.record_error();
            return Err(io::Error::other("Socket unavailable"));
        }
        self.metrics.record_tx(PACKET_LEN);

        if tokio::time::timeout(timeout, rx).await == Ok(Ok(())) {
            debug!("Ping response received from {ip}");
            self.metrics.record_rx(PACKET_LEN);
            Ok(true)
        } else {
            self.registry.lock().remove(&(ip, ident, seq));
            self.metrics.record_error();
            debug!("Ping timeout/failed for {ip}");
            Ok(false)
        }
    }
}

impl TransportStats for IcmpPinger {
    fn snapshot(&self) -> lanforge_types::network::snapshot::TransportSnapshot {
        self.metrics.snapshot()
    }
}

/// Parses a raw IPv4 packet containing an ICMP Echo Reply.
///
/// IPv4 raw sockets deliver the full IP header along with the ICMP payload.
/// This function verifies the IP header length (IHL) and extracts the ICMP
/// Identifier and Sequence Number if the packet is an Echo Reply (Type 0).
#[must_use]
pub const fn parse_icmpv4_echo_reply(bytes: &[u8]) -> Option<(u16, u16)> {
    if bytes.len() < 28 {
        return None;
    }
    let ihl = ((bytes[0] & 0x0f) * 4) as usize;
    if ihl < 20 || bytes.len() < ihl + 8 {
        return None;
    }
    let icmp_type = bytes[ihl];
    if icmp_type == 0 {
        let id = u16::from_be_bytes([bytes[ihl + 4], bytes[ihl + 5]]);
        let seq = u16::from_be_bytes([bytes[ihl + 6], bytes[ihl + 7]]);
        Some((id, seq))
    } else {
        None
    }
}

/// Parses an `ICMPv6` packet containing an `ICMPv6` Echo Reply.
///
/// On Linux raw sockets for `IPPROTO_ICMPV6`, the kernel strips the IPv6 header
/// and delivers the `ICMPv6` message directly. This function extracts the
/// `ICMPv6` Identifier and Sequence Number if the packet is an Echo Reply (Type 129).
#[must_use]
pub const fn parse_icmpv6_echo_reply(bytes: &[u8]) -> Option<(u16, u16)> {
    if bytes.len() < 8 {
        return None;
    }
    let icmp_type = bytes[0];
    if icmp_type == 129 {
        let id = u16::from_be_bytes([bytes[4], bytes[5]]);
        let seq = u16::from_be_bytes([bytes[6], bytes[7]]);
        Some((id, seq))
    } else {
        None
    }
}

/// Computes the Internet Checksum (RFC 1071) over data.
#[must_use]
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let chunks = data.as_chunks::<2>();
    for chunk in chunks.0 {
        sum += u32::from(u16::from_be_bytes(*chunk));
    }
    if let [tail] = chunks.1 {
        sum += u32::from(u16::from_be_bytes([*tail, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    u16::try_from(!sum & 0xffff).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_icmpv4_echo_reply_standard_header() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45; // Version 4, IHL = 5 (20 bytes)
        packet[20] = 0; // ICMP Type: Echo Reply
        packet[21] = 0; // ICMP Code
        packet[24..26].copy_from_slice(&0x1234u16.to_be_bytes()); // ID
        packet[26..28].copy_from_slice(&0x0042u16.to_be_bytes()); // Seq

        let res = parse_icmpv4_echo_reply(&packet);
        assert_eq!(res, Some((0x1234, 0x0042)));
    }

    #[test]
    fn test_parse_icmpv6_echo_reply() {
        let mut packet = vec![0u8; 8];
        packet[0] = 129; // Echo Reply
        packet[1] = 0;
        packet[4..6].copy_from_slice(&0x5678u16.to_be_bytes()); // ID
        packet[6..8].copy_from_slice(&0x0099u16.to_be_bytes()); // Seq

        let res = parse_icmpv6_echo_reply(&packet);
        assert_eq!(res, Some((0x5678, 0x0099)));
    }

    #[test]
    fn test_checksum_calculation() {
        let data = [0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01];
        let cs = checksum(&data);
        assert_ne!(cs, 0);
    }

    #[tokio::test]
    async fn test_icmp_pinger_inert_success() {
        let (handle, pinger) = IcmpPinger::inert();
        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let ident = pinger.ident();
        let seq = 42u16;

        let responder = tokio::spawn(async move {
            if let Some((_req, ip)) = handle.recv_reply().await {
                // Synthesize an IPv4 echo reply packet
                let mut reply = vec![0u8; 28];
                reply[0] = 0x45; // IPv4, IHL = 5
                reply[20] = 0; // Type: Echo reply
                reply[24..26].copy_from_slice(&ident.to_be_bytes());
                reply[26..28].copy_from_slice(&seq.to_be_bytes());
                handle.inject(reply, ip).await;
            }
        });

        let res = pinger
            .ping_timeout(target_ip, seq, Duration::from_millis(500))
            .await;
        assert!(res.unwrap());
        let _ = responder.await;
    }

    #[tokio::test]
    async fn test_icmp_pinger_inert_timeout() {
        let (_handle, pinger) = IcmpPinger::inert();
        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99));
        let res = pinger
            .ping_timeout(target_ip, 1, Duration::from_millis(50))
            .await;
        assert!(!res.unwrap());
    }
}
