use crate::inert::{InertHandle, InertPort};
use crate::metrics::TransportMetrics;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::mem::size_of;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::ptr::from_ref;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tracing::info;

const ALL_ROUTERS_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
const ICMP6_FILTER: libc::c_int = 1;
const ICMPV6_TYPE_RS: u8 = 133;

enum Icmp6Backend {
    Kernel(AsyncFd<Socket>),
    #[cfg(any(test, feature = "inert"))]
    Inert(InertPort<SocketAddrV6>),
}

struct Icmp6Inner {
    backend: Icmp6Backend,
    metrics: TransportMetrics,
}

/// Specialized asynchronous ICMPv6 raw transport for Router Advertisements and NDP.
///
/// Configures kernel-level `ICMP6_FILTER` for zero-overhead filtering of non-RS packets,
/// hop limit 255 validation, and provides an inert mode for rootless testing.
#[derive(Clone)]
pub struct Icmp6Transport {
    inner: Arc<Icmp6Inner>,
}

impl Icmp6Transport {
    /// Creates and binds a raw ICMPv6 socket to `iface`, joining `ff02::2` and filtering for RS (133).
    pub fn bind(iface: &str, iface_index: u32) -> io::Result<Self> {
        let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;

        // Bind to LAN interface
        sock.bind_device(Some(iface.as_bytes()))?;

        // RFC 4861 §6.1.2: Hop limit must be 255
        sock.set_multicast_hops_v6(255)?;
        set_sockopt_int(&sock, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, 255)?;

        // Join ff02::2 (all-routers)
        sock.join_multicast_v6(&ALL_ROUTERS_MULTICAST, iface_index)?;

        // Kernel-level filter: accept only Router Solicitations (133)
        set_icmp6_filter_rs_only(&sock)?;

        sock.set_nonblocking(true)?;
        let async_fd = AsyncFd::new(sock)?;

        info!("ICMPv6: Raw socket bound on {iface} (index {iface_index}), listening for RS");
        Ok(Self {
            inner: Arc::new(Icmp6Inner {
                backend: Icmp6Backend::Kernel(async_fd),
                metrics: TransportMetrics::new(),
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
                metrics: TransportMetrics::new(),
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

    /// Receives an ICMPv6 datagram into the provided buffer.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV6)> {
        match &self.inner.backend {
            Icmp6Backend::Kernel(async_fd) => {
                loop {
                    let mut guard = async_fd.readable().await?;
                    let sock = guard.get_inner();

                    // Read from raw socket
                    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                    let mut socklen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

                    let ret = unsafe {
                        libc::recvfrom(
                            sock.as_raw_fd(),
                            buf.as_mut_ptr().cast::<libc::c_void>(),
                            buf.len(),
                            0,
                            std::ptr::from_mut(&mut storage).cast::<libc::sockaddr>(),
                            &mut socklen,
                        )
                    };

                    if ret >= 0 {
                        guard.clear_ready();
                        let n = ret as usize;
                        let src = unsafe {
                            let sa = &*std::ptr::from_ref(&storage).cast::<libc::sockaddr_in6>();
                            let ip = Ipv6Addr::from(sa.sin6_addr.s6_addr);
                            SocketAddrV6::new(ip, u16::from_be(sa.sin6_port), sa.sin6_flowinfo, sa.sin6_scope_id)
                        };
                        self.inner.metrics.record_rx(n);
                        return Ok((n, src));
                    }

                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        guard.clear_ready();
                        continue;
                    }
                    return Err(err);
                }
            }
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

    /// Sends an ICMPv6 packet to the specified destination address.
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

        if let Ok(n) = res {
            self.inner.metrics.record_tx(n);
        }
        res
    }
}

fn set_icmp6_filter_rs_only(sock: &Socket) -> io::Result<()> {
    let mut filter = [0xFFu8; 32];
    let t = ICMPV6_TYPE_RS as usize;
    filter[t / 8] &= !(1u8 << (t % 8));

    set_sockopt_raw(sock, libc::IPPROTO_ICMPV6, ICMP6_FILTER, &filter)
}

fn set_sockopt_int(
    sock: &Socket,
    level: libc::c_int,
    opt: libc::c_int,
    val: i32,
) -> io::Result<()> {
    let v = val as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            opt,
            from_ref(&v).cast::<libc::c_void>(),
            libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap_or_default(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn set_sockopt_raw(
    sock: &Socket,
    level: libc::c_int,
    opt: libc::c_int,
    val: &[u8],
) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            opt,
            val.as_ptr().cast::<libc::c_void>(),
            libc::socklen_t::try_from(val.len()).unwrap_or_default(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
