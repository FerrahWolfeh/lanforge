use crate::inert::{InertHandle, InertPort};
use crate::metrics::{TransportMetrics, TransportStats};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;

/// EtherType for PPPoE Active Discovery packets.
pub const ETH_P_PPP_DISC: u16 = 0x8863;
/// EtherType for PPPoE Session packets.
pub const ETH_P_PPP_SES: u16 = 0x8864;
/// Protocol constant for PPPoE over PPPOX.
pub const PX_PROTO_OE: u32 = 0;

/// Linux PPPoE sockaddr structure for `AF_PPPOX`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PppoeAddr {
    pub sid: u16,
    pub remote: [u8; 6],
    pub dev: [u8; 16],
}

/// Linux PPPOX generic sockaddr structure.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SockAddrPppox {
    pub sa_family: u16,
    pub sa_protocol: u32,
    pub pppoe: PppoeAddr,
}

#[derive(Clone)]
enum PppoeDiscoveryBackend {
    Kernel(Arc<AsyncFd<OwnedFd>>),
    #[cfg(any(test, feature = "inert"))]
    Inert(InertPort<()>),
}

#[derive(Clone)]
enum PppoeSessionBackend {
    Kernel(Arc<AsyncFd<OwnedFd>>),
    #[cfg(any(test, feature = "inert"))]
    Inert(InertPort<()>),
}

struct PppoeTransportInner {
    discovery: parking_lot::RwLock<Option<PppoeDiscoveryBackend>>,
    session: parking_lot::RwLock<Option<PppoeSessionBackend>>,
    metrics: TransportMetrics,
}

/// Test handle for rootless PPPoE simulation and verification.
#[derive(Clone)]
pub struct PppoeInertHandle {
    pub discovery: InertHandle<()>,
    pub session: InertHandle<()>,
}

impl PppoeInertHandle {
    /// Injects a synthetic discovery frame (e.g. PADO, PADS) to the PPPoE client.
    pub async fn inject_discovery(&self, frame: Vec<u8>) {
        self.discovery.inject(frame, ()).await;
    }

    /// Receives the next discovery frame sent by the PPPoE client (e.g. PADI, PADR, PADT).
    pub async fn recv_discovery(&self) -> Option<Vec<u8>> {
        self.discovery.recv_payload().await
    }

    /// Injects a synthetic session frame (e.g. LCP, Auth, IPCP, Echo-Reply) to the PPPoE client.
    pub async fn inject_session(&self, frame: Vec<u8>) {
        self.session.inject(frame, ()).await;
    }

    /// Receives the next session frame sent by the PPPoE client.
    pub async fn recv_session(&self) -> Option<Vec<u8>> {
        self.session.recv_payload().await
    }
}

/// Asynchronous transport abstraction for PPPoE Discovery and Session frames.
#[derive(Clone)]
pub struct PppoeTransport {
    inner: Arc<PppoeTransportInner>,
}

impl PppoeTransport {
    /// Binds an `AF_PACKET` raw socket to `ifindex` for PPPoE Active Discovery (`ETH_P_PPP_DISC`).
    pub fn bind(ifindex: u32) -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                (libc::ETH_P_ALL as u16).to_be() as libc::c_int,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let saddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: ETH_P_PPP_DISC.to_be(),
            sll_ifindex: ifindex as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 6,
            sll_addr: [0; 8],
        };

        let res = unsafe {
            libc::bind(
                fd,
                std::ptr::addr_of!(saddr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if res < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let async_fd = unsafe { AsyncFd::register(owned_fd)? };

        Ok(Self {
            inner: Arc::new(PppoeTransportInner {
                discovery: parking_lot::RwLock::new(Some(PppoeDiscoveryBackend::Kernel(Arc::new(
                    async_fd,
                )))),
                session: parking_lot::RwLock::new(None),
                metrics: TransportMetrics::new(),
            }),
        })
    }

    /// Creates an inert transport for rootless testing and simulation.
    #[must_use]
    #[cfg(any(test, feature = "inert"))]
    pub fn inert() -> (PppoeInertHandle, Self) {
        let (disc_handle, disc_port) = InertPort::pair(128);
        let (sess_handle, sess_port) = InertPort::pair(128);

        let handle = PppoeInertHandle {
            discovery: disc_handle,
            session: sess_handle,
        };

        let transport = Self {
            inner: Arc::new(PppoeTransportInner {
                discovery: parking_lot::RwLock::new(Some(PppoeDiscoveryBackend::Inert(disc_port))),
                session: parking_lot::RwLock::new(Some(PppoeSessionBackend::Inert(sess_port))),
                metrics: TransportMetrics::new(),
            }),
        };

        (handle, transport)
    }

    /// Connects the PPPoE session data path using `AF_PPPOX`.
    pub fn connect_session(
        &self,
        ifname: &str,
        ac_mac: [u8; 6],
        session_id: u16,
    ) -> io::Result<()> {
        let is_inert = self.is_inert();
        if is_inert {
            return Ok(());
        }

        let fd = unsafe {
            libc::socket(
                libc::AF_PPPOX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut dev_bytes = [0u8; 16];
        let bytes = ifname.as_bytes();
        if bytes.len() >= 16 || bytes.contains(&0) {
            unsafe { libc::close(fd) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid interface name",
            ));
        }
        dev_bytes[..bytes.len()].copy_from_slice(bytes);

        let addr = SockAddrPppox {
            sa_family: libc::AF_PPPOX as u16,
            sa_protocol: PX_PROTO_OE,
            pppoe: PppoeAddr {
                sid: session_id.to_be(),
                remote: ac_mac,
                dev: dev_bytes,
            },
        };

        let res = unsafe {
            libc::connect(
                fd,
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<SockAddrPppox>() as libc::socklen_t,
            )
        };
        if res < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let async_fd = unsafe { AsyncFd::register(owned_fd)? };
        *self.inner.session.write() = Some(PppoeSessionBackend::Kernel(Arc::new(async_fd)));
        Ok(())
    }

    /// Sends a discovery frame (e.g. PADI, PADR, PADT) through the transport.
    pub async fn send_discovery(&self, frame: &[u8]) -> io::Result<usize> {
        let backend = { self.inner.discovery.read().clone() };
        let backend = backend.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Discovery socket not bound")
        })?;

        let res = match backend {
            PppoeDiscoveryBackend::Kernel(async_fd) => {
                let mut guard = async_fd.writable().await?;
                let n = unsafe {
                    libc::write(
                        async_fd.get_ref().as_raw_fd(),
                        frame.as_ptr().cast::<libc::c_void>(),
                        frame.len(),
                    )
                };
                guard.clear_ready();
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(n as usize)
            }
            #[cfg(any(test, feature = "inert"))]
            PppoeDiscoveryBackend::Inert(port) => port
                .out_tx
                .send((frame.to_vec(), ()))
                .await
                .map(|_| frame.len())
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())),
        };

        if let Ok(n) = res {
            self.inner.metrics.record_tx(n);
        } else {
            self.inner.metrics.record_error();
        }
        res
    }

    /// Receives a discovery frame through the transport.
    pub async fn recv_discovery(&self, buf: &mut [u8]) -> io::Result<usize> {
        let backend = { self.inner.discovery.read().clone() };
        let backend = backend.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "Discovery socket not bound")
        })?;

        loop {
            let res = match &backend {
                PppoeDiscoveryBackend::Kernel(async_fd) => {
                    let mut guard = async_fd.readable().await?;
                    let n = unsafe {
                        libc::read(
                            async_fd.get_ref().as_raw_fd(),
                            buf.as_mut_ptr().cast::<libc::c_void>(),
                            buf.len(),
                        )
                    };
                    if n < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() == io::ErrorKind::WouldBlock {
                            guard.clear_ready();
                            continue;
                        }
                        return Err(err);
                    }
                    guard.clear_ready();
                    Ok(n as usize)
                }
                #[cfg(any(test, feature = "inert"))]
                PppoeDiscoveryBackend::Inert(port) => {
                    let mut rx = port.in_rx.lock().await;
                    match rx.recv().await {
                        Some((packet, ())) => {
                            let len = packet.len().min(buf.len());
                            buf[..len].copy_from_slice(&packet[..len]);
                            Ok(len)
                        }
                        None => Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Inert PPPoE discovery channel closed",
                        )),
                    }
                }
            };

            if let Ok(n) = res {
                self.inner.metrics.record_rx(n);
            } else {
                self.inner.metrics.record_error();
            }
            return res;
        }
    }

    /// Sends a PPP session frame (e.g. LCP, PAP/CHAP, IPCP, Echo-Req) through the transport.
    pub async fn send_session(&self, frame: &[u8]) -> io::Result<usize> {
        let backend = { self.inner.session.read().clone() };
        let backend = backend.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "PPPoE session not connected")
        })?;

        let res = match backend {
            PppoeSessionBackend::Kernel(async_fd) => {
                let mut guard = async_fd.writable().await?;
                let n = unsafe {
                    libc::write(
                        async_fd.get_ref().as_raw_fd(),
                        frame.as_ptr().cast::<libc::c_void>(),
                        frame.len(),
                    )
                };
                guard.clear_ready();
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(n as usize)
            }
            #[cfg(any(test, feature = "inert"))]
            PppoeSessionBackend::Inert(port) => port
                .out_tx
                .send((frame.to_vec(), ()))
                .await
                .map(|_| frame.len())
                .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())),
        };

        if let Ok(n) = res {
            self.inner.metrics.record_tx(n);
        } else {
            self.inner.metrics.record_error();
        }
        res
    }

    /// Receives a PPP session frame through the transport.
    pub async fn recv_session(&self, buf: &mut [u8]) -> io::Result<usize> {
        let backend = { self.inner.session.read().clone() };
        let backend = backend.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "PPPoE session not connected")
        })?;

        loop {
            let res = match &backend {
                PppoeSessionBackend::Kernel(async_fd) => {
                    let mut guard = async_fd.readable().await?;
                    let n = unsafe {
                        libc::read(
                            async_fd.get_ref().as_raw_fd(),
                            buf.as_mut_ptr().cast::<libc::c_void>(),
                            buf.len(),
                        )
                    };
                    if n < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() == io::ErrorKind::WouldBlock {
                            guard.clear_ready();
                            continue;
                        }
                        return Err(err);
                    }
                    guard.clear_ready();
                    Ok(n as usize)
                }
                #[cfg(any(test, feature = "inert"))]
                PppoeSessionBackend::Inert(port) => {
                    let mut rx = port.in_rx.lock().await;
                    match rx.recv().await {
                        Some((packet, ())) => {
                            let len = packet.len().min(buf.len());
                            buf[..len].copy_from_slice(&packet[..len]);
                            Ok(len)
                        }
                        None => Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Inert PPPoE session channel closed",
                        )),
                    }
                }
            };

            if let Ok(n) = res {
                self.inner.metrics.record_rx(n);
            } else {
                self.inner.metrics.record_error();
            }
            return res;
        }
    }

    /// Returns `true` if operating in inert testing mode.
    #[must_use]
    pub fn is_inert(&self) -> bool {
        let disc = self.inner.discovery.read();
        match disc.as_ref() {
            #[cfg(any(test, feature = "inert"))]
            Some(PppoeDiscoveryBackend::Inert(_)) => true,
            _ => false,
        }
    }

    /// Returns the raw file descriptor of the connected session socket (if in kernel mode).
    #[must_use]
    pub fn session_raw_fd(&self) -> Option<RawFd> {
        let sess = self.inner.session.read();
        match sess.as_ref()? {
            PppoeSessionBackend::Kernel(async_fd) => Some(async_fd.get_ref().as_raw_fd()),
            #[cfg(any(test, feature = "inert"))]
            PppoeSessionBackend::Inert(_) => None,
        }
    }

    /// Clones the owned file descriptor of the connected session socket (if in kernel mode).
    pub fn try_clone_session_fd(&self) -> io::Result<Option<OwnedFd>> {
        let sess = self.inner.session.read();
        match sess.as_ref() {
            Some(PppoeSessionBackend::Kernel(async_fd)) => {
                Ok(Some(async_fd.get_ref().try_clone()?))
            }
            _ => Ok(None),
        }
    }

    /// Accesses transparent traffic metrics.
    #[must_use]
    pub fn metrics(&self) -> &TransportMetrics {
        &self.inner.metrics
    }
}

impl TransportStats for PppoeTransport {
    fn snapshot(&self) -> lanforge_types::network::snapshot::TransportSnapshot {
        self.inner.metrics.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn should_send_and_receive_in_inert_mode() {
        let (handle, transport) = PppoeTransport::inert();
        assert!(transport.is_inert());

        // Test discovery channel
        handle.inject_discovery(vec![1, 2, 3, 4]).await;
        let mut buf = [0u8; 16];
        let n = transport.recv_discovery(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[1, 2, 3, 4]);

        transport.send_discovery(&[5, 6, 7, 8]).await.unwrap();
        let reply = handle.recv_discovery().await.unwrap();
        assert_eq!(reply, vec![5, 6, 7, 8]);

        // Test session channel
        handle.inject_session(vec![9, 10, 11]).await;
        let n = transport.recv_session(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[9, 10, 11]);

        transport.send_session(&[12, 13]).await.unwrap();
        let reply = handle.recv_session().await.unwrap();
        assert_eq!(reply, vec![12, 13]);

        // Check metrics
        let snap = transport.snapshot();
        assert_eq!(snap.rx_packets, 2);
        assert_eq!(snap.rx_bytes, 7);
        assert_eq!(snap.tx_packets, 2);
        assert_eq!(snap.tx_bytes, 6);
    }
}
