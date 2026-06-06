use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::sync::oneshot;
use tracing::{debug, warn};

use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;

type PendingRegistry = Arc<Mutex<HashMap<(IpAddr, u16, u16), oneshot::Sender<()>>>>;
type ActiveSockets = (
    Option<Arc<AsyncFd<socket2::Socket>>>,
    Option<Arc<AsyncFd<socket2::Socket>>>,
);

/// Decoupled ICMP Ping helper class for active reachability checks.
pub struct IcmpPinger {
    socket_v4: Option<Arc<AsyncFd<socket2::Socket>>>,
    socket_v6: Option<Arc<AsyncFd<socket2::Socket>>>,
    registry: PendingRegistry,
}

impl IcmpPinger {
    /// Creates and initializes a new `IcmpPinger`, spawning the background reader loop.
    pub fn new(ctx: LanforgeContext) -> Result<Self, CoreError> {
        let (socket_v4, socket_v6) = Self::setup_sockets()?;

        if socket_v4.is_none() && socket_v6.is_none() {
            return Err(CoreError::Generic(
                "No raw ICMP sockets available".to_string(),
            ));
        }

        let registry = Arc::new(Mutex::new(HashMap::new()));

        let pinger = Self {
            socket_v4,
            socket_v6,
            registry,
        };

        pinger.spawn_read_loop(ctx);

        Ok(pinger)
    }

    fn setup_sockets() -> Result<ActiveSockets, CoreError> {
        // Setup IPv4 ICMP raw socket
        let socket_v4 = match socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        ) {
            Ok(s) => {
                let _ = s.set_nonblocking(true);
                Some(Arc::new(AsyncFd::new(s).map_err(CoreError::Io)?))
            }
            Err(e) => {
                warn!("Failed to create raw IPv4 ICMP socket: {e}");
                None
            }
        };

        // Setup IPv6 ICMP raw socket
        let socket_v6 = match socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV6),
        ) {
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
                Some(Arc::new(AsyncFd::new(s).map_err(CoreError::Io)?))
            }
            Err(e) => {
                warn!("Failed to create raw IPv6 ICMP socket: {e}");
                None
            }
        };

        Ok((socket_v4, socket_v6))
    }

    fn spawn_read_loop(&self, ctx: LanforgeContext) {
        let registry = self.registry.clone();
        let socket_v4 = self.socket_v4.clone();
        let socket_v6 = self.socket_v6.clone();

        tokio::spawn(async move {
            let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
            loop {
                if !ctx.is_running() {
                    break;
                }

                let mut read_v4_failed = false;
                let mut read_v6_failed = false;

                tokio::select! {
                    guard_res = async {
                        if let Some(ref fd) = socket_v4 {
                            fd.readable().await
                        } else {
                            futures::future::pending().await
                        }
                    } => {
                        if let Ok(mut guard) = guard_res {
                            match guard.get_inner().recv_from(&mut buf) {
                                Ok((n, addr)) => {
                                    guard.clear_ready();
                                    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                                    if let Some(sock_addr) = addr.as_socket() {
                                        let ip = sock_addr.ip();
                                        if n >= 28 {
                                            let ihl = ((bytes[0] & 0x0f) * 4) as usize;
                                            if n >= ihl + 8 {
                                                let icmp_type = bytes[ihl];
                                                if icmp_type == 0 { // Echo Reply
                                                    let id = u16::from_be_bytes([bytes[ihl + 4], bytes[ihl + 5]]);
                                                    let seq = u16::from_be_bytes([bytes[ihl + 6], bytes[ihl + 7]]);
                                                    let mut reg = registry.lock();
                                                    if let Some(tx) = reg.remove(&(ip, id, seq)) {
                                                        let _ = tx.send(());
                                                    }
                                                }
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
                        if let Some(ref fd) = socket_v6 {
                            fd.readable().await
                        } else {
                            futures::future::pending().await
                        }
                    } => {
                        if let Ok(mut guard) = guard_res {
                            match guard.get_inner().recv_from(&mut buf) {
                                Ok((n, addr)) => {
                                    guard.clear_ready();
                                    let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                                    if let Some(sock_addr) = addr.as_socket() {
                                        let ip = sock_addr.ip();
                                        if n >= 8 {
                                            let icmp_type = bytes[0];
                                            if icmp_type == 129 { // Echo Reply
                                                let id = u16::from_be_bytes([bytes[4], bytes[5]]);
                                                let seq = u16::from_be_bytes([bytes[6], bytes[7]]);
                                                let mut reg = registry.lock();
                                                if let Some(tx) = reg.remove(&(ip, id, seq)) {
                                                    let _ = tx.send(());
                                                }
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

    /// Sends a targeted ICMP Echo Request and waits for an Echo Reply with a 1-second timeout.
    pub async fn ping(&self, ip: IpAddr, seq: u16) -> Result<bool, std::io::Error> {
        let ident = 12345u16;
        let (tx, rx) = oneshot::channel();

        // Register pending ping
        {
            let mut reg = self.registry.lock();
            reg.insert((ip, ident, seq), tx);
        }

        let payload = b"LanforgeProberPingPayload";
        let sent = match ip {
            IpAddr::V4(ip4) => self.socket_v4.as_ref().is_some_and(|s_v4| {
                let mut packet = vec![0u8; 8 + payload.len()];
                packet[0] = 8; // Echo Request
                packet[1] = 0;
                packet[4..6].copy_from_slice(&ident.to_be_bytes());
                packet[6..8].copy_from_slice(&seq.to_be_bytes());
                packet[8..].copy_from_slice(payload);
                let cs = checksum(&packet);
                packet[2..4].copy_from_slice(&cs.to_be_bytes());

                let dest = SocketAddr::new(IpAddr::V4(ip4), 0);
                s_v4.get_ref()
                    .send_to(&packet, &socket2::SockAddr::from(dest))
                    .is_ok()
            }),
            IpAddr::V6(ip6) => self.socket_v6.as_ref().is_some_and(|s_v6| {
                let mut packet = vec![0u8; 8 + payload.len()];
                packet[0] = 128; // Echo Request
                packet[1] = 0;
                packet[4..6].copy_from_slice(&ident.to_be_bytes());
                packet[6..8].copy_from_slice(&seq.to_be_bytes());
                packet[8..].copy_from_slice(payload);

                let dest = SocketAddr::new(IpAddr::V6(ip6), 0);
                s_v6.get_ref()
                    .send_to(&packet, &socket2::SockAddr::from(dest))
                    .is_ok()
            }),
        };

        if !sent {
            self.registry.lock().remove(&(ip, ident, seq));
            return Err(std::io::Error::other("Socket unavailable"));
        }

        // Wait with 1-second timeout
        let timeout_duration = Duration::from_secs(1);
        if tokio::time::timeout(timeout_duration, rx).await == Ok(Ok(())) {
            debug!("Ping response received from {ip}");
            Ok(true)
        } else {
            self.registry.lock().remove(&(ip, ident, seq));
            debug!("Ping timeout/failed for {ip}");
            Ok(false)
        }
    }
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    u16::try_from(!sum & 0xffff).unwrap_or(0)
}
