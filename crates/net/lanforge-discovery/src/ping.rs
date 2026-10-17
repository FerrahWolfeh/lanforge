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

    /// Sends a targeted ICMP Echo Request and waits for an Echo Reply with a 1-second timeout.
    pub async fn ping(&self, ip: IpAddr, seq: u16) -> Result<bool, std::io::Error> {
        const PAYLOAD: &[u8] = b"LanforgeProberPingPayload";
        const PACKET_LEN: usize = 8 + PAYLOAD.len();

        let ident = 12345u16;
        let (tx, rx) = oneshot::channel();

        // Register pending ping
        {
            let mut reg = self.registry.lock();
            reg.insert((ip, ident, seq), tx);
        }

        let sent = match ip {
            IpAddr::V4(ip4) => self.socket_v4.as_ref().is_some_and(|s_v4| {
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
            IpAddr::V6(ip6) => self.socket_v6.as_ref().is_some_and(|s_v6| {
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

fn checksum(data: &[u8]) -> u16 {
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

    #[test]
    fn test_parse_icmpv4_echo_reply_standard_header() {
        // Standard IPv4 packet: 20 bytes IP header (IHL = 5) + 8 bytes ICMP Echo Reply
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
    fn test_parse_icmpv4_echo_reply_with_options() {
        // IPv4 packet with options: 24 bytes IP header (IHL = 6) + 8 bytes ICMP Echo Reply
        let mut packet = vec![0u8; 32];
        packet[0] = 0x46; // Version 4, IHL = 6 (24 bytes)
        packet[24] = 0; // ICMP Type: Echo Reply
        packet[25] = 0; // ICMP Code
        packet[28..30].copy_from_slice(&0xABCDu16.to_be_bytes()); // ID
        packet[30..32].copy_from_slice(&0x0100u16.to_be_bytes()); // Seq

        let res = parse_icmpv4_echo_reply(&packet);
        assert_eq!(res, Some((0xABCD, 0x0100)));
    }

    #[test]
    fn test_parse_icmpv4_non_reply_types() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;

        // Type 8: Echo Request
        packet[20] = 8;
        assert_eq!(parse_icmpv4_echo_reply(&packet), None);

        // Type 3: Destination Unreachable
        packet[20] = 3;
        assert_eq!(parse_icmpv4_echo_reply(&packet), None);

        // Type 11: Time Exceeded
        packet[20] = 11;
        assert_eq!(parse_icmpv4_echo_reply(&packet), None);
    }

    #[test]
    fn test_parse_icmpv4_truncated_and_corrupt() {
        // Truncated: less than 28 bytes
        assert_eq!(parse_icmpv4_echo_reply(&[]), None);
        assert_eq!(parse_icmpv4_echo_reply(&[0x45; 27]), None);

        // Invalid IHL (< 5, which means < 20 bytes IP header)
        let mut packet = vec![0u8; 28];
        packet[0] = 0x44; // IHL = 4 (16 bytes, invalid for IPv4)
        assert_eq!(parse_icmpv4_echo_reply(&packet), None);

        // Buffer shorter than IHL + 8
        let mut packet = vec![0u8; 30];
        packet[0] = 0x48; // IHL = 8 (32 bytes required for IP header alone)
        assert_eq!(parse_icmpv4_echo_reply(&packet), None);
    }

    #[test]
    fn test_parse_icmpv6_echo_reply() {
        // Direct ICMPv6 packet: 8 bytes
        let mut packet = [0u8; 8];
        packet[0] = 129; // ICMPv6 Type: Echo Reply
        packet[1] = 0; // Code
        packet[4..6].copy_from_slice(&0xCAFEu16.to_be_bytes()); // ID
        packet[6..8].copy_from_slice(&0x0007u16.to_be_bytes()); // Seq

        let res = parse_icmpv6_echo_reply(&packet);
        assert_eq!(res, Some((0xCAFE, 7)));
    }

    #[test]
    fn test_parse_icmpv6_non_reply_types() {
        let mut packet = [0u8; 8];

        // Type 128: Echo Request
        packet[0] = 128;
        assert_eq!(parse_icmpv6_echo_reply(&packet), None);

        // Type 135: Neighbor Solicitation
        packet[0] = 135;
        assert_eq!(parse_icmpv6_echo_reply(&packet), None);

        // Type 136: Neighbor Advertisement
        packet[0] = 136;
        assert_eq!(parse_icmpv6_echo_reply(&packet), None);
    }

    #[test]
    fn test_parse_icmpv6_truncated() {
        assert_eq!(parse_icmpv6_echo_reply(&[]), None);
        assert_eq!(parse_icmpv6_echo_reply(&[129u8; 7]), None);
    }

    #[test]
    fn test_checksum_calculation() {
        let mut packet = [0u8; 16];
        packet[0] = 8; // Echo request
        packet[1] = 0;
        packet[4..6].copy_from_slice(&12345u16.to_be_bytes());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        packet[8..16].copy_from_slice(b"testping");

        let cs = checksum(&packet);
        assert_ne!(cs, 0);

        // When the checksum is inserted into the packet at offset 2..4,
        // recomputing checksum over the full packet must yield 0.
        packet[2..4].copy_from_slice(&cs.to_be_bytes());
        let verify = checksum(&packet);
        assert_eq!(verify, 0, "Checksum verification should yield 0");
    }
}
