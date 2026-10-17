use crate::inert::{InertHandle, InertPort};
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;

const ETH_P_ARP: u16 = 0x0806;
const ARP_HTYPE_ETHERNET: u16 = 1;
const ARP_PTYPE_IPV4: u16 = 0x0800;
const ARP_OPCODE_REQUEST: u16 = 1;
const ARP_OPCODE_REPLY: u16 = 2;

/// Result of a successful ARP probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpReply {
    pub mac: [u8; 6],
    pub rtt: Duration,
}

enum ArpBackend {
    Kernel {
        fd: AsyncFd<OwnedFd>,
        ifindex: u32,
    },
    #[cfg(any(test, feature = "inert"))]
    Inert(InertPort<()>),
}

/// Asynchronous Layer 2 ARP prober for underlay hardware verification.
///
/// Sends RFC 5227 ARP probe requests and listens for unicast replies without
/// requiring an IP address on the physical interface or modifying the kernel routing table.
#[derive(Clone)]
pub struct ArpProber {
    local_mac: [u8; 6],
    backend: Arc<ArpBackend>,
}

impl ArpProber {
    /// Binds an `AF_PACKET` raw socket to the interface specified by `ifindex`.
    pub fn bind(ifindex: u32, local_mac: [u8; 6]) -> io::Result<Self> {
        let raw_fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                (ETH_P_ARP).to_be() as libc::c_int,
            )
        };

        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let mut saddr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        saddr.sll_family = libc::AF_PACKET as libc::c_ushort;
        saddr.sll_protocol = (ETH_P_ARP).to_be();
        #[allow(clippy::cast_possible_wrap)]
        {
            saddr.sll_ifindex = ifindex as libc::c_int;
        }

        let res = unsafe {
            libc::bind(
                owned_fd.as_raw_fd(),
                std::ptr::from_ref(&saddr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };

        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        let async_fd = AsyncFd::new(owned_fd)?;

        Ok(Self {
            local_mac,
            backend: Arc::new(ArpBackend::Kernel {
                fd: async_fd,
                ifindex,
            }),
        })
    }

    /// Creates an inert `ArpProber` for rootless simulation and testing.
    #[must_use]
    #[cfg(any(test, feature = "inert"))]
    pub fn inert(local_mac: [u8; 6]) -> (InertHandle<()>, Self) {
        let (handle, port) = InertPort::pair(16);
        let prober = Self {
            local_mac,
            backend: Arc::new(ArpBackend::Inert(port)),
        };
        (handle, prober)
    }

    /// Sends an ARP probe to `target` and awaits a matching reply within `timeout`.
    pub async fn probe(
        &self,
        target: Ipv4Addr,
        sender: Option<Ipv4Addr>,
        timeout: Duration,
    ) -> io::Result<Option<ArpReply>> {
        let frame = build_arp_probe(self.local_mac, target, sender);
        let start = Instant::now();

        match self.backend.as_ref() {
            ArpBackend::Kernel { fd, ifindex } => {
                let mut saddr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
                saddr.sll_family = libc::AF_PACKET as libc::c_ushort;
                saddr.sll_protocol = (ETH_P_ARP).to_be();
                #[allow(clippy::cast_possible_wrap)]
                {
                    saddr.sll_ifindex = *ifindex as libc::c_int;
                }
                saddr.sll_halen = 6;
                saddr.sll_addr[..6].copy_from_slice(&[0xff; 6]);

                // Send probe frame
                let sent = unsafe {
                    libc::sendto(
                        fd.as_raw_fd(),
                        frame.as_ptr().cast::<libc::c_void>(),
                        frame.len(),
                        0,
                        std::ptr::from_ref(&saddr).cast::<libc::sockaddr>(),
                        std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                    )
                };

                if sent < 0 {
                    return Err(io::Error::last_os_error());
                }

                // Await reply with timeout
                let mut buf = [0u8; 256];
                let deadline = Instant::now() + timeout;

                loop {
                    let now = Instant::now();
                    if now >= deadline {
                        return Ok(None);
                    }
                    let remaining = deadline - now;

                    let mut guard = match tokio::time::timeout(remaining, fd.readable()).await {
                        Ok(Ok(g)) => g,
                        _ => return Ok(None),
                    };

                    let n = unsafe {
                        libc::recv(
                            fd.as_raw_fd(),
                            buf.as_mut_ptr().cast::<libc::c_void>(),
                            buf.len(),
                            0,
                        )
                    };

                    if n > 0 {
                        guard.clear_ready();
                        #[allow(clippy::cast_sign_loss)]
                        let len = n as usize;
                        if let Some(mac) = parse_arp_reply(&buf[..len], target) {
                            return Ok(Some(ArpReply {
                                mac,
                                rtt: start.elapsed(),
                            }));
                        }
                    } else if n < 0 {
                        let err = io::Error::last_os_error();
                        if err.kind() == io::ErrorKind::WouldBlock {
                            guard.clear_ready();
                        } else {
                            return Err(err);
                        }
                    }
                }
            }
            #[cfg(any(test, feature = "inert"))]
            ArpBackend::Inert(port) => {
                let _ = port.out_tx.send((frame.to_vec(), ())).await;

                let mut rx = port.in_rx.lock().await;
                let deadline = tokio::time::sleep(timeout);
                tokio::pin!(deadline);

                loop {
                    tokio::select! {
                        () = &mut deadline => {
                            return Ok(None);
                        }
                        pkt = rx.recv() => {
                            if let Some((bytes, ())) = pkt {
                                if let Some(mac) = parse_arp_reply(&bytes, target) {
                                    return Ok(Some(ArpReply {
                                        mac,
                                        rtt: start.elapsed(),
                                    }));
                                }
                            } else {
                                return Ok(None);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Builds an Ethernet ARP Request frame (42 bytes).
#[must_use]
pub fn build_arp_probe(src_mac: [u8; 6], target: Ipv4Addr, sender: Option<Ipv4Addr>) -> [u8; 42] {
    let mut pkt = [0u8; 42];
    // Ethernet Header
    pkt[0..6].copy_from_slice(&[0xff; 6]); // Broadcast destination
    pkt[6..12].copy_from_slice(&src_mac);  // Source MAC
    pkt[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes()); // EtherType ARP

    // ARP Payload
    pkt[14..16].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
    pkt[16..18].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
    pkt[18] = 6; // Hardware address length (Ethernet)
    pkt[19] = 4; // Protocol address length (IPv4)
    pkt[20..22].copy_from_slice(&ARP_OPCODE_REQUEST.to_be_bytes());
    pkt[22..28].copy_from_slice(&src_mac);
    let spa = sender.map_or([0u8; 4], |ip| ip.octets());
    pkt[28..32].copy_from_slice(&spa);
    pkt[32..38].copy_from_slice(&[0u8; 6]); // Target MAC unknown in request
    pkt[38..42].copy_from_slice(&target.octets());

    pkt
}

/// Parses an ARP Reply frame and returns the sender's MAC address if it matches `target`.
#[must_use]
pub fn parse_arp_reply(frame: &[u8], target: Ipv4Addr) -> Option<[u8; 6]> {
    if frame.len() < 42 {
        return None;
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != ETH_P_ARP {
        return None;
    }

    let htype = u16::from_be_bytes([frame[14], frame[15]]);
    let ptype = u16::from_be_bytes([frame[16], frame[17]]);
    let hlen = frame[18];
    let plen = frame[19];
    let opcode = u16::from_be_bytes([frame[20], frame[21]]);

    if htype != ARP_HTYPE_ETHERNET || ptype != ARP_PTYPE_IPV4 || hlen != 6 || plen != 4 || opcode != ARP_OPCODE_REPLY {
        return None;
    }

    let sender_ip = &frame[28..32];
    if sender_ip != target.octets() {
        return None;
    }

    let mut mac = [0u8; 6];
    mac.copy_from_slice(&frame[22..28]);
    Some(mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_arp_probe_rfc5227() {
        let src_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let target = Ipv4Addr::new(192, 168, 1, 1);
        let pkt = build_arp_probe(src_mac, target, None);

        assert_eq!(&pkt[0..6], &[0xff; 6]);
        assert_eq!(&pkt[6..12], &src_mac);
        assert_eq!(&pkt[12..14], &ETH_P_ARP.to_be_bytes());
        assert_eq!(&pkt[20..22], &ARP_OPCODE_REQUEST.to_be_bytes());
        assert_eq!(&pkt[22..28], &src_mac);
        assert_eq!(&pkt[28..32], &[0, 0, 0, 0]); // Sender IP 0.0.0.0 per RFC 5227
        assert_eq!(&pkt[38..42], &[192, 168, 1, 1]);
    }

    #[test]
    fn test_build_arp_probe_custom_sender() {
        let src_mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let target = Ipv4Addr::new(192, 168, 1, 1);
        let sender = Ipv4Addr::new(192, 168, 1, 254);
        let pkt = build_arp_probe(src_mac, target, Some(sender));

        assert_eq!(&pkt[28..32], &[192, 168, 1, 254]);
        assert_eq!(&pkt[38..42], &[192, 168, 1, 1]);
    }

    #[test]
    fn test_parse_arp_reply_valid() {
        let mut reply = [0u8; 60];
        let ont_mac = [0x3c, 0x84, 0x6a, 0xbc, 0x8c, 0xe5];
        let target = Ipv4Addr::new(192, 168, 1, 1);

        reply[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
        reply[14..16].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
        reply[16..18].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
        reply[18] = 6;
        reply[19] = 4;
        reply[20..22].copy_from_slice(&ARP_OPCODE_REPLY.to_be_bytes());
        reply[22..28].copy_from_slice(&ont_mac);
        reply[28..32].copy_from_slice(&target.octets());

        assert_eq!(parse_arp_reply(&reply, target), Some(ont_mac));
    }

    #[test]
    fn test_parse_arp_reply_invalid() {
        let target = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(parse_arp_reply(&[], target), None);
        assert_eq!(parse_arp_reply(&[0u8; 40], target), None);

        let mut wrong_opcode = [0u8; 42];
        wrong_opcode[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
        wrong_opcode[14..16].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
        wrong_opcode[16..18].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
        wrong_opcode[18] = 6;
        wrong_opcode[19] = 4;
        wrong_opcode[20..22].copy_from_slice(&ARP_OPCODE_REQUEST.to_be_bytes()); // Request, not reply
        assert_eq!(parse_arp_reply(&wrong_opcode, target), None);
    }

    #[tokio::test]
    async fn test_arp_prober_inert_success() {
        let local_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let ont_mac = [0x3c, 0x84, 0x6a, 0xbc, 0x8c, 0xe5];
        let target = Ipv4Addr::new(192, 168, 1, 1);

        let (handle, prober) = ArpProber::inert(local_mac);

        let handle_task = tokio::spawn(async move {
            let req = handle.recv_payload().await.expect("Expected probe request");
            assert_eq!(req.len(), 42);

            let mut reply = [0u8; 60];
            reply[0..6].copy_from_slice(&local_mac);
            reply[6..12].copy_from_slice(&ont_mac);
            reply[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
            reply[14..16].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes());
            reply[16..18].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
            reply[18] = 6;
            reply[19] = 4;
            reply[20..22].copy_from_slice(&ARP_OPCODE_REPLY.to_be_bytes());
            reply[22..28].copy_from_slice(&ont_mac);
            reply[28..32].copy_from_slice(&target.octets());

            handle.inject(reply.to_vec(), ()).await;
        });

        let res = prober.probe(target, None, Duration::from_millis(500)).await.expect("probe ok");
        handle_task.await.unwrap();

        let reply = res.expect("Should receive reply");
        assert_eq!(reply.mac, ont_mac);
    }

    #[tokio::test]
    async fn test_arp_prober_inert_timeout() {
        let local_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let target = Ipv4Addr::new(192, 168, 1, 1);

        let (_handle, prober) = ArpProber::inert(local_mac);

        let res = prober.probe(target, None, Duration::from_millis(50)).await.expect("probe ok");
        assert!(res.is_none());
    }
}
