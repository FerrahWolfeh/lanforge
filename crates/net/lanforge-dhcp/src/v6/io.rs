use lanforge_core::error::CoreError;
use lanforge_transport::{InertHandle, UdpTransport};
use std::io;
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use tokio::net::UdpSocket as TokioUdpSocket;

const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// Encapsulates UDP socket I/O and MAC address reading for the `DHCPv6` service.
#[derive(Clone)]
pub struct Dhcpv6Transport {
    inner: UdpTransport,
}

fn if_nametoindex(iface: &str) -> u32 {
    let mut buf = [0u8; libc::IFNAMSIZ];
    let bytes = iface.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return 0;
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    unsafe { libc::if_nametoindex(buf.as_ptr().cast()) }
}

impl Dhcpv6Transport {
    /// Binds the UDP socket, joins the `DHCPv6` multicast group on `iface`, and sets non-blocking mode.
    pub fn new(iface: &str, port: u16) -> Result<Self, CoreError> {
        let std_socket = UdpSocket::bind(("::", port))
            .map_err(|e| CoreError::Generic(format!("Failed to bind DHCPv6 socket: {e}")))?;

        let ifindex = if_nametoindex(iface);
        if let Err(e) = std_socket.join_multicast_v6(&ALL_DHCP_RELAY_AGENTS_AND_SERVERS, ifindex) {
            tracing::warn!("Failed to join ff02::1:2 on {iface} (index {ifindex}): {e}");
        }

        let sock = socket2::Socket::from(std_socket);
        if let Err(e) = sock.bind_device(Some(iface.as_bytes())) {
            tracing::debug!("DHCPv6 SO_BINDTODEVICE({iface}): {e} (continuing anyway)");
        }
        let std_socket: UdpSocket = sock.into();

        std_socket.set_nonblocking(true).map_err(CoreError::Io)?;

        let socket = TokioUdpSocket::from_std(std_socket)
            .map_err(|e| CoreError::Generic(format!("tokio UdpSocket conversion: {e}")))?;

        Ok(Self {
            inner: UdpTransport::from_tokio(socket),
        })
    }

    /// Creates an in-memory inert transport for rootless testing and simulation.
    #[must_use]
    pub fn inert() -> (InertHandle<SocketAddr>, Self) {
        let (handle, inner) = UdpTransport::inert();
        (handle, Self { inner })
    }

    /// Returns `true` if operating in inert testing mode.
    #[must_use]
    pub fn is_inert(&self) -> bool {
        self.inner.is_inert()
    }

    /// Receives a packet asynchronously from the UDP transport.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv(buf).await
    }

    /// Sends a `DHCPv6` reply to the destination address synchronously.
    pub fn send_reply(&self, packet: &[u8], dest: SocketAddr) -> io::Result<usize> {
        self.inner.try_send(packet, &dest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::Dhcpv6PacketBuilder;
    use lanforge_types::identifiers::Duid;
    use tokio::time::{Duration, timeout};

    #[test]
    fn should_initialize_inert_transport_and_report_is_inert() {
        let (_handle, transport) = Dhcpv6Transport::inert();
        assert!(transport.is_inert(), "Inert transport must return true for is_inert()");
    }

    #[tokio::test]
    async fn should_receive_and_send_replies_in_inert_mode() {
        let (handle, transport) = Dhcpv6Transport::inert();
        let client_duid = Duid::new(vec![0x00, 0x03, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04]);
        let client_addr: SocketAddr = "[fe80::100]:546".parse().unwrap();
        let solicit_bytes = Dhcpv6PacketBuilder::solicit(client_duid).build();

        // 1. Inject solicit from synthetic client
        handle.inject(solicit_bytes.clone(), client_addr).await;

        let mut buf = [0u8; 1024];
        let (len, peer) = timeout(Duration::from_millis(500), transport.recv(&mut buf))
            .await
            .expect("Recv timed out")
            .expect("Recv failed");

        assert_eq!(&buf[..len], solicit_bytes.as_slice());
        assert_eq!(peer, client_addr);

        // 2. Send synthetic advertise reply
        let advertise_bytes = b"SYNTHETIC_ADVERTISE_REPLY";
        let sent = transport
            .send_reply(advertise_bytes, client_addr)
            .expect("send_reply failed");
        assert_eq!(sent, advertise_bytes.len());

        // 3. Verify reply captured by InertHandle
        let (reply_packet, dest) = timeout(Duration::from_millis(500), handle.recv_reply())
            .await
            .expect("recv_reply timed out")
            .expect("Expected captured reply");

        assert_eq!(reply_packet, advertise_bytes);
        assert_eq!(dest, client_addr);
    }

    #[tokio::test]
    async fn should_return_unexpected_eof_when_handle_channel_closed() {
        let (handle, transport) = Dhcpv6Transport::inert();
        drop(handle);

        let mut buf = [0u8; 64];
        let err = transport.recv(&mut buf).await.expect_err("Expected EOF error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
