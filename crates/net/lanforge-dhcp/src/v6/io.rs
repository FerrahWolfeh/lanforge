use lanforge_core::error::CoreError;
use std::io;
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use tokio::net::UdpSocket as TokioUdpSocket;

const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// Encapsulates UDP socket I/O and MAC address reading for the `DHCPv6` service.
pub struct Dhcpv6Transport {
    socket: TokioUdpSocket,
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

        Ok(Self { socket })
    }

    /// Receives a packet asynchronously from the UDP socket.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }

    /// Sends a `DHCPv6` reply to the destination address.
    pub fn send_reply(&self, packet: &[u8], dest: SocketAddr) -> io::Result<usize> {
        self.socket.try_send_to(packet, dest)
    }
}
