use crate::v4::raw::RawSender;
use lanforge_core::error::CoreError;
use lanforge_types::identifiers::MacAddr;
use parking_lot::Mutex;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use tokio::net::UdpSocket as TokioUdpSocket;

/// Encapsulates raw socket I/O and L2 injection for the `DHCPv4` service.
pub struct Dhcpv4Transport {
    socket: TokioUdpSocket,
    raw_tx: Mutex<RawSender>,
}

impl Dhcpv4Transport {
    /// Binds the UDP socket on the specified interface and port, and initializes the raw L2 sender.
    pub fn new(iface: &str, port: u16) -> Result<Self, CoreError> {
        let socket = bind_dhcp_socket_async(iface, port)?;
        let raw_tx = RawSender::new(iface).map_err(|e| CoreError::Generic(e.to_string()))?;
        Ok(Self {
            socket,
            raw_tx: Mutex::new(raw_tx),
        })
    }

    /// Receives a packet asynchronously from the UDP socket.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }

    /// Sends a DHCP reply, either via raw L2 socket (unicast/broadcast) or via the UDP socket to a relay agent.
    #[allow(clippy::too_many_arguments)]
    pub fn send_reply(
        &self,
        packet: &[u8],
        server_id: Ipv4Addr,
        broadcast: bool,
        dest_ip: Ipv4Addr,
        giaddr: Ipv4Addr,
        mac: MacAddr,
        port: u16,
    ) -> Result<(), CoreError> {
        if giaddr == Ipv4Addr::UNSPECIFIED {
            let (final_dst_ip, dst_mac_arr) = if broadcast {
                (Ipv4Addr::BROADCAST, [0xff; 6])
            } else {
                (dest_ip, *mac.as_ref())
            };
            self.raw_tx
                .lock()
                .send_dhcp(packet, server_id, final_dst_ip, dst_mac_arr)
                .map_err(|e| CoreError::Generic(format!("Failed to inject L2 reply packet: {e}")))
        } else {
            let relay_addr = SocketAddrV4::new(giaddr, port);
            self.socket
                .try_send_to(packet, relay_addr.into())
                .map(|_| ())
                .map_err(|e| CoreError::Generic(format!("Failed to send to relay agent: {e}")))
        }
    }
}

fn bind_dhcp_socket_async(iface: &str, port: u16) -> Result<TokioUdpSocket, CoreError> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| CoreError::Generic(format!("socket(AF_INET, SOCK_DGRAM): {e}")))?;

    sock.set_reuse_address(true)
        .map_err(|e| CoreError::Generic(e.to_string()))?;
    sock.set_broadcast(true)
        .map_err(|e| CoreError::Generic(e.to_string()))?;
    sock.bind_device(Some(iface.as_bytes()))
        .map_err(|e| CoreError::Generic(format!("SO_BINDTODEVICE({iface}): {e}")))?;
    sock.set_nonblocking(true)
        .map_err(|e| CoreError::Generic(e.to_string()))?;
    sock.bind(&socket2::SockAddr::from(addr))
        .map_err(|e| CoreError::Generic(format!("bind(0.0.0.0:{port}): {e}")))?;

    let std_socket: UdpSocket = sock.into();
    TokioUdpSocket::from_std(std_socket)
        .map_err(|e| CoreError::Generic(format!("tokio UdpSocket conversion: {e}")))
}
