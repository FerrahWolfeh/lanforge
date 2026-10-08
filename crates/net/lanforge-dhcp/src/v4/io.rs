use crate::v4::raw::RawSender;
use dhcproto::{Decodable, Decoder};
use lanforge_core::error::CoreError;
use lanforge_types::identifiers::MacAddr;
use parking_lot::Mutex;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use tokio::net::UdpSocket as TokioUdpSocket;

/// A captured `DHCPv4` reply dispatched by `Dhcpv4Transport` in synthetic mode.
#[derive(Debug, Clone)]
pub struct Dhcpv4SyntheticReply {
    pub packet: Vec<u8>,
    pub server_id: Ipv4Addr,
    pub broadcast: bool,
    pub dest_ip: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub mac: MacAddr,
    pub port: u16,
}

impl Dhcpv4SyntheticReply {
    /// Decodes the synthetic DHCP packet into a structured `Message`.
    ///
    /// # Errors
    ///
    /// Returns a decoding error if the packet is malformed.
    pub fn message(&self) -> Result<dhcproto::v4::Message, dhcproto::error::DecodeError> {
        dhcproto::v4::Message::decode(&mut Decoder::new(&self.packet))
    }
}

pub type Dhcpv4SyntheticInRx =
    std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>>>;

#[derive(Clone)]
pub struct Dhcpv4SyntheticChannels {
    pub in_rx: Dhcpv4SyntheticInRx,
    pub out_tx: tokio::sync::mpsc::Sender<Dhcpv4SyntheticReply>,
}

/// Test handle for injecting synthetic `DHCPv4` packets and receiving outgoing replies without raw sockets or root.
#[derive(Clone)]
pub struct Dhcpv4SyntheticHandle {
    in_tx: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
    out_rx: std::sync::Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Dhcpv4SyntheticReply>>>,
}

impl Dhcpv4SyntheticHandle {
    pub(crate) fn new(
        in_tx: tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>,
        out_rx: tokio::sync::mpsc::Receiver<Dhcpv4SyntheticReply>,
    ) -> Self {
        Self {
            in_tx,
            out_rx: std::sync::Arc::new(tokio::sync::Mutex::new(out_rx)),
        }
    }

    /// Injects a synthetic incoming `DHCPv4` packet (e.g. DISCOVER or REQUEST) into the transport.
    pub async fn send_packet(&self, packet: Vec<u8>, src: SocketAddr) {
        let _ = self.in_tx.send((packet, src)).await;
    }

    /// Awaits and receives the next outgoing `DHCPv4` reply (e.g. OFFER or ACK).
    pub async fn recv_reply(&self) -> Option<Dhcpv4SyntheticReply> {
        self.out_rx.lock().await.recv().await
    }
}

enum TransportBackend {
    Kernel {
        socket: TokioUdpSocket,
        raw_tx: Mutex<RawSender>,
    },
    Synthetic {
        channels: Dhcpv4SyntheticChannels,
    },
}

/// Encapsulates raw socket I/O and L2 injection for the `DHCPv4` service.
pub struct Dhcpv4Transport {
    backend: TransportBackend,
}

impl Dhcpv4Transport {
    /// Binds the UDP socket on the specified interface and port, and initializes the raw L2 sender.
    pub fn new(iface: &str, port: u16) -> Result<Self, CoreError> {
        let socket = bind_dhcp_socket_async(iface, port)?;
        let raw_tx = RawSender::new(iface).map_err(|e| CoreError::Generic(e.to_string()))?;
        Ok(Self {
            backend: TransportBackend::Kernel {
                socket,
                raw_tx: Mutex::new(raw_tx),
            },
        })
    }

    /// Creates a synthetic in-memory transport for rootless testing.
    #[must_use]
    pub const fn synthetic(channels: Dhcpv4SyntheticChannels) -> Self {
        Self {
            backend: TransportBackend::Synthetic { channels },
        }
    }

    /// Receives a packet asynchronously from the transport.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match &self.backend {
            TransportBackend::Kernel { socket, .. } => socket.recv_from(buf).await,
            TransportBackend::Synthetic { channels } => {
                let mut rx = channels.in_rx.lock().await;
                match rx.recv().await {
                    Some((packet, addr)) => {
                        let len = packet.len().min(buf.len());
                        buf[..len].copy_from_slice(&packet[..len]);
                        Ok((len, addr))
                    }
                    None => Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Synthetic DHCPv4 channel closed",
                    )),
                }
            }
        }
    }

    /// Sends a DHCP reply, either via raw L2 socket (unicast/broadcast) or via the UDP socket to a relay agent,
    /// or into the synthetic channels when operating rootless.
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
        match &self.backend {
            TransportBackend::Kernel { socket, raw_tx } => {
                if giaddr == Ipv4Addr::UNSPECIFIED {
                    let (final_dst_ip, dst_mac_arr) = if broadcast {
                        (Ipv4Addr::BROADCAST, [0xff; 6])
                    } else {
                        (dest_ip, *mac.as_ref())
                    };
                    raw_tx
                        .lock()
                        .send_dhcp(packet, server_id, final_dst_ip, dst_mac_arr)
                        .map_err(|e| CoreError::Generic(format!("Failed to inject L2 reply packet: {e}")))
                } else {
                    let relay_addr = SocketAddrV4::new(giaddr, port);
                    socket
                        .try_send_to(packet, relay_addr.into())
                        .map(|_| ())
                        .map_err(|e| CoreError::Generic(format!("Failed to send to relay agent: {e}")))
                }
            }
            TransportBackend::Synthetic { channels } => {
                let reply = Dhcpv4SyntheticReply {
                    packet: packet.to_vec(),
                    server_id,
                    broadcast,
                    dest_ip,
                    giaddr,
                    mac,
                    port,
                };
                channels.out_tx.try_send(reply).map_err(|e| {
                    CoreError::Generic(format!("Failed to deliver synthetic DHCP reply: {e}"))
                })
            }
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
