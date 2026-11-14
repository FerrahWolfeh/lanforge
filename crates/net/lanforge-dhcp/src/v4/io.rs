use crate::v4::raw::RawSender;
use dhcproto::error::DecodeError;
use dhcproto::v4::Message;
use dhcproto::{Decodable, Decoder};
use lanforge_core::error::CoreError;
use lanforge_transport::{TransportMetrics, TransportSnapshot, TransportStats, UdpTransport};
use lanforge_types::identifiers::MacAddr;
use parking_lot::Mutex;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::mpsc::{Receiver, Sender, channel};

/// A captured `DHCPv4` reply dispatched by `Dhcpv4Transport` in inert mode.
#[derive(Debug, Clone)]
pub struct Dhcpv4InertReply {
    pub packet: Vec<u8>,
    pub server_id: Ipv4Addr,
    pub broadcast: bool,
    pub dest_ip: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub mac: MacAddr,
    pub port: u16,
}

impl Dhcpv4InertReply {
    /// Decodes the inert DHCP packet into a structured `Message`.
    ///
    /// # Errors
    ///
    /// Returns a decoding error if the packet is malformed.
    pub fn message(&self) -> Result<Message, DecodeError> {
        Message::decode(&mut Decoder::new(&self.packet))
    }
}

pub type Dhcpv4InertInRx = Arc<TokioMutex<Receiver<(Vec<u8>, SocketAddr)>>>;

/// Delivery mode for a `DHCPv4` reply when sending directly on L2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyMode {
    /// Send directly to the client's IP and MAC address.
    Unicast,
    /// Broadcast to `255.255.255.255` and `ff:ff:ff:ff:ff:ff`.
    Broadcast,
}

impl ReplyMode {
    /// Constructs a `ReplyMode` from a broadcast boolean flag.
    #[must_use]
    pub const fn from_broadcast(broadcast: bool) -> Self {
        if broadcast {
            Self::Broadcast
        } else {
            Self::Unicast
        }
    }
}

#[derive(Clone)]
pub struct Dhcpv4InertChannels {
    pub in_rx: Dhcpv4InertInRx,
    pub out_tx: Sender<Dhcpv4InertReply>,
}

/// Test handle for injecting synthetic `DHCPv4` packets and receiving outgoing replies without raw sockets or root.
#[derive(Clone)]
pub struct Dhcpv4InertHandle {
    in_tx: Sender<(Vec<u8>, SocketAddr)>,
    out_rx: Arc<TokioMutex<Receiver<Dhcpv4InertReply>>>,
}

impl Dhcpv4InertHandle {
    #[must_use]
    pub fn new(in_tx: Sender<(Vec<u8>, SocketAddr)>, out_rx: Receiver<Dhcpv4InertReply>) -> Self {
        Self {
            in_tx,
            out_rx: Arc::new(TokioMutex::new(out_rx)),
        }
    }

    /// Injects a synthetic incoming `DHCPv4` packet (e.g. DISCOVER or REQUEST) into the transport.
    pub async fn send_packet(&self, packet: Vec<u8>, src: SocketAddr) {
        let _ = self.in_tx.send((packet, src)).await;
    }

    /// Injects a synthetic incoming packet into the transport.
    pub async fn inject(&self, packet: Vec<u8>, src: SocketAddr) {
        self.send_packet(packet, src).await;
    }

    /// Awaits and receives the next outgoing `DHCPv4` reply (e.g. OFFER or ACK).
    pub async fn recv_reply(&self) -> Option<Dhcpv4InertReply> {
        self.out_rx.lock().await.recv().await
    }
}

#[derive(Clone)]
enum TransportBackend {
    Kernel {
        udp: UdpTransport,
        raw_tx: Arc<Mutex<RawSender>>,
    },
    Inert {
        channels: Dhcpv4InertChannels,
    },
}

/// Encapsulates raw socket I/O and L2 injection for the `DHCPv4` service.
#[derive(Clone)]
pub struct Dhcpv4Transport {
    backend: TransportBackend,
    metrics: Arc<TransportMetrics>,
}

impl Dhcpv4Transport {
    /// Binds the UDP socket on the specified interface and port, and initializes the raw L2 sender.
    pub fn new(iface: &str, port: u16) -> Result<Self, CoreError> {
        let udp =
            UdpTransport::bind_device(iface, SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
        let raw_tx = RawSender::new(iface).map_err(|e| CoreError::Generic(e.to_string()))?;
        Ok(Self {
            // L2 replies count into the UDP socket's counters: one transport for the service.
            metrics: udp.metrics_handle(),
            backend: TransportBackend::Kernel {
                udp,
                raw_tx: Arc::new(Mutex::new(raw_tx)),
            },
        })
    }

    /// Creates an in-memory inert transport for rootless testing and simulation.
    #[must_use]
    pub fn inert() -> (Dhcpv4InertHandle, Self) {
        let (in_tx, in_rx) = channel(64);
        let (out_tx, out_rx) = channel(64);
        let handle = Dhcpv4InertHandle::new(in_tx, out_rx);
        let channels = Dhcpv4InertChannels {
            in_rx: Arc::new(TokioMutex::new(in_rx)),
            out_tx,
        };
        (
            handle,
            Self {
                backend: TransportBackend::Inert { channels },
                metrics: Arc::new(TransportMetrics::new()),
            },
        )
    }

    /// Returns `true` if operating in inert testing mode.
    #[must_use]
    pub const fn is_inert(&self) -> bool {
        matches!(self.backend, TransportBackend::Inert { .. })
    }

    /// Receives a packet asynchronously from the transport.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let res = match &self.backend {
            // Counted by the UDP transport itself.
            TransportBackend::Kernel { udp, .. } => return udp.recv(buf).await,
            TransportBackend::Inert { channels } => {
                let mut rx = channels.in_rx.lock().await;
                match rx.recv().await {
                    Some((packet, addr)) => {
                        let len = packet.len().min(buf.len());
                        buf[..len].copy_from_slice(&packet[..len]);
                        Ok((len, addr))
                    }
                    None => Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Inert DHCPv4 channel closed",
                    )),
                }
            }
        };

        match &res {
            Ok((n, _)) => self.metrics.record_rx(*n),
            Err(_) => self.metrics.record_error(),
        }

        res
    }

    /// Sends a DHCP reply, either via raw L2 socket (unicast/broadcast) or via the UDP socket to a relay agent,
    /// or into the inert channels when operating rootless.
    #[allow(clippy::too_many_arguments)]
    pub fn send_reply(
        &self,
        packet: &[u8],
        server_id: Ipv4Addr,
        mode: ReplyMode,
        dest_ip: Ipv4Addr,
        giaddr: Ipv4Addr,
        mac: MacAddr,
        port: u16,
    ) -> Result<(), CoreError> {
        let res = match &self.backend {
            TransportBackend::Kernel { udp, raw_tx } => {
                if giaddr == Ipv4Addr::UNSPECIFIED {
                    let (final_dst_ip, dst_mac_arr) = match mode {
                        ReplyMode::Broadcast => (Ipv4Addr::BROADCAST, [0xff; 6]),
                        ReplyMode::Unicast => (dest_ip, *mac.as_ref()),
                    };
                    raw_tx
                        .lock()
                        .send_dhcp(packet, server_id, final_dst_ip, dst_mac_arr)
                        .map_err(|e| {
                            CoreError::Generic(format!("Failed to inject L2 reply packet: {e}"))
                        })
                } else {
                    // Counted by the UDP transport itself.
                    let relay_addr = SocketAddrV4::new(giaddr, port);
                    return udp
                        .try_send(packet, &relay_addr.into())
                        .map(|_| ())
                        .map_err(|e| {
                            CoreError::Generic(format!("Failed to send to relay agent: {e}"))
                        });
                }
            }
            TransportBackend::Inert { channels } => {
                let reply = Dhcpv4InertReply {
                    packet: packet.to_vec(),
                    server_id,
                    broadcast: mode == ReplyMode::Broadcast,
                    dest_ip,
                    giaddr,
                    mac,
                    port,
                };
                channels.out_tx.try_send(reply).map_err(|e| {
                    CoreError::Generic(format!("Failed to deliver inert DHCP reply: {e}"))
                })
            }
        };

        match &res {
            Ok(()) => self.metrics.record_tx(packet.len()),
            Err(_) => self.metrics.record_error(),
        }

        res
    }
}

impl Dhcpv4Transport {
    /// The traffic counters alone (no socket), for the service banner.
    #[must_use]
    pub fn metrics_handle(&self) -> Arc<TransportMetrics> {
        Arc::clone(&self.metrics)
    }
}

impl TransportStats for Dhcpv4Transport {
    fn snapshot(&self) -> TransportSnapshot {
        self.metrics.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::Dhcpv4PacketBuilder;
    use dhcproto::v4::{DhcpOption, MessageType, OptionCode};
    use tokio::time::{Duration, timeout};

    /// A LAN interface that does not exist fails the bind as `NoDevice`.
    #[tokio::test]
    async fn a_missing_interface_fails_as_no_device() {
        let Err(err) = Dhcpv4Transport::new("lfnone0", 0) else {
            panic!("bound on an interface that does not exist");
        };
        assert_eq!(
            err.bind_error().map(|e| e.kind),
            Some(lanforge_transport::BindErrorKind::NoDevice),
            "{err}"
        );
    }

    #[test]
    fn should_initialize_inert_transport_and_report_is_inert() {
        let (_handle, transport) = Dhcpv4Transport::inert();
        assert!(
            transport.is_inert(),
            "Inert transport must return true for is_inert()"
        );
    }

    #[tokio::test]
    async fn should_send_and_receive_via_inert_channels() {
        let (handle, transport) = Dhcpv4Transport::inert();
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]);
        let src = SocketAddr::from(([192, 168, 1, 50], 68));
        let packet = Dhcpv4PacketBuilder::discover(mac).build();

        handle.inject(packet.clone(), src).await;

        let mut buf = [0u8; 1024];
        let (len, peer) = timeout(Duration::from_millis(500), transport.recv(&mut buf))
            .await
            .expect("Recv timed out")
            .expect("Recv failed");

        assert_eq!(&buf[..len], packet.as_slice());
        assert_eq!(peer, src);
    }

    #[tokio::test]
    async fn should_send_inert_reply_and_decode_message() {
        let (handle, transport) = Dhcpv4Transport::inert();
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let server_id = Ipv4Addr::new(192, 168, 1, 1);
        let offered_ip = Ipv4Addr::new(192, 168, 1, 105);

        let offer_packet = Dhcpv4PacketBuilder::request(mac, offered_ip, server_id).build();

        transport
            .send_reply(
                &offer_packet,
                server_id,
                ReplyMode::Broadcast,
                offered_ip,
                Ipv4Addr::UNSPECIFIED,
                mac,
                68,
            )
            .expect("send_reply failed");

        let reply = timeout(Duration::from_millis(500), handle.recv_reply())
            .await
            .expect("recv_reply timed out")
            .expect("Expected inert reply");

        assert_eq!(reply.server_id, server_id);
        assert!(reply.broadcast);
        assert_eq!(reply.dest_ip, offered_ip);
        assert_eq!(reply.mac, mac);
        assert_eq!(reply.port, 68);

        let decoded = reply.message().expect("Failed to decode reply message");
        assert_eq!(
            decoded.opts().get(OptionCode::MessageType),
            Some(&DhcpOption::MessageType(MessageType::Request))
        );
    }

    #[tokio::test]
    async fn should_truncate_when_recv_buffer_is_smaller() {
        let (handle, transport) = Dhcpv4Transport::inert();
        let mac = MacAddr([1, 2, 3, 4, 5, 6]);
        let src = SocketAddr::from(([0, 0, 0, 0], 68));
        let packet = Dhcpv4PacketBuilder::discover(mac).build();

        handle.inject(packet.clone(), src).await;

        let mut small_buf = [0u8; 8];
        let (len, peer) = transport.recv(&mut small_buf).await.expect("Recv failed");
        assert_eq!(len, 8);
        assert_eq!(&small_buf, &packet[..8]);
        assert_eq!(peer, src);
    }

    #[tokio::test]
    async fn should_return_unexpected_eof_when_handle_channel_closed() {
        let (handle, transport) = Dhcpv4Transport::inert();
        drop(handle);

        let mut buf = [0u8; 64];
        let err = transport
            .recv(&mut buf)
            .await
            .expect_err("Expected EOF error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
