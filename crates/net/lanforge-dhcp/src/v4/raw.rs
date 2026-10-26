//! DHCP packet injection (Layer 2) via `AF_PACKET` (using pnet).
//!
//! Required by the RFC to send unicast UDP packets to IP addresses that are
//! not yet configured on the client (when the client has an IP but the
//! server's ARP table lacks the entry). This avoids L3 broadcast for unicast packets.

use crate::error::NetworkError;
use pnet::datalink::{self, Channel, Config, MacAddr as PnetMac};
use pnet::packet::MutablePacket;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::udp::{self, MutableUdpPacket};
use std::net::Ipv4Addr;

/// Layer 2 packet sender via `AF_PACKET` (using pnet).
///
/// Used to send unicast DHCP replies directly to clients that don't yet have
/// an ARP entry for the server. Per RFC 2131, when a client's IP is not yet
/// confirmed, the server must use L2 broadcast — but if the server knows the
/// client's MAC, L2 unicast is more efficient.
///
/// # Packet Construction
///
/// The `send_dhcp` method manually assembles:
/// 1. Ethernet header (dst=client MAC, src=server MAC, EtherType=IPv4)
/// 2. IPv4 header (checksum calculated, TTL=64, Don't Fragment)
/// 3. UDP header (src=67, dst=68, checksum calculated)
/// 4. DHCP/BOOTP payload
pub struct RawSender {
    tx: Box<dyn datalink::DataLinkSender>,
    src_mac: PnetMac,
}

impl RawSender {
    /// Opens an `AF_PACKET` channel on the given interface.
    ///
    /// # Arguments
    ///
    /// * `iface_name` — network interface name (e.g., `"eth0"`)
    pub fn new(iface_name: &str) -> Result<Self, NetworkError> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == iface_name)
            .ok_or_else(|| NetworkError::InterfaceNotFound(iface_name.to_string()))?;

        let src_mac = interface.mac.ok_or_else(|| {
            NetworkError::InvalidMac(format!("Interface '{iface_name}' has no MAC addr"))
        })?;

        let (tx, _) = match datalink::channel(&interface, Config::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(NetworkError::RawSocket(
                    "Unsupported AF_PACKET channel type".to_string(),
                ));
            }
            Err(e) => {
                return Err(NetworkError::RawSocket(format!(
                    "Failed to open AF_PACKET channel: {e}"
                )));
            }
        };

        Ok(Self { tx, src_mac })
    }

    /// Wraps the `DHCPv4` (BOOTP) payload in UDP, IPv4, and Ethernet headers,
    /// calculating all checksums manually and sending it over the physical interface.
    pub fn send_dhcp(
        &mut self,
        payload: &[u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_mac_raw: [u8; 6],
    ) -> Result<(), NetworkError> {
        let dst_mac = PnetMac::new(
            dst_mac_raw[0],
            dst_mac_raw[1],
            dst_mac_raw[2],
            dst_mac_raw[3],
            dst_mac_raw[4],
            dst_mac_raw[5],
        );

        let udp_len = 8 + payload.len();
        let ipv4_len = 20 + udp_len;
        let eth_len = 14 + ipv4_len;

        if eth_len > 1514 {
            return Err(NetworkError::RawSocket(
                "DHCP packet exceeds Ethernet frame size (1514 bytes)".to_string(),
            ));
        }

        let mut buf = [0u8; 1514];
        let frame_buf = &mut buf[..eth_len];

        // 1. Assemble Ethernet Header
        let mut eth = MutableEthernetPacket::new(frame_buf).unwrap();
        eth.set_destination(dst_mac);
        eth.set_source(self.src_mac);
        eth.set_ethertype(EtherTypes::Ipv4);

        // 2. Assemble IPv4 Header
        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(u16::try_from(ipv4_len).unwrap_or(u16::MAX));
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        ip.set_flags(Ipv4Flags::DontFragment); // Typical for DHCP

        let ip_checksum = ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(ip_checksum);

        // 3. Assemble UDP Header
        let mut udp = MutableUdpPacket::new(ip.payload_mut()).unwrap();
        udp.set_source(67);
        udp.set_destination(68);
        udp.set_length(u16::try_from(udp_len).unwrap_or(u16::MAX));
        udp.set_payload(payload);

        let udp_checksum = udp::ipv4_checksum(&udp.to_immutable(), &src_ip, &dst_ip);
        udp.set_checksum(udp_checksum);

        // 4. Inject Packet (Layer 2)
        match self.tx.send_to(frame_buf, None) {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(NetworkError::RawSocket(format!(
                "AF_PACKET injection failed: {e}"
            ))),
            None => Err(NetworkError::RawSocket(
                "AF_PACKET Tx buffer full/error".to_string(),
            )),
        }
    }
}
