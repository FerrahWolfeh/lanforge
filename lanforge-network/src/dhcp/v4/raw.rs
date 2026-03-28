//! Injeção de pacotes DHCP (Layer 2) via `AF_PACKET` (pnet).
//!
//! Exigido pelo RFC para enviar pacotes UDP unicast para endereços IP
//! não configurados (quando o cliente tem IP mas a tabela ARP do servidor
//! não tem a entrada). Evita o broadcast em L3 para pacotes unicast.

use crate::error::{NetworkError, Result};
use pnet::datalink::{self, Config, MacAddr as PnetMac};
use pnet::packet::MutablePacket;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ipv4::{self, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::udp::{self, MutableUdpPacket};
use std::net::Ipv4Addr;

pub struct RawSender {
    tx: Box<dyn datalink::DataLinkSender>,
    src_mac: PnetMac,
}

impl RawSender {
    pub fn new(iface_name: &str) -> Result<Self> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == iface_name)
            .ok_or_else(|| NetworkError::InterfaceNotFound(iface_name.to_string()))?;

        let src_mac = interface.mac.ok_or_else(|| {
            NetworkError::InvalidMac(format!("Interface '{iface_name}' has no MAC addr"))
        })?;

        let (tx, _) = match datalink::channel(&interface, Config::default()) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
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

    /// Embrulha o payload `DHCPv4` (BOOTP) em headers UDP, IPv4 e Ethernet,
    /// calculando todos os checksums manuais e enviando na interface física.
    pub fn send_dhcp(
        &mut self,
        payload: &[u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        dst_mac_raw: [u8; 6],
    ) -> Result<()> {
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

        let mut buf = vec![0u8; eth_len];

        // 1. Monta Ethernet
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(dst_mac);
        eth.set_source(self.src_mac);
        eth.set_ethertype(EtherTypes::Ipv4);

        // 2. Monta IPv4
        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(u16::try_from(ipv4_len).unwrap_or(u16::MAX));
        ip.set_ttl(64);
        ip.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        ip.set_flags(Ipv4Flags::DontFragment); // Typical for DHCP

        let ip_checksum = ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(ip_checksum);

        // 3. Monta UDP
        let mut udp = MutableUdpPacket::new(ip.payload_mut()).unwrap();
        udp.set_source(67);
        udp.set_destination(68);
        udp.set_length(u16::try_from(udp_len).unwrap_or(u16::MAX));
        udp.set_payload(payload);

        let udp_checksum = udp::ipv4_checksum(&udp.to_immutable(), &src_ip, &dst_ip);
        udp.set_checksum(udp_checksum);

        // 4. Injeta pacote (Layer 2)
        match self.tx.send_to(&buf, None) {
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
