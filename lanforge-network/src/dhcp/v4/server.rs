//! DORA State Machine — Core `DHCPv4` server logic.
//!
//! This module implements address allocation and message processing logic
//! as defined in RFC 2131. It uses `IpPool` to manage lease states and
//! `DeviceIdentity` to resolve MACs and hostnames.
//!
//! ## Decision Table
//!
//! | Message     | Action                    | Response |
//! |-------------|---------------------------|----------|
//! | Discover    | Allocate IP (offered)     | Offer    |
//! | Request     | Confirm/Extend lease      | Ack/Nak  |
//! | Release     | Free IP in the pool       | (none)   |
//! | Decline     | Mark IP as in conflict    | (none)   |
//! | Inform      | Provide options (no IP)   | Ack      |

use dhcproto::v4::{self, DhcpOption, HType, Message, MessageType, Opcode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::DeviceTable;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

use super::config::Dhcpv4Config;
use super::pool::IpPool;
use crate::dhcp::identity::DeviceIdentity;

/// Result of processing a DHCP message.
pub enum HandleResult {
    /// A reply to be sent.
    Reply {
        /// Encoded packet bytes.
        packet: Vec<u8>,
        /// Whether it should be sent via L2 broadcast.
        broadcast: bool,
        /// L3 destination IP (for IP/UDP header).
        dest_ip: Ipv4Addr,
        /// Relay Agent address (if any).
        giaddr: Ipv4Addr,
        /// Hostname suggested by the client.
        hostname: Option<String>,
    },
    /// No response necessary.
    Ignore,
}

/// Stateful `DHCPv4` Server.
///
/// Maintains configurations and the IP pool for a specific interface.
pub struct DhcpServer {
    /// Server configuration (range, lease time, etc.)
    pub cfg: Dhcpv4Config,
    /// Address pool and reservation management
    pub pool: IpPool,
}

impl DhcpServer {
    pub fn new(cfg: Dhcpv4Config) -> Self {
        let pool = IpPool::new(cfg.range_start, cfg.range_end);
        Self { cfg, pool }
    }

    /// Processes a raw DHCP packet and returns a response (if any).
    pub fn handle_packet(&mut self, data: &[u8], table: Option<&DeviceTable>) -> HandleResult {
        let msg = match Message::decode(&mut Decoder::new(data)) {
            Ok(m) => m,
            Err(e) => {
                debug!("Failed to decode packet: {e}");
                return HandleResult::Ignore;
            }
        };

        // Only handle BOOTREQUEST (client → server)
        if msg.opcode() != Opcode::BootRequest {
            return HandleResult::Ignore;
        }

        let msg_type =
            if let Some(DhcpOption::MessageType(t)) = msg.opts().get(v4::OptionCode::MessageType) {
                *t
            } else {
                debug!("No MessageType option, ignoring");
                return HandleResult::Ignore;
            };

        let chaddr = msg.chaddr();
        if chaddr.len() < 6 {
            debug!("chaddr too short, ignoring");
            return HandleResult::Ignore;
        }

        let mac = MacAddr([
            chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5],
        ]);
        let broadcast = msg.flags().broadcast();

        let identity = DeviceIdentity::resolve(
            mac,
            Self::get_hostname(&msg),
            Self::get_vendor_class(&msg),
            table,
        );

        match msg_type {
            MessageType::Discover => self.handle_discover(&msg, &identity, broadcast),
            MessageType::Request => self.handle_request(&msg, &identity, broadcast),
            MessageType::Release => self.handle_release(&msg, &identity),
            MessageType::Decline => self.handle_decline(&msg, &identity),
            MessageType::Inform => self.handle_inform(&msg, &identity),
            other => {
                debug!("Ignoring message type: {other:?}");
                HandleResult::Ignore
            }
        }
    }

    // ── DISCOVER → OFFER ─────────────────────────────────────────────────

    fn handle_discover(
        &mut self,
        msg: &Message,
        identity: &DeviceIdentity,
        broadcast: bool,
    ) -> HandleResult {
        let mac = identity.mac;
        let requested = Self::get_requested_ip(msg);
        let expiry = SystemTime::now() + Duration::from_secs(u64::from(self.cfg.lease_time));

        let Some(offered_ip) = self.pool.allocate(mac, requested, expiry) else {
            warn!("DHCPv4: Pool exhausted, no IP available for {identity}");
            return HandleResult::Ignore;
        };

        info!("DHCPv4: {identity} is looking for an address -> Offering {offered_ip}");
        let packet = self.build_reply(msg, MessageType::Offer, offered_ip);
        HandleResult::Reply {
            packet,
            broadcast,
            dest_ip: offered_ip,
            giaddr: msg.giaddr(),
            hostname: Self::get_hostname(msg),
        }
    }

    // ── REQUEST → ACK or NAK ─────────────────────────────────────────────

    fn handle_request(
        &mut self,
        msg: &Message,
        identity: &DeviceIdentity,
        broadcast: bool,
    ) -> HandleResult {
        let mac = identity.mac;
        // RFC 2131 §3.1 — REQUEST can happen in multiple contexts

        // Check if this REQUEST is for us (by ServerIdentifier)
        if let Some(DhcpOption::ServerIdentifier(sid)) =
            msg.opts().get(v4::OptionCode::ServerIdentifier)
            && *sid != self.cfg.server_id
        {
            // Client selected a different server — release our offer
            debug!("DHCPv4: {identity} selected different server {sid}");
            self.pool.release_mac(mac);
            return HandleResult::Ignore;
        }

        // Determine the IP the client wants
        let wanted_ip = Self::get_requested_ip(msg).or_else(|| {
            let ci = msg.ciaddr();
            if ci == Ipv4Addr::UNSPECIFIED {
                None
            } else {
                Some(ci)
            }
        });

        let Some(wanted) = wanted_ip else {
            warn!("DHCPv4: {identity} did not specify an IP in REQUEST");
            return self.send_nak(msg, "No IP address specified");
        };

        // Try to allocate
        let expiry = SystemTime::now() + Duration::from_secs(u64::from(self.cfg.lease_time));
        let Some(assigned_ip) = self.pool.allocate(mac, Some(wanted), expiry) else {
            warn!("DHCPv4: {identity} requested {wanted} but it is not available");
            return self.send_nak(msg, "Requested IP not available");
        };

        if assigned_ip != wanted {
            warn!("DHCPv4: {identity} requested {wanted} but was assigned {assigned_ip} instead");
            return self.send_nak(msg, "Requested IP not available");
        }

        info!("DHCPv4: Assigning {assigned_ip} to {identity}");
        let packet = self.build_reply(msg, MessageType::Ack, assigned_ip);
        HandleResult::Reply {
            packet,
            broadcast,
            dest_ip: assigned_ip,
            giaddr: msg.giaddr(),
            hostname: Self::get_hostname(msg),
        }
    }

    // ── RELEASE ──────────────────────────────────────────────────────────

    fn handle_release(&mut self, msg: &Message, identity: &DeviceIdentity) -> HandleResult {
        let ip = msg.ciaddr();
        info!("DHCPv4: {identity} released its address {ip}");
        self.pool.release(ip);
        HandleResult::Ignore
    }

    // ── DECLINE ──────────────────────────────────────────────────────────

    fn handle_decline(&mut self, msg: &Message, identity: &DeviceIdentity) -> HandleResult {
        if let Some(declined_ip) = Self::get_requested_ip(msg) {
            warn!("DHCPv4: {identity} declined {declined_ip} (address conflict)! Quarantining IP.");
            self.pool.mark_declined(declined_ip);
        } else {
            warn!("DHCPv4: {identity} declined an unspecified IP");
            self.pool.release_mac(identity.mac);
        }
        HandleResult::Ignore
    }

    // ── INFORM ───────────────────────────────────────────────────────────

    fn handle_inform(&self, msg: &Message, identity: &DeviceIdentity) -> HandleResult {
        let ip = msg.ciaddr();
        info!("DHCPv4: {identity} ({ip}) requested configuration options");

        let packet = self.build_reply(msg, MessageType::Ack, Ipv4Addr::UNSPECIFIED);

        HandleResult::Reply {
            packet,
            broadcast: false,
            dest_ip: ip,
            giaddr: msg.giaddr(),
            hostname: Self::get_hostname(msg),
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    fn get_requested_ip(msg: &Message) -> Option<Ipv4Addr> {
        match msg.opts().get(v4::OptionCode::RequestedIpAddress) {
            Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
            _ => None,
        }
    }

    fn get_hostname(msg: &Message) -> Option<String> {
        match msg.opts().get(v4::OptionCode::Hostname) {
            Some(DhcpOption::Hostname(h)) => Some(h.clone()),
            _ => None,
        }
    }

    fn get_vendor_class(msg: &Message) -> Option<String> {
        match msg.opts().get(v4::OptionCode::ClassIdentifier) {
            Some(DhcpOption::Unknown(u)) => String::from_utf8(u.data().to_vec()).ok(),
            Some(DhcpOption::ClassIdentifier(v)) => String::from_utf8(v.clone()).ok(),
            _ => None,
        }
    }

    fn build_reply(&self, request: &Message, msg_type: MessageType, yiaddr: Ipv4Addr) -> Vec<u8> {
        let mut reply = Message::default();

        reply
            .set_opcode(Opcode::BootReply)
            .set_htype(request.htype())
            .set_xid(request.xid())
            .set_yiaddr(yiaddr)
            .set_siaddr(self.cfg.server_id)
            .set_giaddr(request.giaddr())
            .set_chaddr(request.chaddr());

        // Copy flags from request (broadcast flag persistence)
        reply.set_flags(request.flags());

        // DHCP options
        let opts = reply.opts_mut();
        opts.insert(DhcpOption::MessageType(msg_type));
        opts.insert(DhcpOption::ServerIdentifier(self.cfg.server_id));

        if msg_type != MessageType::Nak {
            opts.insert(DhcpOption::AddressLeaseTime(self.cfg.lease_time));
            opts.insert(DhcpOption::SubnetMask(self.cfg.subnet_mask));
            opts.insert(DhcpOption::Router(vec![self.cfg.router]));
            opts.insert(DhcpOption::DomainNameServer(self.cfg.dns.clone()));

            if let Some(ref domain) = self.cfg.domain_name {
                opts.insert(DhcpOption::DomainName(domain.clone()));
            }

            // T1 = 50% of lease time, T2 = 87.5%
            opts.insert(DhcpOption::Renewal(self.cfg.lease_time / 2));
            opts.insert(DhcpOption::Rebinding(self.cfg.lease_time * 7 / 8));
        }

        let mut buf = Vec::with_capacity(576);
        let mut enc = Encoder::new(&mut buf);
        reply
            .encode(&mut enc)
            .expect("DHCP message encoding should not fail");
        buf
    }

    fn send_nak(&self, request: &Message, message: &str) -> HandleResult {
        let mut reply = Message::default();
        reply
            .set_opcode(Opcode::BootReply)
            .set_htype(request.htype())
            .set_xid(request.xid())
            .set_giaddr(request.giaddr())
            .set_chaddr(request.chaddr())
            .set_flags(request.flags());

        let opts = reply.opts_mut();
        opts.insert(DhcpOption::MessageType(MessageType::Nak));
        opts.insert(DhcpOption::ServerIdentifier(self.cfg.server_id));
        opts.insert(DhcpOption::Message(message.to_string()));

        let mut buf = Vec::with_capacity(576);
        let mut enc = Encoder::new(&mut buf);
        reply
            .encode(&mut enc)
            .expect("NAK encoding should not fail");
        HandleResult::Reply {
            packet: buf,
            broadcast: true,
            dest_ip: Ipv4Addr::BROADCAST,
            giaddr: request.giaddr(),
            hostname: None,
        }
    }

    /// Returns the MAC and assigned IP from the last successful allocation.
    /// Used by the service loop to publish events.
    pub fn last_assignment_for(&self, mac: MacAddr) -> Option<Ipv4Addr> {
        self.pool.lookup(mac)
    }

    /// Constructs a `FORCERENEW` (RFC 3203) packet for a specific client.
    ///
    /// This follows the "best-effort" approach without RFC 3118 authentication,
    /// which is the standard behavior in environments where secrets aren't
    /// pre-provisioned to every device.
    pub fn build_forcerenew(&self, mac: MacAddr, ip: Ipv4Addr) -> Vec<u8> {
        let mut msg = Message::default();

        msg.set_opcode(Opcode::BootReply)
            .set_htype(HType::Eth)
            .set_xid(rand::random::<u32>())
            .set_ciaddr(ip)
            .set_chaddr(&mac.0);

        // DHCP options
        let opts = msg.opts_mut();
        opts.insert(DhcpOption::MessageType(MessageType::ForceRenew));
        opts.insert(DhcpOption::ServerIdentifier(self.cfg.server_id));

        let mut buf = Vec::with_capacity(576);
        let mut enc = Encoder::new(&mut buf);
        msg.encode(&mut enc)
            .expect("FORCERENEW encoding should not fail");
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode};
    use dhcproto::{Decodable, Decoder, Encodable, Encoder};
    use std::net::Ipv4Addr;

    // -----------------------------------------------------------------------
    // Helpers e Factories para os Testes
    // -----------------------------------------------------------------------

    fn dummy_config() -> Dhcpv4Config {
        Dhcpv4Config {
            iface: "eth0".to_string(),
            range_start: Ipv4Addr::new(192, 168, 1, 100),
            range_end: Ipv4Addr::new(192, 168, 1, 200),
            lease_time: 3600,
            router: Ipv4Addr::new(192, 168, 1, 1),
            dns: vec![Ipv4Addr::new(1, 1, 1, 1)],
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            server_id: Ipv4Addr::new(192, 168, 1, 1),
            domain_name: Some("lanforge.local".to_string()),
            port: 67,
        }
    }

    fn dummy_server() -> DhcpServer {
        DhcpServer::new(dummy_config())
    }

    fn dummy_mac() -> MacAddr {
        MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    }

    fn build_raw_msg(
        msg_type: MessageType,
        mac: MacAddr,
        req_ip: Option<Ipv4Addr>,
        ciaddr: Option<Ipv4Addr>,
        server_id: Option<Ipv4Addr>,
    ) -> Vec<u8> {
        let mut msg = Message::default();
        msg.set_opcode(Opcode::BootRequest).set_chaddr(&mac.0);

        if let Some(ci) = ciaddr {
            msg.set_ciaddr(ci);
        }

        let opts = msg.opts_mut();
        opts.insert(DhcpOption::MessageType(msg_type));

        if let Some(ip) = req_ip {
            opts.insert(DhcpOption::RequestedIpAddress(ip));
        }
        if let Some(sid) = server_id {
            opts.insert(DhcpOption::ServerIdentifier(sid));
        }

        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        msg.encode(&mut enc).unwrap();
        buf
    }

    fn decode_reply(bytes: &[u8]) -> Message {
        Message::decode(&mut Decoder::new(bytes)).expect("Should decode valid DHCPv4 reply")
    }

    // -----------------------------------------------------------------------
    // Suíte de Testes da Máquina de Estados (DORA)
    // -----------------------------------------------------------------------

    #[test]
    fn invalid_packet_is_ignored() {
        let mut srv = dummy_server();
        let junk_data = vec![0x00, 0xFF, 0xAA, 0xBB]; // Lixo puro

        let res = srv.handle_packet(&junk_data, None);
        assert!(matches!(res, HandleResult::Ignore));
    }

    #[test]
    fn discover_yields_offer() {
        let mut srv = dummy_server();
        let mac = dummy_mac();
        let raw_msg = build_raw_msg(MessageType::Discover, mac, None, None, None);

        let res = srv.handle_packet(&raw_msg, None);

        match res {
            HandleResult::Reply {
                packet, dest_ip, ..
            } => {
                let reply = decode_reply(&packet);
                assert_eq!(
                    reply.opts().get(v4::OptionCode::MessageType),
                    Some(&DhcpOption::MessageType(MessageType::Offer))
                );

                // O IP ofertado deve vir no yiaddr (Your IP Address)
                assert_eq!(reply.yiaddr(), dest_ip);
                assert!(dest_ip >= Ipv4Addr::new(192, 168, 1, 100));
            }
            HandleResult::Ignore => panic!("Expected Reply for DISCOVER"),
        }
    }

    #[test]
    fn request_valid_yields_ack() {
        let mut srv = dummy_server();
        let mac = dummy_mac();
        let requested_ip = Ipv4Addr::new(192, 168, 1, 150);

        let raw_msg = build_raw_msg(MessageType::Request, mac, Some(requested_ip), None, None);
        let res = srv.handle_packet(&raw_msg, None);

        match res {
            HandleResult::Reply {
                packet, dest_ip, ..
            } => {
                let reply = decode_reply(&packet);
                assert_eq!(
                    reply.opts().get(v4::OptionCode::MessageType),
                    Some(&DhcpOption::MessageType(MessageType::Ack))
                );
                assert_eq!(dest_ip, requested_ip);
                assert_eq!(reply.yiaddr(), requested_ip);

                // O lease deve ter sido gravado internamente no servidor
                assert_eq!(srv.last_assignment_for(mac), Some(requested_ip));
            }
            HandleResult::Ignore => panic!("Expected ACK Reply for valid REQUEST"),
        }
    }

    #[test]
    fn request_for_different_server_is_ignored() {
        let mut srv = dummy_server();
        let mac = dummy_mac();

        // Simula o cliente escolhendo um servidor concorrente (ServerID = 10.0.0.1)
        let alien_server = Ipv4Addr::new(10, 0, 0, 1);
        let raw_msg = build_raw_msg(
            MessageType::Request,
            mac,
            Some(Ipv4Addr::new(192, 168, 1, 150)),
            None,
            Some(alien_server),
        );

        // Como o ServerID não é o nosso, devemos ignorar silenciosamente
        let res = srv.handle_packet(&raw_msg, None);
        assert!(matches!(res, HandleResult::Ignore));
    }

    #[test]
    fn request_unavailable_ip_yields_nak() {
        let mut srv = dummy_server();
        let mac1 = MacAddr([0x11, 0x11, 0x11, 0x11, 0x11, 0x11]);
        let mac2 = MacAddr([0x22, 0x22, 0x22, 0x22, 0x22, 0x22]);
        let contested_ip = Ipv4Addr::new(192, 168, 1, 105);

        // 1. MAC1 aloca o IP primeiro
        let expiry = SystemTime::now() + Duration::from_secs(3600);
        srv.pool.allocate(mac1, Some(contested_ip), expiry);

        // 2. MAC2 tenta pedir o IP que já é do MAC1
        let raw_msg = build_raw_msg(MessageType::Request, mac2, Some(contested_ip), None, None);
        let res = srv.handle_packet(&raw_msg, None);

        match res {
            HandleResult::Reply {
                packet, broadcast, ..
            } => {
                let reply = decode_reply(&packet);
                assert_eq!(
                    reply.opts().get(v4::OptionCode::MessageType),
                    Some(&DhcpOption::MessageType(MessageType::Nak))
                );
                assert!(
                    broadcast,
                    "NAKs no IPv4 devem ser enviados via Broadcast L2 (segundo a RFC)"
                );
            }
            HandleResult::Ignore => panic!("Expected NAK for contested IP"),
        }
    }

    #[test]
    fn release_frees_allocated_ip() {
        let mut srv = dummy_server();
        let mac = dummy_mac();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let expiry = SystemTime::now() + Duration::from_secs(3600);

        srv.pool.allocate(mac, Some(ip), expiry);
        assert_eq!(srv.last_assignment_for(mac), Some(ip));

        // Envia o Release informando o IP no ciaddr (Client IP Address)
        let raw_msg = build_raw_msg(MessageType::Release, mac, None, Some(ip), None);
        let res = srv.handle_packet(&raw_msg, None);

        assert!(
            matches!(res, HandleResult::Ignore),
            "RELEASE não deve gerar resposta"
        );
        assert_eq!(
            srv.last_assignment_for(mac),
            None,
            "IP deve ter sido liberado no pool interno"
        );
    }

    #[test]
    fn decline_clears_mac_assignment() {
        let mut srv = dummy_server();
        let mac = dummy_mac();
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        let expiry = SystemTime::now() + Duration::from_secs(3600);

        srv.pool.allocate(mac, Some(ip), expiry);

        // Cliente detectou conflito de ARP e enviou DECLINE
        let raw_msg = build_raw_msg(MessageType::Decline, mac, None, Some(ip), None);
        let res = srv.handle_packet(&raw_msg, None);

        assert!(matches!(res, HandleResult::Ignore));
        assert_eq!(
            srv.last_assignment_for(mac),
            None,
            "DECLINE deve revogar a associação do MAC"
        );
    }

    #[test]
    fn inform_yields_ack_without_allocating_ip() {
        let mut srv = dummy_server();
        let mac = dummy_mac();
        let client_static_ip = Ipv4Addr::new(192, 168, 1, 50); // Fora do range dinâmico

        let raw_msg = build_raw_msg(MessageType::Inform, mac, None, Some(client_static_ip), None);
        let res = srv.handle_packet(&raw_msg, None);

        match res {
            HandleResult::Reply {
                packet, dest_ip, ..
            } => {
                let reply = decode_reply(&packet);
                assert_eq!(
                    reply.opts().get(v4::OptionCode::MessageType),
                    Some(&DhcpOption::MessageType(MessageType::Ack))
                );

                // Em um INFORM, o yiaddr (Your IP) deve vir ZERADO, pois o servidor não está alocando IP.
                assert_eq!(reply.yiaddr(), Ipv4Addr::UNSPECIFIED);

                // Mas a resposta é direcionada para o ciaddr (o IP que o cliente disse já possuir)
                assert_eq!(dest_ip, client_static_ip);
            }
            HandleResult::Ignore => panic!("Expected ACK for INFORM request"),
        }
    }

    #[test]
    fn test_build_forcerenew() {
        let srv = dummy_server();
        let mac = dummy_mac();
        let ip = Ipv4Addr::new(192, 168, 1, 50);

        let packet = srv.build_forcerenew(mac, ip);
        let msg = Message::decode(&mut Decoder::new(&packet)).expect("Failed to decode packet");

        assert_eq!(msg.opcode(), Opcode::BootReply);
        assert_eq!(msg.ciaddr(), ip);
        assert_eq!(msg.chaddr(), &mac.0);

        let opts = msg.opts();
        let msg_type = opts.get(v4::OptionCode::MessageType).unwrap();
        if let DhcpOption::MessageType(mt) = msg_type {
            assert_eq!(*mt, MessageType::ForceRenew);
        } else {
            panic!("Missing MessageType option");
        }

        let sid = opts.get(v4::OptionCode::ServerIdentifier).unwrap();
        if let DhcpOption::ServerIdentifier(id) = sid {
            assert_eq!(*id, srv.cfg.server_id);
        } else {
            panic!("Missing ServerIdentifier option");
        }
    }
}
