//! DORA state machine — lógica do servidor DHCPv4.
//!
//! Processa mensagens recebidas e gera respostas conforme RFC 2131.
//! Usa `dhcproto` para encode/decode de mensagens.

use dhcproto::v4::{self, DhcpOption, Message, MessageType, Opcode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use std::net::Ipv4Addr;
use tracing::{debug, info, warn};

use super::config::Dhcpv4Config;
use super::pool::IpPool;
use crate::state::MacAddr;

/// Resultado de processar uma mensagem DHCP.
pub enum HandleResult {
    /// Resposta a enviar (bytes encodados, flag de broadcast L2, IP de destino L3 unicast/broadcast, Hostname do cliente).
    Reply(Vec<u8>, bool, Ipv4Addr, Option<String>),
    /// Nenhuma resposta necessária.
    Ignore,
}

/// Servidor DHCPv4 stateful.
pub struct DhcpServer {
    pub cfg: Dhcpv4Config,
    pub pool: IpPool,
}

impl DhcpServer {
    pub fn new(cfg: Dhcpv4Config) -> Self {
        let pool = IpPool::new(cfg.range_start, cfg.range_end);
        DhcpServer { cfg, pool }
    }

    /// Processa um pacote DHCP raw e retorna a resposta (se houver).
    pub fn handle_packet(&mut self, data: &[u8]) -> HandleResult {
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

        let msg_type = match msg.opts().get(v4::OptionCode::MessageType) {
            Some(DhcpOption::MessageType(t)) => *t,
            _ => {
                debug!("No MessageType option, ignoring");
                return HandleResult::Ignore;
            }
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

        match msg_type {
            MessageType::Discover => self.handle_discover(&msg, mac, broadcast),
            MessageType::Request => self.handle_request(&msg, mac, broadcast),
            MessageType::Release => self.handle_release(&msg, mac),
            MessageType::Decline => self.handle_decline(&msg, mac),
            MessageType::Inform => self.handle_inform(&msg, mac),
            other => {
                debug!("Ignoring message type: {other:?}");
                HandleResult::Ignore
            }
        }
    }

    // ── DISCOVER → OFFER ─────────────────────────────────────────────────

    fn handle_discover(&mut self, msg: &Message, mac: MacAddr, broadcast: bool) -> HandleResult {
        let requested = self.get_requested_ip(msg);
        let Some(offered_ip) = self.pool.allocate(mac, requested) else {
            warn!("DISCOVER from {mac}: pool exhausted, no IP available");
            return HandleResult::Ignore;
        };

        info!("DISCOVER from {mac} → OFFER {offered_ip}");
        let reply = self.build_reply(msg, MessageType::Offer, offered_ip);
        HandleResult::Reply(reply, broadcast, offered_ip, self.get_hostname(msg))
    }

    // ── REQUEST → ACK or NAK ─────────────────────────────────────────────

    fn handle_request(&mut self, msg: &Message, mac: MacAddr, broadcast: bool) -> HandleResult {
        // RFC 2131 §3.1 — REQUEST can happen in multiple contexts:
        // 1. Selecting (after OFFER): has ServerIdentifier option
        // 2. Init-Reboot: has RequestedIpAddress, no ServerIdentifier
        // 3. Renewing/Rebinding: ciaddr is set

        // Check if this REQUEST is for us (by ServerIdentifier)
        if let Some(DhcpOption::ServerIdentifier(sid)) =
            msg.opts().get(v4::OptionCode::ServerIdentifier)
            && *sid != self.cfg.server_id
        {
            // Client selected a different server — release our offer
            debug!("REQUEST from {mac}: selected different server {sid}");
            self.pool.release_mac(&mac);
            return HandleResult::Ignore;
        }

        // Determine the IP the client wants
        let wanted_ip = self.get_requested_ip(msg).or_else(|| {
            let ci = msg.ciaddr();
            if ci != Ipv4Addr::UNSPECIFIED {
                Some(ci)
            } else {
                None
            }
        });

        let Some(wanted) = wanted_ip else {
            warn!("REQUEST from {mac}: no IP specified");
            return self.send_nak(msg, "No IP address specified");
        };

        // Try to allocate (will be sticky if already allocated)
        let Some(assigned_ip) = self.pool.allocate(mac, Some(wanted)) else {
            warn!("REQUEST from {mac} for {wanted}: not available");
            return self.send_nak(msg, "Requested IP not available");
        };

        if assigned_ip != wanted {
            // Pool gave us a different IP (requested was taken)
            warn!("REQUEST from {mac} for {wanted}: assigned {assigned_ip} instead");
            return self.send_nak(msg, "Requested IP not available");
        }

        info!("REQUEST from {mac} for {assigned_ip} → ACK");
        let reply = self.build_reply(msg, MessageType::Ack, assigned_ip);
        HandleResult::Reply(reply, broadcast, assigned_ip, self.get_hostname(msg))
    }

    // ── RELEASE ──────────────────────────────────────────────────────────

    fn handle_release(&mut self, msg: &Message, mac: MacAddr) -> HandleResult {
        let ip = msg.ciaddr();
        info!("RELEASE from {mac} for {ip}");
        self.pool.release(ip);
        HandleResult::Ignore // no reply for RELEASE
    }

    // ── DECLINE ──────────────────────────────────────────────────────────

    fn handle_decline(&mut self, _msg: &Message, mac: MacAddr) -> HandleResult {
        // Client detected IP conflict — release and don't reuse
        info!("DECLINE from {mac}");
        self.pool.release_mac(&mac);
        HandleResult::Ignore
    }

    // ── INFORM ───────────────────────────────────────────────────────────

    fn handle_inform(&mut self, msg: &Message, mac: MacAddr) -> HandleResult {
        // Client has static IP, wants config options (DNS, etc.)
        let ip = msg.ciaddr();
        info!("INFORM from {mac} ({ip}) → ACK (config only)");

        // RFC 2131 §4.3.5: "The server fills in 'yiaddr' with zero."
        let reply = self.build_reply(msg, MessageType::Ack, Ipv4Addr::UNSPECIFIED);

        // Mantemos o `ip` como IP de destino (target_ip) para o socket enviar via unicast
        HandleResult::Reply(reply, false, ip, self.get_hostname(msg))
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    fn get_requested_ip(&self, msg: &Message) -> Option<Ipv4Addr> {
        match msg.opts().get(v4::OptionCode::RequestedIpAddress) {
            Some(DhcpOption::RequestedIpAddress(ip)) => Some(*ip),
            _ => None,
        }
    }

    fn get_hostname(&self, msg: &Message) -> Option<String> {
        match msg.opts().get(v4::OptionCode::Hostname) {
            Some(DhcpOption::Hostname(h)) => Some(h.clone()),
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
        HandleResult::Reply(buf, true, Ipv4Addr::BROADCAST, None) // NAK is always broadcast
    }

    /// Returns the MAC and assigned IP from the last successful allocation.
    /// Used by the service loop to publish events.
    pub fn last_assignment_for(&self, mac: &MacAddr) -> Option<Ipv4Addr> {
        self.pool.lookup(mac)
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

        let res = srv.handle_packet(&junk_data);
        assert!(matches!(res, HandleResult::Ignore));
    }

    #[test]
    fn discover_yields_offer() {
        let mut srv = dummy_server();
        let mac = dummy_mac();
        let raw_msg = build_raw_msg(MessageType::Discover, mac, None, None, None);

        let res = srv.handle_packet(&raw_msg);

        match res {
            HandleResult::Reply(bytes, _is_bcast, target_ip, _) => {
                let reply = decode_reply(&bytes);
                assert_eq!(
                    reply.opts().get(v4::OptionCode::MessageType),
                    Some(&DhcpOption::MessageType(MessageType::Offer))
                );

                // O IP ofertado deve vir no yiaddr (Your IP Address)
                assert_eq!(reply.yiaddr(), target_ip);
                assert!(target_ip >= Ipv4Addr::new(192, 168, 1, 100));
            }
            _ => panic!("Expected Reply for DISCOVER"),
        }
    }

    #[test]
    fn request_valid_yields_ack() {
        let mut srv = dummy_server();
        let mac = dummy_mac();
        let requested_ip = Ipv4Addr::new(192, 168, 1, 150);

        let raw_msg = build_raw_msg(MessageType::Request, mac, Some(requested_ip), None, None);
        let res = srv.handle_packet(&raw_msg);

        match res {
            HandleResult::Reply(bytes, _, target_ip, _) => {
                let reply = decode_reply(&bytes);
                assert_eq!(
                    reply.opts().get(v4::OptionCode::MessageType),
                    Some(&DhcpOption::MessageType(MessageType::Ack))
                );
                assert_eq!(target_ip, requested_ip);
                assert_eq!(reply.yiaddr(), requested_ip);

                // O lease deve ter sido gravado internamente no servidor
                assert_eq!(srv.last_assignment_for(&mac), Some(requested_ip));
            }
            _ => panic!("Expected ACK Reply for valid REQUEST"),
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
        let res = srv.handle_packet(&raw_msg);
        assert!(matches!(res, HandleResult::Ignore));
    }

    #[test]
    fn request_unavailable_ip_yields_nak() {
        let mut srv = dummy_server();
        let mac1 = MacAddr([0x11, 0x11, 0x11, 0x11, 0x11, 0x11]);
        let mac2 = MacAddr([0x22, 0x22, 0x22, 0x22, 0x22, 0x22]);
        let contested_ip = Ipv4Addr::new(192, 168, 1, 105);

        // 1. MAC1 aloca o IP primeiro
        srv.pool.allocate(mac1, Some(contested_ip));

        // 2. MAC2 tenta pedir o IP que já é do MAC1
        let raw_msg = build_raw_msg(MessageType::Request, mac2, Some(contested_ip), None, None);
        let res = srv.handle_packet(&raw_msg);

        match res {
            HandleResult::Reply(bytes, is_broadcast, _, _) => {
                let reply = decode_reply(&bytes);
                assert_eq!(
                    reply.opts().get(v4::OptionCode::MessageType),
                    Some(&DhcpOption::MessageType(MessageType::Nak))
                );
                assert!(
                    is_broadcast,
                    "NAKs no IPv4 devem ser enviados via Broadcast L2 (segundo a RFC)"
                );
            }
            _ => panic!("Expected NAK for contested IP"),
        }
    }

    #[test]
    fn release_frees_allocated_ip() {
        let mut srv = dummy_server();
        let mac = dummy_mac();
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        srv.pool.allocate(mac, Some(ip));
        assert_eq!(srv.last_assignment_for(&mac), Some(ip));

        // Envia o Release informando o IP no ciaddr (Client IP Address)
        let raw_msg = build_raw_msg(MessageType::Release, mac, None, Some(ip), None);
        let res = srv.handle_packet(&raw_msg);

        assert!(
            matches!(res, HandleResult::Ignore),
            "RELEASE não deve gerar resposta"
        );
        assert_eq!(
            srv.last_assignment_for(&mac),
            None,
            "IP deve ter sido liberado no pool interno"
        );
    }

    #[test]
    fn decline_clears_mac_assignment() {
        let mut srv = dummy_server();
        let mac = dummy_mac();
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        srv.pool.allocate(mac, Some(ip));

        // Cliente detectou conflito de ARP e enviou DECLINE
        let raw_msg = build_raw_msg(MessageType::Decline, mac, None, Some(ip), None);
        let res = srv.handle_packet(&raw_msg);

        assert!(matches!(res, HandleResult::Ignore));
        assert_eq!(
            srv.last_assignment_for(&mac),
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
        let res = srv.handle_packet(&raw_msg);

        match res {
            HandleResult::Reply(bytes, _, target_ip, _) => {
                let reply = decode_reply(&bytes);
                assert_eq!(
                    reply.opts().get(v4::OptionCode::MessageType),
                    Some(&DhcpOption::MessageType(MessageType::Ack))
                );

                // Em um INFORM, o yiaddr (Your IP) deve vir ZERADO, pois o servidor não está alocando IP.
                assert_eq!(reply.yiaddr(), Ipv4Addr::UNSPECIFIED);

                // Mas a resposta é direcionada para o ciaddr (o IP que o cliente disse já possuir)
                assert_eq!(target_ip, client_static_ip);
            }
            _ => panic!("Expected ACK for INFORM request"),
        }
    }
}
