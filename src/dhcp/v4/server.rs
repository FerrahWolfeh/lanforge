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
                debug!("[DHCPv4] Failed to decode packet: {e}");
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
                debug!("[DHCPv4] No MessageType option, ignoring");
                return HandleResult::Ignore;
            }
        };

        let chaddr = msg.chaddr();
        if chaddr.len() < 6 {
            debug!("[DHCPv4] chaddr too short, ignoring");
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
                debug!("[DHCPv4] Ignoring message type: {other:?}");
                HandleResult::Ignore
            }
        }
    }

    // ── DISCOVER → OFFER ─────────────────────────────────────────────────

    fn handle_discover(&mut self, msg: &Message, mac: MacAddr, broadcast: bool) -> HandleResult {
        let requested = self.get_requested_ip(msg);
        let Some(offered_ip) = self.pool.allocate(mac, requested) else {
            warn!("[DHCPv4] DISCOVER from {mac}: pool exhausted, no IP available");
            return HandleResult::Ignore;
        };

        info!("[DHCPv4] DISCOVER from {mac} → OFFER {offered_ip}");
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
            debug!("[DHCPv4] REQUEST from {mac}: selected different server {sid}");
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
            warn!("[DHCPv4] REQUEST from {mac}: no IP specified");
            return self.send_nak(msg, "No IP address specified");
        };

        // Try to allocate (will be sticky if already allocated)
        let Some(assigned_ip) = self.pool.allocate(mac, Some(wanted)) else {
            warn!("[DHCPv4] REQUEST from {mac} for {wanted}: not available");
            return self.send_nak(msg, "Requested IP not available");
        };

        if assigned_ip != wanted {
            // Pool gave us a different IP (requested was taken)
            warn!("[DHCPv4] REQUEST from {mac} for {wanted}: assigned {assigned_ip} instead");
            return self.send_nak(msg, "Requested IP not available");
        }

        info!("[DHCPv4] REQUEST from {mac} for {assigned_ip} → ACK");
        let reply = self.build_reply(msg, MessageType::Ack, assigned_ip);
        HandleResult::Reply(reply, broadcast, assigned_ip, self.get_hostname(msg))
    }

    // ── RELEASE ──────────────────────────────────────────────────────────

    fn handle_release(&mut self, msg: &Message, mac: MacAddr) -> HandleResult {
        let ip = msg.ciaddr();
        info!("[DHCPv4] RELEASE from {mac} for {ip}");
        self.pool.release(ip);
        HandleResult::Ignore // no reply for RELEASE
    }

    // ── DECLINE ──────────────────────────────────────────────────────────

    fn handle_decline(&mut self, _msg: &Message, mac: MacAddr) -> HandleResult {
        // Client detected IP conflict — release and don't reuse
        info!("[DHCPv4] DECLINE from {mac}");
        self.pool.release_mac(&mac);
        HandleResult::Ignore
    }

    // ── INFORM ───────────────────────────────────────────────────────────

    fn handle_inform(&mut self, msg: &Message, mac: MacAddr) -> HandleResult {
        // Client has static IP, wants config options (DNS, etc.)
        let ip = msg.ciaddr();
        info!("[DHCPv4] INFORM from {mac} ({ip}) → ACK (config only)");
        let reply = self.build_reply(msg, MessageType::Ack, ip);
        HandleResult::Reply(reply, false, ip, self.get_hostname(msg)) // INFORM responses are always unicast
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
