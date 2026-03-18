use dhcproto::v6::{
    DhcpOption, DhcpOptions, IAAddr, IANA, Message, MessageType, OptionCode, Status, StatusCode,
};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use std::net::Ipv6Addr;
use tracing::{debug, info, warn};

use super::config::Dhcpv6Config;
use super::duid::Duid;
use super::pool::Ipv6Pool;
use crate::state::MacAddr;

/// Result of processing a DHCPv6 message.
pub enum HandleResult {
    /// Reply bytes, destination IP (usually peer's link-local), optional learned DUID, optional MAC
    Reply(Vec<u8>, Ipv6Addr, Option<Duid>, Option<MacAddr>),
    /// No reply
    Ignore,
}

pub struct Dhcpv6Server {
    pub cfg: Dhcpv6Config,
    pub pool: Ipv6Pool,
    pub server_duid: Duid,
}

impl Dhcpv6Server {
    pub fn new(cfg: Dhcpv6Config, pool: Ipv6Pool, server_duid: Duid) -> Self {
        Self {
            cfg,
            pool,
            server_duid,
        }
    }

    pub fn handle_packet(&mut self, data: &[u8], peer: Ipv6Addr) -> HandleResult {
        let msg = match Message::decode(&mut Decoder::new(data)) {
            Ok(m) => m,
            Err(e) => {
                debug!("[DHCPv6] Failed to decode packet: {e}");
                return HandleResult::Ignore;
            }
        };

        let client_id_opt = msg.opts().get(OptionCode::ClientId);
        let client_duid = match client_id_opt {
            Some(DhcpOption::ClientId(duid_bytes)) => Duid::new(duid_bytes.clone()),
            _ => {
                // If there's no Client ID, we must drop it unless it's InformationRequest
                if msg.msg_type() != MessageType::InformationRequest {
                    debug!("[DHCPv6] No ClientId option, ignoring");
                    return HandleResult::Ignore;
                }
                Duid::new(vec![])
            }
        };

        // Try extracting MAC from DUID or Option 79 (Client Link-Layer Address)
        let mac = client_duid.extract_mac().or_else(|| {
            msg.opts().iter().find_map(|opt| {
                if let DhcpOption::Unknown(u) = opt
                    && u.code() == 79.into()
                    && u.data().len() >= 8
                {
                    // 2 bytes type, then MAC
                    return MacAddr::from_slice(&u.data()[2..8]);
                }
                None
            })
        });

        match msg.msg_type() {
            MessageType::Solicit => self.handle_solicit(&msg, client_duid, mac, peer),
            MessageType::Request => self.handle_request(&msg, client_duid, mac, peer),
            MessageType::Renew => self.handle_renew(&msg, client_duid, mac, peer),
            MessageType::Rebind => self.handle_rebind(&msg, client_duid, mac, peer),
            MessageType::Release => self.handle_release(&msg, client_duid, mac, peer),
            MessageType::InformationRequest => {
                self.handle_information_request(&msg, client_duid, peer)
            }
            other => {
                debug!("[DHCPv6] Ignoring message type: {other:?}");
                HandleResult::Ignore
            }
        }
    }

    fn handle_solicit(
        &mut self,
        msg: &Message,
        client_duid: Duid,
        mac: Option<MacAddr>,
        peer: Ipv6Addr,
    ) -> HandleResult {
        let Some(mac) = mac else {
            warn!("[DHCPv6] SOLICIT from {peer} with no extractable MAC. Ignoring.");
            return HandleResult::Ignore;
        };

        let mut reply = self.base_reply(msg, MessageType::Advertise, &client_duid);
        let mut learned_duid = None;

        // Ensure we offer IA_NA if requested
        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA) {
            // Allocate an IP
            if let Some(ip) = self.pool.allocate(mac, None) {
                info!("[DHCPv6] SOLICIT from {mac} -> ADVERTISE {ip}");
                let mut ia_opts = DhcpOptions::new();
                ia_opts.insert(DhcpOption::IAAddr(IAAddr {
                    addr: ip,
                    preferred_life: self.cfg.lease_time / 2,
                    valid_life: self.cfg.lease_time,
                    opts: DhcpOptions::new(),
                }));
                reply.opts_mut().insert(DhcpOption::IANA(IANA {
                    id: iana.id,
                    t1: self.cfg.lease_time / 2,
                    t2: self.cfg.lease_time * 4 / 5,
                    opts: ia_opts,
                }));
                learned_duid = Some(client_duid);
            } else {
                warn!("[DHCPv6] SOLICIT from {mac}: pool exhausted");
                return self.send_status(
                    msg,
                    MessageType::Advertise,
                    &client_duid,
                    Status::NoAddrsAvail,
                    "Pool exhausted",
                    peer,
                );
            }
        }

        self.add_dns_options(&mut reply);
        HandleResult::Reply(encode_msg(&reply), peer, learned_duid, Some(mac))
    }

    fn handle_request(
        &mut self,
        msg: &Message,
        client_duid: Duid,
        mac: Option<MacAddr>,
        peer: Ipv6Addr,
    ) -> HandleResult {
        // Must contain Server ID and match ours
        if !self.check_server_id(msg) {
            return HandleResult::Ignore;
        }

        let Some(mac) = mac else {
            warn!("[DHCPv6] REQUEST from {peer} with no extractable MAC.");
            return HandleResult::Ignore;
        };

        let mut reply = self.base_reply(msg, MessageType::Reply, &client_duid);

        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA) {
            // Look for requested IP inside IAAddr in the IA_NA
            let requested_ip = iana.opts.get(OptionCode::IAAddr).and_then(|opt| {
                if let DhcpOption::IAAddr(ia_addr) = opt {
                    Some(ia_addr.addr)
                } else {
                    None
                }
            });

            if let Some(ip) = self.pool.allocate(mac, requested_ip) {
                info!("[DHCPv6] REQUEST from {mac} -> REPLY {ip}");
                let mut ia_opts = DhcpOptions::new();
                ia_opts.insert(DhcpOption::IAAddr(IAAddr {
                    addr: ip,
                    preferred_life: self.cfg.lease_time / 2,
                    valid_life: self.cfg.lease_time,
                    opts: DhcpOptions::new(),
                }));
                reply.opts_mut().insert(DhcpOption::IANA(IANA {
                    id: iana.id,
                    t1: self.cfg.lease_time / 2,
                    t2: self.cfg.lease_time * 4 / 5,
                    opts: ia_opts,
                }));
            } else {
                // Return NoAddrsAvail
                let mut ia_opts = DhcpOptions::new();
                ia_opts.insert(DhcpOption::StatusCode(StatusCode {
                    status: Status::NoAddrsAvail,
                    msg: "Not available".to_string(),
                }));
                reply.opts_mut().insert(DhcpOption::IANA(IANA {
                    id: iana.id,
                    t1: 0,
                    t2: 0,
                    opts: ia_opts,
                }));
            }
        }

        self.add_dns_options(&mut reply);
        HandleResult::Reply(encode_msg(&reply), peer, Some(client_duid), Some(mac))
    }

    fn handle_renew(
        &mut self,
        msg: &Message,
        client_duid: Duid,
        mac: Option<MacAddr>,
        peer: Ipv6Addr,
    ) -> HandleResult {
        if !self.check_server_id(msg) {
            return HandleResult::Ignore;
        }
        self.handle_request(msg, client_duid, mac, peer)
    }

    fn handle_rebind(
        &mut self,
        msg: &Message,
        client_duid: Duid,
        mac: Option<MacAddr>,
        peer: Ipv6Addr,
    ) -> HandleResult {
        // Rebind is like Renew, but Server ID is omitted
        self.handle_request(msg, client_duid, mac, peer)
    }

    fn handle_release(
        &mut self,
        msg: &Message,
        client_duid: Duid,
        mac: Option<MacAddr>,
        peer: Ipv6Addr,
    ) -> HandleResult {
        if !self.check_server_id(msg) {
            return HandleResult::Ignore;
        }

        let Some(mac) = mac else {
            return HandleResult::Ignore;
        };

        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA)
            && let Some(DhcpOption::IAAddr(ia_addr)) = iana.opts.get(OptionCode::IAAddr)
        {
            info!("[DHCPv6] RELEASE from {mac} for {}", ia_addr.addr);
            self.pool.release(&ia_addr.addr);
        }

        let mut reply = self.base_reply(msg, MessageType::Reply, &client_duid);
        reply.opts_mut().insert(DhcpOption::StatusCode(StatusCode {
            status: Status::Success,
            msg: "Released".to_string(),
        }));
        HandleResult::Reply(encode_msg(&reply), peer, None, Some(mac))
    }

    fn handle_information_request(
        &self,
        msg: &Message,
        client_duid: Duid,
        peer: Ipv6Addr,
    ) -> HandleResult {
        // Send back configuration only, no IA_NA
        let mut reply = self.base_reply(msg, MessageType::Reply, &client_duid);
        self.add_dns_options(&mut reply);
        HandleResult::Reply(encode_msg(&reply), peer, None, None)
    }

    fn base_reply(&self, msg: &Message, msg_type: MessageType, client_duid: &Duid) -> Message {
        let mut reply = Message::new(msg_type);
        reply.set_xid(msg.xid());

        // Echo ClientId if we have one (which we should, except on some InformationRequests)
        if !client_duid.bytes.is_empty() {
            reply
                .opts_mut()
                .insert(DhcpOption::ClientId(client_duid.bytes.clone()));
        }

        reply
            .opts_mut()
            .insert(DhcpOption::ServerId(self.server_duid.bytes.clone()));

        reply
    }

    fn check_server_id(&self, msg: &Message) -> bool {
        match msg.opts().get(OptionCode::ServerId) {
            Some(DhcpOption::ServerId(sid)) => *sid == self.server_duid.bytes,
            _ => false,
        }
    }

    fn send_status(
        &self,
        msg: &Message,
        msg_type: MessageType,
        client_duid: &Duid,
        status: Status,
        text: &str,
        peer: Ipv6Addr,
    ) -> HandleResult {
        let mut reply = self.base_reply(msg, msg_type, client_duid);
        reply.opts_mut().insert(DhcpOption::StatusCode(StatusCode {
            status,
            msg: text.to_string(),
        }));
        HandleResult::Reply(encode_msg(&reply), peer, None, None)
    }

    fn add_dns_options(&self, _reply: &mut Message) {
        // Typically handled by RDNSS in RA, but some clients want it via DHCPv6
        // If config provided DNS, we would add DomainNameServers(Vec<Ipv6Addr>) here.
        // For now, keeping it minimal.
    }

    pub fn last_assignment_for(&self, mac: &MacAddr) -> Option<Ipv6Addr> {
        self.pool.lookup(mac)
    }
}

fn encode_msg(msg: &Message) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    let mut enc = Encoder::new(&mut buf);
    msg.encode(&mut enc)
        .expect("Encoding DHCPv6 message should not fail");
    buf
}
