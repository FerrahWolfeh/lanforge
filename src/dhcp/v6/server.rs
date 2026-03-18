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

    pub async fn handle_packet(
        &mut self,
        data: &[u8],
        peer: Ipv6Addr,
        table: &tokio::sync::RwLock<crate::state::DeviceTable>, // <-- Injetando a tabela aqui
        nl_handle: &rtnetlink::Handle,
    ) -> HandleResult {
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
        let mut mac = client_duid
            .extract_mac()
            .or_else(|| {
                // Opção 79 (Client Link-Layer Address)
                msg.opts().iter().find_map(|opt| {
                    if let DhcpOption::Unknown(u) = opt
                        && u.code() == 79.into()
                        && u.data().len() >= 8
                    {
                        return MacAddr::from_slice(&u.data()[2..8]);
                    }
                    None
                })
            })
            .or_else(|| {
                // EUI-64 matemático link-local
                crate::netlink::mac_from_eui64_link_local(&peer).map(MacAddr)
            });

        // Fallback 1: Cache passivo ultra-rápido na memória
        if mac.is_none()
            && let Some(cached_mac) = table.read().await.get_mac_from_ndp_cache(&peer)
        {
            debug!("[DHCPv6] MAC recuperado instantaneamente do cache NDP para {peer}");
            mac = Some(cached_mac);
        }

        // Fallback 2: O dump do Netlink original (síncrono com kernel)
        if mac.is_none() {
            debug!("[DHCPv6] Cache miss. Fazendo lookup síncrono no kernel para {peer}...");
            if let Some(ndp_mac) = crate::netlink::lookup_mac_for_ipv6(nl_handle, &peer).await {
                mac = Some(MacAddr(ndp_mac));
                // Opcional: já preenche o cache caso aconteça de novo
                table.write().await.update_ndp_cache(peer, MacAddr(ndp_mac));
            }
        }

        let Some(mac) = mac else {
            warn!(
                "[DHCPv6] SOLICIT from {peer}: sem MAC (DUID: {}). Dando um cutucão no Kernel...",
                client_duid.duid_type()
            );

            // O HACK SALVADOR (Agora com Scope/Interface):
            // Usamos a crate 'socket2' para atrelar o socket diretamente à interface (ex: end0).
            // Isso garante que o pacote nulo saia fisicamente pela placa de rede,
            // obrigando o Linux a resolver o MAC instantaneamente.
            let peer_ip = peer;
            let iface = self.cfg.iface.clone(); // Pega o nome da interface ("end0")

            tokio::spawn(async move {
                if let Ok(sock) = socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                ) {
                    let _ = sock.bind_device(Some(iface.as_bytes()));
                    let addr = std::net::SocketAddrV6::new(peer_ip, 546, 0, 0);
                    let _ = sock.send_to(&[0], &addr.into());
                }
            });

            return HandleResult::Ignore;
        };

        match msg.msg_type() {
            MessageType::Solicit => self.handle_solicit(&msg, client_duid, Some(mac), peer),
            MessageType::Request => self.handle_request(&msg, client_duid, Some(mac), peer),
            MessageType::Renew => self.handle_renew(&msg, client_duid, Some(mac), peer),
            MessageType::Rebind => self.handle_rebind(&msg, client_duid, Some(mac), peer),
            MessageType::Release => self.handle_release(&msg, client_duid, Some(mac), peer),
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

        // NetworkManager adora Rapid Commit. Se ele pedir, pulamos o ADVERTISE e damos REPLY direto.
        let is_rapid_commit = msg.opts().get(OptionCode::RapidCommit).is_some();
        let reply_type = if is_rapid_commit {
            MessageType::Reply
        } else {
            MessageType::Advertise
        };

        let mut reply = self.base_reply(msg, reply_type, &client_duid);
        let mut learned_duid = None;

        // Preference 255: Diz ao cliente para não esperar por outros servidores na rede.
        reply.opts_mut().insert(DhcpOption::Preference(255));

        // Se o cliente pediu Rapid Commit, a RFC exige que o servidor devolva a opção para confirmar
        if is_rapid_commit {
            reply.opts_mut().insert(DhcpOption::RapidCommit);
        }

        // Ensure we offer IA_NA if requested
        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA) {
            // Allocate an IP
            if let Some(ip) = self.pool.allocate(mac, None) {
                let action = if is_rapid_commit {
                    "REPLY (Rapid Commit)"
                } else {
                    "ADVERTISE"
                };
                info!("[DHCPv6] SOLICIT from {mac} -> {action} {ip}");

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

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v6::{DhcpOptions, IANA, OptionCode};
    use std::net::Ipv6Addr;

    // -----------------------------------------------------------------------
    // Factories & Helpers para os Testes
    // -----------------------------------------------------------------------

    fn dummy_server() -> Dhcpv6Server {
        let cfg = Dhcpv6Config {
            enabled: true,
            iface: "lo".to_string(),
            lease_time: 86400,
            ula_prefix: Some("fd97:f00d:cafe:3731::".parse().unwrap()),
            range_start: Some("fd97:f00d:cafe:3731::100".parse().unwrap()),
            range_end: Some("fd97:f00d:cafe:3731::200".parse().unwrap()),
        };
        let pool = Ipv6Pool::new(cfg.range_start, cfg.range_end, cfg.ula_prefix);
        let server_duid = Duid::new(vec![
            0x00, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        Dhcpv6Server::new(cfg, pool, server_duid)
    }

    fn dummy_client_duid() -> Duid {
        Duid::new(vec![
            0x00, 0x03, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        ])
    }

    fn dummy_mac() -> MacAddr {
        MacAddr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    }

    fn peer_ip() -> Ipv6Addr {
        "fe80::1".parse().unwrap()
    }

    fn build_solicit(with_rapid_commit: bool) -> Message {
        let mut msg = Message::new(MessageType::Solicit);
        msg.opts_mut().insert(DhcpOption::IANA(IANA {
            id: 12345,
            t1: 0,
            t2: 0,
            opts: DhcpOptions::new(),
        }));
        if with_rapid_commit {
            msg.opts_mut().insert(DhcpOption::RapidCommit);
        }
        msg
    }

    fn decode_reply(bytes: &[u8]) -> Message {
        Message::decode(&mut Decoder::new(bytes)).expect("Should decode valid DHCPv6 reply")
    }

    // -----------------------------------------------------------------------
    // Suíte de Testes DORA / DHCPv6
    // -----------------------------------------------------------------------

    #[test]
    fn solicit_without_mac_is_ignored() {
        let mut srv = dummy_server();
        let msg = build_solicit(false);

        // Passando None para o MAC deve forçar o HandleResult::Ignore
        let res = srv.handle_solicit(&msg, dummy_client_duid(), None, peer_ip());
        assert!(matches!(res, HandleResult::Ignore));
    }

    #[test]
    fn solicit_standard_yields_advertise() {
        let mut srv = dummy_server();
        let msg = build_solicit(false);

        let res = srv.handle_solicit(&msg, dummy_client_duid(), Some(dummy_mac()), peer_ip());

        match res {
            HandleResult::Reply(bytes, target, _, _) => {
                let reply = decode_reply(&bytes);
                assert_eq!(reply.msg_type(), MessageType::Advertise);
                assert_eq!(target, peer_ip());

                // Verifica se a option Preference foi setada com autoridade máxima (255)
                assert!(reply.opts().get(OptionCode::Preference).is_some());

                // Verifica se tem a oferta de IP (IA_NA -> IAAddr)
                if let Some(DhcpOption::IANA(iana)) = reply.opts().get(OptionCode::IANA) {
                    assert!(iana.opts.get(OptionCode::IAAddr).is_some());
                } else {
                    panic!("Missing IA_NA in Advertise");
                }
            }
            _ => panic!("Expected HandleResult::Reply"),
        }
    }

    #[test]
    fn solicit_with_rapid_commit_yields_reply() {
        let mut srv = dummy_server();
        let msg = build_solicit(true); // Habilita Rapid Commit

        let res = srv.handle_solicit(&msg, dummy_client_duid(), Some(dummy_mac()), peer_ip());

        match res {
            HandleResult::Reply(bytes, _, _, _) => {
                let reply = decode_reply(&bytes);
                // Rapid commit pula a fase ADVERTISE e vai direto para REPLY
                assert_eq!(reply.msg_type(), MessageType::Reply);

                // O servidor TEM que devolver a flag de Rapid Commit na resposta segundo a RFC
                assert!(reply.opts().get(OptionCode::RapidCommit).is_some());
            }
            _ => panic!("Expected Reply"),
        }
    }

    #[test]
    fn request_missing_server_id_is_ignored() {
        let mut srv = dummy_server();
        let msg = Message::new(MessageType::Request); // Sem Server ID

        let res = srv.handle_request(&msg, dummy_client_duid(), Some(dummy_mac()), peer_ip());
        assert!(matches!(res, HandleResult::Ignore));
    }

    #[test]
    fn request_valid_yields_reply_with_ip() {
        let mut srv = dummy_server();
        let mut msg = Message::new(MessageType::Request);

        // Insere o Server ID legítimo (mock)
        msg.opts_mut()
            .insert(DhcpOption::ServerId(srv.server_duid.bytes.clone()));
        msg.opts_mut().insert(DhcpOption::IANA(IANA {
            id: 999,
            t1: 0,
            t2: 0,
            opts: DhcpOptions::new(),
        }));

        let res = srv.handle_request(&msg, dummy_client_duid(), Some(dummy_mac()), peer_ip());

        match res {
            HandleResult::Reply(bytes, _, _, _) => {
                let reply = decode_reply(&bytes);
                assert_eq!(reply.msg_type(), MessageType::Reply);

                if let Some(DhcpOption::IANA(iana)) = reply.opts().get(OptionCode::IANA) {
                    // Tem que retornar um endereço real do range
                    let has_ip = iana.opts.get(OptionCode::IAAddr).is_some();
                    assert!(has_ip, "Server failed to allocate IP in Reply");
                } else {
                    panic!("Missing IA_NA in Reply");
                }
            }
            _ => panic!("Expected Reply"),
        }
    }

    #[test]
    fn release_frees_allocated_ip() {
        let mut srv = dummy_server();
        let mac = dummy_mac();
        let requested_ip: Ipv6Addr = "fd97:f00d:cafe:3731::100".parse().unwrap();

        // 1. Forçamos a alocação de um IP para este MAC diretamente na pool
        srv.pool.allocate(mac, Some(requested_ip));
        assert_eq!(srv.last_assignment_for(&mac), Some(requested_ip));

        // 2. Montamos a mensagem de Release
        let mut msg = Message::new(MessageType::Release);
        msg.opts_mut()
            .insert(DhcpOption::ServerId(srv.server_duid.bytes.clone()));

        let mut ia_opts = DhcpOptions::new();
        ia_opts.insert(DhcpOption::IAAddr(IAAddr {
            addr: requested_ip,
            preferred_life: 0,
            valid_life: 0,
            opts: DhcpOptions::new(),
        }));
        msg.opts_mut().insert(DhcpOption::IANA(IANA {
            id: 1,
            t1: 0,
            t2: 0,
            opts: ia_opts,
        }));

        // 3. Enviamos o Release para o servidor
        let res = srv.handle_release(&msg, dummy_client_duid(), Some(mac), peer_ip());

        // 4. Verificamos se o IP foi liberado da pool com sucesso
        assert!(matches!(res, HandleResult::Reply(..)));
        assert_eq!(
            srv.last_assignment_for(&mac),
            None,
            "IP should have been released from the pool"
        );
    }

    #[test]
    fn information_request_yields_reply_without_ia_na() {
        let srv = dummy_server();
        let msg = Message::new(MessageType::InformationRequest);

        let res = srv.handle_information_request(&msg, dummy_client_duid(), peer_ip());

        match res {
            HandleResult::Reply(bytes, _, _, _) => {
                let reply = decode_reply(&bytes);
                assert_eq!(reply.msg_type(), MessageType::Reply);
                // Information request pede parâmetros de rede (DNS), NUNCA endereços IPs
                assert!(reply.opts().get(OptionCode::IANA).is_none());
            }
            _ => panic!("Expected Reply"),
        }
    }
}
