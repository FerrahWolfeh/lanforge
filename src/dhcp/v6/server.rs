//! SARR state machine — Lógica central do servidor `DHCPv6`.
//!
//! Este módulo implementa a alocação de endereços e processamento de mensagens
//! conforme a RFC 8415. Ele foca na identificação por DUID e alocação de
//! endereços no prefixo ULA configurado.
//!
//! ## Tabela de Decisão
//!
//! | Mensagem    | Ação                      | Resposta    |
//! |-------------|---------------------------|-------------|
//! | Solicit     | Ofert/Aloca IA_NA         | Advertise/Reply |
//! | Request     | Confirma lease            | Reply       |
//! | Renew       | Estende lease             | Reply       |
//! | Release     | Libera IA_NA              | Reply       |
//! | Info-Req    | Provedor de opções (DNS)  | Reply       |

use dhcproto::v6::{
    DhcpOption, DhcpOptions, IAAddr, IANA, IAPD, IAPrefix, Message, MessageType, OptionCode,
    Status, StatusCode,
};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use std::net::Ipv6Addr;
use tracing::{debug, info, warn};

use super::config::Dhcpv6Config;
use super::duid::Duid;
use super::pool::Ipv6Pool;
use crate::bus::ManagedTable;
use crate::device::MacAddr;
use crate::dhcp::identity::DeviceIdentity;
use crate::state::update::DeviceUpdate;
use std::sync::Arc;

/// IAIDs atribuídos em uma resposta.
#[derive(Default, Clone, Debug)]
pub struct AssignedIAs {
    pub na: Vec<u32>,
    pub pd: Vec<u32>,
}

/// Resultado de processar uma mensagem `DHCPv6`.
pub enum HandleResult<'a> {
    /// Resposta a organizar (bytes encodados, IP de destino, DUID aprendido, MAC extraído, IAIDs).
    Reply(
        &'a [u8],
        Ipv6Addr,
        Option<Duid>,
        Option<MacAddr>,
        AssignedIAs,
    ),
    /// Nenhuma resposta necessária (ex: mensagem malformada ou para outro servidor).
    Ignore,
}

/// Contexto para envio de status codes
struct StatusContext<'a> {
    msg: &'a Message,
    client_duid: &'a Duid,
    peer: Ipv6Addr,
    mac: Option<MacAddr>,
}

/// Servidor `DHCPv6` stateful.
///
/// Mantém as configurações, o pool de endereços ULA e a identidade (DUID) do servidor.
pub struct Dhcpv6Server {
    /// Configurações do servidor (iface, lease time, etc.)
    pub cfg: Dhcpv6Config,
    /// Pool de endereços ULA /64
    pub pool: Ipv6Pool,
    /// DUID (DHCP Unique Identifier) deste servidor
    pub server_duid: Duid,
    /// Lifetimes aprendidos do prefixo GUA (preferred, valid)
    pub prefix_lifetimes: Option<(u32, u32)>,
    /// Socket persistente para NDP pokes (economiza syscall socket())
    pub ndp_poke_sock: Arc<tokio::net::UdpSocket>,
}

impl Dhcpv6Server {
    pub const fn new(
        cfg: Dhcpv6Config,
        pool: Ipv6Pool,
        server_duid: Duid,
        ndp_poke_sock: Arc<tokio::net::UdpSocket>,
    ) -> Self {
        Self {
            cfg,
            pool,
            server_duid,
            prefix_lifetimes: None,
            ndp_poke_sock,
        }
    }

    fn get_lifetimes(&self) -> (u32, u32) {
        let mut preferred = self.cfg.lease_time / 2;
        let mut valid = self.cfg.lease_time;

        if let Some((p, v)) = self.prefix_lifetimes {
            if preferred > p {
                preferred = p;
            }
            if valid > v {
                valid = v;
            }
        }
        (preferred, valid)
    }

    pub async fn handle_packet<'a>(
        &mut self,
        data: &[u8],
        peer: Ipv6Addr,
        table: &ManagedTable,
        nl_handle: &rtnetlink::Handle,
        buf: &'a mut Vec<u8>,
    ) -> HandleResult<'a> {
        let msg = match Message::decode(&mut Decoder::new(data)) {
            Ok(m) => m,
            Err(e) => {
                debug!("Failed to decode packet: {e}");
                return HandleResult::Ignore;
            }
        };

        let client_id_opt = msg.opts().get(OptionCode::ClientId);
        let client_duid = if let Some(DhcpOption::ClientId(duid_bytes)) = client_id_opt {
            Duid::new(duid_bytes.clone())
        } else {
            if msg.msg_type() != MessageType::InformationRequest {
                debug!("No ClientId option, ignoring");
                return HandleResult::Ignore;
            }
            Duid::new(vec![])
        };

        // Tenta extrair MAC em ordem de custo crescente
        let mut mac = client_duid
            .extract_mac()
            .or_else(|| {
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
            .or_else(|| crate::netlink::mac_from_eui64_link_local(&peer));

        // Pega o lock de leitura da tabela UMA ÚNICA VEZ para:
        // 1. Cache NDP
        // 2. Resolução de DeviceIdentity (se o mac for conhecido)
        // 1. Tenta recuperar MAC do cache NDP (lock síncrono)
        if mac.is_none() {
            let t = table.read();
            if let Some(cached) = t.get_mac_from_ndp_cache(&peer) {
                debug!("MAC recuperado do cache NDP para {peer}");
                mac = Some(cached);
            }
        }

        // 2. Se ainda sem MAC, tenta lookup no kernel (síncrono — SEM LOCK)
        if mac.is_none() {
            debug!("Cache miss. Lookup síncrono no kernel para {peer}...");
            if let Some(ndp_mac) = crate::netlink::lookup_mac_for_ipv6(nl_handle, &peer).await {
                table
                    .update(DeviceUpdate::NdpSeen {
                        mac: ndp_mac,
                        ip: peer,
                    })
                    .await;
                mac = Some(ndp_mac);
            }
        }

        // 3. Resolve identidade (novo lock síncrono)
        let identity = mac.map(|m| {
            let t = table.read();
            DeviceIdentity::resolve(m, None, Self::get_vendor_class(&msg), Some(&t))
        });

        if mac.is_none() {
            warn!(
                "SOLICIT from {peer}: sem MAC (DUID: {}). Continuando sem MAC...",
                client_duid.duid_type()
            );

            // Força o kernel a resolver o MAC enviando um pacote vazio
            // Reusando o socket persistente!
            let poke_sock = self.ndp_poke_sock.clone();
            let peer_ip = peer;
            tokio::spawn(async move {
                let addr = std::net::SocketAddrV6::new(peer_ip, 546, 0, 0);
                let _ = poke_sock.send_to(&[0], addr).await;
            });
        }

        match msg.msg_type() {
            MessageType::Solicit => {
                self.handle_solicit(&msg, client_duid, identity.as_ref(), peer, buf)
            }
            MessageType::Request => {
                self.handle_request(&msg, client_duid, identity.as_ref(), peer, buf)
            }
            MessageType::Renew => {
                self.handle_renew(&msg, client_duid, identity.as_ref(), peer, buf)
            }
            MessageType::Rebind => {
                self.handle_rebind(&msg, client_duid, identity.as_ref(), peer, buf)
            }
            MessageType::Release => {
                self.handle_release(&msg, &client_duid, identity.as_ref(), peer, buf)
            }
            MessageType::Decline => {
                self.handle_decline(&msg, client_duid, identity.as_ref(), peer, buf)
            }
            MessageType::InformationRequest => {
                self.handle_information_request(&msg, &client_duid, peer, buf)
            }
            other => {
                debug!("Ignoring message type: {other:?}");
                HandleResult::Ignore
            }
        }
    }

    fn handle_solicit<'a>(
        &mut self,
        msg: &Message,
        client_duid: Duid,
        identity: Option<&DeviceIdentity>,
        peer: Ipv6Addr,
        buf: &'a mut Vec<u8>,
    ) -> HandleResult<'a> {
        let mac = identity.map(|i| i.mac);

        let is_rapid_commit = msg.opts().get(OptionCode::RapidCommit).is_some();
        let reply_type = if is_rapid_commit {
            MessageType::Reply
        } else {
            MessageType::Advertise
        };

        let mut reply = self.base_reply(msg, reply_type, &client_duid);
        let mut learned_duid = None;

        reply.opts_mut().insert(DhcpOption::Preference(255));

        if is_rapid_commit {
            reply.opts_mut().insert(DhcpOption::RapidCommit);
        }

        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA) {
            if let Some(ip) = self.pool.allocate(&client_duid.bytes, iana.id, mac, None) {
                let (pref, valid) = self.get_lifetimes();
                let action = if is_rapid_commit {
                    "REPLY (Rapid Commit)"
                } else {
                    "ADVERTISE"
                };
                if let Some(id) = identity {
                    info!("DHCPv6: {id} is soliciting an address -> {action} {ip}");
                } else {
                    info!("DHCPv6: Anonymous device is soliciting an address -> {action} {ip}");
                }

                let mut ia_opts = DhcpOptions::new();
                ia_opts.insert(DhcpOption::IAAddr(IAAddr {
                    addr: ip,
                    preferred_life: pref,
                    valid_life: valid,
                    opts: DhcpOptions::new(),
                }));

                reply.opts_mut().insert(DhcpOption::IANA(IANA {
                    id: iana.id,
                    t1: pref / 2,
                    t2: pref * 4 / 5,
                    opts: ia_opts,
                }));
                learned_duid = Some(client_duid.clone());
            } else {
                // RFC 8415: NoAddrsAvail
                let mut opts = DhcpOptions::new();
                opts.insert(DhcpOption::StatusCode(StatusCode {
                    status: Status::NoAddrsAvail,
                    msg: "No addresses available in pool".to_string(),
                }));
                reply.opts_mut().insert(DhcpOption::IANA(IANA {
                    id: iana.id,
                    t1: 0,
                    t2: 0,
                    opts,
                }));
            }
        }

        if let Some(DhcpOption::IAPD(iapd)) = msg.opts().get(OptionCode::IAPD) {
            if let Some((prefix, len)) =
                self.pool.allocate_prefix(&client_duid.bytes, iapd.id, None)
            {
                let (pref, valid) = self.get_lifetimes();
                info!("DHCPv6: Delegating prefix {prefix}/{len} to {identity:?}");

                let mut ia_opts = DhcpOptions::new();
                ia_opts.insert(DhcpOption::IAPrefix(IAPrefix {
                    prefix_ip: prefix,
                    prefix_len: len,
                    preferred_lifetime: pref,
                    valid_lifetime: valid,
                    opts: DhcpOptions::new(),
                }));

                reply.opts_mut().insert(DhcpOption::IAPD(IAPD {
                    id: iapd.id,
                    t1: pref / 2,
                    t2: pref * 4 / 5,
                    opts: ia_opts,
                }));
                learned_duid = Some(client_duid.clone());
            } else {
                // RFC 8415: NoPrefixAvail
                let mut opts = DhcpOptions::new();
                opts.insert(DhcpOption::StatusCode(StatusCode {
                    status: Status::NoPrefixAvail,
                    msg: "No prefixes available for delegation".to_string(),
                }));
                reply.opts_mut().insert(DhcpOption::IAPD(IAPD {
                    id: iapd.id,
                    t1: 0,
                    t2: 0,
                    opts,
                }));
            }
        }

        Self::add_dns_options(&mut reply);
        let mut ias = AssignedIAs::default();
        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA) {
            ias.na.push(iana.id);
        }
        if let Some(DhcpOption::IAPD(iapd)) = msg.opts().get(OptionCode::IAPD) {
            ias.pd.push(iapd.id);
        }

        HandleResult::Reply(encode_msg(&reply, buf), peer, learned_duid, mac, ias)
    }

    fn handle_request<'a>(
        &mut self,
        msg: &Message,
        client_duid: Duid,
        identity: Option<&DeviceIdentity>,
        peer: Ipv6Addr,
        buf: &'a mut Vec<u8>,
    ) -> HandleResult<'a> {
        let mac = identity.map(|i| i.mac);
        if !self.check_server_id(msg) {
            return HandleResult::Ignore;
        }

        let mut reply = self.base_reply(msg, MessageType::Reply, &client_duid);

        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA) {
            let requested_ip = iana.opts.get(OptionCode::IAAddr).and_then(|opt| {
                if let DhcpOption::IAAddr(ia_addr) = opt {
                    Some(ia_addr.addr)
                } else {
                    None
                }
            });

            // RFC 8415 §18.2.1: Se o endereço requisitado não estiver on-link, responder com NotOnLink.
            if let Some(ip) = requested_ip
                && !self.pool.is_on_link(&ip)
            {
                return self.send_ia_status(
                    StatusContext {
                        msg,
                        client_duid: &client_duid,
                        peer,
                        mac,
                    },
                    Status::NotOnLink,
                    "Requested address is not on-link",
                    iana.id,
                    false,
                    buf,
                );
            }

            if let Some(ip) = self
                .pool
                .allocate(&client_duid.bytes, iana.id, mac, requested_ip)
            {
                if let Some(id) = identity {
                    info!("DHCPv6: Assigning {ip} to {id}");
                } else {
                    info!("DHCPv6: Assigning {ip} to anonymous device");
                }
                let (pref, valid) = self.get_lifetimes();
                let mut ia_opts = DhcpOptions::new();
                ia_opts.insert(DhcpOption::IAAddr(IAAddr {
                    addr: ip,
                    preferred_life: pref,
                    valid_life: valid,
                    opts: DhcpOptions::new(),
                }));
                reply.opts_mut().insert(DhcpOption::IANA(IANA {
                    id: iana.id,
                    t1: pref / 2,
                    t2: pref * 4 / 5,
                    opts: ia_opts,
                }));
            }
        }

        if let Some(DhcpOption::IAPD(iapd)) = msg.opts().get(OptionCode::IAPD)
            && let Some((prefix, len)) =
                self.pool.allocate_prefix(&client_duid.bytes, iapd.id, None)
        {
            let (pref, valid) = self.get_lifetimes();
            let mut ia_opts = DhcpOptions::new();
            ia_opts.insert(DhcpOption::IAPrefix(IAPrefix {
                prefix_ip: prefix,
                prefix_len: len,
                preferred_lifetime: pref,
                valid_lifetime: valid,
                opts: DhcpOptions::new(),
            }));
            reply.opts_mut().insert(DhcpOption::IAPD(IAPD {
                id: iapd.id,
                t1: pref / 2,
                t2: pref * 4 / 5,
                opts: ia_opts,
            }));
        }

        Self::add_dns_options(&mut reply);
        let mut ias = AssignedIAs::default();
        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA) {
            ias.na.push(iana.id);
        }
        if let Some(DhcpOption::IAPD(iapd)) = msg.opts().get(OptionCode::IAPD) {
            ias.pd.push(iapd.id);
        }

        HandleResult::Reply(encode_msg(&reply, buf), peer, Some(client_duid), mac, ias)
    }

    fn handle_renew<'a>(
        &mut self,
        msg: &Message,
        client_duid: Duid,
        identity: Option<&DeviceIdentity>,
        peer: Ipv6Addr,
        buf: &'a mut Vec<u8>,
    ) -> HandleResult<'a> {
        let mac = identity.map(|i| i.mac);
        if !self.check_server_id(msg) {
            return HandleResult::Ignore;
        }

        // RFC 8415 §18.2.3: Se o servidor não encontrar binding para o IA_NA/IA_PD,
        // deve responder com Reply contendo Status NoBinding.
        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA)
            && !self.pool.has_binding(&client_duid.bytes, iana.id)
        {
            return self.send_ia_status(
                StatusContext {
                    msg,
                    client_duid: &client_duid,
                    peer,
                    mac,
                },
                Status::NoBinding,
                "No binding found for this IA_NA",
                iana.id,
                false,
                buf,
            );
        }

        if let Some(DhcpOption::IAPD(iapd)) = msg.opts().get(OptionCode::IAPD)
            && !self.pool.has_prefix_binding(&client_duid.bytes, iapd.id)
        {
            return self.send_ia_status(
                StatusContext {
                    msg,
                    client_duid: &client_duid,
                    peer,
                    mac,
                },
                Status::NoBinding,
                "No binding found for this IA_PD",
                iapd.id,
                true,
                buf,
            );
        }

        self.handle_request(msg, client_duid, identity, peer, buf)
    }

    fn handle_rebind<'a>(
        &mut self,
        msg: &Message,
        client_duid: Duid,
        identity: Option<&DeviceIdentity>,
        peer: Ipv6Addr,
        buf: &'a mut Vec<u8>,
    ) -> HandleResult<'a> {
        // Rebind não tem ServerId (broadcast).
        // Mesma lógica de NoBinding do Renew (§18.2.4).
        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA)
            && !self.pool.has_binding(&client_duid.bytes, iana.id)
        {
            // No Rebind, se não temos binding, ignoramos ou respondemos NoBinding?
            // RFC 8415 §18.2.4 diz que o servidor deve responder se tiver binding.
            // Mas se não tivermos, geralmente ficamos quietos para permitir que outro servidor responda,
            // EXCEÇÃO: se soubermos com certeza que o IP não é on-link.
            return HandleResult::Ignore;
        }
        self.handle_request(msg, client_duid, identity, peer, buf)
    }

    fn handle_release<'a>(
        &mut self,
        msg: &Message,
        client_duid: &Duid,
        identity: Option<&DeviceIdentity>,
        peer: Ipv6Addr,
        buf: &'a mut Vec<u8>,
    ) -> HandleResult<'a> {
        if !self.check_server_id(msg) {
            return HandleResult::Ignore;
        }

        let mac = identity.map(|i| i.mac);

        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA)
            && let Some(DhcpOption::IAAddr(ia_addr)) = iana.opts.get(OptionCode::IAAddr)
        {
            if let Some(id) = identity {
                info!("DHCPv6: {id} released its address {}", ia_addr.addr);
            } else {
                info!(
                    "DHCPv6: Anonymous device released its address {}",
                    ia_addr.addr
                );
            }
            self.pool.release(&ia_addr.addr);
        }

        self.send_status(
            StatusContext {
                msg,
                client_duid,
                peer,
                mac,
            },
            MessageType::Reply,
            Status::Success,
            "Released",
            buf,
        )
    }

    fn handle_decline<'a>(
        &mut self,
        msg: &Message,
        client_duid: Duid,
        identity: Option<&DeviceIdentity>,
        peer: Ipv6Addr,
        buf: &'a mut Vec<u8>,
    ) -> HandleResult<'a> {
        if !self.check_server_id(msg) {
            return HandleResult::Ignore;
        }

        let mac = identity.map(|i| i.mac);
        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA) {
            for opt in iana.opts.iter() {
                if let DhcpOption::IAAddr(ia_addr) = opt {
                    if let Some(id) = identity {
                        info!(
                            "DHCPv6: {id} declined address {} (DAD Failure)",
                            ia_addr.addr
                        );
                    } else {
                        info!(
                            "DHCPv6: Anonymous device declined address {} (DAD Failure)",
                            ia_addr.addr
                        );
                    }
                    self.pool.decline(ia_addr.addr);
                }
            }
        }

        self.send_status(
            StatusContext {
                msg,
                client_duid: &client_duid,
                peer,
                mac,
            },
            MessageType::Reply,
            Status::Success,
            "Decline acknowledged",
            buf,
        )
    }

    fn handle_information_request<'a>(
        &self,
        msg: &Message,
        client_duid: &Duid,
        peer: Ipv6Addr,
        buf: &'a mut Vec<u8>,
    ) -> HandleResult<'a> {
        let mut reply = self.base_reply(msg, MessageType::Reply, client_duid);
        Self::add_dns_options(&mut reply);
        HandleResult::Reply(
            encode_msg(&reply, buf),
            peer,
            None,
            None,
            AssignedIAs::default(),
        )
    }

    fn base_reply(&self, msg: &Message, msg_type: MessageType, client_duid: &Duid) -> Message {
        let mut reply = Message::new(msg_type);
        reply.set_xid(msg.xid());

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

    fn send_status<'a>(
        &self,
        ctx: StatusContext<'_>,
        msg_type: MessageType,
        status: Status,
        text: &str,
        buf: &'a mut Vec<u8>,
    ) -> HandleResult<'a> {
        let mut reply = self.base_reply(ctx.msg, msg_type, ctx.client_duid);
        reply.opts_mut().insert(DhcpOption::StatusCode(StatusCode {
            status,
            msg: text.to_string(),
        }));
        HandleResult::Reply(
            encode_msg(&reply, buf),
            ctx.peer,
            Some(ctx.client_duid.clone()),
            ctx.mac,
            AssignedIAs::default(),
        )
    }

    fn send_ia_status<'a>(
        &self,
        ctx: StatusContext<'_>,
        status: Status,
        text: &str,
        iaid: u32,
        is_pd: bool,
        buf: &'a mut Vec<u8>,
    ) -> HandleResult<'a> {
        let mut reply = self.base_reply(ctx.msg, MessageType::Reply, ctx.client_duid);
        let mut opts = DhcpOptions::new();
        opts.insert(DhcpOption::StatusCode(StatusCode {
            status,
            msg: text.to_string(),
        }));

        if is_pd {
            reply.opts_mut().insert(DhcpOption::IAPD(IAPD {
                id: iaid,
                t1: 0,
                t2: 0,
                opts,
            }));
        } else {
            reply.opts_mut().insert(DhcpOption::IANA(IANA {
                id: iaid,
                t1: 0,
                t2: 0,
                opts,
            }));
        }

        let mut ias = AssignedIAs::default();
        if is_pd {
            ias.pd.push(iaid);
        } else {
            ias.na.push(iaid);
        }

        HandleResult::Reply(
            encode_msg(&reply, buf),
            ctx.peer,
            Some(ctx.client_duid.clone()),
            ctx.mac,
            ias,
        )
    }

    const fn add_dns_options(_reply: &mut Message) {
        // Tipicamente via RDNSS no RA. Se config fornecer DNS, adicionar aqui.
    }

    pub fn last_assignment_for(&self, duid: &[u8], iaid: u32) -> Option<Ipv6Addr> {
        self.pool.lookup(duid, iaid)
    }

    fn get_vendor_class(msg: &Message) -> Option<String> {
        match msg.opts().get(OptionCode::VendorClass) {
            Some(DhcpOption::VendorClass(v)) => {
                let strings: Vec<String> = v
                    .data
                    .iter()
                    .filter_map(|b| String::from_utf8(b.clone()).ok())
                    .collect();
                if strings.is_empty() {
                    None
                } else {
                    Some(strings.join(" "))
                }
            }
            _ => None,
        }
    }
}

fn encode_msg<'a>(msg: &Message, buf: &'a mut Vec<u8>) -> &'a [u8] {
    buf.clear();
    let mut enc = Encoder::new(buf);
    msg.encode(&mut enc)
        .expect("Encoding DHCPv6 message should not fail");
    buf.as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v6::{DhcpOptions, IANA, OptionCode};
    use std::net::Ipv6Addr;

    fn dummy_server() -> Dhcpv6Server {
        let cfg = Dhcpv6Config {
            enabled: true,
            iface: "lo".to_string(),
            lease_time: 86400,
            ula_prefix: Some("fd97:f00d:cafe:3731::".parse().unwrap()),
            ula_prefix_len: 64,
            range_start: Some("fd97:f00d:cafe:3731::100".parse().unwrap()),
            range_end: Some("fd97:f00d:cafe:3731::200".parse().unwrap()),
        };
        let pool = Ipv6Pool::new(cfg.range_start, cfg.range_end, cfg.ula_prefix, 64);
        let server_duid = Duid::new(vec![
            0x00, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        let sock = std::net::UdpSocket::bind("::0:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let ndp_poke_sock = Arc::new(tokio::net::UdpSocket::from_std(sock).unwrap());

        Dhcpv6Server::new(cfg, pool, server_duid, ndp_poke_sock)
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

    #[tokio::test]
    async fn solicit_yields_no_addrs_avail_when_pool_empty() {
        let cfg = Dhcpv6Config {
            enabled: true,
            iface: "lo".to_string(),
            lease_time: 86400,
            ula_prefix: None,
            ula_prefix_len: 64,
            range_start: None,
            range_end: None,
        };
        let pool = Ipv6Pool::new(None, None, None, 64);
        let sock = std::net::UdpSocket::bind("::0:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let ndp_poke_sock = Arc::new(tokio::net::UdpSocket::from_std(sock).unwrap());
        let mut srv = Dhcpv6Server::new(cfg, pool, dummy_client_duid(), ndp_poke_sock);

        let msg = build_solicit(true);
        let mut resp_vec = Vec::with_capacity(1024);
        let identity = DeviceIdentity::new(dummy_mac(), None, None);
        let res = srv.handle_solicit(
            &msg,
            dummy_client_duid(),
            Some(&identity),
            peer_ip(),
            &mut resp_vec,
        );

        match res {
            HandleResult::Reply(bytes, _, _, _, _) => {
                let reply = decode_reply(bytes);
                if let Some(DhcpOption::IANA(iana)) = reply.opts().get(OptionCode::IANA) {
                    if let Some(DhcpOption::StatusCode(status)) =
                        iana.opts.get(OptionCode::StatusCode)
                    {
                        assert_eq!(status.status, Status::NoAddrsAvail);
                    } else {
                        panic!("Missing StatusCode in IANA");
                    }
                } else {
                    panic!("Missing IANA in Reply");
                }
            }
            _ => panic!("Expected Reply"),
        }
    }

    #[tokio::test]
    async fn request_not_on_link_yields_status_code() {
        let mut srv = dummy_server();
        let mut msg = Message::new(MessageType::Request);
        msg.opts_mut()
            .insert(DhcpOption::ServerId(srv.server_duid.bytes.clone()));

        let wrong_ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut ia_opts = DhcpOptions::new();
        ia_opts.insert(DhcpOption::IAAddr(IAAddr {
            addr: wrong_ip,
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

        let mut resp_vec = Vec::with_capacity(1024);
        let identity = DeviceIdentity::new(dummy_mac(), None, None);
        let res = srv.handle_request(
            &msg,
            dummy_client_duid(),
            Some(&identity),
            peer_ip(),
            &mut resp_vec,
        );

        match res {
            HandleResult::Reply(bytes, _, _, _, _) => {
                let reply = decode_reply(bytes);
                if let Some(DhcpOption::IANA(iana)) = reply.opts().get(OptionCode::IANA) {
                    if let Some(DhcpOption::StatusCode(status)) =
                        iana.opts.get(OptionCode::StatusCode)
                    {
                        assert_eq!(status.status, Status::NotOnLink);
                    } else {
                        panic!("Missing StatusCode in IANA");
                    }
                } else {
                    panic!("Missing IANA in Reply");
                }
            }
            _ => panic!("Expected Reply with NotOnLink"),
        }
    }

    #[tokio::test]
    async fn renew_no_binding_yields_status_code() {
        let mut srv = dummy_server();
        let mut msg = Message::new(MessageType::Renew);
        msg.opts_mut()
            .insert(DhcpOption::ServerId(srv.server_duid.bytes.clone()));
        msg.opts_mut().insert(DhcpOption::IANA(IANA {
            id: 9991,
            t1: 0,
            t2: 0,
            opts: DhcpOptions::new(),
        }));

        let mut resp_vec = Vec::with_capacity(1024);
        let identity = DeviceIdentity::new(dummy_mac(), None, None);
        let res = srv.handle_renew(
            &msg,
            dummy_client_duid(),
            Some(&identity),
            peer_ip(),
            &mut resp_vec,
        );

        match res {
            HandleResult::Reply(bytes, _, _, _, _) => {
                let reply = decode_reply(bytes);
                if let Some(DhcpOption::IANA(iana)) = reply.opts().get(OptionCode::IANA) {
                    if let Some(DhcpOption::StatusCode(status)) =
                        iana.opts.get(OptionCode::StatusCode)
                    {
                        assert_eq!(status.status, Status::NoBinding);
                    } else {
                        panic!("Missing StatusCode in IANA");
                    }
                } else {
                    panic!("Missing IANA in Reply");
                }
            }
            _ => panic!("Expected Reply with NoBinding"),
        }
    }

    #[tokio::test]
    async fn decline_acknowledgment_and_blacklisting() {
        let mut srv = dummy_server();
        let ip: Ipv6Addr = "fd97:f00d:cafe:3731::101".parse().unwrap();
        let duid = dummy_client_duid();
        let mac = dummy_mac();

        // Simula que o IP foi alocado
        srv.pool.allocate(&duid.bytes, 1, Some(mac), Some(ip));

        let mut msg = Message::new(MessageType::Decline);
        msg.opts_mut()
            .insert(DhcpOption::ServerId(srv.server_duid.bytes.clone()));
        let mut ia_opts = DhcpOptions::new();
        ia_opts.insert(DhcpOption::IAAddr(IAAddr {
            addr: ip,
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

        let mut resp_vec = Vec::with_capacity(1024);
        let identity = DeviceIdentity::new(mac, None, None);
        let res = srv.handle_decline(
            &msg,
            duid.clone(),
            Some(&identity),
            peer_ip(),
            &mut resp_vec,
        );

        match res {
            HandleResult::Reply(bytes, _, _, _, _) => {
                let reply = decode_reply(bytes);
                assert_eq!(reply.msg_type(), MessageType::Reply);
                assert!(reply.opts().get(OptionCode::StatusCode).is_some());
            }
            _ => panic!("Expected Decline acknowledgment"),
        }

        // Verifica que o IP está em blacklist (tentando alocar exatamente ele)
        let ip2 = srv
            .pool
            .allocate(&dummy_client_duid().bytes, 2, Some(mac), Some(ip));
        assert!(ip2.is_none() || ip2.unwrap() != ip);
    }

    #[tokio::test]
    async fn lifetime_capping_respects_wan_prefix() {
        let mut srv = dummy_server();
        // Configura vida útil do WAN prefix para 3600 segundos
        srv.prefix_lifetimes = Some((1800, 3600));

        let msg = build_solicit(true);
        let mut resp_vec = Vec::with_capacity(1024);
        let identity = DeviceIdentity::new(dummy_mac(), None, None);
        let res = srv.handle_solicit(
            &msg,
            dummy_client_duid(),
            Some(&identity),
            peer_ip(),
            &mut resp_vec,
        );

        match res {
            HandleResult::Reply(bytes, _, _, _, _) => {
                let reply = decode_reply(bytes);
                if let Some(DhcpOption::IANA(iana)) = reply.opts().get(OptionCode::IANA)
                    && let Some(DhcpOption::IAAddr(ia_addr)) = iana.opts.get(OptionCode::IAAddr)
                {
                    assert_eq!(ia_addr.preferred_life, 1800);
                    assert_eq!(ia_addr.valid_life, 3600);
                }
            }
            _ => panic!("Expected Reply"),
        }
    }

    #[tokio::test]
    async fn information_request_yields_reply_without_ia_na() {
        let srv = dummy_server();
        let msg = Message::new(MessageType::InformationRequest);
        let mut resp_vec = Vec::with_capacity(1024);
        let res =
            srv.handle_information_request(&msg, &dummy_client_duid(), peer_ip(), &mut resp_vec);

        match res {
            HandleResult::Reply(bytes, _, _, _, _) => {
                let reply = decode_reply(bytes);
                assert_eq!(reply.msg_type(), MessageType::Reply);
                assert!(reply.opts().get(OptionCode::IANA).is_none());
            }
            HandleResult::Ignore => panic!("Expected Reply"),
        }
    }

    #[tokio::test]
    async fn solicit_with_iapd_yields_prefix_delegation() {
        let cfg = Dhcpv6Config {
            enabled: true,
            iface: "lo".to_string(),
            lease_time: 86400,
            ula_prefix: Some("fd97:f00d:cafe::".parse().unwrap()),
            ula_prefix_len: 48,
            range_start: None,
            range_end: None,
        };
        let pool = Ipv6Pool::new(None, None, cfg.ula_prefix, 48);
        let sock = std::net::UdpSocket::bind("::0:0").unwrap();
        sock.set_nonblocking(true).unwrap();
        let ndp_poke_sock = Arc::new(tokio::net::UdpSocket::from_std(sock).unwrap());
        let mut srv = Dhcpv6Server::new(cfg, pool, dummy_client_duid(), ndp_poke_sock);

        let mut msg = Message::new(MessageType::Solicit);
        msg.opts_mut().insert(DhcpOption::IAPD(IAPD {
            id: 888,
            t1: 0,
            t2: 0,
            opts: DhcpOptions::new(),
        }));

        let mut resp_vec = Vec::with_capacity(1024);
        let identity = DeviceIdentity::new(dummy_mac(), None, None);
        let res = srv.handle_solicit(
            &msg,
            dummy_client_duid(),
            Some(&identity),
            peer_ip(),
            &mut resp_vec,
        );

        match res {
            HandleResult::Reply(bytes, _, _, _, _) => {
                let reply = decode_reply(bytes);
                if let Some(DhcpOption::IAPD(iapd)) = reply.opts().get(OptionCode::IAPD) {
                    assert_eq!(iapd.id, 888);
                    if let Some(DhcpOption::IAPrefix(pref)) = iapd.opts.get(OptionCode::IAPrefix) {
                        assert_eq!(pref.prefix_len, 64);
                        assert!(!pref.prefix_ip.is_unspecified());
                    } else {
                        panic!("Missing IAPrefix in IAPD reply");
                    }
                } else {
                    panic!("Missing IAPD in reply");
                }
            }
            _ => panic!("Expected Reply with IA_PD"),
        }
    }
}
