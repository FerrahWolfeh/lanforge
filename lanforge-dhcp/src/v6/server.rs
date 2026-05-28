//! `DHCPv6` `SARR` state machine (`RFC 8415`).
//!
//! Implements the full `DHCPv6` address and prefix delegation lifecycle:
//! `Solicit`→`Advertise`→`Request`→`Reply`, plus `Renew`, `Rebind`, `Release`, `Decline`,
//! and `Information-Request` handling.
//!
//! ## `SARR` State Machine
//!
//! ```mermaid
//! stateDiagram-v2
//!     [*] --> Idle
//!     Idle --> Solicit: Client multicast
//!     Solicit --> Advertise: Pool allocate IA_NA/IA_PD
//!     Advertise --> Request: Client selects
//!     Request --> Reply: Lease confirmed
//!     Reply --> Idle: Lease active
//!     Idle --> Renew: Client extends lease
//!     Renew --> Reply: Lifetime updated
//!     Idle --> Rebind: Client rebinds
//!     Rebind --> Reply
//!     Idle --> Release: Client releases
//!     Release --> Reply: Pool freed
//!     Idle --> Decline: Client declines
//!     Decline --> Reply: Status Code Decline
//!     Idle --> InfoReq: Options only
//!     InfoReq --> Reply: DNS/search domain
//! ```
//!
//! ## Decision Table
//!
//! | Message | Action | Response |
//! | :--- | :--- | :--- |
//! | Solicit | Allocate IA_NA/IA_PD from pool | Advertise (rapid commit) or Reply |
//! | Request | Confirm lease assignment | Reply |
//! | Renew | Extend lease lifetimes | Reply |
//! | Rebind | Rebind to any available server | Reply |
//! | Release | Free IA_NA/IA_PD | Reply |
//! | Decline | Mark address as conflicted | Reply |
//! | Information-Request | Provide DNS/search options | Reply |

use dhcproto::v6::{
    DhcpOption, DhcpOptions, IAAddr, IANA, IAPD, IAPrefix, Message, MessageType, OptionCode,
    Status, StatusCode, UnknownOption,
};
use dhcproto::{Encodable, Encoder, Name};
use lanforge_core::context::LanforgeContext;
use lanforge_core::utils::mac_from_eui64_link_local;
use lanforge_types::identifiers::{Duid, MacAddr};
use std::net::{Ipv6Addr, UdpSocket};
use std::str::FromStr;
use std::string::ToString;
use std::sync::atomic::Ordering;
use tracing::{debug, info};

use super::config::Dhcpv6Config;
use super::pool::Ipv6Pool;
use crate::identity::DeviceIdentity;
use crate::options::parse_typed_option;
use std::sync::Arc;

use crate::traits::DhcpPool;
use lanforge_types::dhcp::Dhcpv6Stats;

/// `IA_NA` and `IA_PD` identifiers assigned in a `DHCPv6` response.
///
/// Collected by the service wrapper to emit `DeviceUpdate` events.
#[derive(Default, Clone, Debug)]
pub struct AssignedIAs {
    /// `IA_NA` (Identity Association — Non-temporary Address) identifiers.
    pub na: Vec<u32>,
    /// `IA_PD` (Identity Association — Prefix Delegation) identifiers.
    pub pd: Vec<u32>,
}

/// Outcome of processing a `DHCPv6` message.
pub enum HandleResult<'a> {
    /// A reply packet is ready (encoded bytes, destination IP, learned DUID, MAC, assigned IAIDs, released IAIDs).
    Reply(
        &'a [u8],
        Ipv6Addr,
        Option<Duid>,
        Option<MacAddr>,
        AssignedIAs,
        AssignedIAs,
    ),
    /// No response necessary — message was malformed or directed to another server.
    Ignore,
}

/// Context for sending status codes to clients.
struct StatusContext<'a> {
    msg: &'a Message,
    client_duid: &'a Duid,
    peer: Ipv6Addr,
    mac: Option<MacAddr>,
}

/// Stateful `DHCPv6` server with multi-prefix address allocation.
///
/// Manages the full `SARR` lifecycle for `IA_NA` and `IA_PD` on a single interface.
/// Uses `DUIDs` (not `MACs`) as primary client identifiers per `RFC 8415`.
pub struct Dhcpv6Server {
    /// Server configuration (interface, lease time, pools, DNS).
    pub cfg: Dhcpv6Config,
    /// Multi-prefix IPv6 pool (`ULA` + `GUA`).
    pub pool: Ipv6Pool,
    /// DUID (DHCP Unique Identifier) of this server.
    pub server_duid: Duid,
    /// Learned lifetimes from the `GUA` prefix (`preferred`, `valid`) via `RA`.
    pub prefix_lifetimes: Option<(u32, u32)>,
    /// Persistent socket for `NDP` probes (avoids repeated `socket()` syscalls).
    pub ndp_poke_sock: Arc<UdpSocket>,
    /// Global context for device lookups and state updates.
    pub ctx: LanforgeContext,
    /// Shared `DHCPv6` statistics.
    pub stats: Arc<Dhcpv6Stats>,
}

impl Dhcpv6Server {
    #[must_use]
    pub const fn new(
        cfg: Dhcpv6Config,
        pool: Ipv6Pool,
        server_duid: Duid,
        ndp_poke_sock: Arc<UdpSocket>,
        ctx: LanforgeContext,
        stats: Arc<Dhcpv6Stats>,
    ) -> Self {
        Self {
            cfg,
            pool,
            server_duid,
            prefix_lifetimes: None,
            ndp_poke_sock,
            ctx,
            stats,
        }
    }

    const fn get_lifetimes(&self) -> (u32, u32) {
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

    /// Processes a decoded `DHCPv6` message and returns a response (if any).
    pub fn handle_packet<'a>(
        &mut self,
        msg: &Message,
        peer: Ipv6Addr,
        resolved_mac: Option<MacAddr>,
        buf: &'a mut Vec<u8>,
    ) -> HandleResult<'a> {
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

        // Try to extract MAC address in increasing order of cost
        let mut mac = resolved_mac
            .or_else(|| client_duid.extract_mac())
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
            .or_else(|| mac_from_eui64_link_local(&peer));

        // 1. Try to recover MAC from NDP cache or DUID index
        if mac.is_none() {
            mac = self.ctx.get_mac_by_ip(peer.into());
        }
        if mac.is_none() {
            mac = self.ctx.get_mac_by_duid(&client_duid);
        }

        // 2. Resolve identity
        let identity = mac.map(|m| {
            DeviceIdentity::resolve(
                m,
                None,
                Self::get_vendor_class(msg),
                self.ctx.get_device(&m),
            )
        });

        if mac.is_none() && msg.msg_type() != MessageType::InformationRequest {
            info!(
                "DHCPv6 from {peer}: MAC addr not resolved (DUID: {client_duid}). Proceeding anonymously...",
            );
        }

        match msg.msg_type() {
            MessageType::Solicit => {
                self.stats.solicits.fetch_add(1, Ordering::Relaxed);
                self.handle_solicit(msg, &client_duid, identity.as_ref(), peer, buf)
            }
            MessageType::Request => {
                self.stats.requests.fetch_add(1, Ordering::Relaxed);
                self.handle_request(msg, client_duid, identity.as_ref(), peer, buf)
            }
            MessageType::Renew => {
                self.stats.renews.fetch_add(1, Ordering::Relaxed);
                self.handle_renew(msg, client_duid, identity.as_ref(), peer, buf)
            }
            MessageType::Rebind => {
                self.stats.rebinds.fetch_add(1, Ordering::Relaxed);
                self.handle_rebind(msg, client_duid, identity.as_ref(), peer, buf)
            }
            MessageType::Release => {
                self.stats.releases.fetch_add(1, Ordering::Relaxed);
                self.handle_release(msg, &client_duid, identity.as_ref(), peer, buf)
            }
            MessageType::Decline => {
                self.stats.declines.fetch_add(1, Ordering::Relaxed);
                self.handle_decline(msg, &client_duid, identity.as_ref(), peer, buf)
            }
            MessageType::InformationRequest => {
                self.stats.info_requests.fetch_add(1, Ordering::Relaxed);
                self.handle_information_request(msg, &client_duid, peer, buf)
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
        client_duid: &Duid,
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

        let mut reply = self.base_reply(msg, reply_type, client_duid);
        let mut learned_duid = None;

        reply.opts_mut().insert(DhcpOption::Preference(255));
        if is_rapid_commit {
            reply.opts_mut().insert(DhcpOption::RapidCommit);
        }

        // 1. Process IA_NA (Address Allocation)
        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA)
            && let Some(duid) =
                self.process_iana_solicit(&mut reply, iana, client_duid, identity, is_rapid_commit)
        {
            learned_duid = Some(duid);
        }

        // 2. Process IA_PD (Prefix Delegation)
        if let Some(DhcpOption::IAPD(iapd)) = msg.opts().get(OptionCode::IAPD)
            && let Some(duid) = self.process_iapd_solicit(&mut reply, iapd, client_duid, identity)
        {
            learned_duid = Some(duid);
        }

        self.add_dns_options(&mut reply);
        self.add_boot_options(&mut reply, identity);
        self.add_custom_options(&mut reply);
        let mut ias = AssignedIAs::default();
        if let Some(DhcpOption::StatusCode(_)) = msg.opts().get(OptionCode::StatusCode) {
            // keep standard behavior
        }
        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA) {
            ias.na.push(iana.id);
        }
        if let Some(DhcpOption::IAPD(iapd)) = msg.opts().get(OptionCode::IAPD) {
            ias.pd.push(iapd.id);
        }

        HandleResult::Reply(
            encode_msg(&reply, buf),
            peer,
            learned_duid,
            mac,
            ias,
            AssignedIAs::default(),
        )
    }

    fn process_iana_solicit(
        &mut self,
        reply: &mut Message,
        iana: &IANA,
        client_duid: &Duid,
        identity: Option<&DeviceIdentity>,
        is_rapid_commit: bool,
    ) -> Option<Duid> {
        let mac = identity.map(|i| i.mac);
        let requested_ip = iana.opts.get(OptionCode::IAAddr).and_then(|opt| {
            if let DhcpOption::IAAddr(ia_addr) = opt {
                Some(ia_addr.addr)
            } else {
                None
            }
        });

        let ips = self
            .pool
            .allocate(&self.ctx, client_duid, iana.id, mac, requested_ip);

        if ips.is_empty() {
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
            return None;
        }

        let (pref, valid) = self.get_lifetimes();
        let action = if is_rapid_commit {
            "REPLY (RC)"
        } else {
            "ADVERTISE"
        };
        let mut ia_opts = DhcpOptions::new();
        let ip_list: Vec<String> = ips.iter().map(ToString::to_string).collect();

        if let Some(id) = identity {
            info!(
                "DHCPv6: {id} is soliciting -> {action} [{}]",
                ip_list.join(", ")
            );
        } else {
            info!(
                "DHCPv6: Anonymous soliciting -> {action} [{}]",
                ip_list.join(", ")
            );
        }

        for ip in &ips {
            ia_opts.insert(DhcpOption::IAAddr(IAAddr {
                addr: *ip,
                preferred_life: pref,
                valid_life: valid,
                opts: DhcpOptions::new(),
            }));
        }

        reply.opts_mut().insert(DhcpOption::IANA(IANA {
            id: iana.id,
            t1: pref / 2,
            t2: pref * 4 / 5,
            opts: ia_opts,
        }));
        Some(client_duid.clone())
    }

    fn process_iapd_solicit(
        &mut self,
        reply: &mut Message,
        iapd: &IAPD,
        client_duid: &Duid,
        identity: Option<&DeviceIdentity>,
    ) -> Option<Duid> {
        if let Some((prefix, len)) =
            self.pool
                .allocate_prefix(&self.ctx, client_duid, iapd.id, None)
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
            Some(client_duid.clone())
        } else {
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
            None
        }
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

            // RFC 8415 §18.2.1: If the requested address is not on-link, respond with NotOnLink.
            if let Some(ip) = requested_ip
                && !self.pool.is_on_link(&ip)
            {
                return self.send_ia_status(
                    &StatusContext {
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

            let ips = self
                .pool
                .allocate(&self.ctx, &client_duid, iana.id, mac, requested_ip);

            if !ips.is_empty() {
                let (pref, valid) = self.get_lifetimes();
                let mut ia_opts = DhcpOptions::new();
                let ip_list: Vec<String> = ips.iter().map(ToString::to_string).collect();

                if let Some(id) = identity {
                    info!("DHCPv6: Assigning [{}] to {id}", ip_list.join(", "));
                } else {
                    info!(
                        "DHCPv6: Assigning [{}] to anonymous device",
                        ip_list.join(", ")
                    );
                }

                for ip in &ips {
                    ia_opts.insert(DhcpOption::IAAddr(IAAddr {
                        addr: *ip,
                        preferred_life: pref,
                        valid_life: valid,
                        opts: DhcpOptions::new(),
                    }));
                }
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
                self.pool
                    .allocate_prefix(&self.ctx, &client_duid, iapd.id, None)
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

        self.add_dns_options(&mut reply);
        self.add_boot_options(&mut reply, identity);
        let mut ias = AssignedIAs::default();
        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA) {
            ias.na.push(iana.id);
        }
        if let Some(DhcpOption::IAPD(iapd)) = msg.opts().get(OptionCode::IAPD) {
            ias.pd.push(iapd.id);
        }

        HandleResult::Reply(
            encode_msg(&reply, buf),
            peer,
            Some(client_duid),
            mac,
            ias,
            AssignedIAs::default(),
        )
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

        // RFC 8415 §18.2.3: If the server cannot find a binding for IA_NA/IA_PD,
        // it must respond with a Reply containing a NoBinding status.
        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA)
            && !self.pool.has_binding(&self.ctx, &client_duid, iana.id)
        {
            return self.send_ia_status(
                &StatusContext {
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
            && !self
                .pool
                .has_prefix_binding(&self.ctx, &client_duid, iapd.id)
        {
            return self.send_ia_status(
                &StatusContext {
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
        // Rebind does not have a ServerId (multicast).
        // Same NoBinding logic as Renew (§18.2.4).
        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA)
            && !self.pool.has_binding(&self.ctx, &client_duid, iana.id)
        {
            // In Rebind, if we don't have a binding, do we ignore or respond NoBinding?
            // RFC 8415 §18.2.4 says the server must respond if it has a binding.
            // If we don't, we usually stay quiet to allow another server to respond.
            // EXCEPTION: If we know for sure the IP is not on-link.
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
        let mut released_ias = AssignedIAs::default();

        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA)
            && let Some(DhcpOption::IAAddr(ia_addr)) = iana.opts.get(OptionCode::IAAddr)
        {
            // Validate client lease ownership
            if self.pool.has_binding(&self.ctx, client_duid, iana.id) {
                let bindings = self.pool.lookup(&self.ctx, client_duid, iana.id);
                if bindings.contains(&ia_addr.addr) {
                    if let Some(id) = identity {
                        info!("DHCPv6: {id} released its address {}", ia_addr.addr);
                    } else {
                        info!(
                            "DHCPv6: Anonymous device released its address {}",
                            ia_addr.addr
                        );
                    }
                    self.pool.release(&ia_addr.addr);
                    released_ias.na.push(iana.id);
                } else {
                    tracing::warn!(
                        "DHCPv6: RELEASE from {} for {} ignored: client does not own this lease.",
                        client_duid,
                        ia_addr.addr
                    );
                }
            } else {
                tracing::warn!(
                    "DHCPv6: RELEASE from {} for {} ignored: no binding found for IAID {}.",
                    client_duid,
                    ia_addr.addr,
                    iana.id
                );
            }
        }

        if let Some(DhcpOption::IAPD(iapd)) = msg.opts().get(OptionCode::IAPD) {
            // Validate client prefix lease ownership
            if self
                .pool
                .has_prefix_binding(&self.ctx, client_duid, iapd.id)
            {
                if let Some(id) = identity {
                    info!(
                        "DHCPv6: {id} released prefix delegation for IAID {}",
                        iapd.id
                    );
                } else {
                    info!(
                        "DHCPv6: Anonymous device released prefix delegation for IAID {}",
                        iapd.id
                    );
                }
                released_ias.pd.push(iapd.id);
            } else {
                tracing::warn!(
                    "DHCPv6: RELEASE prefix delegation from {} for IAID {} ignored: no binding found.",
                    client_duid,
                    iapd.id
                );
            }
        }

        self.send_status_with_releases(
            &StatusContext {
                msg,
                client_duid,
                peer,
                mac,
            },
            MessageType::Reply,
            Status::Success,
            "Released",
            released_ias,
            buf,
        )
    }

    fn handle_decline<'a>(
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
        let mut released_ias = AssignedIAs::default();

        if let Some(DhcpOption::IANA(iana)) = msg.opts().get(OptionCode::IANA) {
            for opt in iana.opts.iter() {
                if let DhcpOption::IAAddr(ia_addr) = opt {
                    // Validate client lease ownership
                    if self.pool.has_binding(&self.ctx, client_duid, iana.id) {
                        let bindings = self.pool.lookup(&self.ctx, client_duid, iana.id);
                        if bindings.contains(&ia_addr.addr) {
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
                            if !released_ias.na.contains(&iana.id) {
                                released_ias.na.push(iana.id);
                            }
                        } else {
                            tracing::warn!(
                                "DHCPv6: DECLINE from {} for {} ignored: client does not own this lease.",
                                client_duid,
                                ia_addr.addr
                            );
                        }
                    } else {
                        tracing::warn!(
                            "DHCPv6: DECLINE from {} for {} ignored: no binding found for IAID {}.",
                            client_duid,
                            ia_addr.addr,
                            iana.id
                        );
                    }
                }
            }
        }

        self.send_status_with_releases(
            &StatusContext {
                msg,
                client_duid,
                peer,
                mac,
            },
            MessageType::Reply,
            Status::Success,
            "Decline acknowledged",
            released_ias,
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
        self.add_dns_options(&mut reply);
        self.add_boot_options(&mut reply, None);
        self.add_custom_options(&mut reply);
        HandleResult::Reply(
            encode_msg(&reply, buf),
            peer,
            None,
            None,
            AssignedIAs::default(),
            AssignedIAs::default(),
        )
    }

    fn base_reply(&self, msg: &Message, msg_type: MessageType, client_duid: &Duid) -> Message {
        match msg_type {
            MessageType::Reply => {
                self.stats.replies.fetch_add(1, Ordering::Relaxed);
            }
            MessageType::Advertise => {
                self.stats.advertises.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        let mut reply = Message::new(msg_type);
        reply.set_xid(msg.xid());

        if !client_duid.bytes.is_empty() {
            reply
                .opts_mut()
                .insert(DhcpOption::ClientId(client_duid.bytes.to_vec()));
        }

        reply
            .opts_mut()
            .insert(DhcpOption::ServerId(self.server_duid.bytes.to_vec()));

        reply
    }

    fn check_server_id(&self, msg: &Message) -> bool {
        // RFC 8415 §18.2.4: REBIND messages are multicast and do not include a Server Identifier.
        if msg.msg_type() == MessageType::Rebind {
            return true;
        }
        match msg.opts().get(OptionCode::ServerId) {
            Some(DhcpOption::ServerId(sid)) => sid.as_slice() == self.server_duid.bytes.as_ref(),
            _ => false,
        }
    }

    fn send_status_with_releases<'a>(
        &self,
        ctx: &StatusContext<'_>,
        msg_type: MessageType,
        status: Status,
        text: &str,
        released_ias: AssignedIAs,
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
            released_ias,
        )
    }

    fn send_ia_status<'a>(
        &self,
        ctx: &StatusContext<'_>,
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
            AssignedIAs::default(),
        )
    }

    fn add_dns_options(&self, reply: &mut Message) {
        if !self.cfg.dns_servers.is_empty() {
            reply
                .opts_mut()
                .insert(DhcpOption::DomainNameServers(self.cfg.dns_servers.clone()));
        }
        if !self.cfg.search_domains.is_empty() {
            let names: Vec<Name> = self
                .cfg
                .search_domains
                .iter()
                .filter_map(|d| Name::from_str(d).ok())
                .collect();
            reply.opts_mut().insert(DhcpOption::DomainSearchList(names));
        }
    }

    fn add_boot_options(&self, reply: &mut Message, identity: Option<&DeviceIdentity>) {
        let mac = identity.map(|i| i.mac);
        let dev = mac.and_then(|m| self.ctx.get_device(&m));
        let boot_file = dev
            .as_ref()
            .and_then(|d| d.boot_file.clone())
            .or_else(|| self.cfg.boot_file.clone());

        if let Some(file) = boot_file {
            let url = if file.starts_with("http://") || file.starts_with("https://") {
                file
            } else {
                // For DHCPv6 HTTP Boot, we construct a URL.
                let server_ip = self
                    .cfg
                    .ula_prefix
                    .unwrap_or(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
                format!("http://[{server_ip}]:8080/boot/{file}")
            };

            // Option 59 (Bootfile URL)
            reply
                .opts_mut()
                .insert(DhcpOption::Unknown(UnknownOption::new(
                    59.into(),
                    url.into_bytes(),
                )));
        }
    }

    fn add_custom_options(&self, reply: &mut Message) {
        for (code, val) in &self.cfg.options {
            // Protect critical protocol options from being overwritten
            if matches!(*code, 1 | 2 | 3 | 5 | 25) {
                tracing::warn!(
                    "DHCPv6: Custom option {} ignored: cannot overwrite critical protocol options.",
                    code
                );
                continue;
            }
            if let Some(data) = parse_typed_option(val) {
                reply
                    .opts_mut()
                    .insert(DhcpOption::Unknown(UnknownOption::new(
                        (*code).into(),
                        data,
                    )));
            }
        }
    }

    /// Returns the last assignment for a given DUID and IAID.
    #[must_use]
    pub fn last_assignment_for(&self, duid: &Duid, iaid: u32) -> Vec<Ipv6Addr> {
        self.pool.lookup(&self.ctx, duid, iaid)
    }

    /// Constructs a `RECONFIGURE` (RFC 3315/8415) message.
    ///
    /// This tells the client to initiate a `Renew` or `Information-Request`
    /// to synchronization its state with the server.
    #[must_use]
    pub fn build_reconfigure(&self, client_duid: &Duid, reconf_msg_type: MessageType) -> Vec<u8> {
        let mut msg = Message::new(MessageType::Reconfigure);
        msg.set_xid(rand::random::<[u8; 3]>());

        let opts = msg.opts_mut();
        opts.insert(DhcpOption::ClientId(client_duid.bytes.to_vec()));
        opts.insert(DhcpOption::ServerId(self.server_duid.bytes.to_vec()));
        opts.insert(DhcpOption::ReconfMsg(reconf_msg_type));

        let mut buf = Vec::with_capacity(512);
        let mut enc = Encoder::new(&mut buf);
        msg.encode(&mut enc)
            .expect("RECONFIGURE encoding should not fail");
        buf
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
    use crate::{test_utils::init_test_context, v6::config::Dhcpv6PoolConfig, v6::pool::PoolRange};
    use dhcproto::{
        Decodable, Decoder,
        v6::{DhcpOptions, IANA, OptionCode},
    };
    use lanforge_types::{
        device::{Device, Ipv6AddrOrSuffix, Origin},
        update::{CliHostUpdate, DeviceUpdate, FieldUpdate, InterfaceState},
    };
    use std::{collections::HashMap, time::Duration};
    use std::{
        net::{Ipv6Addr, UdpSocket},
        time::SystemTime,
    };

    fn dummy_server() -> Dhcpv6Server {
        let ctx = init_test_context();

        let ula = "fd97:f00d:cafe:3731::".parse::<Ipv6Addr>().unwrap();
        let start = "fd97:f00d:cafe:3731::100".parse::<Ipv6Addr>().unwrap();
        let end = "fd97:f00d:cafe:3731::200".parse::<Ipv6Addr>().unwrap();

        let state = InterfaceState {
            v4: None,
            link_local: None,
            gua: None,
            ula: Some(ula),
            gua_preferred: 3600,
            gua_valid: 3600,
        };

        // Use instance apply instead of global singleton
        let _ = ctx.apply(DeviceUpdate::InterfaceIpsChanged { ifindex: 0, state });

        let cfg = Dhcpv6Config {
            enabled: true,
            iface: "lo".to_string(),
            lease_time: 86400,
            ula_prefix: Some(ula),
            ula_prefix_len: 64,
            port: 547,
            pools: vec![Dhcpv6PoolConfig {
                range_start: Some(Ipv6AddrOrSuffix::Full(start)),
                range_end: Some(Ipv6AddrOrSuffix::Full(end)),
                address: None,
            }],
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            boot_file: None,
            options: HashMap::new(),
        };
        let pool = Ipv6Pool::new(&cfg.pools, cfg.ula_prefix, 64);
        let server_duid = Duid::new(vec![
            0x00, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        let ndp_poke_sock = Arc::new(UdpSocket::bind("[::1]:0").unwrap());
        Dhcpv6Server::new(
            cfg,
            pool,
            server_duid,
            ndp_poke_sock,
            ctx.clone(),
            ctx.dhcpv6_stats(),
        )
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

    #[test]
    fn solicit_yields_no_addrs_avail_when_pool_empty() {
        let cfg = Dhcpv6Config {
            enabled: true,
            iface: "lo".to_string(),
            lease_time: 86400,
            ula_prefix: None,
            ula_prefix_len: 64,
            port: 547,
            pools: Vec::new(),
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            boot_file: None,
            options: HashMap::new(),
        };
        let pool = Ipv6Pool::new(&Vec::new(), None, 64);
        let sock = UdpSocket::bind("::0:0").unwrap();
        let ndp_poke_sock = Arc::new(sock);
        let ctx = init_test_context();
        let mut srv = Dhcpv6Server::new(
            cfg,
            pool,
            Duid::new(vec![1, 2, 3]),
            ndp_poke_sock,
            ctx.clone(),
            ctx.dhcpv6_stats(),
        );

        let msg = build_solicit(true);
        let mut resp_vec = Vec::with_capacity(1024);
        let identity = DeviceIdentity::new(dummy_mac(), None, None);
        let res = srv.handle_solicit(
            &msg,
            &dummy_client_duid(),
            Some(&identity),
            peer_ip(),
            &mut resp_vec,
        );

        match res {
            HandleResult::Reply(bytes, _, _, _, _, _) => {
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
            HandleResult::Ignore => panic!("Expected Reply"),
        }
    }

    #[test]
    fn request_not_on_link_yields_status_code() {
        let mut srv = dummy_server();
        let mut msg = Message::new(MessageType::Request);
        msg.opts_mut()
            .insert(DhcpOption::ServerId(srv.server_duid.bytes.to_vec()));

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
            HandleResult::Reply(bytes, _, _, _, _, _) => {
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
            HandleResult::Ignore => panic!("Expected Reply with NotOnLink"),
        }
    }

    #[test]
    fn renew_no_binding_yields_status_code() {
        let mut srv = dummy_server();
        let mut msg = Message::new(MessageType::Renew);
        msg.opts_mut()
            .insert(DhcpOption::ServerId(srv.server_duid.bytes.to_vec()));
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
            HandleResult::Reply(bytes, _, _, _, _, _) => {
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
            HandleResult::Ignore => panic!("Expected Reply with NoBinding"),
        }
    }

    #[test]
    fn decline_acknowledgment_and_blacklisting() {
        let mut srv = dummy_server();
        let ip: Ipv6Addr = "fd97:f00d:cafe:3731::101".parse().unwrap();
        let duid = dummy_client_duid();
        let mac = dummy_mac();

        // Simulate allocation
        srv.pool.allocate(&srv.ctx, &duid, 1, Some(mac), None);

        let mut msg = Message::new(MessageType::Decline);
        msg.opts_mut()
            .insert(DhcpOption::ServerId(srv.server_duid.bytes.to_vec()));
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
        let res = srv.handle_decline(&msg, &duid, Some(&identity), peer_ip(), &mut resp_vec);

        match res {
            HandleResult::Reply(bytes, _, _, _, _, _) => {
                let reply = decode_reply(bytes);
                assert_eq!(reply.msg_type(), MessageType::Reply);
                assert!(reply.opts().get(OptionCode::StatusCode).is_some());
            }
            HandleResult::Ignore => panic!("Expected Decline acknowledgment"),
        }

        // Verify blacklist (ip is no longer available)
        srv.pool.decline(ip);
        let ips = srv
            .pool
            .allocate(&srv.ctx, &dummy_client_duid(), 2, Some(mac), None);
        assert!(!ips.contains(&ip));
    }

    #[test]
    fn lifetime_capping_respects_wan_prefix() {
        let mut srv = dummy_server();
        // WAN prefix lifetime = 3600s
        srv.prefix_lifetimes = Some((1800, 3600));

        let msg = build_solicit(true);
        let mut resp_vec = Vec::with_capacity(1024);
        let identity = DeviceIdentity::new(dummy_mac(), None, None);
        let res = srv.handle_solicit(
            &msg,
            &dummy_client_duid(),
            Some(&identity),
            peer_ip(),
            &mut resp_vec,
        );

        match res {
            HandleResult::Reply(bytes, _, _, _, _, _) => {
                let reply = decode_reply(bytes);
                if let Some(DhcpOption::IANA(iana)) = reply.opts().get(OptionCode::IANA)
                    && let Some(DhcpOption::IAAddr(ia_addr)) = iana.opts.get(OptionCode::IAAddr)
                {
                    assert_eq!(ia_addr.preferred_life, 1800);
                    assert_eq!(ia_addr.valid_life, 3600);
                }
            }
            HandleResult::Ignore => panic!("Expected Reply"),
        }
    }

    #[test]
    fn information_request_yields_reply_without_ia_na() {
        let srv = dummy_server();
        let msg = Message::new(MessageType::InformationRequest);
        let mut resp_vec = Vec::with_capacity(1024);
        let res =
            srv.handle_information_request(&msg, &dummy_client_duid(), peer_ip(), &mut resp_vec);

        match res {
            HandleResult::Reply(bytes, _, _, _, _, _) => {
                let reply = decode_reply(bytes);
                assert_eq!(reply.msg_type(), MessageType::Reply);
                assert!(reply.opts().get(OptionCode::IANA).is_none());
            }
            HandleResult::Ignore => panic!("Expected Reply"),
        }
    }

    #[test]
    fn solicit_with_iapd_yields_prefix_delegation() {
        let ula = "fd97:f00d:cafe::".parse::<Ipv6Addr>().unwrap();
        let cfg = Dhcpv6Config {
            enabled: true,
            iface: "lo".to_string(),
            lease_time: 86400,
            ula_prefix: Some(ula),
            ula_prefix_len: 48,
            port: 547,
            pools: Vec::new(),
            dns_servers: Vec::new(),
            search_domains: Vec::new(),
            boot_file: None,
            options: HashMap::new(),
        };
        let pool = Ipv6Pool::new(&Vec::new(), Some(ula), 48);
        let sock = UdpSocket::bind("::0:0").unwrap();
        let ndp_poke_sock = Arc::new(sock);
        let ctx = init_test_context();
        let mut srv = Dhcpv6Server::new(
            cfg,
            pool,
            dummy_client_duid(),
            ndp_poke_sock,
            ctx.clone(),
            ctx.dhcpv6_stats(),
        );

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
            &dummy_client_duid(),
            Some(&identity),
            peer_ip(),
            &mut resp_vec,
        );

        match res {
            HandleResult::Reply(bytes, _, _, _, _, _) => {
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
            HandleResult::Ignore => panic!("Expected Reply with IA_PD"),
        }
    }

    #[tokio::test]
    async fn test_build_reconfigure() {
        let srv = dummy_server();
        let duid = dummy_client_duid();

        let packet = srv.build_reconfigure(&duid, MessageType::Renew);
        let msg = Message::decode(&mut Decoder::new(&packet)).expect("Failed to decode packet");

        assert_eq!(msg.msg_type(), MessageType::Reconfigure);

        let opts = msg.opts();
        assert_eq!(
            opts.get(OptionCode::ClientId),
            Some(&DhcpOption::ClientId(duid.bytes.to_vec()))
        );
        assert_eq!(
            opts.get(OptionCode::ServerId),
            Some(&DhcpOption::ServerId(srv.server_duid.bytes.to_vec()))
        );
        assert_eq!(
            opts.get(OptionCode::ReconfMsg),
            Some(&DhcpOption::ReconfMsg(MessageType::Renew))
        );
    }

    #[test]
    fn test_boot_options() {
        let mut srv = dummy_server();
        srv.cfg.boot_file = Some("http://[fd00::1]/boot/ipxe.efi".into());

        let mac = dummy_mac();
        let mut reply = Message::new(MessageType::Reply);
        reply.set_xid([1, 2, 3]);

        // 1. Global config
        srv.add_boot_options(&mut reply, None);
        assert!(
            reply.opts().get(OptionCode::Unknown(59)).is_some(),
            "Missing Bootfile URL (Option 59)"
        );

        // 2. Per-device override
        let mut dev = Device::new(mac);
        dev.hostname.name = "host".to_string();
        dev.origin = Origin::Static;
        dev.boot_file = Some("http://custom/boot.efi".into());
        // Register it so srv.ctx can find it
        let _ = srv.ctx.apply(DeviceUpdate::CliHostUpdated {
            mac,
            update: CliHostUpdate {
                hostname: FieldUpdate::Set("host".to_string()),
                duid: FieldUpdate::NoChange,
                v4_static: FieldUpdate::NoChange,
                v6_suffix: FieldUpdate::NoChange,
                origin: Origin::Static,
                boot_file: FieldUpdate::Set("http://custom/boot.efi".to_string()),
                dns_fallback: FieldUpdate::NoChange,
                class: FieldUpdate::NoChange,
            },
        });

        let identity = DeviceIdentity::new(mac, None, None);
        let mut reply = Message::new(MessageType::Reply);
        reply.set_xid([0, 1, 2]);
        srv.add_boot_options(&mut reply, Some(&identity));
        assert!(
            reply.opts().get(OptionCode::Unknown(59)).is_some(),
            "Missing custom Bootfile URL (Option 59)"
        );
    }

    #[test]
    fn unauthorized_v6_release_is_ignored() {
        let mut srv = dummy_server();
        let ctx = srv.ctx.clone();
        let duid_legit = Duid::new(vec![1, 2, 3]);
        let duid_rogue = Duid::new(vec![9, 9, 9]);
        let ip = "fd00::100".parse().unwrap();
        let iaid = 777;

        // 1. DUID legit has the lease in context
        let _ = ctx.apply(DeviceUpdate::V6LeaseGranted {
            mac: Some(dummy_mac()),
            duid: duid_legit,
            iaid,
            ip,
            expires: SystemTime::now() + Duration::from_hours(1),
        });

        // 2. DUID rogue tries to release the IP
        let mut msg = Message::new(MessageType::Release);
        msg.opts_mut()
            .insert(DhcpOption::ServerId(srv.server_duid.bytes.to_vec()));
        msg.opts_mut()
            .insert(DhcpOption::ClientId(duid_rogue.bytes.to_vec()));

        let mut iana_opts = DhcpOptions::new();
        iana_opts.insert(DhcpOption::IAAddr(IAAddr {
            addr: ip,
            preferred_life: 3600,
            valid_life: 3600,
            opts: DhcpOptions::new(),
        }));
        msg.opts_mut().insert(DhcpOption::IANA(IANA {
            id: iaid,
            t1: 1800,
            t2: 2880,
            opts: iana_opts,
        }));

        let mut resp_vec = Vec::new();
        let res = srv.handle_release(&msg, &duid_rogue, None, peer_ip(), &mut resp_vec);

        match res {
            HandleResult::Reply(_, _, _, _, _, released) => {
                assert!(
                    released.na.is_empty(),
                    "Rogue RELEASE should not release anything"
                );
            }
            HandleResult::Ignore => panic!("Expected Reply"),
        }
    }

    #[test]
    fn unauthorized_v6_decline_is_ignored() {
        let mut srv = dummy_server();
        let ctx = srv.ctx.clone();
        let duid_legit = Duid::new(vec![1, 2, 3]);
        let duid_rogue = Duid::new(vec![9, 9, 9]);
        let ip = "fd00::100".parse().unwrap();
        let iaid = 777;

        // 1. DUID legit has the lease
        let _ = ctx.apply(DeviceUpdate::V6LeaseGranted {
            mac: Some(dummy_mac()),
            duid: duid_legit,
            iaid,
            ip,
            expires: SystemTime::now() + Duration::from_hours(1),
        });

        // 2. DUID rogue declines the IP
        let mut msg = Message::new(MessageType::Decline);
        msg.opts_mut()
            .insert(DhcpOption::ServerId(srv.server_duid.bytes.to_vec()));
        msg.opts_mut()
            .insert(DhcpOption::ClientId(duid_rogue.bytes.to_vec()));

        let mut iana_opts = DhcpOptions::new();
        iana_opts.insert(DhcpOption::IAAddr(IAAddr {
            addr: ip,
            preferred_life: 3600,
            valid_life: 3600,
            opts: DhcpOptions::new(),
        }));
        msg.opts_mut().insert(DhcpOption::IANA(IANA {
            id: iaid,
            t1: 1800,
            t2: 2880,
            opts: iana_opts,
        }));

        let mut resp_vec = Vec::new();
        let res = srv.handle_decline(&msg, &duid_rogue, None, peer_ip(), &mut resp_vec);

        match res {
            HandleResult::Reply(_, _, _, _, _, released) => {
                assert!(
                    released.na.is_empty(),
                    "Rogue DECLINE should not release anything"
                );
            }
            HandleResult::Ignore => panic!("Expected Reply"),
        }
    }

    #[test]
    fn v6_custom_options_overwriting_is_prevented() {
        let mut srv = dummy_server();
        srv.cfg.options.insert(1, "hex:01".to_string()); // Client ID override attempt
        srv.cfg.options.insert(2, "hex:02".to_string()); // Server ID override attempt
        srv.cfg.options.insert(99, "s:hello".to_string()); // allowed custom option

        let mut reply = Message::new(MessageType::Reply);
        srv.add_custom_options(&mut reply);

        // Option 1 and 2 must NOT be present in custom options output
        assert!(reply.opts().get(OptionCode::Unknown(1)).is_none());
        assert!(reply.opts().get(OptionCode::Unknown(2)).is_none());
        // Option 99 must be present
        assert!(reply.opts().get(OptionCode::Unknown(99)).is_some());
    }

    #[test]
    fn invalid_v6_pool_range_underflow_protection() {
        // Create pool configuration with range_start > range_end
        let cfg = Dhcpv6PoolConfig {
            range_start: Some(Ipv6AddrOrSuffix::Full("fd00::200".parse().unwrap())),
            range_end: Some(Ipv6AddrOrSuffix::Full("fd00::100".parse().unwrap())),
            address: None,
        };
        let range = PoolRange::from_config(&cfg);
        // Should fallback to empty Floating range
        assert!(matches!(range, PoolRange::Floating { .. }));
        if let PoolRange::Floating {
            start_suffix,
            end_suffix,
        } = range
        {
            assert_eq!(start_suffix, [0; 8]);
            assert_eq!(end_suffix, [0; 8]);
        }
    }
}
