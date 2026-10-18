//! `DHCPv4` `DORA` state machine (`RFC 2131`).
//!
//! Implements the full `DHCPv4` address assignment lifecycle: `Discover`→`Offer`,
//! `Request`→`Ack`/`Nak`, `Release`, `Decline`, and `Inform` handling.
//!
//! ## `DORA` State Machine
//!
//! ```mermaid
//! stateDiagram-v2
//!     [*] --> Idle
//!     Idle --> Discover: Client broadcast
//!     Discover --> Offer: Pool allocate
//!     Offer --> Request: Client selects offer
//!     Request --> Ack: Lease confirmed
//!     Request --> Nak: IP unavailable
//!     Ack --> Idle: Lease active
//!     Idle --> Release: Client RELEASE
//!     Release --> [*]: Pool free
//!     Idle --> Decline: Client DECLINE
//!     Decline --> [*]: IP quarantined
//!     Idle --> Inform: Client INFORM
//!     Inform --> Ack: Options only
//! ```
//!
//! ## Decision Table
//!
//! | Message | Action | Response |
//! | :--- | :--- | :--- |
//! | Discover | Allocate IP from pool | Offer (unicast/broadcast) |
//! | Request | Confirm or extend lease | Ack / Nak |
//! | Release | Free IP in pool | None |
//! | Decline | Mark IP as conflicted (2h quarantine) | None |
//! | Inform | Provide config options (no IP) | Ack |

const MAX_LEASE_TIME: u32 = 30 * 24 * 60 * 60; // 30 dias em segundos
const PROTECTED_OPTIONS: &[u8] = &[53, 54, 51, 1];

use dhcproto::v4::{self, DhcpOption, HType, Message, MessageType, Opcode, UnknownOption};
use dhcproto::{Decodable, Decoder, Encodable, Encoder, Name};
use lanforge_core::context::LanforgeContext;
use lanforge_types::device::{Device, IPv4State};
use lanforge_types::identifiers::MacAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;
use tracing::{debug, info, warn};

use crate::traits::DhcpPool;

use super::config::Dhcpv4Config;
use super::pool::IpPool;
use crate::identity::{resolve_device, DeviceIdentity};
use crate::options::iter_custom_options;

/// Outcome of processing a DHCP message from a client.
pub enum HandleResult {
    /// A reply packet is ready to be sent.
    ///
    /// The service wrapper decides how to dispatch it:
    /// - If `giaddr` is set → UDP to relay agent
    /// - If `broadcast` → L2 broadcast (`ff:ff:ff:ff:ff:ff`)
    /// - Otherwise → L2 unicast via `RawSender`
    Reply {
        /// Encoded DHCP packet (wire format).
        packet: Vec<u8>,
        /// Whether to use L2 broadcast (client has no IP yet).
        broadcast: bool,
        /// L3 destination IP for the UDP/IP headers.
        dest_ip: Ipv4Addr,
        /// Relay agent address (0.0.0.0 if no relay).
        giaddr: Ipv4Addr,
        /// Hostname suggested by the client (Option 12), for logging.
        hostname: Option<String>,
        /// Outgoing message type.
        msg_type: MessageType,
    },
    /// Client formally released its lease (RELEASE message).
    ///
    /// The IP should be returned to the available pool.
    Release {
        /// The released IP address.
        ip: Ipv4Addr,
    },
    /// No response necessary — client message was processed silently.
    Ignore,
}

/// Stateful `DHCPv4` server with pool-based address allocation.
///
/// Manages the full `DORA` lifecycle for a single interface. The pool
/// (`IpPool`) tracks available addresses, static reservations, and
/// quarantined (`DECLINEd`) IPs.
///
/// # Lifecycle
///
/// 1. `DhcpServer::new(cfg, ctx)` — creates pool from config range
/// 2. `handle_packet(data, device)` — processes raw bytes, returns `HandleResult`
/// 3. `last_assignment_for()` — retrieves the IP allocated during the last call
/// 4. `build_forcerenew(mac, ip)` — constructs a FORCERENEW message for lease renewal
pub struct DhcpServer {
    /// Server configuration (range, lease time, router, DNS, etc.).
    pub cfg: Dhcpv4Config,
    /// Dynamic IP pool with quarantine and sticky lease support.
    pub pool: IpPool,
    /// Temporarily stores the last allocated IP during `handle_packet()`.
    ///
    /// This is consumed by the service wrapper to emit `DeviceUpdate::V4LeaseGranted`.
    pub last_assigned_ip: Option<Ipv4Addr>,
    /// Global context for device lookups and state updates.
    pub ctx: LanforgeContext,
    /// Cached physical interface MTU to avoid blocking sysfs reads per packet.
    pub cached_mtu: u16,
    /// Precompiled custom options to avoid runtime parsing on the packet hot-path.
    pub precompiled_custom_options: Vec<(u8, Vec<u8>)>,
    /// Precomputed ASCII bytes of the server identifier IP.
    pub server_id_bytes: Vec<u8>,
}

impl DhcpServer {
    /// Creates a new DHCP server with an empty pool seeded from the config range.
    #[must_use]
    pub fn new(cfg: Dhcpv4Config, ctx: LanforgeContext) -> Self {
        let pool = IpPool::new(cfg.get_effective_pools());
        let cached_mtu = get_interface_mtu(&cfg.iface).unwrap_or(1500);
        let precompiled_custom_options =
            iter_custom_options(&cfg.options, PROTECTED_OPTIONS).collect();
        let server_id_bytes = cfg.server_id.to_string().into_bytes();
        Self {
            cfg,
            pool,
            last_assigned_ip: None,
            ctx,
            cached_mtu,
            precompiled_custom_options,
            server_id_bytes,
        }
    }

    /// Processes a raw DHCP packet and returns a response action.
    ///
    /// Decodes the packet, determines the message type, and dispatches to
    /// the appropriate handler (Discover, Request, Release, Decline, Inform).
    /// The result (`HandleResult`) contains the response packet or signals
    /// a release/ignore action.
    /// Processes a decoded DHCP message and returns a response action.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn handle_message(&mut self, msg: &Message, device: Option<&Device>) -> HandleResult {
        self.last_assigned_ip = None;

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
            Self::get_hostname(msg),
            Self::get_vendor_class(msg),
            device,
        );

        match msg_type {
            MessageType::Discover => self.handle_discover(msg, &identity, broadcast, device),
            MessageType::Request => self.handle_request(msg, &identity, broadcast, device),
            MessageType::Release => self.handle_release(msg, &identity, device),
            MessageType::Decline => self.handle_decline(msg, &identity, device),
            MessageType::Inform => self.handle_inform(msg, &identity, device),
            other => {
                debug!("Ignoring message type: {other:?}");
                HandleResult::Ignore
            }
        }
    }

    /// Processes a raw DHCP packet and returns a response action.
    ///
    /// Decodes the packet, determines the message type, and dispatches to
    /// the appropriate handler (Discover, Request, Release, Decline, Inform).
    /// The result (`HandleResult`) contains the response packet or signals
    /// a release/ignore action.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn handle_packet(&mut self, data: &[u8], device: Option<&Device>) -> HandleResult {
        let msg = match Message::decode(&mut Decoder::new(data)) {
            Ok(m) => m,
            Err(e) => {
                debug!("Failed to decode packet: {e}");
                return HandleResult::Ignore;
            }
        };
        self.handle_message(&msg, device)
    }

    // ── DISCOVER → OFFER ─────────────────────────────────────────────────

    fn handle_discover(
        &mut self,
        msg: &Message,
        identity: &DeviceIdentity,
        broadcast: bool,
        device: Option<&Device>,
    ) -> HandleResult {
        let mac = identity.mac;
        let requested = Self::get_requested_ip(msg);

        let Some(offered_ip) = self.pool.allocate_with_device(&self.ctx, mac, requested, device) else {
            warn!("DHCPv4: Pool exhausted, no IP available for {identity}");
            return HandleResult::Ignore;
        };

        self.last_assigned_ip = Some(offered_ip);

        info!("DHCPv4: {identity} is looking for an address -> Offering {offered_ip}");
        let packet = self.build_reply(msg, MessageType::Offer, offered_ip, device);
        HandleResult::Reply {
            packet,
            broadcast,
            dest_ip: offered_ip,
            giaddr: msg.giaddr(),
            hostname: Self::get_hostname(msg),
            msg_type: MessageType::Offer,
        }
    }

    // ── REQUEST → ACK or NAK ─────────────────────────────────────────────

    fn handle_request(
        &mut self,
        msg: &Message,
        identity: &DeviceIdentity,
        broadcast: bool,
        device: Option<&Device>,
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

        // RFC 2131 §4.3.2 SANITY CHECK:
        // A client is permitted to request `wanted` IF:
        // 1. It is a static host reservation explicitly assigned to this MAC.
        // 2. OR `wanted` falls within active dynamic pools and aligns with the subnet mask & gateway.
        // Otherwise, the address is invalid for this subnet/pool; reply with DHCPNAK to force the
        // client back to INIT state so it broadcasts DHCPDISCOVER and receives a valid lease.
        let mut dev_owned = None;
        let dev_ref = resolve_device(&self.ctx, mac, device, &mut dev_owned);

        let is_static_for_client = self.ctx.get_static_registry().v4.get(&wanted) == Some(&mac)
            || dev_ref
                .is_some_and(|d| matches!(d.v4, IPv4State::Static(ip) if ip == wanted));

        if !is_static_for_client && !self.pool.is_valid_dynamic_ip(wanted, self.cfg.subnet_mask, Some(self.cfg.router)) {
            warn!("DHCPv4: {identity} requested {wanted} which is outside configured pools or on a mismatched subnet; sending DHCPNAK");
            return self.send_nak(msg, "Requested IP address is not valid for this subnet or dynamic pool");
        }

        // Try to allocate
        let Some(assigned_ip) = self.pool.allocate_with_device(&self.ctx, mac, Some(wanted), device) else {
            warn!("DHCPv4: {identity} requested {wanted} but it is not available");
            return self.send_nak(msg, "Requested IP not available");
        };

        if assigned_ip != wanted {
            warn!("DHCPv4: {identity} requested {wanted} but was assigned {assigned_ip} instead");
            self.pool.release(&assigned_ip);
            return self.send_nak(msg, "Requested IP not available");
        }

        self.last_assigned_ip = Some(assigned_ip);

        info!("DHCPv4: Assigning {assigned_ip} to {identity}");
        let packet = self.build_reply(msg, MessageType::Ack, assigned_ip, device);
        HandleResult::Reply {
            packet,
            broadcast,
            dest_ip: assigned_ip,
            giaddr: msg.giaddr(),
            hostname: Self::get_hostname(msg),
            msg_type: MessageType::Ack,
        }
    }

    // ── RELEASE ──────────────────────────────────────────────────────────

    fn handle_release(
        &mut self,
        msg: &Message,
        identity: &DeviceIdentity,
        device: Option<&Device>,
    ) -> HandleResult {
        let ip = msg.ciaddr();

        // Validate client lease ownership to prevent spoofed/rogue release DoS
        let mut dev_owned = None;
        let dev_ref = resolve_device(&self.ctx, identity.mac, device, &mut dev_owned);

        let owned_ip = dev_ref.and_then(|d| d.v4.ip());
        if owned_ip != Some(ip) {
            warn!(
                "DHCPv4: RELEASE from {} for {} ignored: client does not own this lease.",
                identity, ip
            );
            return HandleResult::Ignore;
        }

        info!("DHCPv4: {identity} released its address {ip}");
        self.pool.release(&ip);
        HandleResult::Release { ip }
    }

    // ── DECLINE ──────────────────────────────────────────────────────────

    fn handle_decline(
        &mut self,
        msg: &Message,
        identity: &DeviceIdentity,
        device: Option<&Device>,
    ) -> HandleResult {
        if let Some(declined_ip) = Self::get_requested_ip(msg) {
            // Validate client lease ownership to prevent rogue decline starvation DoS
            let mut dev_owned = None;
            let dev_ref = resolve_device(&self.ctx, identity.mac, device, &mut dev_owned);

            let owned_ip = dev_ref.and_then(|d| d.v4.ip());
            if owned_ip != Some(declined_ip) {
                warn!(
                    "DHCPv4: DECLINE from {} for {} ignored: client does not own this lease.",
                    identity, declined_ip
                );
                return HandleResult::Ignore;
            }

            warn!("DHCPv4: {identity} declined {declined_ip} (address conflict)! Quarantining IP.");
            self.pool.decline(declined_ip);
            HandleResult::Release { ip: declined_ip }
        } else {
            warn!("DHCPv4: {identity} declined an unspecified IP");
            HandleResult::Ignore
        }
    }

    // ── INFORM ───────────────────────────────────────────────────────────

    fn handle_inform(
        &self,
        msg: &Message,
        identity: &DeviceIdentity,
        device: Option<&Device>,
    ) -> HandleResult {
        let ip = msg.ciaddr();
        info!("DHCPv4: {identity} ({ip}) requested configuration options");

        let packet = self.build_reply(msg, MessageType::Ack, Ipv4Addr::UNSPECIFIED, device);

        HandleResult::Reply {
            packet,
            broadcast: false,
            dest_ip: ip,
            giaddr: msg.giaddr(),
            hostname: Self::get_hostname(msg),
            msg_type: MessageType::Ack,
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
            Some(DhcpOption::Hostname(h)) => {
                let sanitized = h.replace('\0', "").trim().to_string();
                if sanitized.is_empty() {
                    None
                } else {
                    Some(sanitized)
                }
            }
            _ => None,
        }
    }

    fn get_vendor_class(msg: &Message) -> Option<String> {
        let raw = match msg.opts().get(v4::OptionCode::ClassIdentifier) {
            Some(DhcpOption::Unknown(u)) => String::from_utf8(u.data().to_vec()).ok(),
            Some(DhcpOption::ClassIdentifier(v)) => String::from_utf8(v.clone()).ok(),
            _ => None,
        }?;
        let sanitized = raw.replace('\0', "").trim().to_string();
        if sanitized.is_empty() {
            None
        } else {
            Some(sanitized)
        }
    }

    fn get_arch(msg: &Message) -> Option<u16> {
        match msg.opts().get(93.into()) {
            Some(DhcpOption::Unknown(u)) if u.data().len() >= 2 => {
                Some(u16::from_be_bytes([u.data()[0], u.data()[1]]))
            }
            Some(DhcpOption::ClientSystemArchitecture(arch)) => Some(u16::from(*arch)),
            _ => None,
        }
    }

    fn populate_reply_options(
        &self,
        request: &Message,
        opts: &mut v4::DhcpOptions,
        yiaddr: Ipv4Addr,
        device: Option<&Device>,
    ) {
        let chaddr = request.chaddr();
        let mac = MacAddr::from_slice(&chaddr[..6]).unwrap_or(MacAddr::ZERO);
        let mut dev_owned = None;
        let dev_ref = resolve_device(&self.ctx, mac, device, &mut dev_owned);
        let is_static = dev_ref.is_some_and(lanforge_types::device::Device::is_static);

        let pool_opt = self.pool.pool_for_ip(yiaddr);
        let pool_router = pool_opt.and_then(|p| p.router).unwrap_or(self.cfg.router);
        let pool_mask = pool_opt.and_then(|p| p.subnet_mask).unwrap_or(self.cfg.subnet_mask);
        let pool_dns = pool_opt.map_or(&self.cfg.dns, |p| {
            if p.dns_servers.is_empty() {
                &self.cfg.dns
            } else {
                &p.dns_servers
            }
        });
        let pool_domain = pool_opt
            .and_then(|p| p.domain_name.as_ref())
            .or(self.cfg.domain_name.as_ref());
        let pool_search = pool_opt.map_or(&self.cfg.search_domains, |p| {
            if p.search_domains.is_empty() {
                &self.cfg.search_domains
            } else {
                &p.search_domains
            }
        });
        let pool_ntp = pool_opt.map_or(&self.cfg.ntp_servers, |p| {
            if p.ntp_servers.is_empty() {
                &self.cfg.ntp_servers
            } else {
                &p.ntp_servers
            }
        });

        let effective_lease_time = pool_opt
            .and_then(|p| p.lease_time)
            .unwrap_or(self.cfg.lease_time);
        let lease_time = if is_static {
            u32::MAX
        } else {
            effective_lease_time
        };

        opts.insert(DhcpOption::AddressLeaseTime(lease_time));
        opts.insert(DhcpOption::SubnetMask(pool_mask));
        opts.insert(DhcpOption::Router(vec![pool_router]));
        opts.insert(DhcpOption::DomainNameServer(pool_dns.clone()));

        if let Some(domain) = pool_domain {
            opts.insert(DhcpOption::DomainName(domain.clone()));
        }

        if !pool_search.is_empty() {
            // Option 119: Domain Search List (RFC 3397)
            let names: Vec<Name> = pool_search
                .iter()
                .filter_map(|d| Name::from_str(d).ok())
                .collect();
            opts.insert(DhcpOption::DomainSearch(names));
        }

        let (t1, t2) = if is_static {
            (u32::MAX, u32::MAX)
        } else {
            let safe_lease_time = std::cmp::min(effective_lease_time, MAX_LEASE_TIME);
            (safe_lease_time / 2, safe_lease_time.saturating_mul(7) / 8)
        };
        opts.insert(DhcpOption::Renewal(t1));
        opts.insert(DhcpOption::Rebinding(t2));

        // Dynamic MTU (Option 26)
        if let Some(DhcpOption::ParameterRequestList(req_list)) =
            request.opts().get(v4::OptionCode::ParameterRequestList)
            && req_list.contains(&v4::OptionCode::InterfaceMtu)
        {
            opts.insert(DhcpOption::InterfaceMtu(self.cached_mtu));
        }

        // NTP Servers (Option 42)
        if !pool_ntp.is_empty() {
            let mut ntp_bytes = Vec::with_capacity(pool_ntp.len() * 4);
            for ip in pool_ntp {
                ntp_bytes.extend_from_slice(&ip.octets());
            }
            opts.insert(DhcpOption::Unknown(UnknownOption::new(
                42.into(),
                ntp_bytes,
            )));
        }

        // Hybrid PXE / HTTP Boot Support
        self.add_boot_options(request, opts, pool_opt, device);

        // Custom Options
        self.add_custom_options(opts);
    }

    fn build_reply(
        &self,
        request: &Message,
        msg_type: MessageType,
        yiaddr: Ipv4Addr,
        device: Option<&Device>,
    ) -> Vec<u8> {
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
            self.populate_reply_options(request, opts, yiaddr, device);
        }

        let mut buf = Vec::with_capacity(576);
        let mut enc = Encoder::new(&mut buf);
        reply
            .encode(&mut enc)
            .expect("DHCP message encoding should not fail");
        buf
    }

    fn add_boot_options(
        &self,
        request: &Message,
        opts: &mut v4::DhcpOptions,
        pool_opt: Option<&lanforge_types::network::dhcp::Dhcpv4Pool>,
        device: Option<&Device>,
    ) {
        let vendor_class = Self::get_vendor_class(request);
        let arch = Self::get_arch(request);

        // UEFI HTTP Boot (Arch 15 or 16, or Vendor Class contains HTTPClient)
        let is_http_boot = vendor_class
            .as_ref()
            .is_some_and(|v| v.contains("HTTPClient"))
            || matches!(arch, Some(15 | 16));

        let chaddr = request.chaddr();
        let mac = MacAddr::from_slice(&chaddr[..6]).unwrap_or(MacAddr::ZERO);
        let mut dev_owned = None;
        let dev_ref = resolve_device(&self.ctx, mac, device, &mut dev_owned);

        let boot_file = dev_ref
            .and_then(|d| d.boot_file.clone())
            .or_else(|| pool_opt.and_then(|p| p.boot_file.clone()))
            .or_else(|| self.cfg.boot_file.clone());

        if let Some(file) = boot_file {
            if is_http_boot {
                // UEFI HTTP Boot: Option 67 is a full URL
                let url = format!("http://{}/boot/{}", self.cfg.server_id, file);
                opts.insert(DhcpOption::BootfileName(url.into_bytes()));
                opts.insert(DhcpOption::ClassIdentifier(b"HTTPClient".to_vec()));
            } else {
                // Traditional PXE: Option 67 is a filename
                opts.insert(DhcpOption::BootfileName(file.into_bytes()));
                let tftp = pool_opt
                    .and_then(|p| p.tftp_server.as_ref())
                    .or(self.cfg.tftp_server.as_ref());
                if let Some(tftp) = tftp {
                    opts.insert(DhcpOption::TFTPServerName(tftp.as_bytes().to_vec()));
                } else {
                    opts.insert(DhcpOption::TFTPServerName(self.server_id_bytes.clone()));
                }
            }
        }
    }

    pub fn recompile_options(&mut self) {
        self.precompiled_custom_options =
            iter_custom_options(&self.cfg.options, PROTECTED_OPTIONS).collect();
    }

    fn add_custom_options(&self, opts: &mut v4::DhcpOptions) {
        if !self.precompiled_custom_options.is_empty() {
            for (code, data) in &self.precompiled_custom_options {
                opts.insert(DhcpOption::Unknown(UnknownOption::new((*code).into(), data.clone())));
            }
        } else if !self.cfg.options.is_empty() {
            for (code, data) in iter_custom_options(&self.cfg.options, PROTECTED_OPTIONS) {
                opts.insert(DhcpOption::Unknown(UnknownOption::new(code.into(), data)));
            }
        }
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
            msg_type: MessageType::Nak,
        }
    }

    /// Returns the MAC and assigned IP from the last successful allocation.
    /// Used by the service loop to publish events.
    pub const fn last_assignment_for(&mut self) -> Option<Ipv4Addr> {
        self.last_assigned_ip.take()
    }

    /// Constructs a `FORCERENEW` (RFC 3203) packet for a specific client.
    ///
    /// This follows the "best-effort" approach without RFC 3118 authentication,
    /// which is the standard behavior in environments where secrets aren't
    /// pre-provisioned to every device.
    #[must_use]
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

fn get_interface_mtu(iface: &str) -> Option<u16> {
    use std::io::Read;
    let path = format!("/sys/class/net/{iface}/mtu");
    let mut file = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; 16];
    let n = file.read(&mut buf).ok()?;
    std::str::from_utf8(&buf[..n]).ok()?.trim().parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_context;
    use dhcproto::v4::{Architecture, DhcpOption, Message, MessageType, Opcode};
    use dhcproto::{Decodable, Decoder, Encodable, Encoder};
    use lanforge_core::context::LanforgeContext;
    use lanforge_types::device::Origin;
    use lanforge_types::update::{CliHostUpdate, DeviceUpdate, FieldUpdate};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    // -----------------------------------------------------------------------
    // Helpers e Factories para os Testes
    // -----------------------------------------------------------------------

    fn dummy_config() -> Dhcpv4Config {
        Dhcpv4Config {
            enabled: true,
            iface: "eth0".to_string(),
            range_start: Some(Ipv4Addr::new(192, 168, 1, 100)),
            range_end: Some(Ipv4Addr::new(192, 168, 1, 200)),
            pools: Vec::new(),
            lease_time: 3600,
            router: Ipv4Addr::new(192, 168, 1, 1),
            dns: vec![Ipv4Addr::new(1, 1, 1, 1)],
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            server_id: Ipv4Addr::new(192, 168, 1, 1),
            domain_name: Some("lanforge.local".to_string()),
            search_domains: vec!["lanforge.local".to_string()],
            port: 67,
            tftp_server: None,
            boot_file: None,
            options: HashMap::new(),
            ntp_servers: vec![
                Ipv4Addr::new(162, 159, 200, 1),
                Ipv4Addr::new(216, 239, 35, 0),
            ],
        }
    }

    fn dummy_server() -> (DhcpServer, LanforgeContext) {
        let ctx = init_test_context();
        (DhcpServer::new(dummy_config(), ctx.clone()), ctx)
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
        let (mut srv, _ctx) = dummy_server();
        let junk_data = vec![0x00, 0xFF, 0xAA, 0xBB]; // Lixo puro

        let res = srv.handle_packet(&junk_data, None);
        assert!(matches!(res, HandleResult::Ignore));
    }

    #[test]
    fn discover_yields_offer() {
        let (mut srv, _ctx) = dummy_server();
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
            HandleResult::Ignore | HandleResult::Release { .. } => {
                panic!("Expected Reply for DISCOVER")
            }
        }
    }

    #[test]
    fn request_valid_yields_ack() {
        let (mut srv, _ctx) = dummy_server();
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
                assert_eq!(srv.last_assignment_for(), Some(requested_ip));
            }
            HandleResult::Ignore | HandleResult::Release { .. } => {
                panic!("Expected ACK Reply for valid REQUEST")
            }
        }
    }

    #[test]
    fn request_for_different_server_is_ignored() {
        let (mut srv, _ctx) = dummy_server();
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
        let (mut srv, ctx) = dummy_server();
        let mac1 = MacAddr([0x11, 0x11, 0x11, 0x11, 0x11, 0x11]);
        let mac2 = MacAddr([0x22, 0x22, 0x22, 0x22, 0x22, 0x22]);
        let contested_ip = Ipv4Addr::new(192, 168, 1, 105);

        // 1. MAC1 aloca o IP primeiro
        let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
            mac: mac1,
            ip: contested_ip,
            expires: SystemTime::now() + Duration::from_hours(1),
        });

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
            HandleResult::Ignore | HandleResult::Release { .. } => {
                panic!("Expected NAK for contested IP")
            }
        }
    }

    #[test]
    fn request_out_of_pool_or_wrong_subnet_ip_yields_nak() {
        let (mut srv, ctx) = dummy_server();
        let mac = dummy_mac();

        // 1. Client requests an out-of-pool IP from an old network (10.0.100.50)
        let stale_ip = Ipv4Addr::new(10, 0, 100, 50);
        let raw_msg = build_raw_msg(MessageType::Request, mac, Some(stale_ip), None, None);
        let res = srv.handle_packet(&raw_msg, None);

        match res {
            HandleResult::Reply {
                packet, broadcast, ..
            } => {
                let reply = decode_reply(&packet);
                assert_eq!(
                    reply.opts().get(v4::OptionCode::MessageType),
                    Some(&DhcpOption::MessageType(MessageType::Nak)),
                    "Must NAK out-of-pool / out-of-subnet requested IP"
                );
                assert!(broadcast, "NAKs must be broadcast");
            }
            HandleResult::Ignore | HandleResult::Release { .. } => {
                panic!("Expected NAK for out-of-pool requested IP")
            }
        }

        // 2. But if that out-of-pool IP is a static reservation for this MAC, it must be honored!
        let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
            mac,
            update: Box::new(CliHostUpdate {
                hostname: FieldUpdate::Set("static-device".to_string()),
                duid: FieldUpdate::NoChange,
                v4_static: FieldUpdate::Set(stale_ip),
                v6_suffix: FieldUpdate::NoChange,
                origin: Origin::Static,
                boot_file: FieldUpdate::NoChange,
                dns_fallback: FieldUpdate::NoChange,
                class: FieldUpdate::NoChange,
            }),
        });

        let res_static = srv.handle_packet(&raw_msg, None);
        match res_static {
            HandleResult::Reply { packet, .. } => {
                let reply = decode_reply(&packet);
                assert_eq!(
                    reply.opts().get(v4::OptionCode::MessageType),
                    Some(&DhcpOption::MessageType(MessageType::Ack)),
                    "Must ACK static reservation even if outside dynamic pool"
                );
            }
            HandleResult::Ignore | HandleResult::Release { .. } => {
                panic!("Expected ACK for static reservation")
            }
        }
    }

    #[test]
    fn release_frees_allocated_ip() {
        let (mut srv, ctx) = dummy_server();
        let mac = dummy_mac();
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        srv.pool.allocate(&ctx, mac, Some(ip));
        let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
            mac,
            ip,
            expires: SystemTime::now() + Duration::from_hours(1),
        });
        srv.last_assigned_ip = Some(ip);
        assert_eq!(srv.last_assignment_for(), Some(ip));

        // Envia o Release informando o IP no ciaddr (Client IP Address)
        let raw_msg = build_raw_msg(MessageType::Release, mac, None, Some(ip), None);
        let res = srv.handle_packet(&raw_msg, None);

        assert!(
            matches!(res, HandleResult::Release { .. }),
            "RELEASE deve retornar HandleResult::Release"
        );
        assert_eq!(
            srv.last_assignment_for(),
            None,
            "IP deve ter sido liberado no pool interno"
        );
    }

    #[test]
    fn decline_clears_mac_assignment() {
        let (mut srv, ctx) = dummy_server();
        let mac = dummy_mac();
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        srv.pool.allocate(&ctx, mac, Some(ip));
        let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
            mac,
            ip,
            expires: SystemTime::now() + Duration::from_hours(1),
        });

        // Cliente detectou conflito de ARP e enviou DECLINE
        let raw_msg = build_raw_msg(MessageType::Decline, mac, Some(ip), None, None);
        let res = srv.handle_packet(&raw_msg, None);

        assert!(matches!(res, HandleResult::Release { ip: declined_ip } if declined_ip == ip));
        assert_eq!(
            srv.last_assignment_for(),
            None,
            "DECLINE deve revogar a associação do MAC"
        );
    }

    #[test]
    fn inform_yields_ack_without_allocating_ip() {
        let (mut srv, _ctx) = dummy_server();
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
            HandleResult::Ignore | HandleResult::Release { .. } => {
                panic!("Expected ACK for INFORM request")
            }
        }
    }

    #[test]
    fn test_build_forcerenew() {
        let (srv, _ctx) = dummy_server();
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

    #[test]
    fn test_boot_options() {
        let (mut srv, _ctx) = dummy_server();
        srv.cfg.tftp_server = Some("1.2.3.4".into());
        srv.cfg.boot_file = Some("global.efi".into());

        let mac = dummy_mac();
        let mut request = Message::default();
        request.set_opcode(Opcode::BootRequest);
        request.set_xid(123);
        request.set_chaddr(&mac.0);
        request
            .opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Discover));

        let mut reply_opts = v4::DhcpOptions::new();

        // 1. Global config only
        srv.add_boot_options(&request, &mut reply_opts, None, None);
        assert_eq!(
            reply_opts.get(66.into()),
            Some(&DhcpOption::TFTPServerName(b"1.2.3.4".to_vec()))
        );
        assert_eq!(
            reply_opts.get(67.into()),
            Some(&DhcpOption::BootfileName(b"global.efi".to_vec()))
        );

        // 2. Per-device override
        let _ = srv.ctx.apply(DeviceUpdate::CliHostUpdated {
            mac,
            update: Box::new(CliHostUpdate {
                hostname: FieldUpdate::Set("host".to_string()),
                duid: FieldUpdate::NoChange,
                v4_static: FieldUpdate::NoChange,
                v6_suffix: FieldUpdate::NoChange,
                origin: Origin::Static,
                boot_file: FieldUpdate::Set("custom.efi".to_string()),
                dns_fallback: FieldUpdate::NoChange,
                class: FieldUpdate::NoChange,
            }),
        });

        let mut reply_opts = v4::DhcpOptions::new();
        srv.add_boot_options(&request, &mut reply_opts, None, None);
        assert_eq!(
            reply_opts.get(v4::OptionCode::BootfileName),
            Some(&DhcpOption::BootfileName(b"custom.efi".to_vec()))
        );

        // 3. UEFI HTTP Boot detection (arch 16)
        request
            .opts_mut()
            .insert(DhcpOption::ClientSystemArchitecture(Architecture::from(16))); // UEFI HTTP
        let mut reply_opts = v4::DhcpOptions::new();
        srv.add_boot_options(&request, &mut reply_opts, None, None);
        assert!(
            reply_opts.get(v4::OptionCode::ClassIdentifier).is_some(),
            "Missing Class Identifier (Option 60)"
        );
    }

    #[test]
    fn unauthorized_release_is_ignored() {
        let (mut srv, ctx) = dummy_server();
        let mac_legit = dummy_mac();
        let mac_rogue = MacAddr([0x99, 0x99, 0x99, 0x99, 0x99, 0x99]);
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        // 1. MAC legit has the lease in context
        let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
            mac: mac_legit,
            ip,
            expires: SystemTime::now() + Duration::from_hours(1),
        });

        // 2. MAC rogue tries to release the IP
        let raw_msg = build_raw_msg(MessageType::Release, mac_rogue, None, Some(ip), None);
        let res = srv.handle_packet(&raw_msg, None);

        assert!(
            matches!(res, HandleResult::Ignore),
            "Rogue RELEASE must be ignored"
        );
    }

    #[test]
    fn unauthorized_decline_is_ignored() {
        let (mut srv, ctx) = dummy_server();
        let mac_legit = dummy_mac();
        let mac_rogue = MacAddr([0x99, 0x99, 0x99, 0x99, 0x99, 0x99]);
        let ip = Ipv4Addr::new(192, 168, 1, 100);

        // 1. MAC legit has the lease
        let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
            mac: mac_legit,
            ip,
            expires: SystemTime::now() + Duration::from_hours(1),
        });

        // 2. MAC rogue declines the IP
        let raw_msg = build_raw_msg(MessageType::Decline, mac_rogue, Some(ip), None, None);
        let res = srv.handle_packet(&raw_msg, None);

        assert!(
            matches!(res, HandleResult::Ignore),
            "Rogue DECLINE must be ignored"
        );
    }

    #[test]
    fn custom_options_overwriting_is_prevented() {
        let (mut srv, _ctx) = dummy_server();
        srv.cfg.options.insert(53, "hex:01".to_string()); // MessageType override attempt
        srv.cfg.options.insert(54, "hex:c0a80101".to_string()); // ServerIdentifier override attempt
        srv.cfg.options.insert(99, "s:hello".to_string()); // allowed custom option

        let mut opts = v4::DhcpOptions::new();
        srv.add_custom_options(&mut opts);

        // Option 53 and 54 must NOT be present in custom options output
        assert!(opts.get(53.into()).is_none());
        assert!(opts.get(54.into()).is_none());
        // Option 99 must be present
        assert!(opts.get(99.into()).is_some());
    }

    #[test]
    fn pool_exhaustion_ignores_discover_and_naks_request() {
        let ctx = init_test_context();
        // Configure a server with a pool of only 2 IPs (.100 and .101)
        let mut cfg = dummy_config();
        cfg.range_start = Some(Ipv4Addr::new(192, 168, 1, 100));
        cfg.range_end = Some(Ipv4Addr::new(192, 168, 1, 101));
        let mut srv = DhcpServer::new(cfg, ctx.clone());

        let mac1 = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01]);
        let mac2 = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02]);
        let mac3 = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03]);

        // 1. MAC1 DISCOVER -> OFFER (192.168.1.100 or .101)
        let disc1 = build_raw_msg(MessageType::Discover, mac1, None, None, None);
        let res1 = srv.handle_packet(&disc1, None);
        assert!(matches!(
            res1,
            HandleResult::Reply {
                msg_type: MessageType::Offer,
                ..
            }
        ));

        // Simulate lease assignment in DB context for MAC1 (consumes .100)
        let ip1 = srv.last_assignment_for().unwrap();
        let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
            mac: mac1,
            ip: ip1,
            expires: SystemTime::now() + Duration::from_hours(1),
        });

        // 2. MAC2 DISCOVER -> OFFER (the other IP)
        let disc2 = build_raw_msg(MessageType::Discover, mac2, None, None, None);
        let res2 = srv.handle_packet(&disc2, None);
        assert!(matches!(
            res2,
            HandleResult::Reply {
                msg_type: MessageType::Offer,
                ..
            }
        ));

        // Simulate lease assignment for MAC2 (consumes .101)
        let ip2 = srv.last_assignment_for().unwrap();
        let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
            mac: mac2,
            ip: ip2,
            expires: SystemTime::now() + Duration::from_hours(1),
        });

        assert_ne!(ip1, ip2);

        // 3. MAC3 DISCOVER -> IGNORED (pool exhausted!)
        let disc3 = build_raw_msg(MessageType::Discover, mac3, None, None, None);
        let res3 = srv.handle_packet(&disc3, None);
        assert!(matches!(res3, HandleResult::Ignore));

        // 4. MAC3 REQUEST for any IP -> NAK (pool exhausted!)
        let reqst3 = build_raw_msg(
            MessageType::Request,
            mac3,
            Some(Ipv4Addr::new(192, 168, 1, 102)),
            None,
            None,
        );
        let res4 = srv.handle_packet(&reqst3, None);
        match res4 {
            HandleResult::Reply { packet, .. } => {
                let reply = decode_reply(&packet);
                assert_eq!(
                    reply.opts().get(v4::OptionCode::MessageType),
                    Some(&DhcpOption::MessageType(MessageType::Nak))
                );
            }
            _ => panic!("Expected NAK for REQUEST when pool is exhausted"),
        }
    }

    #[test]
    fn test_dhcpv4_options_and_static_lease() {
        let (mut srv, ctx) = dummy_server();
        let mac = dummy_mac();

        // 1. Check NTP default options are sent
        let disc = build_raw_msg(MessageType::Discover, mac, None, None, None);
        let res = srv.handle_packet(&disc, None);
        if let HandleResult::Reply { packet, .. } = res {
            let reply = decode_reply(&packet);
            // Option 42 (NTP) should be present and contain our default NTP servers
            let ntp_opt = reply.opts().get(42.into());
            assert!(ntp_opt.is_some());
            if let Some(DhcpOption::Unknown(opt)) = ntp_opt {
                assert_eq!(opt.data().len(), 8); // Two IPv4 addresses = 8 bytes
            }
        } else {
            panic!("Expected offer");
        }

        // 2. Check MTU option is sent if requested in Option 55
        let mut msg = Message::default();
        msg.set_opcode(Opcode::BootRequest).set_chaddr(&mac.0);
        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Discover));
        msg.opts_mut().insert(DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::InterfaceMtu,
        ]));
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        msg.encode(&mut enc).unwrap();

        let res_mtu = srv.handle_packet(&buf, None);
        if let HandleResult::Reply { packet, .. } = res_mtu {
            let reply = decode_reply(&packet);
            // Option 26 (Interface MTU) should be present
            let mtu_opt = reply.opts().get(v4::OptionCode::InterfaceMtu);
            assert!(mtu_opt.is_some());
            if let Some(DhcpOption::InterfaceMtu(mtu)) = mtu_opt {
                // Should default to 1500 if reading /sys/class/net/eth0/mtu fails
                assert_eq!(*mtu, 1500);
            }
        } else {
            panic!("Expected offer");
        }

        // 3. Check static lease receives infinite lifetime
        // Make the device static in context
        let static_ip = Ipv4Addr::new(192, 168, 1, 10);
        let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
            mac,
            update: Box::new(CliHostUpdate {
                hostname: FieldUpdate::Set("static-host".to_string()),
                duid: FieldUpdate::NoChange,
                v4_static: FieldUpdate::Set(static_ip),
                v6_suffix: FieldUpdate::NoChange,
                origin: Origin::Static,
                boot_file: FieldUpdate::NoChange,
                dns_fallback: FieldUpdate::NoChange,
                class: FieldUpdate::NoChange,
            }),
        });

        // Request lease
        let req = build_raw_msg(MessageType::Request, mac, Some(static_ip), None, None);
        let device = ctx.get_device(&mac);
        let res_static = srv.handle_packet(&req, device.as_deref());
        if let HandleResult::Reply { packet, .. } = res_static {
            let reply = decode_reply(&packet);
            let lease_time = reply.opts().get(v4::OptionCode::AddressLeaseTime);
            assert_eq!(lease_time, Some(&DhcpOption::AddressLeaseTime(u32::MAX)));
            let renewal = reply.opts().get(v4::OptionCode::Renewal);
            assert_eq!(renewal, Some(&DhcpOption::Renewal(u32::MAX)));
            let rebinding = reply.opts().get(v4::OptionCode::Rebinding);
            assert_eq!(rebinding, Some(&DhcpOption::Rebinding(u32::MAX)));
        } else {
            panic!("Expected ack");
        }
    }
}
