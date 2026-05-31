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

use dhcproto::v4::{self, DhcpOption, HType, Message, MessageType, Opcode, UnknownOption};
use dhcproto::{Decodable, Decoder, Encodable, Encoder, Name};
use lanforge_core::context::LanforgeContext;
use lanforge_types::device::Device;
use lanforge_types::identifiers::MacAddr;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::traits::DhcpPool;

use super::config::Dhcpv4Config;
use super::pool::IpPool;
use crate::identity::DeviceIdentity;
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
}

impl DhcpServer {
    /// Creates a new DHCP server with an empty pool seeded from the config range.
    #[must_use]
    pub fn new(cfg: Dhcpv4Config, ctx: LanforgeContext) -> Self {
        let pool = IpPool::new(cfg.get_effective_pools());
        Self {
            cfg,
            pool,
            last_assigned_ip: None,
            ctx,
        }
    }

    /// Processes a raw DHCP packet and returns a response action.
    ///
    /// Decodes the packet, determines the message type, and dispatches to
    /// the appropriate handler (Discover, Request, Release, Decline, Inform).
    /// The result (`HandleResult`) contains the response packet or signals
    /// a release/ignore action.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn handle_packet(&mut self, data: &[u8], device: Option<Arc<Device>>) -> HandleResult {
        self.last_assigned_ip = None;
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
            device,
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

        let Some(offered_ip) = self.pool.allocate(&self.ctx, mac, requested) else {
            warn!("DHCPv4: Pool exhausted, no IP available for {identity}");
            return HandleResult::Ignore;
        };

        self.last_assigned_ip = Some(offered_ip);

        info!("DHCPv4: {identity} is looking for an address -> Offering {offered_ip}");
        let packet = self.build_reply(msg, MessageType::Offer, offered_ip);
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

        // Try to allocate
        let Some(assigned_ip) = self.pool.allocate(&self.ctx, mac, Some(wanted)) else {
            warn!("DHCPv4: {identity} requested {wanted} but it is not available");
            return self.send_nak(msg, "Requested IP not available");
        };

        if assigned_ip != wanted {
            warn!("DHCPv4: {identity} requested {wanted} but was assigned {assigned_ip} instead");
            return self.send_nak(msg, "Requested IP not available");
        }

        self.last_assigned_ip = Some(assigned_ip);

        info!("DHCPv4: Assigning {assigned_ip} to {identity}");
        let packet = self.build_reply(msg, MessageType::Ack, assigned_ip);
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

    fn handle_release(&mut self, msg: &Message, identity: &DeviceIdentity) -> HandleResult {
        let ip = msg.ciaddr();

        // Validate client lease ownership to prevent spoofed/rogue release DoS
        let owned_ip = self.ctx.get_device(&identity.mac).and_then(|d| d.v4.ip());
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

    fn handle_decline(&mut self, msg: &Message, identity: &DeviceIdentity) -> HandleResult {
        if let Some(declined_ip) = Self::get_requested_ip(msg) {
            // Validate client lease ownership to prevent rogue decline starvation DoS
            let owned_ip = self.ctx.get_device(&identity.mac).and_then(|d| d.v4.ip());
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

    fn get_arch(msg: &Message) -> Option<u16> {
        match msg.opts().get(93.into()) {
            Some(DhcpOption::Unknown(u)) if u.data().len() >= 2 => {
                Some(u16::from_be_bytes([u.data()[0], u.data()[1]]))
            }
            Some(DhcpOption::ClientSystemArchitecture(arch)) => Some(u16::from(*arch)),
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

            if !self.cfg.search_domains.is_empty() {
                // Option 119: Domain Search List (RFC 3397)
                let names: Vec<Name> = self
                    .cfg
                    .search_domains
                    .iter()
                    .filter_map(|d| Name::from_str(d).ok())
                    .collect();
                opts.insert(DhcpOption::DomainSearch(names));
            }

            let safe_lease_time = std::cmp::min(self.cfg.lease_time, MAX_LEASE_TIME);

            // T1 = 50% of lease time, T2 = 87.5%
            opts.insert(DhcpOption::Renewal(safe_lease_time / 2));
            opts.insert(DhcpOption::Rebinding(safe_lease_time.saturating_mul(7) / 8));

            // Hybrid PXE / HTTP Boot Support
            self.add_boot_options(request, opts);

            // Custom Options
            self.add_custom_options(opts);
        }

        let mut buf = Vec::with_capacity(576);
        let mut enc = Encoder::new(&mut buf);
        reply
            .encode(&mut enc)
            .expect("DHCP message encoding should not fail");
        buf
    }

    fn add_boot_options(&self, request: &Message, opts: &mut v4::DhcpOptions) {
        let vendor_class = Self::get_vendor_class(request);
        let arch = Self::get_arch(request);

        // UEFI HTTP Boot (Arch 15 or 16, or Vendor Class contains HTTPClient)
        let is_http_boot = vendor_class
            .as_ref()
            .is_some_and(|v| v.contains("HTTPClient"))
            || matches!(arch, Some(15 | 16));

        let chaddr = request.chaddr();
        let mac = MacAddr::from_slice(&chaddr[..6]).unwrap_or(MacAddr::ZERO);
        let dev = self.ctx.get_device(&mac);
        let boot_file = dev
            .as_ref()
            .and_then(|d| d.boot_file.clone())
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
                if let Some(tftp) = &self.cfg.tftp_server {
                    opts.insert(DhcpOption::TFTPServerName(tftp.as_bytes().to_vec()));
                } else {
                    opts.insert(DhcpOption::TFTPServerName(
                        self.cfg.server_id.to_string().into_bytes(),
                    ));
                }
            }
        }
    }

    fn add_custom_options(&self, opts: &mut v4::DhcpOptions) {
        const PROTECTED: &[u8] = &[53, 54, 51, 1];
        for (code, data) in iter_custom_options(&self.cfg.options, PROTECTED) {
            opts.insert(DhcpOption::Unknown(UnknownOption::new(code.into(), data)));
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
        srv.add_boot_options(&request, &mut reply_opts);
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
            update: CliHostUpdate {
                hostname: FieldUpdate::Set("host".to_string()),
                duid: FieldUpdate::NoChange,
                v4_static: FieldUpdate::NoChange,
                v6_suffix: FieldUpdate::NoChange,
                origin: Origin::Static,
                boot_file: FieldUpdate::Set("custom.efi".to_string()),
                dns_fallback: FieldUpdate::NoChange,
                class: FieldUpdate::NoChange,
            },
        });

        let mut reply_opts = v4::DhcpOptions::new();
        srv.add_boot_options(&request, &mut reply_opts);
        assert_eq!(
            reply_opts.get(v4::OptionCode::BootfileName),
            Some(&DhcpOption::BootfileName(b"custom.efi".to_vec()))
        );

        // 3. UEFI HTTP Boot detection (arch 16)
        request
            .opts_mut()
            .insert(DhcpOption::ClientSystemArchitecture(Architecture::Unknown(
                16,
            ))); // UEFI HTTP
        let mut reply_opts = v4::DhcpOptions::new();
        srv.add_boot_options(&request, &mut reply_opts);
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
}
