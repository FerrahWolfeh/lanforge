//! `DHCPv4` service — Dynamic IPv4 address management (RFC 2131).
//!
//! This service listens for requests on port 67/UDP and manages an address pool,
//! supporting static MAC-based reservations.
//!
//! ## DORA Cycle (Discovery, Offer, Request, Ack)
//!
//! ```mermaid
//! sequenceDiagram
//!     participant C as Client
//!     participant S as DhcpServer (Lanforge)
//!     participant Ctx as LanforgeContext
//!
//!     C->>S: 1. DHCP Discover (Broadcast)
//!     S->>C: 2. DHCP Offer (Unicast/Broadcast)
//!
//!     C->>S: 3. DHCP Request
//!     S->>Ctx: 4. apply(DeviceUpdate::V4LeaseGranted)
//!     Ctx-->>S: 5. EventBus Signal
//!     S->>C: 6. DHCP Ack
//! ```
//!
//! ## Manager Integration
//!
//! The `dhcpv4_service` uses the `LanforgeContext` to persist leases and suggest
//! hostnames learned via Option 12. State merging and `EventBus` signaling
//! are handled automatically by the `LanforgeContext`.

pub mod config;
pub mod pool;
pub mod raw;
pub mod server;

use dhcproto::v4::{Message, Opcode};
use dhcproto::{Decodable, Decoder};
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::{DeviceUpdate, LeaseTarget};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant, SystemTime};
use tracing::{info, warn};

use raw::RawSender;
use server::{DhcpServer, HandleResult};

use crate::dhcp::v4::config::Dhcpv4Config;
use crate::error::NetworkError;

use lanforge_core::error::CoreError;
use lanforge_core::service::{LanforgeService, ServiceMeta, SyncBusReceiver, SyncService};

pub struct Dhcpv4Service {
    cfg: Dhcpv4Config,
    ctx: LanforgeContext,
}

impl Dhcpv4Service {
    #[must_use]
    pub const fn new(cfg: Dhcpv4Config, ctx: LanforgeContext) -> Self {
        Self { cfg, ctx }
    }
}

impl LanforgeService for Dhcpv4Service {
    fn meta(&self) -> ServiceMeta {
        ServiceMeta {
            id: "dhcpv4",
            display_name: "DHCPv4 Server",
            critical: true,
            max_retries: 0,
            base_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(30),
            stack_kb: 512,
        }
    }

    fn describe(&self) -> String {
        format!(
            "DHCPv4 on {} (range {}–{}, lease {}s)",
            self.cfg.iface, self.cfg.range_start, self.cfg.range_end, self.cfg.lease_time
        )
    }
}

impl SyncService for Dhcpv4Service {
    fn run(&mut self, bus_rx: &SyncBusReceiver) -> Result<(), CoreError> {
        // 1. Wait for DB and Interface Ready
        info!("DHCPv4: Waiting for dependencies (DB and Interfaces)...");
        bus_rx.wait_for_db();
        bus_rx.wait_for_interfaces();

        let mut server = DhcpServer::new(self.cfg.clone(), self.ctx.clone());

        // Pre-allocate static reservations to avoid collisions with dynamic pool
        let registry = self.ctx.get_static_registry();
        server.pool.reserve_statics(registry.v4_ips());

        let socket = bind_dhcp_socket_sync(&self.cfg.iface, self.cfg.port)
            .map_err(|e| CoreError::Generic(e.to_string()))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .map_err(CoreError::Io)?;

        let mut raw_tx =
            RawSender::new(&self.cfg.iface).map_err(|e| CoreError::Generic(e.to_string()))?;

        let mut buf = [0u8; 1500];
        let mut last_cleanup = Instant::now();

        loop {
            if !self.ctx.is_running() {
                break;
            }

            // 1. Process network packets
            match socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    self.handle_incoming_packet(&buf[..len], &mut server, &mut raw_tx, &socket);
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => warn!("DHCPv4: recv_from error: {e}"),
            }

            // 2. Process Bus events
            for timed_event in bus_rx.try_recv_all() {
                if let Err(e) = self.handle_bus_event(&timed_event.event, &mut server, &mut raw_tx)
                {
                    if matches!(e, CoreError::Shutdown) {
                        return Ok(());
                    }
                    warn!("DHCPv4: Bus event error: {e}");
                }
            }

            // 3. Periodic Cleanup
            if last_cleanup.elapsed() >= Duration::from_secs(60) {
                server.pool.cleanup_quarantine(SystemTime::now());
                last_cleanup = Instant::now();
            }
        }
        Ok(())
    }
}

impl Dhcpv4Service {
    fn handle_incoming_packet(
        &self,
        data: &[u8],
        server: &mut DhcpServer,
        raw_tx: &mut RawSender,
        socket: &std::net::UdpSocket,
    ) {
        if let Ok(msg) = Message::decode(&mut Decoder::new(data))
            && msg.opcode() == Opcode::BootRequest
        {
            let chaddr = msg.chaddr();
            if chaddr.len() >= 6 {
                let mac = MacAddr([
                    chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5],
                ]);
                let handle_res = {
                    let device = self.ctx.get_device(&mac);
                    server.handle_packet(data, device)
                };

                match handle_res {
                    HandleResult::Reply {
                        packet,
                        broadcast,
                        dest_ip,
                        giaddr,
                        hostname: req_hostname,
                    } => {
                        if giaddr == Ipv4Addr::UNSPECIFIED {
                            let (final_dst_ip, dst_mac_arr) = if broadcast {
                                (Ipv4Addr::BROADCAST, [0xff; 6])
                            } else {
                                (dest_ip, *mac.as_ref())
                            };
                            let _ = raw_tx.send_dhcp(
                                &packet,
                                self.cfg.server_id,
                                final_dst_ip,
                                dst_mac_arr,
                            );
                        } else {
                            let relay_addr = SocketAddrV4::new(giaddr, self.cfg.port);
                            let _ = socket.send_to(&packet, relay_addr);
                        }

                        if let Some(assigned_ip) = server.last_assignment_for() {
                            let expires = SystemTime::now()
                                + Duration::from_secs(u64::from(self.cfg.lease_time));

                            let _ = self.ctx.apply(&DeviceUpdate::V4LeaseGranted {
                                mac,
                                ip: assigned_ip,
                                expires,
                            });

                            if let Some(hostname) = req_hostname
                                && !hostname.is_empty()
                            {
                                let _ = self
                                    .ctx
                                    .apply(&DeviceUpdate::DhcpHostnameHint { mac, hostname });
                            }
                        }
                    }
                    HandleResult::Release { ip: _ } => {
                        let _ = self.ctx.apply(&DeviceUpdate::LeaseReleased {
                            mac,
                            target: LeaseTarget::V4,
                        });
                    }
                    HandleResult::Ignore => {}
                }
            }
        }
    }

    fn handle_bus_event(
        &self,
        event: &LanforgeEvent,
        server: &mut DhcpServer,
        raw_tx: &mut RawSender,
    ) -> Result<(), CoreError> {
        use lanforge_core::bus::DeviceChange;
        match event {
            LanforgeEvent::LeaseRelease {
                mac,
                target: LeaseTarget::V4,
            } => {
                info!("DHCPv4: Forcing release of {} via CLI", mac);
                let ip = self.ctx.get_device(mac).and_then(|d| d.v4.ip());
                if let Some(i) = ip {
                    server.pool.release(i);
                }
            }
            LanforgeEvent::LeaseRenew {
                mac,
                target: LeaseTarget::V4,
            } => {
                let ip = self.ctx.get_device(mac).and_then(|d| d.v4.ip());
                if let Some(ip) = ip {
                    let packet = server.build_forcerenew(*mac, ip);
                    let _ = raw_tx.send_dhcp(&packet, self.cfg.server_id, ip, *mac.as_ref());
                }
            }
            LanforgeEvent::DeviceUpdated {
                mac,
                change: DeviceChange::V4StaticChanged { ip },
            } => match ip {
                Some(v) => {
                    info!("DHCPv4: New static reservation via CLI: {mac} -> {v}");
                    server.pool.mark_declined(*v);
                    info!("DHCPv4: Handled statically.");
                }
                None => {
                    info!("DHCPv4: Static reservation cleared for {mac}");
                }
            },
            LanforgeEvent::Shutdown => {
                info!("DHCPv4: Shutdown received");
                return Err(CoreError::Shutdown);
            }
            _ => {}
        }
        Ok(())
    }
}

/// Binds UDP with `SO_BROADCAST` and `SO_BINDTODEVICE`. (Sync version)
fn bind_dhcp_socket_sync(iface: &str, port: u16) -> Result<std::net::UdpSocket, NetworkError> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);

    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|e| NetworkError::Socket(format!("socket(AF_INET, SOCK_DGRAM): {e}")))?;

    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;

    sock.bind_device(Some(iface.as_bytes()))
        .map_err(|e| NetworkError::Socket(format!("SO_BINDTODEVICE({iface}): {e}")))?;

    sock.bind(&socket2::SockAddr::from(addr))
        .map_err(|e| NetworkError::Socket(format!("bind(0.0.0.0:{port}): {e}")))?;

    Ok(sock.into())
}
