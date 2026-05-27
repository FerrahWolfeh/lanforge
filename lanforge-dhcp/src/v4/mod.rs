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

use dhcproto::v4::{DhcpOption, Message, Opcode, OptionCode};
use dhcproto::{Decodable, Decoder};
use lanforge_core::bus::{AdminChange, DeviceEvent, DhcpV4MessageType, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_macros::lanforge_service;
use lanforge_types::device::IPv4State;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::system::{ServiceBanner, ServiceState};
use lanforge_types::update::{DeviceUpdate, LeaseTarget};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket as TokioUdpSocket;
use tracing::{info, warn};

use raw::RawSender;
use server::{DhcpServer, HandleResult};

use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceControl, StatusProvider};

use crate::v4::config::Dhcpv4Config;

#[lanforge_service(
    id = "dhcpv4",
    name = "DHCPv4 Server",
    critical = true,
    retries = 0,
    base_backoff = 2,
    max_backoff = 30,
    describe = format!(
        "DHCPv4 on {} ({} pools, lease {}s)",
        self.cfg.iface, self.cfg.get_effective_pools().len(), self.cfg.lease_time
    )
)]
#[derive(Clone)]
pub struct Dhcpv4Service {
    cfg: Dhcpv4Config,
    ctx: LanforgeContext,
}

impl Dhcpv4Service {
    #[must_use]
    pub fn new(cfg: Dhcpv4Config, ctx: LanforgeContext) -> Self {
        ctx.register_status_provider(Arc::new(Self {
            cfg: cfg.clone(),
            ctx: ctx.clone(),
        }));
        Self { cfg, ctx }
    }
}

impl StatusProvider for Dhcpv4Service {
    fn banner(&self) -> ServiceBanner {
        let (active_leases, pool_total, pool_available) = {
            let state = self.ctx.read();
            let leases = u32::try_from(
                state
                    .devices
                    .values()
                    .filter(|dev| matches!(dev.v4, IPv4State::Dynamic(_)))
                    .count(),
            )
            .unwrap_or(0);
            let (total, avail) = state
                .interfaces
                .v4_pool
                .as_ref()
                .map_or((0, 0), |p| (p.total, p.available));
            drop(state);
            (leases, total, avail)
        };
        let stats = vec![
            (std::borrow::Cow::Borrowed("iface"), self.cfg.iface.clone()),
            (
                std::borrow::Cow::Borrowed("lease_time"),
                self.cfg.lease_time.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("port"),
                self.cfg.port.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("leases_active"),
                active_leases.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("pool_total"),
                pool_total.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("pool_available"),
                pool_available.to_string(),
            ),
        ];
        ServiceBanner {
            name: "DHCPv4 Server".to_string(),
            state: ServiceState::Online,
            uptime_secs: self.ctx.uptime_secs(),
            stats,
        }
    }
}

impl AsyncService for Dhcpv4Service {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        // 1. Wait for DB and Interface Ready
        info!("DHCPv4: Waiting for dependencies (DB and Interfaces)...");
        self.ctx.wait_for_db().await?;
        self.ctx.wait_for_interfaces().await?;

        let mut server = DhcpServer::new(self.cfg.clone(), self.ctx.clone());

        // Pre-allocate static reservations to avoid collisions with dynamic pool
        let registry = self.ctx.get_static_registry();
        server.pool.reserve_statics(registry.v4_ips());

        let socket = bind_dhcp_socket_async(&self.cfg.iface, self.cfg.port)?;

        let mut raw_tx =
            RawSender::new(&self.cfg.iface).map_err(|e| CoreError::Generic(e.to_string()))?;

        ctrl.signal_ready();

        let mut buf = [0u8; 1500];
        let mut handle = self.ctx.service_handle();
        let mut cleanup_timer = tokio::time::interval(Duration::from_mins(1));

        loop {
            tokio::select! {
                res = socket.recv_from(&mut buf) => {
                    match res {
                        Ok((len, _)) => {
                            self.handle_incoming_packet(
                                &buf[..len],
                                &mut server,
                                &mut raw_tx,
                                &socket,
                            );
                        }
                        Err(e) => warn!("DHCPv4: recv_from error: {e}"),
                    }
                }
                event = handle.next_event() => {
                    let Some(timed_event) = event else { break; };
                    if let Err(e) = self.handle_bus_event(&timed_event.event, &mut server, &mut raw_tx) {
                        if matches!(e, CoreError::Shutdown) {
                            return Ok(());
                        }
                        warn!("DHCPv4: Bus event error: {e}");
                    }
                }
                _ = cleanup_timer.tick() => {
                    server.pool.cleanup_quarantine(std::time::Instant::now());
                    let (total, used, available, util_pct) = server.pool.stats();
                    let range_start = self.cfg.range_start.or_else(|| self.cfg.pools.first().map(|p| p.range_start)).unwrap_or(Ipv4Addr::UNSPECIFIED);
                    let range_end = self.cfg.range_end.or_else(|| self.cfg.pools.first().map(|p| p.range_end)).unwrap_or(Ipv4Addr::UNSPECIFIED);
                    let _ = self.ctx.apply(DeviceUpdate::DhcpV4PoolUpdated {
                        range_start,
                        range_end,
                        subnet_mask: self.cfg.subnet_mask,
                        total,
                        used,
                        available,
                        utilization_percent: util_pct,
                    });
                }
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
        socket: &TokioUdpSocket,
    ) {
        if let Ok(msg) = Message::decode(&mut Decoder::new(data))
            && msg.opcode() == Opcode::BootRequest
        {
            let chaddr = msg.chaddr();
            if chaddr.len() >= 6 {
                let mac = MacAddr([
                    chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5],
                ]);

                // Diagnostic: Publish DHCPv4 Transaction
                if let Some(DhcpOption::MessageType(t)) = msg.opts().get(OptionCode::MessageType) {
                    let _ = self.ctx.bus().publish(LanforgeEvent::Device(
                        DeviceEvent::DhcpV4Transaction {
                            mac,
                            msg_type: DhcpV4MessageType::from(u8::from(*t)),
                            details: None,
                        },
                    ));
                }

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
                            let _ = socket.try_send_to(&packet, relay_addr.into());
                        }

                        if let Some(assigned_ip) = server.last_assignment_for() {
                            let expires = SystemTime::now()
                                + Duration::from_secs(u64::from(self.cfg.lease_time));

                            let _ = self.ctx.apply(DeviceUpdate::V4LeaseGranted {
                                mac,
                                ip: assigned_ip,
                                expires,
                            });

                            if let Some(hostname) = req_hostname
                                && !hostname.is_empty()
                            {
                                let _ = self
                                    .ctx
                                    .apply(DeviceUpdate::DhcpHostnameHint { mac, hostname });
                            }
                        }
                    }
                    HandleResult::Release { ip: _ } => {
                        let _ = self.ctx.apply(DeviceUpdate::LeaseReleased {
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
        match event {
            LanforgeEvent::Device(DeviceEvent::LeaseRelease {
                mac,
                target: LeaseTarget::V4,
            }) => {
                info!("DHCPv4: Forcing release of {} via CLI", mac);
                let ip = self.ctx.get_device(mac).and_then(|d| d.v4.ip());
                if let Some(i) = ip {
                    server.pool.release(i);
                }
            }
            LanforgeEvent::Device(DeviceEvent::LeaseRenew {
                mac,
                target: LeaseTarget::V4,
            }) => {
                let ip = self.ctx.get_device(mac).and_then(|d| d.v4.ip());
                if let Some(ip) = ip {
                    let packet = server.build_forcerenew(*mac, ip);
                    let _ = raw_tx.send_dhcp(&packet, self.cfg.server_id, ip, *mac.as_ref());
                }
            }
            LanforgeEvent::Device(DeviceEvent::AdminUpdate { mac, change, .. }) => {
                if let AdminChange::V4StaticChanged { ip } = change.as_ref() {
                    match ip {
                        Some(v) => {
                            info!("DHCPv4: New static reservation via CLI: {mac} -> {v}");
                            server.pool.mark_declined(*v);
                            info!("DHCPv4: Handled statically.");
                        }
                        None => {
                            info!("DHCPv4: Static reservation cleared for {mac}");
                        }
                    }
                }
            }
            LanforgeEvent::System(SystemEvent::Shutdown) => {
                info!("DHCPv4: Shutdown received");
                return Err(CoreError::Shutdown);
            }
            _ => {}
        }
        Ok(())
    }
}

/// Binds a tokio UDP socket with `SO_BROADCAST` and `SO_BINDTODEVICE`.
fn bind_dhcp_socket_async(iface: &str, port: u16) -> Result<TokioUdpSocket, CoreError> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);

    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| CoreError::Generic(format!("socket(AF_INET, SOCK_DGRAM): {e}")))?;

    sock.set_reuse_address(true)
        .map_err(|e| CoreError::Generic(e.to_string()))?;
    sock.set_broadcast(true)
        .map_err(|e| CoreError::Generic(e.to_string()))?;
    sock.bind_device(Some(iface.as_bytes()))
        .map_err(|e| CoreError::Generic(format!("SO_BINDTODEVICE({iface}): {e}")))?;
    sock.set_nonblocking(true)
        .map_err(|e| CoreError::Generic(e.to_string()))?;
    sock.bind(&socket2::SockAddr::from(addr))
        .map_err(|e| CoreError::Generic(format!("bind(0.0.0.0:{port}): {e}")))?;

    let std_socket: UdpSocket = sock.into();
    TokioUdpSocket::from_std(std_socket)
        .map_err(|e| CoreError::Generic(format!("tokio UdpSocket conversion: {e}")))
}
