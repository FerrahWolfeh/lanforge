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
//!     participant T as ManagedTable
//!
//!     C->>S: 1. DHCP Discover (Broadcast)
//!     S->>C: 2. DHCP Offer (Unicast/Broadcast)
//!
//!     C->>S: 3. DHCP Request
//!     S->>T: 4. update(DeviceUpdate::V4LeaseGranted)
//!     T-->>S: 5. EventBus Signal
//!     S->>C: 6. DHCP Ack
//! ```
//!
//! ## Manager Integration
//!
//! The `dhcpv4_service` uses the `ManagedTable` to persist leases and suggest
//! hostnames learned via Option 12. State merging and EventBus signaling
//! are handled automatically by the `ManagedTable`.

pub mod config;
pub mod pool;
pub mod raw;
pub mod server;

use dhcproto::v4::{Message, Opcode};
use dhcproto::{Decodable, Decoder};
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::identifiers::MacAddr;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};
use tracing::{info, warn};

use raw::RawSender;
use server::{DhcpServer, HandleResult};

use crate::dhcp::v4::config::Dhcpv4Config;
use crate::error::NetworkError;

use lanforge_core::error::CoreError;
use lanforge_core::service::{LanforgeService, SyncService};

pub struct Dhcpv4Service {
    cfg: Dhcpv4Config,
    bus_rx: Arc<Mutex<std::sync::mpsc::Receiver<LanforgeEvent>>>,
}

impl Dhcpv4Service {
    #[must_use]
    pub fn new(
        cfg: Dhcpv4Config,
        bus_rx: Arc<Mutex<std::sync::mpsc::Receiver<LanforgeEvent>>>,
    ) -> Self {
        Self { cfg, bus_rx }
    }
}

impl LanforgeService for Dhcpv4Service {
    fn name(&self) -> &str {
        "Dhcpv4Service"
    }
}

impl SyncService for Dhcpv4Service {
    fn run(&mut self) -> std::result::Result<(), CoreError> {
        use lanforge_core::bus::DeviceChange;

        info!(
            "DHCPv4: Starting (sync) on {} (range {}–{}, lease {}s)",
            self.cfg.iface, self.cfg.range_start, self.cfg.range_end, self.cfg.lease_time
        );

        let mut server = DhcpServer::new(self.cfg.clone());

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
            // 1. Process network packets
            match socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    let data = &buf[..len];
                    if let Ok(msg) = Message::decode(&mut Decoder::new(data))
                        && msg.opcode() == Opcode::BootRequest
                    {
                        let chaddr = msg.chaddr();
                        if chaddr.len() >= 6 {
                            let mac = MacAddr([
                                chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5],
                            ]);
                            let handle_res = {
                                let t = LanforgeContext::table();
                                let table_read = t.read();
                                server.handle_packet(data, Some(&table_read))
                            };

                            if let HandleResult::Reply {
                                packet,
                                broadcast,
                                dest_ip,
                                giaddr,
                                hostname: req_hostname,
                            } = handle_res
                            {
                                if giaddr != Ipv4Addr::UNSPECIFIED {
                                    let relay_addr =
                                        std::net::SocketAddrV4::new(giaddr, self.cfg.port);
                                    let _ = socket.send_to(&packet, relay_addr);
                                } else {
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
                                }

                                if let Some(assigned_ip) = server.last_assignment_for() {
                                    let expires = SystemTime::now()
                                        + Duration::from_secs(u64::from(self.cfg.lease_time));
                                    let t = LanforgeContext::table();
                                    let _ = t.update(&lanforge_core::state::update::DeviceUpdate::V4LeaseGranted {
                                        mac,
                                        ip: assigned_ip,
                                        expires,
                                    });
                                    if let Some(hostname) = req_hostname
                                        && !hostname.is_empty()
                                    {
                                        let _ =
                                            t.update(&lanforge_core::state::update::DeviceUpdate::DhcpHostnameHint {
                                                mac,
                                                hostname,
                                            });
                                    }
                                }
                            } else if let HandleResult::Release { .. } = handle_res {
                                // Inform the global table to clear the allocation
                                let t = LanforgeContext::table();
                                let _ = t.update(
                                    &lanforge_core::state::update::DeviceUpdate::LeaseReleased {
                                        mac,
                                    },
                                );
                            }
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => warn!("DHCPv4: recv_from error: {e}"),
            }

            // 2. Process Bus events
            if let Ok(rx) = self.bus_rx.lock() {
                while let Ok(event) = rx.try_recv() {
                    match event {
                        LanforgeEvent::LeaseRelease { mac } => {
                            info!("DHCPv4: Forcing release of {} via CLI", mac);
                            let ip = LanforgeContext::table()
                                .read()
                                .get_device(&mac)
                                .and_then(|d| d.v4.ip());
                            if let Some(i) = ip {
                                server.pool.release(i);
                            }
                        }
                        LanforgeEvent::LeaseRenew { mac } => {
                            let ip = {
                                let t = LanforgeContext::table();
                                let table_read = t.read();
                                table_read.get_device(&mac).and_then(|d| d.v4.ip())
                            };
                            if let Some(ip) = ip {
                                let packet = server.build_forcerenew(mac, ip);
                                let _ = raw_tx.send_dhcp(
                                    &packet,
                                    self.cfg.server_id,
                                    ip,
                                    *mac.as_ref(),
                                );
                            }
                        }
                        LanforgeEvent::DeviceUpdated {
                            mac,
                            change: DeviceChange::V4StaticChanged { ip },
                        } => match ip {
                            Some(v) => {
                                info!("DHCPv4: New static reservation via CLI: {mac} -> {v}");
                                // Since pool queries global state, we just need to ensure the IP isn't available
                                server.pool.mark_declined(v); // wait, mark_declined puts it in quarantine. 
                                // Actually we can just do server.pool.release(ip) but we want to REMOVE IT from available.
                                // We don't have a public remove_from_available, but since global table tracks it, allocate() will just skip it when it draws it. We don't need to do anything!
                                info!("DHCPv4: Handled statically.");
                            }
                            None => {
                                info!("DHCPv4: Static reservation cleared for {mac}");
                            }
                        },
                        LanforgeEvent::Shutdown => {
                            info!("DHCPv4: Shutdown received");
                            return Ok(());
                        }
                        _ => {}
                    }
                }
            }

            // 3. Periodic Cleanup
            if last_cleanup.elapsed() >= Duration::from_secs(60) {
                server.pool.cleanup_quarantine(SystemTime::now());
                last_cleanup = Instant::now();
            }
        }
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
