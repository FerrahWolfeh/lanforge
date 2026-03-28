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

use crate::error::{NetworkError, Result};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

use config::Dhcpv4Config;
use dhcproto::v4::{Message, Opcode};
use dhcproto::{Decodable, Decoder};
use lanforge_core::bus::{DeviceChange, LanforgeEvent, ManagedTable};
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::update::DeviceUpdate;
use raw::RawSender;
use server::{DhcpServer, HandleResult};

pub async fn dhcpv4_service(cfg: Dhcpv4Config, table: Arc<ManagedTable>) -> Result<()> {
    info!(
        "Starting DHCPv4: range {}–{}, lease {}s, router {}, server_id {}",
        cfg.range_start, cfg.range_end, cfg.lease_time, cfg.router, cfg.server_id
    );

    // Load static reservations into the pool
    let mut server = DhcpServer::new(cfg.clone());
    {
        let t = table.read();
        for entry in t.static_entries() {
            if let Some(ip) = entry.v4_ip {
                server.pool.add_reservation(ip, entry.mac);
                info!(
                    "Static reservation: {} ({}) → {ip}",
                    entry.mac, entry.hostname
                );
            }
        }
    }

    let socket = bind_dhcp_socket(&cfg.iface)?;
    info!("Receiving on 0.0.0.0:67 (iface: {})", cfg.iface);

    let mut raw_tx = RawSender::new(&cfg.iface)?;
    info!("Transmitting via AF_PACKET raw socket (Layer 2 injection)");

    let mut buf = vec![0u8; 1500];
    let mut bus_rx = table.bus().subscribe();

    // Timer for periodic lease cleanup (every 1 minute)
    let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        tokio::select! {
            // -- DHCP Messages from the network --
            res = socket.recv_from(&mut buf) => {
                let (len, _src) = match res {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("recv_from error: {e}");
                        continue;
                    }
                };

                let data = &buf[..len];

                // 1. Decode outside the lock to reduce contention
                let msg = match Message::decode(&mut Decoder::new(data)) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                if msg.opcode() != Opcode::BootRequest {
                    continue;
                }

                let chaddr = msg.chaddr();
                if chaddr.len() < 6 { continue; }
                let mac = MacAddr([chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]]);

                // 2. Short lock only for logic processing and IP allocation
                let handle_res = {
                    let t = table.read();
                    server.handle_packet(data, Some(&t))
                };

                // 3. I/O outside the lock
                match handle_res {
                    HandleResult::Reply { packet, broadcast, dest_ip, giaddr, hostname: req_hostname } => {
                        // RFC 2131: If giaddr != 0, send via UDP unicast to the relay agent
                        if giaddr != Ipv4Addr::UNSPECIFIED {
                            let relay_addr = SocketAddrV4::new(giaddr, 67);
                            if let Err(e) = socket.send_to(&packet, relay_addr).await {
                                error!("Failed to send to relay {giaddr}: {e}");
                            }
                        } else {
                            // Otherwise, use Layer 2 for local clients without an IP
                            let (final_dst_ip, dst_mac_arr) = if broadcast {
                                (Ipv4Addr::BROADCAST, [0xff; 6])
                            } else {
                                (dest_ip, *mac.as_ref())
                            };

                            if let Err(e) = raw_tx.send_dhcp(&packet, cfg.server_id, final_dst_ip, dst_mac_arr) {
                                error!("AF_PACKET injection error: {e}");
                                continue;
                            }
                        }

                        // Update the global table (triggers EventBus events)
                        if let Some(assigned_ip) = server.last_assignment_for(mac) {
                            let expires = SystemTime::now() + Duration::from_secs(u64::from(cfg.lease_time));
                            table.update(DeviceUpdate::V4LeaseGranted { mac, ip: assigned_ip, expires }).await;

                            if let Some(hostname) = req_hostname && !hostname.is_empty() {
                                table.update(DeviceUpdate::HostnameHint { mac, hostname }).await;
                            }
                        }
                    }
                    HandleResult::Ignore => {}
                }
            }

            // -- Periodic Cleanup --
            _ = cleanup_interval.tick() => {
                server.pool.cleanup_expired_leases(SystemTime::now());
            }

            // -- Commands from Admin via CLI/Bus --
            event = bus_rx.recv() => {
                match event {
                    Ok(LanforgeEvent::LeaseRelease { mac }) => {
                        info!("DHCPv4: Forcing release of {} via CLI", mac);
                        server.pool.release_mac(mac);
                    }
                    Ok(LanforgeEvent::DeviceUpdated { mac, change: DeviceChange::V4StaticChanged { ip } }) => {
                        match ip {
                            Some(v) => {
                                info!("DHCPv4: New static reservation via CLI: {mac} -> {v}");
                                server.pool.add_reservation(v, mac);
                            }
                            None => {
                                info!("DHCPv4: Static reservation removed via CLI: {mac}");
                                server.pool.release_mac(mac);
                            }
                        }
                    }
                    Ok(LanforgeEvent::Shutdown) => break,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

/// Binds UDP to port 67 with `SO_BROADCAST` and `SO_BINDTODEVICE`.
fn bind_dhcp_socket(iface: &str) -> Result<UdpSocket> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 67);

    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|e| NetworkError::Socket(format!("socket(AF_INET, SOCK_DGRAM): {e}")))?;

    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;

    sock.bind_device(Some(iface.as_bytes()))
        .map_err(|e| NetworkError::Socket(format!("SO_BINDTODEVICE({iface}): {e}")))?;

    sock.bind(&socket2::SockAddr::from(addr))
        .map_err(|e| NetworkError::Socket(format!("bind(0.0.0.0:67): {e}")))?;

    let std_socket: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_socket)
        .map_err(|e| NetworkError::Socket(format!("UdpSocket::from_std: {e}")))
}
