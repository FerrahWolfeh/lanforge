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
use lanforge_core::bus::{DeviceChange, LanforgeEvent, ManagedTable};
use lanforge_core::device::IPv4State;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::update::DeviceUpdate;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tracing::{error, info, warn};

use raw::RawSender;
use server::{DhcpServer, HandleResult};

use crate::dhcp::v4::config::Dhcpv4Config;
use crate::error::NetworkError;

pub fn dhcpv4_service(
    cfg: Dhcpv4Config,
    table: Arc<ManagedTable>,
    bus_rx: std::sync::mpsc::Receiver<LanforgeEvent>,
) -> Result<(), NetworkError> {
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

    let socket = bind_dhcp_socket(&cfg.iface, cfg.port)?;
    info!("Receiving on 0.0.0.0:{} (iface: {})", cfg.port, cfg.iface);

    let mut raw_tx = RawSender::new(&cfg.iface)?;
    info!("Transmitting via AF_PACKET raw socket (Layer 2 injection)");

    // Startup Sync: Send ForceRenew to active dynamic leases to synchronize client state
    {
        let to_renew = {
            let t = table.read();
            t.devices()
                .filter_map(|dev| {
                    if let IPv4State::Dynamic(lease) = &dev.v4 {
                        Some((dev.mac, lease.ip))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };

        let mut count = 0;
        for (mac, ip) in to_renew {
            let packet = server.build_forcerenew(mac, ip);
            if let Err(e) = raw_tx.send_dhcp(&packet, cfg.server_id, ip, *mac.as_ref()) {
                error!("DHCPv4: Failed to send startup FORCERENEW to {mac}: {e}");
            } else {
                count += 1;
            }
            // Small delay to prevent network/client storm
            std::thread::sleep(Duration::from_millis(50));
        }

        if count > 0 {
            info!("DHCPv4: Triggered refresh (FORCERENEW) for {count} devices");
        }
    }

    let mut buf = vec![0u8; 1500];
    let mut last_cleanup = Instant::now();

    // Set a read timeout to allow checking the bus_rx channel periodically
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(NetworkError::Io)?;

    loop {
        // 1. Process network packets
        match socket.recv_from(&mut buf) {
            Ok((len, _src)) => {
                let data = &buf[..len];

                // Decode outside the lock to reduce contention
                let msg = match Message::decode(&mut Decoder::new(data)) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                if msg.opcode() != Opcode::BootRequest {
                    continue;
                }

                let chaddr = msg.chaddr();
                if chaddr.len() < 6 {
                    continue;
                }
                let mac = MacAddr([
                    chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5],
                ]);

                // Short lock only for logic processing and IP allocation
                let handle_res = {
                    let t = table.read();
                    server.handle_packet(data, Some(&t))
                };

                match handle_res {
                    HandleResult::Reply {
                        packet,
                        broadcast,
                        dest_ip,
                        giaddr,
                        hostname: req_hostname,
                    } => {
                        // RFC 2131: If giaddr != 0, send via UDP unicast to the relay agent
                        if giaddr != Ipv4Addr::UNSPECIFIED {
                            let relay_addr = SocketAddrV4::new(giaddr, cfg.port);
                            if let Err(e) = socket.send_to(&packet, relay_addr) {
                                error!("Failed to send to relay {giaddr}: {e}");
                            }
                        } else {
                            // Otherwise, use Layer 2 for local clients without an IP
                            let (final_dst_ip, dst_mac_arr) = if broadcast {
                                (Ipv4Addr::BROADCAST, [0xff; 6])
                            } else {
                                (dest_ip, *mac.as_ref())
                            };

                            if let Err(e) =
                                raw_tx.send_dhcp(&packet, cfg.server_id, final_dst_ip, dst_mac_arr)
                            {
                                error!("AF_PACKET injection error: {e}");
                                continue;
                            }
                        }

                        // Update the global table (triggers EventBus events)
                        if let Some(assigned_ip) = server.last_assignment_for(mac) {
                            let expires =
                                SystemTime::now() + Duration::from_secs(u64::from(cfg.lease_time));
                            let _ = table.update(DeviceUpdate::V4LeaseGranted {
                                mac,
                                ip: assigned_ip,
                                expires,
                            });

                            if let Some(hostname) = req_hostname
                                && !hostname.is_empty()
                            {
                                let _ =
                                    table.update(DeviceUpdate::DhcpHostnameHint { mac, hostname });
                            }
                        }
                    }
                    HandleResult::Ignore => {}
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Timeout, continue to check bus
            }
            Err(e) => {
                warn!("DHCPv4: recv_from error: {e}");
            }
        }

        // 2. Process Bus events
        while let Ok(event) = bus_rx.try_recv() {
            match event {
                LanforgeEvent::LeaseRelease { mac } => {
                    info!("DHCPv4: Forcing release of {} via CLI", mac);
                    server.pool.release_mac(mac);
                }
                LanforgeEvent::LeaseRenew { mac } => {
                    let ip = {
                        let t = table.read();
                        t.get_device(&mac).and_then(|d| d.v4.ip())
                    };
                    if let Some(ip) = ip {
                        info!("DHCPv4: Sending manual FORCERENEW to {} ({})", ip, mac);
                        let packet = server.build_forcerenew(mac, ip);
                        if let Err(e) = raw_tx.send_dhcp(&packet, cfg.server_id, ip, *mac.as_ref())
                        {
                            error!("DHCPv4: Failed to send manual FORCERENEW: {e}");
                        }
                    }
                }
                LanforgeEvent::DeviceUpdated {
                    mac,
                    change: DeviceChange::V4StaticChanged { ip },
                } => match ip {
                    Some(v) => {
                        info!("DHCPv4: New static reservation via CLI: {mac} -> {v}");
                        server.pool.add_reservation(v, mac);
                    }
                    None => {
                        info!("DHCPv4: Static reservation removed via CLI: {mac}");
                        server.pool.release_mac(mac);
                    }
                },
                LanforgeEvent::Shutdown => {
                    info!("DHCPv4: Shutdown recebido");
                    return Ok(());
                }
                _ => {}
            }
        }

        // 3. Periodic Cleanup
        if last_cleanup.elapsed() >= Duration::from_secs(60) {
            server.pool.cleanup_expired_leases(SystemTime::now());
            last_cleanup = Instant::now();
        }
    }
}

/// Binds UDP with `SO_BROADCAST` and `SO_BINDTODEVICE`.
fn bind_dhcp_socket(iface: &str, port: u16) -> Result<UdpSocket, NetworkError> {
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
