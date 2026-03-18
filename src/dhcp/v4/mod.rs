//! DHCPv4 service — task supervisionada que escuta na porta 67.
//!
//! Usa socket UDP com SO_BROADCAST para receber/enviar DHCP.

pub mod config;
pub mod pool;
pub mod raw;
pub mod server;

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::bus::{EventBus, LanforgeEvent};
use crate::state::{DeviceTable, MacAddr, V4Lease};
use config::Dhcpv4Config;
use raw::RawSender;
use server::{DhcpServer, HandleResult};

/// Entry point do serviço DHCPv4. Invocar via `tokio::spawn` + supervisor.
pub async fn dhcpv4_service(
    cfg: Dhcpv4Config,
    bus: Arc<EventBus>,
    table: Arc<RwLock<DeviceTable>>,
) -> Result<()> {
    info!(
        "[DHCPv4] Starting server: range {}–{}, lease {}s, router {}, server_id {}",
        cfg.range_start, cfg.range_end, cfg.lease_time, cfg.router, cfg.server_id
    );

    // Load static reservations into the pool
    let mut server = DhcpServer::new(cfg.clone());
    {
        let t = table.read().await;
        for entry in t.static_entries() {
            if let Some(ip) = entry.v4_ip {
                server.pool.add_reservation(ip, entry.mac);
                info!("[DHCPv4] Static reservation: {} → {ip}", entry.mac);
            }
        }
    }

    // Bind to 0.0.0.0:67 with SO_BROADCAST for receiving
    let socket = bind_dhcp_socket(&cfg.iface).await?;
    info!("[DHCPv4] Receiving on 0.0.0.0:67 (iface: {})", cfg.iface);

    // Initialize raw AF_PACKET sender for transmitting
    let mut raw_tx = RawSender::new(&cfg.iface)?;
    info!("[DHCPv4] Transmitting via AF_PACKET raw sock (Layer 2)");

    let mut buf = vec![0u8; 1500];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!("[DHCPv4] recv_from error: {e}");
                continue;
            }
        };

        let data = &buf[..len];
        debug!("[DHCPv4] Received {len} bytes from {src}");

        // Extract MAC before processing (for event publishing)
        let mac_bytes = if len >= 34 {
            // chaddr at offset 28 in DHCP packet
            Some([data[28], data[29], data[30], data[31], data[32], data[33]])
        } else {
            None
        };

        match server.handle_packet(data) {
            HandleResult::Reply(reply, broadcast, dst_ip, req_hostname) => {
                let (final_dst_ip, dst_mac_arr) = if broadcast {
                    (Ipv4Addr::BROADCAST, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
                } else {
                    let mac = mac_bytes.unwrap_or([0xff; 6]);
                    (dst_ip, mac)
                };

                if let Err(e) = raw_tx.send_dhcp(&reply, cfg.server_id, final_dst_ip, dst_mac_arr) {
                    error!("[DHCPv4] AF_PACKET injection error: {e}");
                    continue;
                }

                // Update DeviceTable and publish events
                if let Some(mac_raw) = mac_bytes {
                    let mac = MacAddr(mac_raw);
                    if let Some(assigned_ip) = server.last_assignment_for(&mac) {
                        let mut final_hostname = req_hostname.unwrap_or_default();

                        // Update DeviceTable with the lease
                        {
                            let mut t = table.write().await;
                            let dev = t.get_or_insert(mac);
                            dev.v4 = Some(V4Lease {
                                ip: assigned_ip,
                                expires: std::time::SystemTime::now()
                                    + std::time::Duration::from_secs(cfg.lease_time as u64),
                            });
                            dev.last_seen = std::time::SystemTime::now();

                            // Use dynamic hostname if no static hostname exists
                            if dev.hostname.is_empty() && !final_hostname.is_empty() {
                                dev.hostname = final_hostname.clone();
                            } else {
                                // Prefer the existing hostname (static or learned earlier) for the event
                                final_hostname = dev.hostname.clone();
                            }
                        }

                        bus.publish(LanforgeEvent::LeaseGranted {
                            mac: mac_raw,
                            ip: std::net::IpAddr::V4(assigned_ip),
                            hostname: final_hostname,
                        });
                        bus.publish(LanforgeEvent::DeviceTableDirty);
                    }
                }
            }
            HandleResult::Ignore => {}
        }
    }
}

/// Bind a UDP socket to port 67 with SO_BROADCAST and SO_BINDTODEVICE.
async fn bind_dhcp_socket(iface: &str) -> Result<UdpSocket> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 67);

    // Use socket2 for SO_REUSEADDR + SO_BROADCAST + SO_BINDTODEVICE before converting to tokio
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .context("socket(AF_INET, SOCK_DGRAM)")?;

    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;

    // SO_BINDTODEVICE — ensures we only see packets from the LAN interface
    sock.bind_device(Some(iface.as_bytes()))
        .context("SO_BINDTODEVICE")?;

    sock.bind(&socket2::SockAddr::from(addr))
        .context("bind(0.0.0.0:67)")?;

    let std_socket: std::net::UdpSocket = sock.into();
    let tokio_socket = UdpSocket::from_std(std_socket).context("UdpSocket::from_std")?;

    Ok(tokio_socket)
}
