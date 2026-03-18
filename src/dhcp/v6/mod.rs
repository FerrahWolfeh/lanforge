use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::bus::{EventBus, LanforgeEvent};
use crate::state::DeviceTable;
use config::Dhcpv6Config;
use duid::Duid;
use pool::Ipv6Pool;
use server::{Dhcpv6Server, HandleResult};

pub mod config;
pub mod duid;
pub mod pool;
pub mod server;

const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// Inicia o serviço DHCPv6 (porta UDP 547, multicast ff02::1:2).
pub async fn dhcpv6_service(
    config: Dhcpv6Config,
    table: Arc<RwLock<DeviceTable>>,
    bus: Arc<EventBus>,
) -> Result<()> {
    if !config.enabled {
        info!("[DHCPv6] DHCPv6 is disabled in config.");
        return std::future::pending().await;
    }

    // Configura o socket UDP para IPv6 (V6Only true)
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create IPv6 UDP socket")?;

    // Bind à porta 547 (qualquer IP)
    let addr = std::net::SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED), 547);
    socket
        .bind(&addr.into())
        .context("Failed to bind DHCPv6 port 547")?;

    // Configura para apenas uso IPv6
    socket.set_only_v6(true)?;

    // Junta-se ao grupo multicast ff02::1:2
    // Obter index da interface não é estritamente obrigatório em todas as OS, mas recomendado se soubermos a iface
    // Para simplificar a POC, juntamos na iface 0 (todas as interfaces)
    if let Err(e) = socket.join_multicast_v6(&ALL_DHCP_RELAY_AGENTS_AND_SERVERS, 0) {
        warn!("[DHCPv6] Failed to join DHCPv6 multicast group ff02::1:2 - check iface config: {e}");
    }

    let udp = std::net::UdpSocket::from(socket);
    udp.set_nonblocking(true)?;
    let udp = UdpSocket::from_std(udp)?;

    info!(
        "[DHCPv6] Server listening on UDP [ff02::1:2]:547 (interface {})",
        config.iface
    );

    let mut server = Dhcpv6Server::new(
        config.clone(),
        Ipv6Pool::new(vec![], config.ula_prefix),
        Duid::new(vec![
            0x00, 0x03, 0x00, 0x01, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c,
        ]),
    );

    let mut buf = [0u8; 2048];

    info!("[DHCPv6] State Machine started");

    loop {
        match udp.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let payload = &buf[..len];
                let peer_ip = match peer.ip() {
                    std::net::IpAddr::V6(ip) => ip,
                    _ => continue,
                };

                match server.handle_packet(payload, peer_ip) {
                    HandleResult::Reply(reply_bytes, dest_ip, learned_duid, opt_mac) => {
                        let dest_addr =
                            std::net::SocketAddr::new(std::net::IpAddr::V6(dest_ip), 546);
                        if let Err(e) = udp.send_to(&reply_bytes, dest_addr).await {
                            warn!("[DHCPv6] send error to {dest_ip} (port 546): {e}");
                        }

                        if let (Some(mac), Some(duid)) = (opt_mac, learned_duid) {
                            bus.publish(LanforgeEvent::DuidLearned {
                                mac: mac.0,
                                duid: duid.bytes.clone(),
                            });

                            let mut t = table.write().await;
                            t.set_duid(mac, duid);
                        }

                        if let Some(mac) = opt_mac
                            && let Some(ip) = server.last_assignment_for(&mac)
                        {
                            let hostname = {
                                let mut t = table.write().await;
                                let dev = t.get_or_insert(mac);
                                dev.v6 = Some(crate::state::V6Lease {
                                    ip,
                                    expires: std::time::SystemTime::now()
                                        + std::time::Duration::from_secs(config.lease_time as u64),
                                });
                                dev.hostname.clone()
                            };
                            bus.publish(LanforgeEvent::LeaseGranted {
                                mac: mac.0,
                                ip: std::net::IpAddr::V6(ip),
                                hostname,
                            });
                            bus.publish(LanforgeEvent::DeviceTableDirty);
                        }
                    }
                    HandleResult::Ignore => {}
                }
            }
            Err(e) => {
                warn!("[DHCPv6] recv error: {e}");
            }
        }
    }
}
