use anyhow::{Context, Result};
use rtnetlink::Handle;
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
    nl_handle: &Handle,
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

    // Configura para apenas uso IPv6
    socket
        .set_only_v6(true)
        .context("Failed to set IPV6_V6ONLY")?;
    socket
        .bind(&addr.into())
        .context("Failed to bind DHCPv6 port 547")?;

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

    // Lê o MAC real da interface (ex: "end0") para gerar um DUID legítimo
    let mac_str = std::fs::read_to_string(format!("/sys/class/net/{}/address", config.iface))
        .unwrap_or_else(|_| "02:04:06:08:0a:0c\n".to_string());

    let mut server_mac = [0u8; 6];
    let mac_bytes: Vec<u8> = mac_str
        .trim()
        .split(':')
        .filter_map(|x| u8::from_str_radix(x, 16).ok())
        .collect();
    if mac_bytes.len() == 6 {
        server_mac.copy_from_slice(&mac_bytes);
    }

    let mut server = Dhcpv6Server::new(
        config.clone(),
        Ipv6Pool::new(config.range_start, config.range_end, config.ula_prefix),
        Duid::generate_ll_from_mac(&server_mac), // <-- DUID Legítimo e dinâmico!
    );

    {
        let t = table.read().await;
        for entry in t.static_entries() {
            if let Some(suffix) = &entry.v6_suffix {
                // Junta o ULA da rede com o sufixo do TOML
                if let Some(ip) = server.pool.construct_static_ula(suffix) {
                    server.pool.add_reservation(ip, entry.mac);
                    tracing::info!("[DHCPv6] Static reservation: {} → {}", entry.mac, ip);
                } else {
                    tracing::warn!("[DHCPv6] Falha ao construir ULA para o sufixo: {}", suffix);
                }
            }
        }
    }

    let mut buf = [0u8; 2048];

    info!("[DHCPv6] State Machine started");

    loop {
        match udp.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let payload = &buf[..len];

                // 1. Extrai o IP puro e o scope_id
                let (peer_ip, scope_id) = match peer {
                    std::net::SocketAddr::V6(v6) => (*v6.ip(), v6.scope_id()),
                    _ => continue,
                };

                match server
                    .handle_packet(payload, peer_ip, &table, nl_handle)
                    .await
                {
                    HandleResult::Reply(reply_bytes, dest_ip, learned_duid, opt_mac) => {
                        // 2. Constrói a resposta usando SocketAddrV6 e INJETANDO o scope_id
                        let dest_addr = std::net::SocketAddrV6::new(dest_ip, 546, 0, scope_id);

                        // Agora o .send_to sabe exatamente por qual interface cuspir o pacote!
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
