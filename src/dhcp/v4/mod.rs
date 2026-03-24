//! `DHCPv4` service — Gerenciamento de endereços IPv4 dinâmicos (RFC 2131).
//!
//! Este serviço escuta solicitações na porta 67/UDP e gerencia um pool de
//! endereços, suportando reservas estáticas baseadas em MAC.
//!
//! ## Ciclo DORA (Discovery, Offer, Request, Ack)
//!
//! ```text
//! Pacote DHCP recebido
//!     └─► DhcpServer::handle_packet()
//!               │
//!               ▼
//!     DeviceUpdate::V4LeaseGranted   ← IP + expiração
//!     DeviceUpdate::HostnameHint     ← opção 12 (se presente)
//!               │
//!               ▼
//!         ManagedTable::update()
//!               │
//!     ┌─────────┴──────────┐
//!     ▼                    ▼
//! DeviceDiscovered    DeviceUpdated   (publicados no EventBus automaticamente)
//! ```
//!
//! ## Integração com o Manager
//!
//! O `dhcpv4_service` utiliza o `ManagedTable` para persistir leases e sugerir
//! hostnames aprendidos via Option 12. O merging de estado e a emissão de
//! eventos no `EventBus` são feitos automaticamente pelo `ManagedTable`.

pub mod config;
pub mod pool;
pub mod raw;
pub mod server;

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

use crate::bus::ManagedTable;
use crate::state::{DeviceUpdate, MacAddr};
use config::Dhcpv4Config;
use raw::RawSender;
use server::{DhcpServer, HandleResult};

/// Entry point do serviço `DHCPv4`. Invocar via `tokio::spawn` + supervisor.
pub async fn dhcpv4_service(cfg: Dhcpv4Config, table: Arc<ManagedTable>) -> Result<()> {
    info!(
        "Starting DHCPv4: range {}–{}, lease {}s, router {}, server_id {}",
        cfg.range_start, cfg.range_end, cfg.lease_time, cfg.router, cfg.server_id
    );

    // Carrega reservas estáticas no pool
    let mut server = DhcpServer::new(cfg.clone());
    {
        let t = table.read().await;
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
    info!("Transmitting via AF_PACKET raw sock (Layer 2)");

    let mut buf = vec![0u8; 1500];
    let mut bus_rx = table.bus().subscribe();

    loop {
        tokio::select! {
            // -- Mensagens DHCP vindas da rede --
            res = socket.recv_from(&mut buf) => {
                let (len, _src) = match res {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("recv_from error: {e}");
                        continue;
                    }
                };

                let data = &buf[..len];
                // chaddr começa no offset 28 do pacote DHCP
                let mac = if len >= 34 {
                    MacAddr([data[28], data[29], data[30], data[31], data[32], data[33]])
                } else {
                    continue;
                };

                let res = {
                    let t = table.read().await;
                    server.handle_packet(data, Some(&t))
                };

                match res {
                    HandleResult::Reply(reply, broadcast, dst_ip, req_hostname) => {
                        let (final_dst_ip, dst_mac_arr) = if broadcast {
                            (Ipv4Addr::BROADCAST, [0xff; 6])
                        } else {
                            (dst_ip, *mac.as_ref())
                        };

                        if let Err(e) = raw_tx.send_dhcp(&reply, cfg.server_id, final_dst_ip, dst_mac_arr) {
                            error!("AF_PACKET injection error: {e}");
                            continue;
                        }

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

            // -- Comandos vindos do Admin via CLI/Bus --
            event = bus_rx.recv() => {
                match event {
                    Ok(crate::bus::LanforgeEvent::LeaseRelease { mac }) => {
                        info!("DHCPv4: Forcing release of {} via CLI", mac);
                        server.pool.release_mac(mac);
                    }
                    Ok(crate::bus::LanforgeEvent::Shutdown) => break,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

/// Bind UDP na porta 67 com `SO_BROADCAST` e `SO_BINDTODEVICE`.
fn bind_dhcp_socket(iface: &str) -> Result<UdpSocket> {
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 67);

    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .context("socket(AF_INET, SOCK_DGRAM)")?;

    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;

    sock.bind_device(Some(iface.as_bytes()))
        .context("SO_BINDTODEVICE")?;

    sock.bind(&socket2::SockAddr::from(addr))
        .context("bind(0.0.0.0:67)")?;

    let std_socket: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_socket).context("UdpSocket::from_std")
}
