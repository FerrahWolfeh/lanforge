//! DHCPv6 service — Gerenciamento de endereços IPv6 dinâmicos (RFC 8415).
//!
//! Este serviço gerencia a atribuição de endereços IPv6 via DHCPv6 (Stateful),
//! servindo como alternativa ou complemento ao SLAAC.
//!
//! ## Ciclo SARR (Solicit, Advertise, Request, Reply)
//!
//! ```text
//! Pacote DHCPv6 recebido
//!     └─► Dhcpv6Server::handle_packet()
//!               │
//!               ▼
//!     HandleResult::Reply(bytes, dest, opt_duid, opt_mac)
//!               │
//!       ┌───────┴────────────────────┐
//!       │ tem mac + duid + ip        │ tem mac + duid, sem ip
//!       ▼                            ▼
//!   V6LeaseGranted              DuidAssociated
//!       │                            │
//!       └───────────┬────────────────┘
//!                   ▼
//!           ManagedTable::update()
//!           (Manager decide, EventBus notifica)
//! ```
//!
//! ## Integração com o Manager
//!
//! O `dhcpv6_service` reporta DUIDs e concessões de IP ao `ManagedTable`.
//! Diferente do v4, o DHCPv6 depende fortemente do DUID para identificação
//! persistente do cliente, mesmo que o MAC mude ou não esteja disponível.

pub mod config;
pub mod duid;
pub mod pool;
pub mod server;

use anyhow::{Context, Result};
use rtnetlink::Handle;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;
use tracing::{info, warn};

use crate::bus::ManagedTable;
use crate::state::{DeviceUpdate, MacAddr};
use config::Dhcpv6Config;
use duid::Duid;
use pool::Ipv6Pool;
use server::{Dhcpv6Server, HandleResult};

const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// Inicia o serviço DHCPv6 (porta UDP 547, multicast ff02::1:2).
pub async fn dhcpv6_service(
    config: Dhcpv6Config,
    table: Arc<ManagedTable>,
    nl_handle: &Handle,
) -> Result<()> {
    if !config.enabled {
        info!("DHCPv6 is disabled in config.");
        return std::future::pending().await;
    }

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .context("Failed to create IPv6 UDP socket")?;

    let addr = std::net::SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED), 547);

    socket.set_only_v6(true).context("IPV6_V6ONLY")?;
    socket.bind(&addr.into()).context("bind :547")?;

    if let Err(e) = socket.join_multicast_v6(&ALL_DHCP_RELAY_AGENTS_AND_SERVERS, 0) {
        warn!("Failed to join ff02::1:2: {e}");
    }

    let udp: std::net::UdpSocket = socket.into();
    udp.set_nonblocking(true)?;
    let udp = UdpSocket::from_std(udp)?;

    info!(
        "DHCPv6 listening on [ff02::1:2]:547 (iface: {})",
        config.iface
    );

    // Lê o MAC da interface para gerar um DUID legítimo
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
        Duid::generate_ll_from_mac(&server_mac),
    );

    {
        let t = table.read().await;
        for entry in t.static_entries() {
            if let Some(suffix) = &entry.v6_suffix {
                if let Some(ip) = server.pool.construct_static_ula(suffix) {
                    server.pool.add_reservation(ip, entry.mac);
                    info!("Static reservation: {} → {}", entry.mac, ip);
                } else {
                    warn!("Falha ao construir ULA para sufixo: {}", suffix);
                }
            }
        }
    }

    let mut buf = [0u8; 2048];
    info!("DHCPv6 state machine started");

    loop {
        match udp.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let payload = &buf[..len];

                let (peer_ip, scope_id) = match peer {
                    std::net::SocketAddr::V6(v6) => (*v6.ip(), v6.scope_id()),
                    _ => continue,
                };

                match server
                    .handle_packet(payload, peer_ip, &table, nl_handle)
                    .await
                {
                    HandleResult::Reply(reply_bytes, dest_ip, learned_duid, opt_mac) => {
                        let dest_addr = std::net::SocketAddrV6::new(dest_ip, 546, 0, scope_id);

                        if let Err(e) = udp.send_to(&reply_bytes, dest_addr).await {
                            warn!("send error to {dest_ip}: {e}");
                        }

                        // Reporta ao Manager o que foi aprendido neste ciclo
                        apply_learned_state(&table, opt_mac, learned_duid, &server, &config).await;
                    }
                    HandleResult::Ignore => {}
                }
            }
            Err(e) => {
                warn!("recv error: {e}");
            }
        }
    }
}

/// Traduz o resultado de um ciclo DHCP em `DeviceUpdate`s para o Manager.
///
/// Separado do loop principal para clareza — toda a lógica de "o que
/// aprendemos com este pacote" fica aqui, sem misturar com I/O de rede.
async fn apply_learned_state(
    table: &ManagedTable,
    opt_mac: Option<MacAddr>,
    learned_duid: Option<Duid>,
    server: &Dhcpv6Server,
    config: &Dhcpv6Config,
) {
    let Some(mac) = opt_mac else { return };

    let assigned_ip = server.last_assignment_for(&mac);

    match (learned_duid, assigned_ip) {
        (Some(duid), Some(ip)) => {
            // Caso completo: DUID conhecido + IP alocado → lease v6
            let expires = SystemTime::now() + Duration::from_secs(config.lease_time as u64);
            table
                .update(DeviceUpdate::V6LeaseGranted {
                    mac,
                    duid,
                    ip,
                    expires,
                })
                .await;
        }
        (Some(duid), None) => {
            // DUID aprendido mas ainda sem IP (ex: Advertise sem Rapid Commit)
            table
                .update(DeviceUpdate::DuidAssociated { mac, duid })
                .await;
        }
        (None, Some(ip)) => {
            // IP renovado sem novo DUID (Renew/Rebind de device já conhecido)
            let expires = SystemTime::now() + Duration::from_secs(config.lease_time as u64);
            // Recupera o DUID existente do Manager, se houver
            let existing_duid = table.read().await.find_duid_by_mac(mac).cloned();
            if let Some(duid) = existing_duid {
                table
                    .update(DeviceUpdate::V6LeaseGranted {
                        mac,
                        duid,
                        ip,
                        expires,
                    })
                    .await;
            }
            // Se não tem DUID nem no Manager, não temos como emitir V6LeaseGranted completo.
            // O device já existe (foi criado em ciclo anterior), last_seen será atualizado
            // pelo NdpSeen do netlink naturalmente.
        }
        (None, None) => {
            // Release ou InformationRequest — nada a persistir
        }
    }
}
