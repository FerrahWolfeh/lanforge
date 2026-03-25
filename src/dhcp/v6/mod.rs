//! `DHCPv6` service — Gerenciamento de endereços IPv6 dinâmicos (RFC 8415).
//!
//! Este serviço gerencia a atribuição de endereços IPv6 via `DHCPv6` (Stateful),
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
//! Diferente do v4, o `DHCPv6` depende fortemente do DUID para identificação
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
use tracing::{debug, info, warn};

use crate::bus::ManagedTable;
use crate::device::MacAddr;
use crate::state::update::DeviceUpdate;
use config::Dhcpv6Config;
use duid::Duid;
use pool::Ipv6Pool;
use server::{Dhcpv6Server, HandleResult};

const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// Inicia o serviço `DHCPv6` (porta UDP 547, multicast `ff02::1:2`).
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

    // Socket persistente para NDP pokes (Optimization 2)
    let poke_sock = std::net::UdpSocket::bind("::0:0").context("Failed to bind NDP poke socket")?;
    poke_sock.set_nonblocking(true)?;
    let ndp_poke_sock = Arc::new(UdpSocket::from_std(poke_sock)?);

    let mut server = Dhcpv6Server::new(
        config.clone(),
        Ipv6Pool::new(
            config.range_start,
            config.range_end,
            config.ula_prefix,
            config.ula_prefix_len,
        ),
        Duid::generate_ll_from_mac(server_mac),
        ndp_poke_sock,
    );

    {
        let t = table.read();
        for entry in t.static_entries() {
            if let Some(suffix) = &entry.v6_suffix {
                if let Some(ip) = server.pool.construct_static_ula(suffix) {
                    server.pool.add_reservation(ip, entry.mac);
                    info!(
                        "Static reservation: {} ({}) → {}",
                        entry.mac, entry.hostname, ip
                    );
                } else {
                    warn!("Falha ao construir ULA para sufixo: {:?}", suffix);
                }
            }
        }
    }

    let mut buf = [0u8; 2048];
    let mut bus_rx = table.bus().subscribe();

    info!("DHCPv6 state machine started");

    loop {
        tokio::select! {
            res = udp.recv_from(&mut buf) => {
                match res {
                    Ok((len, peer)) => {
                        let payload = &buf[..len];

                        let (peer_ip, scope_id) = match peer {
                            std::net::SocketAddr::V6(v6) => (*v6.ip(), v6.scope_id()),
                            std::net::SocketAddr::V4(_) => continue,
                        };

                        // Reutiliza o buffer para codificação da resposta (Optimization 1)
                        let mut resp_vec = Vec::with_capacity(1024);
                        match server
                            .handle_packet(payload, peer_ip, &table, nl_handle, &mut resp_vec)
                            .await
                        {
                            HandleResult::Reply(reply_bytes, dest_ip, learned_duid, opt_mac, ias) => {
                                let dest_addr = std::net::SocketAddrV6::new(dest_ip, 546, 0, scope_id);

                                if let Err(e) = udp.send_to(reply_bytes, dest_addr).await {
                                    warn!("send error to {dest_ip}: {e}");
                                }

                                apply_learned_state(&table, opt_mac, learned_duid, ias, &server, &config).await;
                            }
                            HandleResult::Ignore => {}
                        }
                    }
                    Err(e) => {
                        warn!("recv error: {e}");
                    }
                }
            }
            event = bus_rx.recv() => {
                match event {
                    Ok(crate::bus::LanforgeEvent::LeaseRelease { mac }) => {
                        info!("DHCPv6: Forcing release of {} via CLI", mac);
                        server.pool.release_mac(mac);
                    }
                    Ok(crate::bus::LanforgeEvent::DeviceUpdated { mac, change: crate::bus::DeviceChange::V6SuffixChanged { suffix } }) => {
                        match suffix {
                            Some(s) => {
                                if let Some(ip) = server.pool.construct_static_ula(&s) {
                                    info!("DHCPv6: New static reservation via CLI: {mac} -> {ip}");
                                    server.pool.add_reservation(ip, mac);
                                }
                            }
                            None => {
                                info!("DHCPv6: Static reservation removed via CLI: {mac}");
                                server.pool.release_mac(mac);
                            }
                        }
                    }
                    Ok(crate::bus::LanforgeEvent::PrefixChanged { gua: _, preferred, valid }) => {
                        server.prefix_lifetimes = Some((preferred, valid));
                        debug!("DHCPv6: Updated prefix lifetimes from bus: pref={}, valid={}", preferred, valid);
                    }
                    Ok(crate::bus::LanforgeEvent::Shutdown) => break,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

/// Traduz o resultado de um ciclo DHCP em `DeviceUpdate`s para o Manager.
///
/// Separado do loop principal para clareza — toda a lógica de "o que
/// aprendemos com este pacote" fica aqui, sem misturar com I/O de rede.
async fn apply_learned_state(
    table: &ManagedTable,
    opt_mac: Option<MacAddr>,
    learned_duid: Option<Duid>,
    ias: server::AssignedIAs,
    server: &Dhcpv6Server,
    config: &Dhcpv6Config,
) {
    let expires = SystemTime::now() + Duration::from_secs(u64::from(config.lease_time));

    // 1. Processa IA_NA (Endereços)
    for iaid in &ias.na {
        let iaid = *iaid;
        let assigned_ip = if let Some(duid) = &learned_duid {
            server.last_assignment_for(&duid.bytes, iaid)
        } else if let Some(mac) = opt_mac {
            server.pool.lookup_by_mac_legacy(mac)
        } else {
            None
        };

        if let (Some(duid), Some(ip)) = (learned_duid.clone(), assigned_ip) {
            table
                .update(DeviceUpdate::V6LeaseGranted {
                    mac: opt_mac,
                    duid,
                    iaid,
                    ip,
                    expires,
                })
                .await;
        } else if let (Some(duid), None) = (learned_duid.clone(), assigned_ip) {
            table
                .update(DeviceUpdate::DuidAssociated {
                    mac: opt_mac,
                    duid,
                    iaid,
                })
                .await;
        } else if let (None, Some(ip)) = (learned_duid.clone(), assigned_ip)
            && let Some(mac) = opt_mac
        {
            let existing_duid = table.read().find_duid_by_mac(mac).cloned();
            if let Some(duid) = existing_duid {
                table
                    .update(DeviceUpdate::V6LeaseGranted {
                        mac: Some(mac),
                        duid,
                        iaid,
                        ip,
                        expires,
                    })
                    .await;
            }
        }
    }

    // 2. Processa IA_PD (Prefixos)
    for iaid in &ias.pd {
        let iaid = *iaid;
        let assigned_prefix = if let Some(duid) = &learned_duid {
            server.pool.lookup_prefix(&duid.bytes, iaid)
        } else {
            None
        };

        if let (Some(duid), Some((prefix, len))) = (learned_duid.clone(), assigned_prefix) {
            table
                .update(DeviceUpdate::V6PrefixAssigned {
                    mac: opt_mac,
                    duid,
                    iaid,
                    prefix,
                    len,
                    expires,
                })
                .await;
        }
    }

    // 3. Fallback: DUID associado mesmo sem IAID de endereço se foi aprendido
    if ias.na.is_empty()
        && ias.pd.is_empty()
        && let Some(duid) = learned_duid
    {
        table
            .update(DeviceUpdate::DuidAssociated {
                mac: opt_mac,
                duid,
                iaid: 0,
            })
            .await;
    }
}
