//! `DHCPv6` service — Dynamic IPv6 address management (RFC 8415).
//!
//! This service manages IPv6 address assignment via stateful `DHCPv6`,
//! serving as an alternative or complement to SLAAC.
//!
//! ## SARR Cycle (Solicit, Advertise, Request, Reply)
//!
//! ```mermaid
//! sequenceDiagram
//!     participant C as Client
//!     participant S as Dhcpv6Server (Lanforge)
//!     participant T as ManagedTable
//!
//!     C->>S: 1. Solicit (Multicast ff02::1:2)
//!     S->>C: 2. Advertise (Unicast)
//!
//!     C->>S: 3. Request
//!     S->>T: 4. update(DeviceUpdate::V6LeaseGranted / V6PrefixAssigned)
//!     T-->>S: 5. EventBus Signal
//!     S->>C: 6. Reply
//! ```
//!
//! ## Manager Integration
//!
//! The `dhcpv6_service` reports DUIDs and IP leases to the `ManagedTable`.
//! Unlike v4, `DHCPv6` relies heavily on DUIDs for persistent client
//! identification, even if the MAC address changes or is unavailable.

pub mod config;
pub mod pool;
pub mod server;

use crate::error::{NetworkError, Result};
use lanforge_core::bus::{DeviceChange, LanforgeEvent, ManagedTable};
use lanforge_core::identifiers::{Duid, MacAddr};
use lanforge_core::state::update::DeviceUpdate;
use rtnetlink::Handle;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use config::Dhcpv6Config;
use pool::Ipv6Pool;
use server::{Dhcpv6Server, HandleResult};

const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// Starts the `DHCPv6` service (UDP port 547, multicast `ff02::1:2`).
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
        .map_err(|e| NetworkError::Socket(format!("Failed to create IPv6 UDP socket: {e}")))?;

    let addr = std::net::SocketAddr::new(std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED), 547);

    socket
        .set_only_v6(true)
        .map_err(|e| NetworkError::Socket(format!("IPV6_V6ONLY: {e}")))?;
    socket
        .bind(&addr.into())
        .map_err(|e| NetworkError::Socket(format!("bind :547: {e}")))?;

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

    // Read interface MAC to generate a legitimate DUID-LL
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

    // Persistent socket for NDP pokes (Optimization 2)
    let poke_sock = std::net::UdpSocket::bind("::0:0")
        .map_err(|e| NetworkError::Socket(format!("Failed to bind NDP poke socket: {e}")))?;
    poke_sock.set_nonblocking(true)?;
    let ndp_poke_sock = Arc::new(
        UdpSocket::from_std(poke_sock)
            .map_err(|e| NetworkError::Socket(format!("UdpSocket::from_std: {e}")))?,
    );

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
                    warn!("Failed to construct ULA for suffix: {:?}", suffix);
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

                        // Reuses the buffer for response encoding (Optimization 1)
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
                    Ok(LanforgeEvent::LeaseRelease { mac }) => {
                        info!("DHCPv6: Forcing release of {} via CLI", mac);
                        server.pool.release_mac(mac);
                    }
                    Ok(LanforgeEvent::DeviceUpdated { mac, change: DeviceChange::V6SuffixChanged { suffix } }) => {
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
                    Ok(LanforgeEvent::PrefixChanged { gua: _, preferred, valid }) => {
                        server.prefix_lifetimes = Some((preferred, valid));
                        debug!("DHCPv6: Updated prefix lifetimes from bus: pref={}, valid={}", preferred, valid);
                    }
                    Ok(LanforgeEvent::Shutdown) => break,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

/// Translates the result of a DHCP cycle into `DeviceUpdate`s for the Manager.
///
/// Separated from the main loop for clarity — all logic regarding "what we
/// learned from this packet" lives here, without mixing with network I/O.
async fn apply_learned_state(
    table: &ManagedTable,
    opt_mac: Option<MacAddr>,
    learned_duid: Option<Duid>,
    ias: server::AssignedIAs,
    server: &Dhcpv6Server,
    config: &Dhcpv6Config,
) {
    let expires = SystemTime::now() + Duration::from_secs(u64::from(config.lease_time));

    // 1. Process IA_NA (Non-temporary Addresses)
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
            let existing_duid = table.read().get_duid_by_mac(mac).cloned();
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

    // 2. Process IA_PD (Prefix Delegation)
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

    // 3. Fallback: Associate DUID even without IAID if it was learned
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
