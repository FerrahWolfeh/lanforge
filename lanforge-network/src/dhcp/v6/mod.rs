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
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, warn};

use config::Dhcpv6Config;
use pool::Ipv6Pool;
use server::{Dhcpv6Server, HandleResult};

const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

use dhcproto::v6::{DhcpOption, Message, OptionCode};
use dhcproto::{Decodable, Decoder};
use tokio::sync::mpsc::UnboundedReceiver;

/// Starts the `DHCPv6` service (UDP port 547, multicast `ff02::1:2`).
pub async fn dhcpv6_service(
    config: Dhcpv6Config,
    table: Arc<ManagedTable>,
    nl_handle: &Handle,
    mut bus_rx: UnboundedReceiver<LanforgeEvent>,
) -> Result<()> {
    if !config.enabled {
        info!("DHCPv6 is disabled in config.");
        return Ok(());
    }

    let socket = tokio::net::UdpSocket::bind(("::", config.port))
        .await
        .map_err(|e| NetworkError::Socket(format!("Failed to bind DHCPv6 socket: {e}")))?;

    if let Err(e) = socket.join_multicast_v6(&ALL_DHCP_RELAY_AGENTS_AND_SERVERS, 0) {
        warn!("Failed to join ff02::1:2: {e}");
    }

    info!(
        "DHCPv6 listening on [ff02::1:2]:{} (iface: {})",
        config.port, config.iface
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

    // Persistent socket for NDP pokes
    let poke_sock = std::net::UdpSocket::bind("::0:0")
        .map_err(|e| NetworkError::Socket(format!("Failed to bind NDP poke socket: {e}")))?;
    let ndp_poke_sock = Arc::new(poke_sock);

    let mut server = Dhcpv6Server::new(
        config.clone(),
        Ipv6Pool::new(
            config.pools.clone(),
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
    info!("DHCPv6 state machine started");

    loop {
        tokio::select! {
            // 1. Process network packets
            Ok((len, peer)) = socket.recv_from(&mut buf) => {
                let payload = &buf[..len];

                let (peer_ip, scope_id) = match peer {
                    std::net::SocketAddr::V6(v6) => (*v6.ip(), v6.scope_id()),
                    std::net::SocketAddr::V4(_) => continue,
                };

                let mut resp_vec = Vec::with_capacity(1024);
                let msg = match Message::decode(&mut Decoder::new(payload)) {
                    Ok(m) => m,
                    Err(e) => {
                        debug!("Failed to decode packet: {e}");
                        continue;
                    }
                };

                // 1. Try to extract MAC address without async lookups
                let client_id_opt = msg.opts().get(OptionCode::ClientId);
                let client_duid = if let Some(DhcpOption::ClientId(duid_bytes)) = client_id_opt {
                    Some(Duid::new(duid_bytes.clone()))
                } else {
                    None
                };

                let mut resolved_mac = client_duid.as_ref().and_then(|d| d.extract_mac())
                    .or_else(|| {
                        msg.opts().iter().find_map(|opt| {
                            if let DhcpOption::Unknown(u) = opt
                                && u.code() == 79.into()
                                && u.data().len() >= 8
                            {
                                return MacAddr::from_slice(&u.data()[2..8]);
                            }
                            None
                        })
                    })
                    .or_else(|| lanforge_core::utils::mac_from_eui64_link_local(&peer_ip));

                // 2. Try NDP cache (sync check)
                if resolved_mac.is_none() {
                    let t = table.read();
                    if let Some(cached) = t.get_mac_from_ndp_cache(&peer_ip) {
                        resolved_mac = Some(cached);
                    }
                }

                // 3. Fallback to async netlink lookup if still unknown
                if resolved_mac.is_none() {
                    debug!("Cache miss. Performing kernel lookup for {peer_ip}...");
                    if let Some(ndp_mac) = crate::netlink::lookup_mac_for_ipv6(nl_handle, &peer_ip).await {
                        let _ = table.update(DeviceUpdate::NdpSeen {
                            mac: ndp_mac,
                            ip: peer_ip,
                        });
                        resolved_mac = Some(ndp_mac);
                    }
                }

                let res = server.handle_packet(&msg, peer_ip, &table, resolved_mac, &mut resp_vec);

                match res {
                    HandleResult::Reply(reply_bytes, dest_ip, learned_duid, opt_mac, ias) => {
                        let client_port = if config.port == 547 {
                            546
                        } else {
                            config.port - 1
                        };
                        let dest_addr =
                            std::net::SocketAddrV6::new(dest_ip, client_port, 0, scope_id);

                        if let Err(e) = socket.send_to(reply_bytes, dest_addr).await {
                            warn!("send error to {dest_ip}: {e}");
                        }

                        apply_learned_state(&table, opt_mac, learned_duid, ias, &server, &config);
                    }
                    HandleResult::Ignore => {}
                }
            }

            // 2. Process Bus events
            Some(event) = bus_rx.recv() => {
                match event {
                    LanforgeEvent::LeaseRelease { mac } => {
                        info!("DHCPv6: Forcing release of {} via CLI", mac);
                        server.pool.release_mac(mac);
                    }
                    LanforgeEvent::DeviceUpdated {
                        mac,
                        change: DeviceChange::V6SuffixChanged { suffix },
                    } => match suffix {
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
                    },
                    LanforgeEvent::PrefixChanged {
                        gua,
                        preferred,
                        valid,
                    } => {
                        server.prefix_lifetimes = Some((preferred, valid));
                        if let Some(g) = gua {
                            info!("DHCPv6: Propagating new GUA prefix to pool: {g}");
                            server.pool.set_gua_prefix(g);
                        }
                        debug!(
                            "DHCPv6: Updated prefix lifetimes from bus: pref={}, valid={}",
                            preferred, valid
                        );
                    }
                    LanforgeEvent::LeaseRenew { mac } => {
                        let (duid, target_ip) = {
                            let t = table.read();
                            let device = t.get_device(&mac);
                            let duid = device.and_then(|d| d.duid.clone());

                            let ll_ip = device.and_then(|d| {
                                d.v6.iter().find_map(|s| {
                                    s.ip().filter(|ip| (ip.segments()[0] & 0xffc0) == 0xfe80)
                                })
                            });

                            (duid, ll_ip)
                        };

                        if let (Some(duid), Some(ip)) = (duid, target_ip) {
                            info!("DHCPv6: Sending manual RECONFIGURE to {} ({})", ip, mac);
                            let packet =
                                server.build_reconfigure(&duid, dhcproto::v6::MessageType::Renew);

                            let client_port = if config.port == 547 {
                                546
                            } else {
                                config.port - 1
                            };
                            let dest_addr = std::net::SocketAddrV6::new(ip, client_port, 0, 0);

                            if let Err(e) = socket.send_to(&packet, dest_addr).await {
                                warn!("DHCPv6: Failed to send RECONFIGURE to {ip}: {e}");
                            }
                        } else {
                            warn!(
                                "DHCPv6: Cannot send RECONFIGURE to {mac}: DUID or Link-Local IP not found"
                            );
                        }
                    }
                    LanforgeEvent::Shutdown => {
                        info!("DHCPv6: Shutdown recebido");
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Translates the result of a DHCP cycle into `DeviceUpdate`s for the Manager.
///
/// Separated from the main loop for clarity — all logic regarding "what we
/// learned from this packet" lives here, without mixing with network I/O.
fn apply_learned_state(
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
        let assigned_ips = if let Some(duid) = &learned_duid {
            server.last_assignment_for(&duid.bytes, iaid)
        } else if let Some(mac) = opt_mac {
            server.pool.lookup_by_mac_legacy(mac)
        } else {
            Vec::new()
        };

        if let Some(duid) = learned_duid.clone() {
            if assigned_ips.is_empty() {
                // No IPs assigned yet, but IAID is known
                let _ = table.update(DeviceUpdate::DuidAssociated {
                    mac: opt_mac,
                    duid,
                    iaid,
                });
            } else {
                // One or more IPs assigned
                for ip in assigned_ips {
                    let _ = table.update(DeviceUpdate::V6LeaseGranted {
                        mac: opt_mac,
                        duid: duid.clone(),
                        iaid,
                        ip,
                        expires,
                    });
                }
            }
        } else if !assigned_ips.is_empty()
            && let Some(mac) = opt_mac
        {
            // Case where we have IPs but no DUID in current message?
            // (Unlikely in DHCPv6, but handled for consistency)
            let existing_duid = table.read().get_duid_by_mac(mac).cloned();
            if let Some(duid) = existing_duid {
                for ip in assigned_ips {
                    let _ = table.update(DeviceUpdate::V6LeaseGranted {
                        mac: Some(mac),
                        duid: duid.clone(),
                        iaid,
                        ip,
                        expires,
                    });
                }
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
            let _ = table.update(DeviceUpdate::V6PrefixAssigned {
                mac: opt_mac,
                duid,
                iaid,
                prefix,
                len,
                expires,
            });
        }
    }

    // 3. Fallback: Associate DUID even without IAID if it was learned
    if ias.na.is_empty()
        && ias.pd.is_empty()
        && let Some(duid) = learned_duid
    {
        let _ = table.update(DeviceUpdate::DuidAssociated {
            mac: opt_mac,
            duid,
            iaid: 0,
        });
    }
}
