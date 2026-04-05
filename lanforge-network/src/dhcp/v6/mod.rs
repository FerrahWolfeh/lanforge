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

use lanforge_core::bus::{DeviceChange, LanforgeEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::device::IPv6State;
use lanforge_core::identifiers::{Duid, MacAddr};
use lanforge_core::state::update::DeviceUpdate;
use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

use config::Dhcpv6Config;
use pool::Ipv6Pool;
use server::{Dhcpv6Server, HandleResult};

const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

use dhcproto::v6::{DhcpOption, Message, OptionCode};
use dhcproto::{Decodable, Decoder};

use lanforge_core::error::CoreError;
use lanforge_core::service::{LanforgeService, SyncService};

pub struct Dhcpv6Service {
    config: Dhcpv6Config,
    bus_rx: Arc<Mutex<std::sync::mpsc::Receiver<LanforgeEvent>>>,
}

impl Dhcpv6Service {
    #[must_use]
    pub fn new(
        config: Dhcpv6Config,
        bus_rx: Arc<Mutex<std::sync::mpsc::Receiver<LanforgeEvent>>>,
    ) -> Self {
        Self { config, bus_rx }
    }
}

impl LanforgeService for Dhcpv6Service {
    fn name(&self) -> &str {
        "Dhcpv6Service"
    }
}

impl SyncService for Dhcpv6Service {
    fn run(&mut self) -> std::result::Result<(), CoreError> {
        if !self.config.enabled {
            info!("DHCPv6 is disabled in config.");
            return Ok(());
        }

        let socket = std::net::UdpSocket::bind(("::", self.config.port))
            .map_err(|e| CoreError::Generic(format!("Failed to bind DHCPv6 socket: {e}")))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .map_err(CoreError::Io)?;

        if let Err(e) = socket.join_multicast_v6(&ALL_DHCP_RELAY_AGENTS_AND_SERVERS, 0) {
            warn!("Failed to join ff02::1:2: {e}");
        }

        info!(
            "DHCPv6 listening on [ff02::1:2]:{} (iface: {})",
            self.config.port, self.config.iface
        );

        // 1. Wait for DB and Interface Ready
        if let Ok(rx) = self.bus_rx.lock() {
            info!("DHCPv6: Waiting for dependencies (DB and Interfaces)...");
            LanforgeContext::wait_for_db_sync(&rx);
            LanforgeContext::wait_for_interfaces_sync(&rx);
        }

        // Read interface MAC to generate a legitimate DUID-LL
        let mac_str =
            std::fs::read_to_string(format!("/sys/class/net/{}/address", self.config.iface))
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
        let std_poke_sock = std::net::UdpSocket::bind("::0:0")
            .map_err(|e| CoreError::Generic(format!("Failed to bind NDP poke socket: {e}")))?;
        let ndp_poke_sock = Arc::new(std_poke_sock);

        let mut server = Dhcpv6Server::new(
            self.config.clone(),
            Ipv6Pool::new(
                self.config.pools.clone(),
                self.config.ula_prefix,
                self.config.ula_prefix_len,
            ),
            Duid::generate_ll_from_mac(server_mac),
            ndp_poke_sock,
        );

        // 2. Re-sync GUA from global state (honoring configured interface)
        // This ensures that if the prefix was discovered while we were waiting
        // for DB/Interfaces, we catch up now.
        if let Some(ifindex) = pnet::datalink::interfaces()
            .iter()
            .find(|i| i.name == self.config.iface)
            .map(|i| i.index)
            && let Some((gua, pref, val)) = LanforgeContext::table()
                .read()
                .get_interface_gua_at(ifindex)
        {
            info!(
                "DHCPv6: Resyncing GUA from global state: {} (pref={}, valid={})",
                gua, pref, val
            );
            server.pool.set_gua_prefix(gua);
            server.prefix_lifetimes = Some((pref, val));
        }

        let mut buf = [0u8; 2048];
        info!("DHCPv6 state machine started");

        // Signal readiness
        let _ = LanforgeContext::bus().publish(LanforgeEvent::ServiceReady {
            name: "dhcpv6".to_string(),
        });

        loop {
            if !LanforgeContext::is_running() {
                break;
            }
            // 1. Process network packets
            match socket.recv_from(&mut buf) {
                Ok((len, peer)) => {
                    let payload = &buf[..len];
                    let (peer_ip, scope_id) = match peer {
                        std::net::SocketAddr::V6(v6) => (*v6.ip(), v6.scope_id()),
                        _ => continue,
                    };

                    let mut resp_vec = Vec::with_capacity(1024);
                    if let Ok(msg) = Message::decode(&mut Decoder::new(payload)) {
                        let mut resolved_mac = msg
                            .opts()
                            .get(OptionCode::ClientId)
                            .and_then(|opt| {
                                if let DhcpOption::ClientId(duid) = opt {
                                    Some(Duid::new(duid.clone()))
                                } else {
                                    None
                                }
                            })
                            .and_then(|d| d.extract_mac());

                        if resolved_mac.is_none() {
                            resolved_mac =
                                lanforge_core::utils::mac_from_eui64_link_local(&peer_ip);
                        }

                        let handle_res =
                            server.handle_packet(&msg, peer_ip, resolved_mac, &mut resp_vec);
                        if let HandleResult::Reply(
                            reply_bytes,
                            dest_ip,
                            learned_duid,
                            opt_mac,
                            ias,
                        ) = handle_res
                        {
                            let client_port = if self.config.port == 547 {
                                546
                            } else {
                                self.config.port - 1
                            };
                            let dest_addr =
                                std::net::SocketAddrV6::new(dest_ip, client_port, 0, scope_id);
                            let _ = socket.send_to(reply_bytes, dest_addr);
                            apply_learned_state(opt_mac, learned_duid, ias, &server, &self.config);
                        }
                    }
                }
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(e) => warn!("DHCPv6 socket error: {e}"),
            }

            // 2. Process Bus events
            if let Ok(rx) = self.bus_rx.lock() {
                while let Ok(event) = rx.try_recv() {
                    match event {
                        LanforgeEvent::LeaseRelease { mac } => {
                            info!("DHCPv6: Forcing release of {} via CLI", mac);
                            // Pool state is stateless, so we don't need to do anything. Global state is updated.
                        }
                        LanforgeEvent::DeviceUpdated {
                            mac,
                            change: DeviceChange::V6SuffixChanged { suffix },
                        } => {
                            if let Some(s) = suffix {
                                info!(
                                    "DHCPv6: New static reservation handled globally for {mac} -> {s}"
                                );
                            } else {
                                info!("DHCPv6: Static reservation cleared globally for {mac}");
                            }
                        }
                        LanforgeEvent::PrefixChanged {
                            gua,
                            ula: _,
                            preferred,
                            valid,
                        } => {
                            server.prefix_lifetimes = Some((preferred, valid));
                            if let Some(g) = gua {
                                let old_gua = server.pool.gua_prefix;
                                server.pool.set_gua_prefix(g);

                                if old_gua != Some(g) {
                                    info!(
                                        "DHCPv6: GUA prefix changed ({:?} -> {}), notifying clients",
                                        old_gua, g
                                    );
                                    let table = LanforgeContext::table();
                                    let table_read = table.read();
                                    for dev in table_read.devices() {
                                        if let Some(duid) = &dev.duid {
                                            let has_gua_lease = dev.v6.iter().any(|s| {
                                                if let IPv6State::Dynamic(lease) = s {
                                                    let o = lease.ip.octets();
                                                    (0x20..=0x3F).contains(&o[0])
                                                } else {
                                                    false
                                                }
                                            });
                                            if has_gua_lease {
                                                // Find link-local for sending
                                                if let Some(ll_ip) = dev.v6.iter().find_map(|s| {
                                                    s.ip().filter(|ip| {
                                                        (ip.segments()[0] & 0xffc0) == 0xfe80
                                                    })
                                                }) {
                                                    let packet = server.build_reconfigure(
                                                        duid,
                                                        dhcproto::v6::MessageType::Renew,
                                                    );
                                                    let client_port = if self.config.port == 547 {
                                                        546
                                                    } else {
                                                        self.config.port - 1
                                                    };
                                                    let dest_addr = std::net::SocketAddrV6::new(
                                                        ll_ip,
                                                        client_port,
                                                        0,
                                                        0,
                                                    );
                                                    let _ = socket.send_to(&packet, dest_addr);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        LanforgeEvent::LeaseRenew { mac } => {
                            let (duid, target_ip) = {
                                let t = LanforgeContext::table();
                                let table_read = t.read();
                                let device = table_read.get_device(&mac);
                                let duid = device.as_ref().and_then(|d| d.duid.clone());
                                let ll_ip = device.as_ref().and_then(|d| {
                                    d.v6.iter().find_map(|s| {
                                        s.ip().filter(|ip| (ip.segments()[0] & 0xffc0) == 0xfe80)
                                    })
                                });
                                (duid, ll_ip)
                            };

                            if let (Some(duid), Some(ip)) = (duid, target_ip) {
                                info!("DHCPv6: Sending manual RECONFIGURE to {} ({})", ip, mac);
                                let packet = server
                                    .build_reconfigure(&duid, dhcproto::v6::MessageType::Renew);
                                let client_port = if self.config.port == 547 {
                                    546
                                } else {
                                    self.config.port - 1
                                };
                                let dest_addr = std::net::SocketAddrV6::new(ip, client_port, 0, 0);
                                let _ = socket.send_to(&packet, dest_addr);
                            }
                        }
                        LanforgeEvent::Shutdown => {
                            info!("DHCPv6: Shutdown received");
                            return Ok(());
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
}

/// Translates the result of a DHCP cycle into `DeviceUpdate`s for the Manager.
///
/// Separated from the main loop for clarity — all logic regarding "what we
/// learned from this packet" lives here, without mixing with network I/O.
fn apply_learned_state(
    opt_mac: Option<MacAddr>,
    learned_duid: Option<Duid>,
    ias: server::AssignedIAs,
    server: &Dhcpv6Server,
    config: &Dhcpv6Config,
) {
    let expires = SystemTime::now() + Duration::from_secs(u64::from(config.lease_time));
    let table = LanforgeContext::table();

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
                let _ = table.update(&DeviceUpdate::DuidAssociated {
                    mac: opt_mac,
                    duid,
                    iaid,
                });
            } else {
                // One or more IPs assigned
                for ip in assigned_ips {
                    let _ = table.update(&DeviceUpdate::V6LeaseGranted {
                        mac: opt_mac,
                        duid: duid.clone(),
                        iaid,
                        ip,
                        expires,
                    });
                }
            }
        } else {
            if !assigned_ips.is_empty()
                && let Some(mac) = opt_mac
            {
                let existing_duid = table.read().get_duid_by_mac(mac).cloned();
                if let Some(duid) = existing_duid {
                    for ip in assigned_ips {
                        let _ = table.update(&DeviceUpdate::V6LeaseGranted {
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
            let _ = table.update(&DeviceUpdate::V6PrefixAssigned {
                mac: opt_mac,
                duid,
                iaid,
                prefix,
                len,
                expires,
            });
        }
    }

    if ias.na.is_empty()
        && ias.pd.is_empty()
        && let Some(duid) = learned_duid
    {
        let _ = table.update(&DeviceUpdate::DuidAssociated {
            mac: opt_mac,
            duid,
            iaid: 0,
        });
    }
}
