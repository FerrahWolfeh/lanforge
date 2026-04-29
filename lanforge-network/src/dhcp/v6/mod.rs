//! `DHCPv6` service — Dynamic IPv6 address management (`RFC 8415`).
//!
//! Manages `IA_NA` (non-temporary addresses) and `IA_PD` (prefix delegation)
//! via the `SARR` cycle (`Solicit`→`Advertise`→`Request`→`Reply`).
//!
//! ## `SARR` Cycle
//!
//! ```mermaid
//! sequenceDiagram
//!     participant C as Client
//!     participant S as Dhcpv6Server (Lanforge)
//!     participant Ctx as LanforgeContext
//!
//!     C->>S: 1. Solicit (multicast ff02::1:2)
//!     S->>C: 2. Advertise (unicast)
//!     C->>S: 3. Request
//!     S->>Ctx: 4. apply(V6LeaseGranted / V6PrefixAssigned)
//!     S->>C: 5. Reply
//! ```
//!
//! ## Key Differences from `DHCPv4`
//!
//! - Uses **DUIDs** (not MACs) as primary client identifiers
//! - Supports **prefix delegation** (`IA_PD`) for clients that need subnets
//! - Multi-prefix operation (`ULA` + `GUA` simultaneously)
//! - `RECONFIGURE` messages for lease renewal (`RFC 8415` Section 18.16)
//!
//! ## Service Model
//!
//! Runs as `SyncService` (blocking UDP I/O, 200ms timeout) like `DHCPv4`.
//!
//! ## Module Structure
//!
//! | Submodule | Purpose |
//! | :--- | :--- |
//! | `config` | `Dhcpv6Config`, `Dhcpv6PoolConfig` |
//! | `pool` | `Ipv6Pool` — multi-prefix, deterministic + random allocation |
//! | `server` | `Dhcpv6Server` — full SARR state machine |

pub mod config;
pub mod pool;
pub mod server;

use lanforge_core::bus::{DeviceChange, DeviceEvent, LanforgeEvent, NetworkEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::device::IPv6State;
use lanforge_core::identifiers::{Duid, MacAddr};
use lanforge_core::state::{DeviceUpdate, LeaseTarget};
use lanforge_core::utils::mac_from_eui64_link_local;
use std::io::ErrorKind;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

use config::Dhcpv6Config;
use pool::Ipv6Pool;
use server::{Dhcpv6Server, HandleResult};

const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

use dhcproto::v6::{DhcpOption, Message, MessageType, OptionCode};
use dhcproto::{Decodable, Decoder};

use lanforge_core::error::CoreError;
use lanforge_core::service::{ServiceControl, SyncBusReceiver, SyncService};

/// `DHCPv6` service wrapper — manages `IA_NA` and `IA_PD` address assignment.
///
/// Wraps the `Dhcpv6Server` state machine with bus event handling for:
/// - `LeaseRelease` (`v4` and `v6-prefix`)
/// - `DeviceUpdated` (`V6` suffix changes)
/// - `PrefixChanged` (`GUA` updates → client `RECONFIGURE`)
/// - `LeaseRenew` (manual RECONFIGURE send)
#[lanforge_macros::lanforge_service(
    id = "dhcpv6",
    name = "DHCPv6 Server",
    critical = true,
    retries = 0,
    base_backoff = 2,
    max_backoff = 30,
    describe = format!(
        "DHCPv6 on [{}]:{} (iface: {})",
        ALL_DHCP_RELAY_AGENTS_AND_SERVERS, self.config.port, self.config.iface
    )
)]
pub struct Dhcpv6Service {
    config: Dhcpv6Config,
    ctx: LanforgeContext,
}

impl Dhcpv6Service {
    #[must_use]
    pub const fn new(config: Dhcpv6Config, ctx: LanforgeContext) -> Self {
        Self { config, ctx }
    }
}

impl SyncService for Dhcpv6Service {
    fn run(&mut self, ctrl: ServiceControl, bus_rx: &SyncBusReceiver) -> Result<(), CoreError> {
        if !self.config.enabled {
            info!("DHCPv6 is disabled in config.");
            return Ok(());
        }

        let socket = UdpSocket::bind(("::", self.config.port))
            .map_err(|e| CoreError::Generic(format!("Failed to bind DHCPv6 socket: {e}")))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .map_err(CoreError::Io)?;

        if let Err(e) = socket.join_multicast_v6(&ALL_DHCP_RELAY_AGENTS_AND_SERVERS, 0) {
            warn!("Failed to join ff02::1:2: {e}");
        }

        // 1. Wait for DB and Interface Ready
        bus_rx.wait_for_db();
        bus_rx.wait_for_interfaces();

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
        let std_poke_sock = UdpSocket::bind("::0:0")
            .map_err(|e| CoreError::Generic(format!("Failed to bind NDP poke socket: {e}")))?;
        let ndp_poke_sock = Arc::new(std_poke_sock);

        let mut server = Dhcpv6Server::new(
            self.config.clone(),
            Ipv6Pool::new(
                &self.config.pools,
                self.config.ula_prefix,
                self.config.ula_prefix_len,
            ),
            Duid::generate_ll_from_mac(server_mac),
            ndp_poke_sock,
            self.ctx.clone(),
        );

        // Pre-allocate static reservations for ULA prefix
        let registry = self.ctx.get_static_registry();
        if let Some(ula) = self.config.ula_prefix {
            let ula_ips: Vec<_> = registry
                .v6_reservations()
                .map(|s| server.pool.construct_addr(ula, &s))
                .collect();
            server.pool.reserve_statics(ula_ips);
        }

        // 2. Re-sync GUA from global state (honoring configured interface)
        // This ensures that if the prefix was discovered while we were waiting
        // for DB/Interfaces, we catch up now.
        if let Some(ifindex) = pnet::datalink::interfaces()
            .iter()
            .find(|i| i.name == self.config.iface)
            .map(|i| i.index)
            && let Some((gua, pref, val)) = self.ctx.get_interface_gua_at(ifindex)
        {
            info!(
                "DHCPv6: Resyncing GUA from global state: {} (pref={}, valid={})",
                gua, pref, val
            );
            server.pool.set_gua_prefix(gua);
            server.prefix_lifetimes = Some((pref, val));

            // Also pre-allocate static reservations for the newly discovered GUA prefix
            let gua_ips: Vec<_> = registry
                .v6_reservations()
                .map(|s| server.pool.construct_addr(gua, &s))
                .collect();
            server.pool.reserve_statics(gua_ips);
        }

        let mut buf = [0u8; 2048];
        info!("DHCPv6 state machine started");
        ctrl.signal_ready();

        loop {
            if !self.ctx.is_running() {
                break;
            }

            // 1. Process network packets
            match socket.recv_from(&mut buf) {
                Ok((len, peer)) => {
                    self.handle_incoming_packet(&buf[..len], peer, &mut server, &socket);
                }
                Err(ref e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(e) => warn!("DHCPv6 socket error: {e}"),
            }

            // 2. Process Bus events
            for event in bus_rx.try_recv_all() {
                if let Err(e) = self.handle_bus_event(event.event, &mut server, &socket) {
                    if matches!(e, CoreError::Shutdown) {
                        return Ok(());
                    }
                    warn!("DHCPv6: Bus event error: {e}");
                }
            }
        }
        Ok(())
    }
}

impl Dhcpv6Service {
    fn handle_incoming_packet(
        &self,
        payload: &[u8],
        peer: SocketAddr,
        server: &mut Dhcpv6Server,
        socket: &UdpSocket,
    ) {
        let (peer_ip, scope_id) = match peer {
            SocketAddr::V6(v6) => (*v6.ip(), v6.scope_id()),
            SocketAddr::V4(_) => return,
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
                resolved_mac = mac_from_eui64_link_local(&peer_ip);
            }

            let handle_res = server.handle_packet(&msg, peer_ip, resolved_mac, &mut resp_vec);
            if let HandleResult::Reply(reply_bytes, dest_ip, learned_duid, opt_mac, ias) =
                handle_res
            {
                let client_port = if self.config.port == 547 {
                    546
                } else {
                    self.config.port - 1
                };
                let dest_addr = SocketAddrV6::new(dest_ip, client_port, 0, scope_id);
                let _ = socket.send_to(reply_bytes, dest_addr);
                apply_learned_state(
                    &self.ctx,
                    opt_mac,
                    learned_duid.as_ref(),
                    &ias,
                    server,
                    &self.config,
                );
            }
        }
    }

    fn handle_bus_event(
        &self,
        event: LanforgeEvent,
        server: &mut Dhcpv6Server,
        socket: &UdpSocket,
    ) -> Result<(), CoreError> {
        match event {
            LanforgeEvent::Device(DeviceEvent::LeaseRelease {
                mac,
                target: LeaseTarget::V6 { iaid },
            }) => {
                info!("DHCPv6: Forcing release of {} (IAID {}) via CLI", mac, iaid);
            }
            LanforgeEvent::Device(DeviceEvent::LeaseRelease {
                mac,
                target: LeaseTarget::V6Prefix { iaid },
            }) => {
                info!(
                    "DHCPv6: Forcing release of prefix for {} (IAID {}) via CLI",
                    mac, iaid
                );
            }
            LanforgeEvent::Device(DeviceEvent::Updated { mac, change, .. }) => {
                if let DeviceChange::V6SuffixChanged { suffix } = change.as_ref() {
                    if let Some(s) = suffix {
                        info!("DHCPv6: New static reservation handled globally for {mac} -> {s}");
                    } else {
                        info!("DHCPv6: Static reservation cleared globally for {mac}");
                    }
                }
            }
            LanforgeEvent::Network(NetworkEvent::PrefixChanged {
                gua,
                ula: _,
                preferred,
                valid,
            }) => {
                self.handle_prefix_change(server, socket, gua, preferred, valid);
            }
            LanforgeEvent::Device(DeviceEvent::LeaseRenew {
                mac,
                target: LeaseTarget::V6 { .. } | LeaseTarget::V6Prefix { .. },
            }) => {
                let (duid, target_ip) = {
                    let device = self.ctx.get_device(&mac);
                    let duid = device.as_ref().and_then(|d| d.duid.clone());
                    let ll_ip = device.as_ref().and_then(|d| {
                        d.v6.iter()
                            .find_map(|s| s.ip().filter(|ip| (ip.segments()[0] & 0xffc0) == 0xfe80))
                    });
                    (duid, ll_ip)
                };

                if let (Some(duid), Some(ip)) = (duid, target_ip) {
                    info!("DHCPv6: Sending manual RECONFIGURE to {} ({})", ip, mac);
                    let packet = server.build_reconfigure(&duid, MessageType::Renew);
                    let client_port = if self.config.port == 547 {
                        546
                    } else {
                        self.config.port - 1
                    };
                    let dest_addr = SocketAddrV6::new(ip, client_port, 0, 0);
                    let _ = socket.send_to(&packet, dest_addr);
                }
            }
            LanforgeEvent::System(SystemEvent::Shutdown) => {
                info!("DHCPv6: Shutdown received");
                return Err(CoreError::Shutdown);
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_prefix_change(
        &self,
        server: &mut Dhcpv6Server,
        socket: &UdpSocket,
        gua: Option<Ipv6Addr>,
        preferred: u32,
        valid: u32,
    ) {
        server.prefix_lifetimes = Some((preferred, valid));
        if let Some(g) = gua {
            let old_gua = server.pool.gua_prefix;
            server.pool.set_gua_prefix(g);

            if old_gua != Some(g) {
                info!(
                    "DHCPv6: GUA prefix changed ({:?} -> {}), notifying clients",
                    old_gua, g
                );

                // Update static reservations for the new GUA prefix
                let registry = self.ctx.get_static_registry();
                let gua_ips: Vec<_> = registry
                    .v6_reservations()
                    .map(|s| server.pool.construct_addr(g, &s))
                    .collect();
                server.pool.reserve_statics(gua_ips);

                for dev in self.ctx.all_devices() {
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
                                s.ip().filter(|ip| (ip.segments()[0] & 0xffc0) == 0xfe80)
                            }) {
                                let packet = server.build_reconfigure(duid, MessageType::Renew);
                                let client_port = if self.config.port == 547 {
                                    546
                                } else {
                                    self.config.port - 1
                                };
                                let dest_addr = SocketAddrV6::new(ll_ip, client_port, 0, 0);
                                let _ = socket.send_to(&packet, dest_addr);
                            }
                        }
                    }
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
    ctx: &LanforgeContext,
    opt_mac: Option<MacAddr>,
    learned_duid: Option<&Duid>,
    ias: &server::AssignedIAs,
    server: &Dhcpv6Server,
    config: &Dhcpv6Config,
) {
    let expires = SystemTime::now() + Duration::from_secs(u64::from(config.lease_time));

    // 1. Process IA_NA (Non-temporary Addresses)
    for &iaid in &ias.na {
        let assigned_ips = learned_duid.map_or_else(
            || opt_mac.map_or_else(Vec::new, |mac| server.pool.lookup_by_mac_legacy(ctx, mac)),
            |duid| server.last_assignment_for(duid, iaid),
        );

        if assigned_ips.is_empty() {
            if let Some(duid) = learned_duid {
                // No IPs assigned yet, but IAID is known
                let _ = ctx.apply(&DeviceUpdate::DuidAssociated {
                    mac: opt_mac,
                    duid: duid.clone(),
                    iaid,
                });
            }
        } else {
            // One or more IPs assigned
            for ip in assigned_ips {
                if let Some(duid) = learned_duid {
                    let _ = ctx.apply(&DeviceUpdate::V6LeaseGranted {
                        mac: opt_mac,
                        duid: duid.clone(),
                        iaid,
                        ip,
                        expires,
                    });
                } else if let Some(mac) = opt_mac {
                    // Search for DUID in our table if not provided in packet
                    if let Some(device) = ctx.get_device(&mac)
                        && let Some(duid) = device.duid.clone()
                    {
                        let _ = ctx.apply(&DeviceUpdate::V6LeaseGranted {
                            mac: Some(mac),
                            duid,
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
    for &iaid in &ias.pd {
        let assigned_prefix = learned_duid
            .as_ref()
            .and_then(|duid| server.pool.lookup_prefix(ctx, duid, iaid));

        if let (Some(duid), Some((prefix, len))) = (learned_duid, assigned_prefix) {
            let _ = ctx.apply(&DeviceUpdate::V6PrefixAssigned {
                mac: opt_mac,
                duid: duid.clone(),
                iaid,
                prefix,
                len,
                expires,
            });
        }
    }
}
