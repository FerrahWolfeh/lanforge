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
//! Runs as `AsyncService` (non-blocking UDP I/O via tokio) like `DHCPv4`.
//!
//! ## Module Structure
//!
//! | Submodule | Purpose |
//! | :--- | :--- |
//! | `config` | `Dhcpv6Config`, `Dhcpv6PoolConfig` |
//! | `pool` | `Ipv6Pool` — multi-prefix, deterministic + random allocation |
//! | `server` | `Dhcpv6Server` — full SARR state machine |

pub mod config;
pub mod io;
pub mod pool;
pub mod server;

use lanforge_core::bus::{
    AdminChange, DeviceEvent, DhcpV6MessageType, LanforgeEvent, NetworkEvent, SystemEvent,
};
use lanforge_core::context::{LanforgeContext, ServiceHandle};
use lanforge_core::match_event;
use lanforge_core::utils::mac_from_eui64_link_local;
use lanforge_types::device::IPv6State;
use lanforge_types::events::TimedEvent;
use lanforge_types::identifiers::{Duid, MacAddr};
use lanforge_types::network::dhcp::Dhcpv6Pool;
use lanforge_types::system::RunResult;
use lanforge_types::update::{DeviceUpdate, LeaseTarget};
use std::borrow::Cow;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};
use tracing::{info, warn};

use crate::traits::DhcpPool;
use config::Dhcpv6Config;
use pool::Ipv6Pool;
use server::{Dhcpv6Server, HandleResult};

const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

use dhcproto::v6::{DhcpOption, Message, MessageType, OptionCode};
use dhcproto::{Decodable, Decoder};

use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceDependency};

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
#[derive(Clone)]
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

impl AsyncService for Dhcpv6Service {
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[ServiceDependency::Database, ServiceDependency::Interfaces]
    }

    fn stats(&self, ctx: &LanforgeContext) -> Vec<(Cow<'static, str>, String)> {
        let (active_leases, pool_total, pool_available) = ctx.with_state(|state| {
            let leases = u32::try_from(
                state
                    .devices
                    .values()
                    .filter(|dev| dev.v6.iter().any(|s| matches!(s, IPv6State::Dynamic(_))))
                    .count(),
            )
            .unwrap_or(0);
            let mut total = 0;
            let mut avail = 0;
            for pool in state.interfaces.v6_pools.values() {
                total += pool.total;
                avail += pool.available;
            }
            (leases, total, avail)
        });
        let v6_stats = ctx.dhcpv6_stats().snapshot();
        vec![
            (Cow::Borrowed("iface"), self.config.iface.clone()),
            (Cow::Borrowed("port"), self.config.port.to_string()),
            (Cow::Borrowed("leases_active"), active_leases.to_string()),
            (Cow::Borrowed("pool_total"), pool_total.to_string()),
            (Cow::Borrowed("pool_available"), pool_available.to_string()),
            (Cow::Borrowed("solicits"), v6_stats.solicits.to_string()),
            (Cow::Borrowed("advertises"), v6_stats.advertises.to_string()),
            (Cow::Borrowed("requests"), v6_stats.requests.to_string()),
            (Cow::Borrowed("replies"), v6_stats.replies.to_string()),
            (Cow::Borrowed("renews"), v6_stats.renews.to_string()),
            (Cow::Borrowed("rebinds"), v6_stats.rebinds.to_string()),
            (Cow::Borrowed("releases"), v6_stats.releases.to_string()),
            (Cow::Borrowed("declines"), v6_stats.declines.to_string()),
            (
                Cow::Borrowed("info_requests"),
                v6_stats.info_requests.to_string(),
            ),
        ]
    }

    async fn serve(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        if !self.config.enabled {
            info!("DHCPv6 is disabled in config.");
            return Ok(());
        }

        loop {
            let pools = ctx.get_dhcp_v6_pools();

            if pools.is_empty() {
                warn!("⚠️ DHCPv6 enabled but no pools configured — server will remain idle");
                match self.wait_for_config_change_or_shutdown().await? {
                    RunResult::Shutdown => break,
                    RunResult::ConfigChanged => continue,
                }
            }

            match self.run_server(pools).await? {
                RunResult::Shutdown => break,
                RunResult::ConfigChanged => {}
            }
        }

        Ok(())
    }
}

impl Dhcpv6Service {
    async fn wait_for_config_change_or_shutdown(&self) -> Result<RunResult, CoreError> {
        let mut handle = self.ctx.service_handle();
        loop {
            let event = handle.next_event().await;
            let Some(timed_event) = event else {
                return Ok(RunResult::Shutdown);
            };
            if matches!(
                timed_event.event,
                LanforgeEvent::System(
                    SystemEvent::ConfigDhcpV6Changed | SystemEvent::ConfigDhcpOptionsChanged
                )
            ) {
                // Absorb any immediately consecutive config change events
                tokio::time::sleep(Duration::from_millis(50)).await;
                while let Ok(Some(ev)) =
                    tokio::time::timeout(Duration::from_millis(10), handle.next_event()).await
                {
                    if matches!(ev.event, LanforgeEvent::System(SystemEvent::Shutdown)) {
                        return Ok(RunResult::Shutdown);
                    }
                }
                return Ok(RunResult::ConfigChanged);
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn run_server(
        &self,
        pools: Vec<Dhcpv6Pool>,
    ) -> Result<RunResult, CoreError> {
        let mut current_cfg = self.config.clone();
        current_cfg.pools = pools;

        let target_ifindex = self.ctx.target_ifindex().ok_or_else(|| {
            CoreError::Generic("Target interface index is not configured in context".to_string())
        })?;
        let server_mac = self
            .ctx
            .with_state(|state| {
                state
                    .interfaces
                    .interface_ips
                    .get(&target_ifindex)
                    .and_then(|i| i.mac)
            })
            .or_else(|| {
                std::fs::read_to_string(format!("/sys/class/net/{}/address", current_cfg.iface))
                    .ok()
                    .and_then(|s| MacAddr::parse(s.trim()))
            })
            .or_else(|| {
                self.ctx
                    .get_interface_state(target_ifindex)
                    .link_local
                    .and_then(|ll| lanforge_core::utils::mac_from_eui64_link_local(&ll))
            })
            .or_else(|| {
                pnet::datalink::interfaces()
                    .into_iter()
                    .find(|i| i.index == target_ifindex || i.name == current_cfg.iface)
                    .and_then(|i| i.mac)
                    .and_then(|m| MacAddr::from_slice(&m.octets()))
            })
            .ok_or_else(|| {
                CoreError::Generic(format!(
                    "MAC address for interface index {target_ifindex} is not resolved"
                ))
            })?;

        let mut server = Dhcpv6Server::new(
            current_cfg.clone(),
            Ipv6Pool::new(
                &current_cfg.pools,
                current_cfg.ula_prefix,
                current_cfg.ula_prefix_len,
            ),
            Duid::generate_ll_from_mac(server_mac.as_bytes()),
            self.ctx.clone(),
        );

        // Pre-allocate static reservations for ULA prefix
        let registry = self.ctx.get_static_registry();
        if let Some(ula) = current_cfg.ula_prefix {
            let ula_ips: Vec<_> = registry
                .v6_reservations()
                .map(|s| server.pool.construct_addr(ula, &s))
                .collect();
            server.pool.reserve_statics(ula_ips);
        }

        // Seed with active dynamic leases from context
        let active_dynamic_ips: Vec<Ipv6Addr> = self.ctx.with_state(|state| {
            state
                .devices
                .values()
                .flat_map(|dev| {
                    dev.v6.iter().filter_map(|s| match s {
                        IPv6State::Dynamic(lease) => Some(lease.ip),
                        _ => None,
                    })
                })
                .collect()
        });
        server.pool.reserve_statics(active_dynamic_ips);

        // 2. Re-sync GUA from global state (honoring configured interface)
        if let Some(ifindex) = pnet::datalink::interfaces()
            .iter()
            .find(|i| i.name == current_cfg.iface)
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

        // Setup transport socket
        let transport = io::Dhcpv6Transport::new(&current_cfg.iface, current_cfg.port)?;
        self.publish_pool_stats(&server);

        let mut buf = [0u8; 2048];
        let mut handle = self.ctx.service_handle();
        let mut stats_timer = tokio::time::interval(Duration::from_mins(1));

        info!("DHCPv6 state machine started");

        loop {
            tokio::select! {
                res = transport.recv(&mut buf) => {
                    match res {
                        Ok((len, peer)) => {
                            self.handle_incoming_packet(&buf[..len], peer, &mut server, &transport, &handle);
                        }
                        Err(e) => warn!("DHCPv6 socket error: {e}"),
                    }
                }
                event = handle.next_event() => {
                    let Some(timed_event) = event else {
                        return Ok(RunResult::Shutdown);
                    };
                    if matches!(
                        timed_event.event,
                        LanforgeEvent::System(
                            SystemEvent::ConfigDhcpV6Changed | SystemEvent::ConfigDhcpOptionsChanged
                        )
                    ) {
                        // Absorb any immediately consecutive config change events
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        while let Ok(Some(ev)) =
                            tokio::time::timeout(Duration::from_millis(10), handle.next_event()).await
                        {
                            if matches!(ev.event, LanforgeEvent::System(SystemEvent::Shutdown)) {
                                return Ok(RunResult::Shutdown);
                            }
                        }
                        return Ok(RunResult::ConfigChanged);
                    }
                    self.handle_bus_event(&timed_event, &mut server, &transport);
                }
                _ = stats_timer.tick() => {
                    self.publish_pool_stats(&server);
                }
            }
        }
    }
}

impl Dhcpv6Service {
    fn publish_pool_stats(&self, server: &Dhcpv6Server) {
        let stats = server.pool.stats_per_prefix(&self.ctx);
        for (i, (prefix, prefix_len, total, used, available, utilization_percent)) in
            stats.into_iter().enumerate()
        {
            let _ = self.ctx.apply(DeviceUpdate::DhcpV6PoolUpdated {
                pool_id: u32::try_from(i).unwrap_or(0),
                prefix,
                prefix_len,
                total,
                used,
                available,
                utilization_percent,
            });
        }
    }

    fn handle_incoming_packet(
        &self,
        payload: &[u8],
        peer: SocketAddr,
        server: &mut Dhcpv6Server,
        transport: &io::Dhcpv6Transport,
        handle: &ServiceHandle,
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

            // Diagnostic: Publish DHCPv6 Transaction
            if let Some(mac) = resolved_mac {
                let _ = handle.publish(LanforgeEvent::Device(DeviceEvent::DhcpV6Transaction {
                    mac,
                    msg_type: DhcpV6MessageType::from(u8::from(msg.msg_type())),
                    details: None,
                }));
            }

            let stats = self.ctx.dhcpv6_stats();
            match msg.msg_type() {
                MessageType::Solicit => {
                    stats.solicits.fetch_add(1, Ordering::Relaxed);
                }
                MessageType::Request => {
                    stats.requests.fetch_add(1, Ordering::Relaxed);
                }
                MessageType::Renew => {
                    stats.renews.fetch_add(1, Ordering::Relaxed);
                }
                MessageType::Rebind => {
                    stats.rebinds.fetch_add(1, Ordering::Relaxed);
                }
                MessageType::Release => {
                    stats.releases.fetch_add(1, Ordering::Relaxed);
                }
                MessageType::Decline => {
                    stats.declines.fetch_add(1, Ordering::Relaxed);
                }
                MessageType::InformationRequest => {
                    stats.info_requests.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }

            let handle_res = server.handle_packet(&msg, peer_ip, resolved_mac, &mut resp_vec);
            if let HandleResult::Reply(
                reply_bytes,
                dest_ip,
                learned_duid,
                opt_mac,
                assigned_ias,
                released_ias,
                msg_type,
            ) = handle_res
            {
                match msg_type {
                    MessageType::Reply => {
                        stats.replies.fetch_add(1, Ordering::Relaxed);
                    }
                    MessageType::Advertise => {
                        stats.advertises.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
                let client_port = if self.config.port == 547 {
                    546
                } else {
                    self.config.port - 1
                };
                let dest_addr = SocketAddrV6::new(dest_ip, client_port, 0, scope_id);
                let _ = transport.send_reply(reply_bytes, dest_addr.into());
                apply_learned_state(
                    &self.ctx,
                    opt_mac,
                    learned_duid.as_ref(),
                    &assigned_ias,
                    &released_ias,
                    server,
                    &self.config,
                );
            }
        }
    }

    fn handle_bus_event(
        &self,
        event: &TimedEvent,
        server: &mut Dhcpv6Server,
        transport: &io::Dhcpv6Transport,
    ) {
        match_event!(event, {
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
            LanforgeEvent::Device(DeviceEvent::AdminUpdate { mac, change, .. }) => {
                if let AdminChange::V6SuffixChanged { suffix } = change.as_ref() {
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
                self.handle_prefix_change(server, transport, *gua, *preferred, *valid);
            }
            LanforgeEvent::Device(DeviceEvent::LeaseRenew {
                mac,
                target: LeaseTarget::V6 { .. } | LeaseTarget::V6Prefix { .. },
            }) => {
                let (duid, target_ip) = {
                    let device = self.ctx.get_device(mac);
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
                    let _ = transport.send_reply(&packet, dest_addr.into());
                }
            }
        });
    }

    fn handle_prefix_change(
        &self,
        server: &mut Dhcpv6Server,
        transport: &io::Dhcpv6Transport,
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

                let reconfigs = self.ctx.with_state(|state| {
                    let mut list = Vec::new();
                    for dev in state.devices.values() {
                        if let Some(duid) = &dev.duid {
                            let has_gua_lease = dev.v6.iter().any(|s| {
                                if let IPv6State::Dynamic(lease) = s {
                                    let o = lease.ip.octets();
                                    (0x20..=0x3F).contains(&o[0])
                                } else {
                                    false
                                }
                            });
                            if has_gua_lease
                                && let Some(ll_ip) = dev.v6.iter().find_map(|s| {
                                    s.ip().filter(|ip| (ip.segments()[0] & 0xffc0) == 0xfe80)
                                })
                            {
                                list.push((duid.clone(), ll_ip));
                            }
                        }
                    }
                    list
                });

                for (duid, ll_ip) in reconfigs {
                    let packet = server.build_reconfigure(&duid, MessageType::Renew);
                    let client_port = if self.config.port == 547 {
                        546
                    } else {
                        self.config.port - 1
                    };
                    let dest_addr = std::net::SocketAddrV6::new(ll_ip, client_port, 0, 0);
                    let _ = transport.send_reply(&packet, dest_addr.into());
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
    assigned_ias: &server::AssignedIAs,
    released_ias: &server::AssignedIAs,
    server: &Dhcpv6Server,
    config: &Dhcpv6Config,
) {
    let expires = SystemTime::now() + Duration::from_secs(u64::from(config.lease_time));

    // 1. Process IA_NA (Non-temporary Addresses)
    for &iaid in &assigned_ias.na {
        let assigned_ip_addrs = learned_duid.map_or_else(
            || opt_mac.map_or_else(Vec::new, |mac| server.pool.lookup_by_mac_legacy(ctx, mac)),
            |duid| server.last_assignment_for(duid, iaid),
        );

        if assigned_ip_addrs.is_empty() {
            if let Some(duid) = learned_duid {
                // No IPs assigned yet, but IAID is known
                let _ = ctx.apply(DeviceUpdate::DuidAssociated {
                    mac: opt_mac,
                    duid: duid.clone(),
                    iaid,
                });
            }
        } else {
            // One or more IPs assigned
            for ip in assigned_ip_addrs {
                if let Some(duid) = learned_duid {
                    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted {
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
                        let _ = ctx.apply(DeviceUpdate::V6LeaseGranted {
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
    for &iaid in &assigned_ias.pd {
        let assigned_prefix = learned_duid
            .as_ref()
            .and_then(|duid| server.pool.lookup_prefix(ctx, duid, iaid));

        if let (Some(duid), Some((prefix, len))) = (learned_duid, assigned_prefix) {
            let _ = ctx.apply(DeviceUpdate::V6PrefixAssigned {
                mac: opt_mac,
                duid: duid.clone(),
                iaid,
                prefix,
                len,
                expires,
            });
        }
    }

    // 3. Process Released/Declined IA_NAs and IA_PDs
    if let Some(mac) = opt_mac {
        for &iaid in &released_ias.na {
            let _ = ctx.apply(DeviceUpdate::LeaseReleased {
                mac,
                target: LeaseTarget::V6 { iaid },
            });
        }
        for &iaid in &released_ias.pd {
            let _ = ctx.apply(DeviceUpdate::LeaseReleased {
                mac,
                target: LeaseTarget::V6Prefix { iaid },
            });
        }
    }
}
