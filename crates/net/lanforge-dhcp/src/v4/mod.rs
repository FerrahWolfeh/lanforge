//! `DHCPv4` service — Dynamic IPv4 address management (RFC 2131).
//!
//! This service listens for requests on port 67/UDP and manages an address pool,
//! supporting static MAC-based reservations.
//!
//! ## DORA Cycle (Discovery, Offer, Request, Ack)
//!
//! ```mermaid
//! sequenceDiagram
//!     participant C as Client
//!     participant S as DhcpServer (Lanforge)
//!     participant Ctx as LanforgeContext
//!
//!     C->>S: 1. DHCP Discover (Broadcast)
//!     S->>C: 2. DHCP Offer (Unicast/Broadcast)
//!
//!     C->>S: 3. DHCP Request
//!     S->>Ctx: 4. apply(DeviceUpdate::V4LeaseGranted)
//!     Ctx-->>S: 5. EventBus Signal
//!     S->>C: 6. DHCP Ack
//! ```
//!
//! ## Manager Integration
//!
//! The `dhcpv4_service` uses the `LanforgeContext` to persist leases and suggest
//! hostnames learned via Option 12. State merging and `EventBus` signaling
//! are handled automatically by the `LanforgeContext`.

pub mod config;
pub mod io;
pub mod pool;
pub mod raw;
pub mod server;

use dhcproto::v4::{DhcpOption, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Decodable, Decoder};
use lanforge_core::bus::{AdminChange, DeviceEvent, DhcpV4MessageType, LanforgeEvent, SystemEvent};
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceDependency};
use lanforge_macros::lanforge_service;
use lanforge_types::device::IPv4State;
use lanforge_types::events::TimedEvent;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::Dhcpv4Pool;
use lanforge_types::system::RunResult;
use lanforge_types::update::{DeviceUpdate, LeaseTarget};
use server::{DhcpServer, HandleResult};
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime};
use tracing::{debug, info, warn};

pub use config::Dhcpv4Config;
use crate::traits::DhcpPool;
use io::Dhcpv4Transport;
use lanforge_core::context::{LanforgeContext, ServiceHandle};

/// `DHCPv4` Server Service.
#[lanforge_service(
    id = "dhcpv4",
    name = "DHCPv4 Server",
    critical = true,
    retries = 0,
    base_backoff = 2,
    max_backoff = 30
)]
#[derive(Clone)]
pub struct Dhcpv4Service {
    cfg: Dhcpv4Config,
    ctx: LanforgeContext,
}

impl Dhcpv4Service {
    #[must_use]
    pub const fn new(cfg: Dhcpv4Config, ctx: LanforgeContext) -> Self {
        Self { cfg, ctx }
    }
}

impl AsyncService for Dhcpv4Service {
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[ServiceDependency::Database, ServiceDependency::Interfaces]
    }

    fn stats(&self, ctx: &LanforgeContext) -> Vec<(std::borrow::Cow<'static, str>, String)> {
        let (active_leases, pool_total, pool_available) = ctx.with_state(|state| {
            let leases = u32::try_from(
                state
                    .devices
                    .values()
                    .filter(|dev| matches!(dev.v4, IPv4State::Dynamic(_)))
                    .count(),
            )
            .unwrap_or(0);
            let (total, avail) = state
                .interfaces
                .v4_pool
                .as_ref()
                .map_or((0, 0), |p| (p.total, p.available));
            (leases, total, avail)
        });
        let v4_stats = ctx.dhcpv4_stats().snapshot();
        vec![
            (std::borrow::Cow::Borrowed("iface"), self.cfg.iface.clone()),
            (
                std::borrow::Cow::Borrowed("lease_time"),
                self.cfg.lease_time.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("port"),
                self.cfg.port.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("leases_active"),
                active_leases.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("pool_total"),
                pool_total.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("pool_available"),
                pool_available.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("discovers"),
                v4_stats.discovers.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("offers"),
                v4_stats.offers.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("requests"),
                v4_stats.requests.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("acks"),
                v4_stats.acks.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("naks"),
                v4_stats.naks.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("releases"),
                v4_stats.releases.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("declines"),
                v4_stats.declines.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("informs"),
                v4_stats.informs.to_string(),
            ),
        ]
    }

    async fn serve(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        loop {
            let pools = ctx.get_dhcp_v4_pools();

            if pools.is_empty() {
                warn!("DHCPv4: Service enabled but no pools configured — server idle");
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

impl Dhcpv4Service {
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
                    SystemEvent::ConfigDhcpV4Changed | SystemEvent::ConfigDhcpOptionsChanged
                )
            ) {
                return Ok(RunResult::ConfigChanged);
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn run_server(
        &self,
        pools: Vec<Dhcpv4Pool>,
    ) -> Result<RunResult, CoreError> {
        let mut current_cfg = self.cfg.clone();
        let options = self.ctx.get_dhcp_options();
        if !options.v4.enabled {
            warn!("DHCPv4: Service disabled via options configuration — server idle");
            return self.wait_for_config_change_or_shutdown().await;
        }

        if let Some(r) = options.v4.router {
            current_cfg.router = r;
            current_cfg.server_id = r;
        }
        if let Some(m) = options.v4.subnet_mask {
            current_cfg.subnet_mask = m;
        }
        if !options.v4.dns_servers.is_empty() {
            current_cfg.dns = options.v4.dns_servers;
        }
        if let Some(d) = options.v4.domain_name {
            current_cfg.domain_name = Some(d);
        }
        if !options.v4.search_domains.is_empty() {
            current_cfg.search_domains = options.v4.search_domains;
        }
        if !options.v4.ntp_servers.is_empty() {
            current_cfg.ntp_servers = options.v4.ntp_servers;
        }
        if options.v4.lease_time > 0 {
            current_cfg.lease_time = options.v4.lease_time;
        }
        if let Some(t) = options.v4.tftp_server {
            current_cfg.tftp_server = Some(t);
        }
        if let Some(b) = options.v4.boot_file {
            current_cfg.boot_file = Some(b);
        }
        current_cfg.pools = pools;

        let mut server = DhcpServer::new(current_cfg.clone(), self.ctx.clone());
        let transport = Dhcpv4Transport::new(&current_cfg.iface, current_cfg.port)?;

        // Pre-allocate static reservations to avoid collisions with dynamic pool
        let registry = self.ctx.get_static_registry();
        server.pool.reserve_statics(registry.v4_ips());

        // Sanity check: audit and reconcile all dynamic leases loaded from DB/previous config.
        // Static leases (fixed IPs) are untouched; stale dynamic leases outside active pools/subnet
        // are invalidated and clients are prompted to re-authenticate via RFC 3203 FORCERENEW.
        self.reconcile_dynamic_leases(&mut server, &transport, &current_cfg);

        let (total, used, available, util_pct) = server.pool.stats();
        let range_start = current_cfg
            .range_start
            .or_else(|| current_cfg.pools.first().map(|p| p.range_start))
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        let range_end = current_cfg
            .range_end
            .or_else(|| current_cfg.pools.first().map(|p| p.range_end))
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        let _ = self.ctx.apply(DeviceUpdate::DhcpV4PoolUpdated {
            range_start,
            range_end,
            subnet_mask: current_cfg.subnet_mask,
            total,
            used,
            available,
            utilization_percent: util_pct,
        });

        let mut buf = [0u8; 1500];
        let mut handle = self.ctx.service_handle();
        let mut cleanup_timer = tokio::time::interval(Duration::from_mins(1));

        loop {
            tokio::select! {
                res = transport.recv(&mut buf) => {
                    match res {
                        Ok((len, _)) => {
                            self.handle_incoming_packet(
                                &buf[..len],
                                &mut server,
                                &transport,
                                &handle,
                            );
                        }
                        Err(e) => warn!("DHCPv4: recv_from error: {e}"),
                    }
                }
                event = handle.next_event() => {
                    let Some(timed_event) = event else {
                        return Ok(RunResult::Shutdown);
                    };
                    if matches!(
                        timed_event.event,
                        LanforgeEvent::System(
                            SystemEvent::ConfigDhcpV4Changed | SystemEvent::ConfigDhcpOptionsChanged
                        )
                    ) {
                        return Ok(RunResult::ConfigChanged);
                    }
                    self.handle_bus_event(&timed_event, &mut server, &transport);
                }
                _ = cleanup_timer.tick() => {
                    server.pool.cleanup_quarantine(Instant::now());
                    self.reconcile_dynamic_leases(&mut server, &transport, &current_cfg);
                    let (total, used, available, util_pct) = server.pool.stats();
                    let range_start = current_cfg.range_start.or_else(|| current_cfg.pools.first().map(|p| p.range_start)).unwrap_or(Ipv4Addr::UNSPECIFIED);
                    let range_end = current_cfg.range_end.or_else(|| current_cfg.pools.first().map(|p| p.range_end)).unwrap_or(Ipv4Addr::UNSPECIFIED);
                    let _ = self.ctx.apply(DeviceUpdate::DhcpV4PoolUpdated {
                        range_start,
                        range_end,
                        subnet_mask: current_cfg.subnet_mask,
                        total,
                        used,
                        available,
                        utilization_percent: util_pct,
                    });
                }
            }
        }
    }
}

impl Dhcpv4Service {
    #[allow(clippy::too_many_lines)]
    fn handle_incoming_packet(
        &self,
        data: &[u8],
        server: &mut DhcpServer,
        transport: &Dhcpv4Transport,
        handle: &ServiceHandle,
    ) {
        if let Ok(msg) = Message::decode(&mut Decoder::new(data))
            && msg.opcode() == Opcode::BootRequest
        {
            let chaddr = msg.chaddr();
            if chaddr.len() >= 6 {
                let mac = MacAddr([
                    chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5],
                ]);

                // Diagnostic: Publish DHCPv4 Transaction
                if let Some(DhcpOption::MessageType(t)) = msg.opts().get(OptionCode::MessageType) {
                    let msg_type = u8::from(*t);
                    let stats = self.ctx.dhcpv4_stats();
                    match msg_type {
                        1 => {
                            stats.discovers.fetch_add(1, Ordering::Relaxed);
                        }
                        3 => {
                            stats.requests.fetch_add(1, Ordering::Relaxed);
                        }
                        4 => {
                            stats.declines.fetch_add(1, Ordering::Relaxed);
                        }
                        7 => {
                            stats.releases.fetch_add(1, Ordering::Relaxed);
                        }
                        8 => {
                            stats.informs.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                    let _ = handle.publish(LanforgeEvent::Device(DeviceEvent::DhcpV4Transaction {
                        mac,
                        msg_type: DhcpV4MessageType::from(msg_type),
                        details: None,
                    }));
                }

                let handle_res = {
                    let device = self.ctx.get_device(&mac);
                    server.handle_packet(data, device)
                };

                match handle_res {
                    HandleResult::Reply {
                        packet,
                        broadcast,
                        dest_ip,
                        giaddr,
                        hostname: req_hostname,
                        msg_type,
                    } => {
                        let stats = self.ctx.dhcpv4_stats();
                        match msg_type {
                            MessageType::Offer => {
                                stats.offers.fetch_add(1, Ordering::Relaxed);
                            }
                            MessageType::Ack => {
                                stats.acks.fetch_add(1, Ordering::Relaxed);
                            }
                            MessageType::Nak => {
                                stats.naks.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {}
                        }

                        if let Err(e) = transport.send_reply(
                            &packet,
                            self.cfg.server_id,
                            broadcast,
                            dest_ip,
                            giaddr,
                            mac,
                            self.cfg.port,
                        ) {
                            warn!("DHCPv4: Failed to send reply: {e}");
                        }

                        if let Some(assigned_ip) = server.last_assignment_for() {
                            let expires = SystemTime::now()
                                + Duration::from_secs(u64::from(self.cfg.lease_time));

                            let _ = self.ctx.apply(DeviceUpdate::V4LeaseGranted {
                                mac,
                                ip: assigned_ip,
                                expires,
                            });

                            if !self.cfg.iface.is_empty() {
                                let _ = self.ctx.apply(DeviceUpdate::DeviceInterfaceSeen {
                                    mac,
                                    iface: self.cfg.iface.clone(),
                                });
                            }

                            if let Some(hostname) = req_hostname
                                && !hostname.is_empty()
                            {
                                let _ = self
                                    .ctx
                                    .apply(DeviceUpdate::DhcpHostnameHint { mac, hostname });
                            }
                        }
                    }
                    HandleResult::Release { ip: _ } => {
                        let _ = self.ctx.apply(DeviceUpdate::LeaseReleased {
                            mac,
                            target: LeaseTarget::V4,
                        });
                    }
                    HandleResult::Ignore => {}
                }
            }
        }
    }

    fn handle_bus_event(
        &self,
        event: &TimedEvent,
        server: &mut DhcpServer,
        transport: &Dhcpv4Transport,
    ) {
        lanforge_core::match_event!(event, {
            LanforgeEvent::Device(DeviceEvent::LeaseRelease {
                mac,
                target: LeaseTarget::V4,
            }) => {
                info!("DHCPv4: Forcing release of {} via CLI", mac);
                let ip = self.ctx.get_device(mac).and_then(|d| d.v4.ip());
                if let Some(i) = ip {
                    server.pool.release(&i);
                }
            }
            LanforgeEvent::Device(DeviceEvent::LeaseRenew {
                mac,
                target: LeaseTarget::V4,
            }) => {
                let ip = self.ctx.get_device(mac).and_then(|d| d.v4.ip());
                if let Some(ip) = ip {
                    let packet = server.build_forcerenew(*mac, ip);
                    if let Err(e) = transport.send_reply(
                        &packet,
                        self.cfg.server_id,
                        false,
                        ip,
                        Ipv4Addr::UNSPECIFIED,
                        *mac,
                        self.cfg.port,
                    ) {
                        warn!("DHCPv4: Failed to send FORCERENEW to {ip} ({mac}): {e}");
                    }
                }
            }
            LanforgeEvent::Device(DeviceEvent::AdminUpdate { mac, change, .. }) => {
                if let AdminChange::V4StaticChanged { ip } = change.as_ref() {
                    match ip {
                        Some(v) => {
                            info!("DHCPv4: New static reservation via CLI: {mac} -> {v}");
                            server.pool.decline(*v);
                            info!("DHCPv4: Handled statically.");
                        }
                        None => {
                            info!("DHCPv4: Static reservation cleared for {mac}");
                        }
                    }
                }
            }
        });
    }

    /// Audits and reconciles all in-memory and database dynamic leases against the active pools
    /// and subnet configuration.
    ///
    /// - Static leases with fixed IPs (inside or outside pools) are NEVER touched.
    /// - Dynamic leases outside active pools or with mismatched subnet/router are invalidated
    ///   via `DeviceUpdate::LeaseReleased`, removing them from limbo.
    /// - A proactive RFC 3203 `FORCERENEW` packet is injected via raw L2 to prompt the client
    ///   to immediately renew/re-authenticate into the valid pool range.
    /// - Only verified valid dynamic leases are seeded into the pool allocation bitmap.
    fn reconcile_dynamic_leases(
        &self,
        server: &mut DhcpServer,
        transport: &Dhcpv4Transport,
        cfg: &Dhcpv4Config,
    ) {
        let dynamic_leases: Vec<(MacAddr, Ipv4Addr, String)> = self.ctx.with_state(|state| {
            state
                .devices
                .values()
                .filter_map(|dev| match &dev.v4 {
                    IPv4State::Dynamic(lease) => {
                        Some((dev.mac, lease.ip, dev.hostname.name.clone()))
                    }
                    // Static reservations (fixed IPs inside or outside pool ranges) MUST NOT be touched
                    IPv4State::Static(_) | IPv4State::None => None,
                })
                .collect()
        });

        let mut valid_dynamic_ips = Vec::new();

        for (mac, ip, hostname) in dynamic_leases {
            if server.pool.is_valid_dynamic_ip(ip, cfg.subnet_mask, Some(cfg.router)) {
                valid_dynamic_ips.push(ip);
            } else {
                let name = if hostname.is_empty() { "unknown" } else { &hostname };
                let reason = if server.pool.is_in_range(ip) {
                    format!(
                        "IP {ip} does not match subnet mask {} or gateway {}",
                        cfg.subnet_mask, cfg.router
                    )
                } else {
                    format!("IP {ip} is outside active dynamic pool ranges")
                };

                warn!(
                    "DHCPv4 SANITY CHECK: Invalidating stale dynamic lease {ip} for {mac} ({name}) — {reason}"
                );

                // 1. Proactively notify the client to re-authenticate (RFC 3203 FORCERENEW)
                let packet = server.build_forcerenew(mac, ip);
                if let Err(e) = transport.send_reply(
                    &packet,
                    cfg.server_id,
                    false,
                    ip,
                    Ipv4Addr::UNSPECIFIED,
                    mac,
                    cfg.port,
                ) {
                    debug!("DHCPv4: Could not send FORCERENEW to {ip} ({mac}): {e}");
                }

                // 2. Invalidate lease in State and DB so it no longer lingers in limbo
                let _ = self.ctx.apply(DeviceUpdate::LeaseReleased {
                    mac,
                    target: LeaseTarget::V4,
                });
            }
        }

        // Reserve only valid dynamic leases in the pool
        server.pool.reserve_statics(valid_dynamic_ips);
    }
}
