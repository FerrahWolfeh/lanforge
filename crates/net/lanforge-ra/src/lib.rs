//! # Lanforge Router Advertisement Server
//!
//! `ICMPv6` Router Advertisement daemon for Lanforge.
//! Router Advertisement service (RFC 4861 + RFC 8106).
//!
//! Full RFC-compliant RA implementation for IPv6 clients. Supports startup
//! burst, rate-limited periodic advertisements, RS-triggered unicast responses
//! with random delay, and DNS options (RDNSS + DNSSL).
//!
//! ## RA/RS Cycle
//!
//! ```mermaid
//! sequenceDiagram
//!     participant R as Router (Lanforge)
//!     participant C as Client
//!
//!     Note over R,C: Startup Burst (3 RAs, 16s interval)
//!     R->>C: RA multicast (ff02::1)
//!     R->>C: RA multicast
//!     R->>C: RA multicast
//!     Note over R,C: Periodic (MinRtrAdvInterval)
//!     R->>C: RA multicast
//!     Note over R,C: RS Triggered
//!     C->>R: RS (solicitation)
//!     Note right of R: Random delay 0-500ms
//!     R->>C: RA unicast (response)
//! ```
//!
//! ## Implemented RFCs
//!
//! | RFC | Purpose |
//! | :--- | :--- |
//! | 4861 | Neighbor Discovery — Full RA/RS support |
//! | 8106 | RA Options for DNS (RDNSS + DNSSL) |
//! | 4191 | Default Router Preferences (Low/Medium/High) |
//! | 3775 | `AdvRouterAddr` flag in Prefix Information |
//!
//! ## Design
//!
//! - Uses **raw `ICMPv6` sockets** (not async `UdpSocket`) for direct packet control
//! - `ICMP6_FILTER` kernel optimization to only receive `RS` packets (reduces CPU)
//! - **`RaState`** handles `RFC` timing independently of the service struct
//! - `RaContext` is a `Copy` reference holder for zero-allocation packet building
//!
//! ## Service Model
//!
//! Runs as `AsyncService` with raw socket wrapped in `AsyncFd` for tokio readiness.
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod error;

pub mod config;
pub mod packet;

pub use config::*;
use lanforge_core::context::LanforgeContext;
use lanforge_types::config::ChangeImpact;
use lanforge_types::network::ra::{
    ICMPV6_TYPE_RS, MAX_INITIAL_RTR_ADVERT_INTERVAL, MAX_INITIAL_RTR_ADVERTISEMENTS,
    MAX_RA_DELAY_TIME_MS, MIN_DELAY_BETWEEN_RAS, PreviousLanPrefixes, RAPrefix, RaServerConfig,
};
use lanforge_types::system::{DormantReason, RaStatusResponse, RunResult};

pub use packet::{build_ra_packet, icmpv6_checksum};

use crate::error::NetworkError;
use lanforge_core::bus::{LanforgeEvent, NetworkEvent};
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    Activation, AsyncService, Condition, Edge, LanforgeService, RestartPolicy, RuntimeClass,
    ServiceCommand, ServiceHandle, ServiceSpec,
};
use lanforge_transport::{Icmp6Transport, TransportSnapshot, TransportStats};
use rand::RngExt;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

const ALL_NODES_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

// ---------------------------------------------------------------------------
// Runtime State — Handles RFC-compliant timing
// ---------------------------------------------------------------------------

/// Runtime timing state and live metrics for the RA service.
///
/// Tracks RFC 4861 startup burst counters, last multicast/unicast timestamps,
/// packet metrics, and rate limiting logic. Designed to be used independently of the service struct.
///
/// # RFC 4861 Timing Rules
///
/// - **Startup burst**: 3 RAs at 16s intervals (§6.2.6)
/// - **Min delay between multicast RAs**: 3s (§6.2.4)
/// - **Max random delay after RS**: 500ms (§6.2.6)
pub struct RaState {
    /// Count of initial RAs sent (startup phase tracking).
    initial_sent: u8,
    /// Timestamp of the last multicast RA sent (applies `MIN_DELAY_BETWEEN_RAS`).
    last_multicast_ra: Option<Instant>,
    /// Unicast rate limiting: tracks the last RA sent per destination IP.
    unicast_rl: HashMap<Ipv6Addr, Instant>,
    /// Last detected GUA — used to publish `PrefixChanged` only when a change occurs.
    last_gua: Option<lanforge_types::network::Ipv6Prefix>,
    /// Last detected ULA
    last_ula: Option<lanforge_types::network::Ipv6Prefix>,
    /// Deprecated prefixes: (Prefix, `deprecation_end`, `valid_end`)
    pub(crate) deprecated_prefixes: Vec<(Ipv6Addr, Instant, Instant)>,
    /// Total multicast RAs sent to `ff02::1`
    pub(crate) sent_multicast_ras: u64,

    /// Total unicast RAs sent directly to clients
    pub(crate) sent_unicast_ras: u64,
    /// Total Router Solicitations received
    pub(crate) received_solicitations: u64,
    /// Total Router Solicitations ignored due to rate limit
    pub(crate) ignored_solicitations: u64,
    /// Instant when the last RA was sent
    pub(crate) last_ra_sent: Option<Instant>,
    /// Instant when the last RS was received
    pub(crate) last_rs_received: Option<Instant>,
    /// Instant when the service was initialized
    pub(crate) start_time: Instant,
}

impl RaState {
    pub(crate) fn new() -> Self {
        Self {
            initial_sent: 0,
            last_multicast_ra: None,
            unicast_rl: HashMap::new(),
            last_gua: None,
            last_ula: None,
            deprecated_prefixes: Vec::new(),
            sent_multicast_ras: 0,
            sent_unicast_ras: 0,
            received_solicitations: 0,
            ignored_solicitations: 0,
            last_ra_sent: None,
            last_rs_received: None,
            start_time: Instant::now(),
        }
    }

    /// Determine the interval for the next periodic RA (RFC 4861 §6.2.4).
    ///
    /// During startup phase: uses shorter intervals (up to `MAX_INITIAL_RTR_ADVERT_INTERVAL`)
    /// for fast convergence. Afterwards: uniform random interval within [Min, Max].
    fn next_interval(&self, cfg: &RaConfig) -> Duration {
        let mut rng = rand::rng();
        if self.initial_sent < MAX_INITIAL_RTR_ADVERTISEMENTS {
            let ms = rng.random_range(
                0..u64::try_from(MAX_INITIAL_RTR_ADVERT_INTERVAL.as_millis()).unwrap_or(u64::MAX),
            );
            Duration::from_millis(ms)
        } else {
            let min_ms =
                u64::try_from(cfg.effective_min_interval().as_millis()).unwrap_or(u64::MAX);
            let max_ms = u64::try_from(cfg.max_interval.as_millis()).unwrap_or(u64::MAX);
            Duration::from_millis(rng.random_range(min_ms..=max_ms))
        }
    }

    pub(crate) fn can_multicast_now(&self) -> bool {
        self.last_multicast_ra
            .is_none_or(|t| t.elapsed() >= MIN_DELAY_BETWEEN_RAS)
    }

    pub(crate) fn can_unicast_now(&self, dst: &Ipv6Addr) -> bool {
        self.unicast_rl
            .get(dst)
            .is_none_or(|t| t.elapsed() >= MIN_DELAY_BETWEEN_RAS)
    }

    pub(crate) fn record_multicast(&mut self) {
        let now = Instant::now();
        self.last_multicast_ra = Some(now);
        self.last_ra_sent = Some(now);
        self.initial_sent = self.initial_sent.saturating_add(1);
        self.sent_multicast_ras = self.sent_multicast_ras.saturating_add(1);
    }

    pub(crate) fn record_unicast(&mut self, dst: Ipv6Addr) {
        let now = Instant::now();
        if self.unicast_rl.len() >= 32 {
            self.unicast_rl
                .retain(|_, last_sent| now.duration_since(*last_sent) < Duration::from_secs(10));
        }
        self.unicast_rl.insert(dst, now);
        self.last_ra_sent = Some(now);
        self.sent_unicast_ras = self.sent_unicast_ras.saturating_add(1);
    }

    pub(crate) fn record_solicitation_received(&mut self) {
        self.received_solicitations = self.received_solicitations.saturating_add(1);
        self.last_rs_received = Some(Instant::now());
    }

    pub(crate) const fn record_solicitation_ignored(&mut self) {
        self.ignored_solicitations = self.ignored_solicitations.saturating_add(1);
    }

    pub(crate) fn deprecated_list(&self, now: Instant) -> Vec<(Ipv6Addr, u32)> {
        if self.deprecated_prefixes.is_empty() {
            return Vec::new();
        }
        self.deprecated_prefixes
            .iter()
            .map(|&(ip, _, valid_end)| {
                let remaining = if valid_end > now {
                    u32::try_from((valid_end - now).as_secs()).unwrap_or(u32::MAX)
                } else {
                    0
                };
                (ip, remaining)
            })
            .collect()
    }

    pub(crate) fn build_status(
        &self,
        cfg: &RaConfig,
        ctx: &LanforgeContext,
        next_ra_at: Option<Instant>,
    ) -> RaStatusResponse {
        let target_ifindex = ctx.target_ifindex().unwrap_or(0);
        let if_ips = ctx.get_interface_state(target_ifindex);
        let now = Instant::now();
        let deprecated_list = self.deprecated_list(now);

        RaStatusResponse {
            enabled: true,
            interface: Some(cfg.iface.clone()),
            link_local: if_ips.link_local,
            active_gua_prefix: if_ips.gua,
            active_ula_prefix: if_ips.ula,
            prefixes: cfg.prefixes.clone(),
            rdnss: cfg.rdnss.clone(),
            dnssl: cfg.dnssl.clone(),
            deprecated_prefixes: deprecated_list,
            sent_multicast_ras: self.sent_multicast_ras,
            sent_unicast_ras: self.sent_unicast_ras,
            received_solicitations: self.received_solicitations,
            ignored_solicitations: self.ignored_solicitations,
            last_ra_sent_secs_ago: self.last_ra_sent.map(|t| t.elapsed().as_secs()),
            last_rs_received_secs_ago: self.last_rs_received.map(|t| t.elapsed().as_secs()),
            next_ra_in_secs: next_ra_at.map(|t| if t > now { (t - now).as_secs() } else { 0 }),
            managed: cfg.managed,
            other_config: cfg.other_config,
            hop_limit: cfg.hop_limit,
            priority: cfg.priority,
            max_interval_secs: cfg.max_interval.as_secs(),
            min_interval_secs: cfg.effective_min_interval().as_secs(),
            router_lifetime_secs: cfg.effective_router_lifetime().as_secs(),
            mtu: cfg.mtu,
            uptime_secs: Some(self.start_time.elapsed().as_secs()),
        }
    }

    pub(crate) fn update_prefix_and_deprecate(
        &mut self,
        current: Option<lanforge_types::network::Ipv6Prefix>,
        is_gua: bool,
        deprecate_on_renumber: bool,
    ) -> bool {
        let last = if is_gua { self.last_gua } else { self.last_ula };
        if current == last {
            false
        } else {
            if let Some(old) = last
                && deprecate_on_renumber
            {
                let now = Instant::now();
                // RFC 4862 §5.5.3e:
                // Deprecate old prefix with preferred_lifetime = 0 and valid_lifetime = min(remaining, 7200) (2 hours).
                let valid_duration = Duration::from_secs(7200);
                let valid_end = now + valid_duration;
                let deprecation_end = valid_end;
                let old_addr = old.to_addr();
                if !self
                    .deprecated_prefixes
                    .iter()
                    .any(|(ip, _, _)| *ip == old_addr)
                {
                    self.deprecated_prefixes
                        .push((old_addr, deprecation_end, valid_end));
                }
            }
            // A prefix that comes back (address flap) is live again: never advertise it twice,
            // once valid and once deprecated.
            if let Some(cur) = current {
                let cur_addr = cur.to_addr();
                self.deprecated_prefixes
                    .retain(|(ip, _, _)| *ip != cur_addr);
            }
            let prefix_type = if is_gua { "GUA" } else { "ULA" };
            debug!("Internal {prefix_type} prefix state updated: {current:?}");
            if is_gua {
                self.last_gua = current;
            } else {
                self.last_ula = current;
            }
            true
        }
    }
}

use lanforge_types::system::ServiceId;

const RA_DEPS: &[Edge] = &[
    Edge::requires(
        ServiceId::Interfaces,
        lanforge_core::service::LossPolicy::Continue,
    ),
    Edge::wants(ServiceId::Wan),
];
#[derive(Clone)]
pub struct RaService {
    cfg: RaConfig,
    ctx: LanforgeContext,
    transport: Option<Icmp6Transport>,
}

impl RaService {
    /// Static identifier for the service.
    pub const SERVICE_ID: ServiceId = ServiceId::Ra;

    #[must_use]
    pub const fn new(cfg: RaConfig, ctx: LanforgeContext) -> Self {
        Self {
            cfg,
            ctx,
            transport: None,
        }
    }

    /// Creates an instance of `RaService` with an injected transport.
    #[must_use]
    pub const fn with_transport(
        cfg: RaConfig,
        ctx: LanforgeContext,
        transport: Icmp6Transport,
    ) -> Self {
        Self {
            cfg,
            ctx,
            transport: Some(transport),
        }
    }

    async fn resolve_interface_resources(
        &self,
        iface_index: u32,
    ) -> Result<([u8; 6], Icmp6Transport), CoreError> {
        // Parallel optimization: Wait for interface data ONLY if not already present
        if self
            .ctx
            .get_interface_state(iface_index)
            .link_local
            .is_none()
        {
            info!("Waiting for interface discovery on '{}'...", self.cfg.iface);
            self.ctx.wait_for_interfaces().await?;
        }

        let mac = self
            .ctx
            .with_state(|state| {
                state
                    .interfaces
                    .interface_ips
                    .get(&iface_index)
                    .and_then(|i| i.mac)
            })
            .or_else(|| {
                std::fs::read_to_string(format!("/sys/class/net/{}/address", self.cfg.iface))
                    .ok()
                    .and_then(|s| lanforge_types::identifiers::MacAddr::parse(s.trim()))
            })
            .or_else(|| {
                self.ctx
                    .get_interface_state(iface_index)
                    .link_local
                    .and_then(|ll| lanforge_types::utils::mac_from_eui64_link_local(&ll))
            })
            .ok_or_else(|| {
                CoreError::Generic(format!(
                    "MAC address for interface index {iface_index} is not resolved"
                ))
            })?
            .0;

        let transport = Icmp6Transport::bind(&self.cfg.iface, iface_index)
            .map_err(|e| CoreError::Generic(e.to_string()))?;

        Ok((mac, transport))
    }

    async fn wait_for_config_change_or_shutdown(
        &self,
        h: &ServiceHandle,
    ) -> Result<RunResult, CoreError> {
        let mut ra_sub = self.ctx.config_subscription::<RaServerConfig>();
        let mut prefix_sub = self.ctx.config_subscription::<Vec<RAPrefix>>();

        loop {
            tokio::select! {
                cmd = h.next_command() => {
                    match cmd {
                        ServiceCommand::Stop | ServiceCommand::Shutdown => return Ok(RunResult::Shutdown),
                        ServiceCommand::Restart => {
                            h.request_restart();
                            return Ok(RunResult::Shutdown);
                        }
                        _ => {}
                    }
                }
                delta_opt = ra_sub.next() => {
                    if let Some(delta) = delta_opt
                        && delta.new.enabled
                        && !delta.new.prefixes.is_empty()
                    {
                        return Ok(RunResult::ConfigChanged);
                    }
                }
                delta_opt = prefix_sub.next() => {
                    if let Some(delta) = delta_opt
                        && !delta.new.is_empty()
                    {
                        return Ok(RunResult::ConfigChanged);
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn run_server(
        &mut self,
        mut current_cfg: RaConfig,
        h: &ServiceHandle,
    ) -> Result<RunResult, CoreError> {
        current_cfg
            .validate()
            .map_err(|e| CoreError::Generic(e.to_string()))?;

        info!(
            iface = %current_cfg.iface,
            managed = u8::from(current_cfg.managed),
            other_config = u8::from(current_cfg.other_config),
            max_interval_secs = current_cfg.max_interval.as_secs(),
            router_lifetime_secs = current_cfg.effective_router_lifetime().as_secs(),
            "Server active"
        );

        let iface_index = self.ctx.target_ifindex().unwrap_or(1);

        let (mac, transport) = if let Some(ref t) = self.transport {
            let mac = self
                .ctx
                .with_state(|state| {
                    state
                        .interfaces
                        .interface_ips
                        .get(&iface_index)
                        .and_then(|i| i.mac)
                })
                .map_or([0x02, 0x11, 0x22, 0x33, 0x44, 0x55], |m| m.0);
            (mac, t.clone())
        } else {
            let (mac, t) = self.resolve_interface_resources(iface_index).await?;
            self.transport = Some(t.clone());
            (mac, t)
        };

        let mut state = RaState::new();
        // Seed the advertised prefixes from the LAN interface, so a renumbering after startup
        // deprecates the prefix clients already hold. A prefix advertised before the daemon
        // restarted that is no longer delegated is the starting point instead, so the first RA
        // already deprecates it.
        let lan_ips = self.ctx.get_interface_state(iface_index);
        let current_gua = lan_ips
            .gua
            .map(lanforge_types::network::Ipv6Prefix::from_addr);
        state.last_ula = lan_ips
            .ula
            .map(lanforge_types::network::Ipv6Prefix::from_addr);
        let previous = self.ctx.get_shared::<PreviousLanPrefixes>();
        for prev in previous.iter().flat_map(|p| p.0.iter().copied()) {
            state.last_gua = Some(prev);
            state.update_prefix_and_deprecate(current_gua, true, current_cfg.deprecate_on_renumber);
        }
        state.last_gua = current_gua;

        // Immediate RA on startup
        send_ra_internal(
            &self.ctx,
            &transport,
            &current_cfg,
            mac,
            iface_index,
            None,
            &mut state,
        )
        .map_err(|e| CoreError::Generic(e.to_string()))?;
        state.record_multicast();

        let mut next_ra_at = Instant::now() + state.next_interval(&current_cfg);

        // Update live status in context
        let initial_status = state.build_status(&current_cfg, &self.ctx, Some(next_ra_at));
        self.ctx.set_ra_status(Some(initial_status));
        h.ready();

        let mut buf = [0u8; 1500];
        let mut handle = self.ctx.service_handle_network();
        let mut ra_sub = self.ctx.config_subscription::<RaServerConfig>();
        let mut prefix_sub = self.ctx.config_subscription::<Vec<RAPrefix>>();

        loop {
            let now = Instant::now();
            let sleep_duration = if next_ra_at > now {
                next_ra_at - now
            } else {
                Duration::ZERO
            };

            let ctx = RaContext {
                transport: &transport,
                mac,
                iface_index,
                lctx: &self.ctx,
            };

            tokio::select! {
                cmd = h.next_command() => {
                    match cmd {
                        ServiceCommand::Stop | ServiceCommand::Shutdown => return Ok(RunResult::Shutdown),
                        ServiceCommand::Restart => {
                            h.request_restart();
                            return Ok(RunResult::Shutdown);
                        }
                        _ => {}
                    }
                }

                // 1. Periodic Advertisement & Timers
                () = tokio::time::sleep(sleep_duration) => {
                    Self::perform_periodic_ra(ctx, &current_cfg, &mut state, &mut next_ra_at);
                }

                // 2. Packet processing (RS)
                recv_res = transport.recv(&mut buf) => {
                    match recv_res {
                        Ok((n, src_sa)) => {
                            let rs_src: Option<Ipv6Addr> = if src_sa.ip().is_unspecified() {
                                None
                            } else {
                                Some(*src_sa.ip())
                            };
                            self.process_rs_packet(&buf[..n], rs_src, &current_cfg, ctx, &mut state, next_ra_at).await;
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => warn!("RA transport error: {e}"),
                    }
                }

                // 3. Config subscription updates
                delta_opt = ra_sub.next() => {
                    if let Some(delta) = delta_opt {
                        match delta.impact {
                            ChangeImpact::None => {}
                            ChangeImpact::Hot => {
                                info!("Server config updated in place");
                                current_cfg.update_from_server_config(&delta.new);
                                if !delta.new.enabled || current_cfg.prefixes.is_empty() {
                                    return Ok(RunResult::ConfigChanged);
                                }
                                state.initial_sent = 0;
                                next_ra_at = Instant::now();
                            }
                            ChangeImpact::Rebind | ChangeImpact::Reconnect => {
                                info!("Interface rebind requested");
                                return Ok(RunResult::ConfigChanged);
                            }
                        }
                    }
                }

                delta_opt = prefix_sub.next() => {
                    if let Some(delta) = delta_opt {
                        match delta.impact {
                            ChangeImpact::None => {}
                            ChangeImpact::Hot | ChangeImpact::Rebind | ChangeImpact::Reconnect => {
                                info!("RA prefix configuration updated in place — sending immediate RA burst");
                                current_cfg.prefixes.clone_from(&(*delta.new));
                                if current_cfg.prefixes.is_empty() {
                                    return Ok(RunResult::ConfigChanged);
                                }
                                state.initial_sent = 0;
                                next_ra_at = Instant::now();
                            }
                        }
                    }
                }

                // 5. EventBus signals
                res = handle.next_event() => {
                    let Some(timed_event) = res else {
                        return Ok(RunResult::Shutdown);
                    };
                    lanforge_core::match_event!(timed_event, {
                        // The advertised GUA is the one on the LAN interface (e.g. delegated by the
                        // OS DHCPv6-PD client); `ppp0`'s own prefix must never be advertised. A lost
                        // prefix is deprecated right away, a new one is advertised with a burst.
                        LanforgeEvent::Network(NetworkEvent::PrefixChanged(details)) => {
                            if details.ifindex == iface_index && details.gua != state.last_gua {
                                let old_str = state.last_gua.map_or_else(|| "None".to_string(), |p| p.to_string());
                                let new_str = details.gua.map_or_else(|| "None".to_string(), |p| p.to_string());
                                info!(
                                    old_prefix = %old_str,
                                    new_prefix = %new_str,
                                    "LAN GUA prefix changed — sending immediate RA burst"
                                );
                                state.update_prefix_and_deprecate(details.gua, true, current_cfg.deprecate_on_renumber);
                                state.initial_sent = 0;
                                next_ra_at = Instant::now();
                            }
                        }
                        LanforgeEvent::Network(NetworkEvent::RaTriggerRequested) => {
                            info!("Immediate advertisement burst requested via API");
                            state.initial_sent = 0;
                            next_ra_at = Instant::now();
                        }
                    });
                }
            }
        }
    }
}

impl LanforgeService for RaService {
    fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: Self::SERVICE_ID,
            display_name: "RA Server",
            runtime: RuntimeClass::Shared,
            restart: RestartPolicy {
                base_backoff: Duration::from_secs(2),
                max_backoff: Duration::from_secs(30),
                max_retries: 0,
                healthy_uptime: Duration::from_secs(30),
            },
            shutdown_timeout: Duration::from_secs(3),
            deps: RA_DEPS,
            condition: Condition {
                sections: &[lanforge_types::config::ConfigDomain::RaServer],
                eval: |ctx| {
                    if ctx.get_ra_server_config().enabled {
                        Activation::Active
                    } else {
                        Activation::Dormant(lanforge_types::system::DormantReason::disabled(
                            "ra.enabled",
                        ))
                    }
                },
            },
        }
    }

    fn describe(&self) -> String {
        format!("RA Server on {}", self.cfg.iface)
    }
}

impl TransportStats for RaService {
    fn snapshot(&self) -> TransportSnapshot {
        self.transport
            .as_ref()
            .map(TransportStats::snapshot)
            .unwrap_or_default()
    }
}

impl AsyncService for RaService {
    fn transport_snapshot(&self, _ctx: &LanforgeContext) -> Option<TransportSnapshot> {
        self.transport.as_ref().map(TransportStats::snapshot)
    }

    fn stats(&self, ctx: &LanforgeContext) -> Vec<(std::borrow::Cow<'static, str>, String)> {
        let ra_status = ctx.ra_status();
        let if_state = ctx.get_interface_state(ctx.target_ifindex().unwrap_or(0));
        let prefixes = ctx.get_ra_prefixes();
        let mut list = vec![
            (std::borrow::Cow::Borrowed("iface"), self.cfg.iface.clone()),
            (
                std::borrow::Cow::Borrowed("max_interval_secs"),
                self.cfg.max_interval.as_secs().to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("managed"),
                self.cfg.managed.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("other_config"),
                self.cfg.other_config.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("prefixes_count"),
                prefixes.len().to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("gua_prefix"),
                if_state
                    .gua
                    .map_or_else(|| "none".to_string(), |g| g.to_string()),
            ),
            (
                std::borrow::Cow::Borrowed("ula_prefix"),
                if_state
                    .ula
                    .map_or_else(|| "none".to_string(), |u| u.to_string()),
            ),
        ];
        if let Some(ref st) = ra_status {
            list.push((
                std::borrow::Cow::Borrowed("sent_multicast"),
                st.sent_multicast_ras.to_string(),
            ));
            list.push((
                std::borrow::Cow::Borrowed("sent_unicast"),
                st.sent_unicast_ras.to_string(),
            ));
            list.push((
                std::borrow::Cow::Borrowed("received_rs"),
                st.received_solicitations.to_string(),
            ));
            list.push((
                std::borrow::Cow::Borrowed("ignored_rs"),
                st.ignored_solicitations.to_string(),
            ));
        }
        list
    }

    async fn serve(&mut self, ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        loop {
            let ra_server_cfg = ctx.get_ra_server_config();
            if !ra_server_cfg.enabled {
                info!("Service disabled via runtime config — server idle");
                h.dormant(DormantReason::disabled("ra.enabled"));
                ctx.set_ra_status(None);
                match self.wait_for_config_change_or_shutdown(h).await? {
                    RunResult::Shutdown => break,
                    RunResult::ConfigChanged => continue,
                }
            }

            let mut current_cfg = self.cfg.clone();
            current_cfg.update_from_server_config(&ra_server_cfg);

            if current_cfg.prefixes.is_empty() {
                warn!("Service enabled but no prefixes configured — server idle");
                h.dormant(DormantReason::not_applicable("no prefixes configured"));
                ctx.set_ra_status(None);
                match self.wait_for_config_change_or_shutdown(h).await? {
                    RunResult::Shutdown => break,
                    RunResult::ConfigChanged => continue,
                }
            }

            match self.run_server(current_cfg, h).await? {
                RunResult::Shutdown => break,
                RunResult::ConfigChanged => {}
            }
        }

        ctx.set_ra_status(None);
        Ok(())
    }
}

/// Thread-safe context for Router Advertisement operations.
#[derive(Clone, Copy)]
struct RaContext<'a> {
    transport: &'a Icmp6Transport,
    mac: [u8; 6],
    iface_index: u32,
    lctx: &'a LanforgeContext,
}

impl RaService {
    fn perform_periodic_ra(
        ctx: RaContext<'_>,
        cfg: &RaConfig,
        state: &mut RaState,
        next_ra_at: &mut Instant,
    ) {
        if let Err(e) = send_ra_internal(
            ctx.lctx,
            ctx.transport,
            cfg,
            ctx.mac,
            ctx.iface_index,
            None,
            state,
        ) {
            warn!("RA periodic error: {e:?}");
        } else {
            state.record_multicast();
            let interval = state.next_interval(cfg);
            *next_ra_at = Instant::now() + interval;
            debug!("Next periodic RA in {:.1}s", interval.as_secs_f64());
            let status = state.build_status(cfg, ctx.lctx, Some(*next_ra_at));
            ctx.lctx.set_ra_status(Some(status));
        }
    }

    async fn process_rs_packet(
        &self,
        data: &[u8],
        rs_src: Option<Ipv6Addr>,
        cfg: &RaConfig,
        ctx: RaContext<'_>,
        state: &mut RaState,
        next_ra_at: Instant,
    ) {
        if data.first() == Some(&ICMPV6_TYPE_RS) {
            state.record_solicitation_received();
            debug!("RS received from {rs_src:?}");

            let delay_ms = if ctx.transport.is_inert() {
                0
            } else {
                rand::rng().random_range(0..MAX_RA_DELAY_TIME_MS)
            };
            if delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }

            let dst = rs_src.filter(|ip| !ip.is_unspecified());
            match dst {
                Some(unicast_dst) if state.can_unicast_now(&unicast_dst) => {
                    if let Err(e) = send_ra_internal(
                        ctx.lctx,
                        ctx.transport,
                        cfg,
                        ctx.mac,
                        ctx.iface_index,
                        Some(unicast_dst),
                        state,
                    ) {
                        warn!("RA unicast error: {e:?}");
                    } else {
                        debug!("RA unicast -> {unicast_dst}");
                        state.record_unicast(unicast_dst);
                    }
                }
                None if state.can_multicast_now() => {
                    if let Err(e) = send_ra_internal(
                        ctx.lctx,
                        ctx.transport,
                        cfg,
                        ctx.mac,
                        ctx.iface_index,
                        None,
                        state,
                    ) {
                        warn!("RA multicast error: {e:?}");
                    } else {
                        debug!("RA multicast -> ff02::1");
                        state.record_multicast();
                    }
                }
                _ => {
                    debug!("RS discarded: rate limit active");
                    state.record_solicitation_ignored();
                }
            }

            // Passive discovery: se conseguirmos o MAC do cara que pediu o RA,
            // avisamos o sistema para tentar o prober de SLAAC.
            if let Some(src) = rs_src
                && let Some(mac) = ctx.lctx.get_mac_by_ip(IpAddr::V6(src))
            {
                tracing::event!(target:(module_path!()),tracing::Level::DEBUG,"RS trigger: emitindo RsReceived para {}",mac);
                let _ = ctx
                    .lctx
                    .bus()
                    .publish(LanforgeEvent::Network(NetworkEvent::RsReceived { mac }));
            }

            let status = state.build_status(cfg, ctx.lctx, Some(next_ra_at));
            ctx.lctx.set_ra_status(Some(status));
        }
    }
}

#[cfg_attr(feature = "hotpath", hotpath::measure)]
fn send_ra_internal(
    lctx: &LanforgeContext,
    transport: &Icmp6Transport,
    cfg: &RaConfig,
    mac: [u8; 6],
    iface_index: u32,
    unicast_dst: Option<Ipv6Addr>,
    state: &mut RaState,
) -> Result<(), NetworkError> {
    let if_ips = lctx.get_interface_state(iface_index);

    let src_ll = match if_ips.link_local {
        Some(ll) => ll,
        None if transport.is_inert() => Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0200, 0, 0, 1),
        None => return Err(NetworkError::NoLinkLocal(iface_index)),
    };
    // Only the LAN interface's own GUA (e.g. delegated by the OS DHCPv6-PD client) is
    // advertised. Never fall back to the WAN link prefix: it is not routed to the LAN, and
    // clients that autoconfigure from it lose IPv6 connectivity. No LAN GUA => the previous one
    // is deprecated below and nothing new is advertised until a prefix is delegated again.
    let gua = if_ips.gua;
    let ula = if_ips.ula;

    let now = Instant::now();

    let gua_prefix = gua.map(lanforge_types::network::Ipv6Prefix::from_addr);
    let ula_prefix = ula.map(lanforge_types::network::Ipv6Prefix::from_addr);
    state.update_prefix_and_deprecate(gua_prefix, true, cfg.deprecate_on_renumber);
    state.update_prefix_and_deprecate(ula_prefix, false, cfg.deprecate_on_renumber);

    // Clean up expired deprecated prefixes
    state
        .deprecated_prefixes
        .retain(|(_, deprecation_end, _)| *deprecation_end > now);

    let deprecated_list = state.deprecated_list(now);

    let dst_ip: Ipv6Addr = unicast_dst.unwrap_or(ALL_NODES_MULTICAST);
    let dst_sa = SocketAddrV6::new(dst_ip, 0, 0, iface_index);

    let gua_pref = if if_ips.gua_preferred > 0 {
        if_ips.gua_preferred
    } else {
        3600
    };
    let gua_val = if if_ips.gua_valid > 0 {
        if_ips.gua_valid
    } else {
        7200
    };
    let gua_info = gua.as_ref().map(|g| (g, gua_pref, gua_val));
    let mut pkt = build_ra_packet(cfg, mac, gua_info, ula.as_ref(), &deprecated_list);

    let csum = icmpv6_checksum(&src_ll, &dst_ip, &pkt);
    pkt[2] = (csum >> 8) as u8;
    pkt[3] = (csum & 0xFF) as u8;

    transport
        .send(&pkt, &dst_sa)
        .map_err(|e| NetworkError::Socket(format!("ICMPv6 send: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use lanforge_core::{bus::EventBus, context::state::State};
    use lanforge_types::{
        identifiers::MacAddr,
        network::ra::RAPrefix,
        update::{DeviceUpdate, InterfaceState},
    };

    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn state_rate_limits_multicast_and_unicast() {
        let mut state = RaState::new();
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();

        // Inicialmente, tudo liberado
        assert!(state.can_multicast_now());
        assert!(state.can_unicast_now(&ip));

        // Após registrar um envio, deve bloquear pelo MIN_DELAY_BETWEEN_RAS (3s)
        state.record_multicast();
        assert!(
            !state.can_multicast_now(),
            "Multicast deve sofrer rate limit"
        );

        state.record_unicast(ip);
        assert!(
            !state.can_unicast_now(&ip),
            "Unicast deve sofrer rate limit"
        );

        // Um IP diferente não deve ser afetado pelo rate limit do primeiro
        let ip2: Ipv6Addr = "fe80::2".parse().unwrap();
        assert!(state.can_unicast_now(&ip2));
    }

    #[test]
    fn state_startup_phase_uses_short_intervals() {
        let cfg = RaConfig {
            max_interval: Duration::from_secs(100),
            ..Default::default()
        };
        let mut state = RaState::new();

        // Os 3 primeiros RAs devem ter um intervalo curto (<= 16s)
        for _ in 0..3 {
            let interval = state.next_interval(&cfg);
            assert!(
                interval <= MAX_INITIAL_RTR_ADVERT_INTERVAL,
                "Intervalo de startup muito longo: {interval:?}"
            );
            state.record_multicast();
        }

        // Do 4º em diante, deve entrar no regime normal [Min, Max]
        // Min = 0.33 * Max = 33s. Max = 100s.
        let normal_interval = state.next_interval(&cfg);
        assert!(
            normal_interval >= Duration::from_secs(33)
                && normal_interval <= Duration::from_secs(100),
            "Intervalo normal fora dos limites: {normal_interval:?}",
        );
    }

    #[test]
    fn prefix_rotation_and_deprecation() {
        // 1. Setup LanforgeContext
        let bus = Arc::new(EventBus::new());
        let ctx = LanforgeContext::new(bus, State::new(), Some(1));

        // 2. Set initial interface state (old prefix)
        let old_gua: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        let initial_iface = InterfaceState {
            v4: None,
            link_local: Some(link_local),
            gua: Some(old_gua),
            ula: None,
            gua_preferred: 3600,
            gua_valid: 7200,
            mac: Some(MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])),
        };
        let _ = ctx.apply(DeviceUpdate::InterfaceIpsChanged {
            ifindex: 1,
            state: Box::new(initial_iface),
        });

        // 3. Initialize RaState and run the check
        let mut state = RaState::new();

        // Perform first send (mocked or just executing the internal logic)
        let if_ips = ctx.get_interface_state(1);
        assert_eq!(if_ips.gua, Some(old_gua));

        // First transition: last_gua becomes Some(old_gua)
        state.last_gua = if_ips
            .gua
            .map(lanforge_types::network::Ipv6Prefix::from_addr);

        // 4. Trigger rotation: change GUA in interface state
        let new_gua: Ipv6Addr = "2001:db8:abc::1".parse().unwrap();
        let rotated_iface = InterfaceState {
            v4: None,
            link_local: Some(link_local),
            gua: Some(new_gua),
            ula: None,
            gua_preferred: 3600,
            gua_valid: 7200,
            mac: Some(MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])),
        };
        let _ = ctx.apply(DeviceUpdate::InterfaceIpsChanged {
            ifindex: 1,
            state: Box::new(rotated_iface),
        });

        // Get the updated interface state
        let if_ips = ctx.get_interface_state(1);
        assert_eq!(if_ips.gua, Some(new_gua));

        // 5. Simulate send_ra_internal transition for rotation:
        state.update_prefix_and_deprecate(
            if_ips
                .gua
                .map(lanforge_types::network::Ipv6Prefix::from_addr),
            true,
            true,
        );

        // Verify that old_gua is now deprecated in state with RFC 4862 §5.5.3e valid lifetime (2 hours = 7200s)
        assert_eq!(state.deprecated_prefixes.len(), 1);
        let expected_prefix = lanforge_types::network::Ipv6Prefix::from_addr(old_gua).to_addr();
        assert_eq!(state.deprecated_prefixes[0].0, expected_prefix);
        let deprecated_list = state.deprecated_list(std::time::Instant::now());
        assert_eq!(deprecated_list.len(), 1);
        assert_eq!(deprecated_list[0].0, expected_prefix);
        assert!(deprecated_list[0].1 >= 7199 && deprecated_list[0].1 <= 7200);

        // 6. Test build_ra_packet with the deprecated prefix list
        let cfg = RaConfig {
            prefixes: vec![RAPrefix::gua_dynamic()],
            ..Default::default()
        };
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let deprecated_list = vec![(old_gua, 7200)];
        let pkt = build_ra_packet(
            &cfg,
            mac,
            Some((&new_gua, 7 * 24 * 3600, 30 * 24 * 3600)),
            None,
            &deprecated_list,
        );

        // Find prefix options in the packet
        let mut idx = 0;
        let mut found_prefixes = Vec::new();
        while idx + 32 <= pkt.len() {
            if pkt[idx] == 3 && pkt[idx + 1] == 4 {
                let prefix_len = pkt[idx + 2];
                let flags = pkt[idx + 3];
                let valid_lt = u32::from_be_bytes(pkt[idx + 4..idx + 8].try_into().unwrap());
                let preferred_lt = u32::from_be_bytes(pkt[idx + 8..idx + 12].try_into().unwrap());
                let prefix_bytes: [u8; 16] = pkt[idx + 16..idx + 32].try_into().unwrap();
                let prefix_addr = Ipv6Addr::from(prefix_bytes);
                found_prefixes.push((prefix_addr, prefix_len, flags, valid_lt, preferred_lt));
                idx += 32;
            } else {
                idx += 1;
            }
        }

        assert_eq!(
            found_prefixes.len(),
            2,
            "Expected 2 prefix options in RA packet"
        );

        // Match first (new GUA)
        let (p1, len1, _, valid1, pref1) = found_prefixes[0];
        let mut expected_p1 = new_gua.octets();
        expected_p1[8..16].copy_from_slice(&[0; 8]); // mask out /64 host bits
        assert_eq!(p1, Ipv6Addr::from(expected_p1));
        assert_eq!(len1, 64);
        assert_eq!(valid1, 30 * 24 * 3600); // default valid
        assert_eq!(pref1, 7 * 24 * 3600); // default preferred

        // Match second (deprecated old GUA)
        let (p2, len2, _, valid2, pref2) = found_prefixes[1];
        let mut expected_p2 = old_gua.octets();
        expected_p2[8..16].copy_from_slice(&[0; 8]);
        assert_eq!(p2, Ipv6Addr::from(expected_p2));
        assert_eq!(len2, 64);
        assert_eq!(valid2, 7200);
        assert_eq!(pref2, 0); // Must be deprecated (preferred=0)
    }
}
