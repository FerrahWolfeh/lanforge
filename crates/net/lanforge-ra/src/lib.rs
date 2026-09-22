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
use lanforge_types::network::ra::{
    ICMPV6_TYPE_RS, MAX_INITIAL_RTR_ADVERT_INTERVAL, MAX_INITIAL_RTR_ADVERTISEMENTS,
    MAX_RA_DELAY_TIME_MS, MIN_DELAY_BETWEEN_RAS,
};
use lanforge_types::system::{RaStatusResponse, RunResult, ServiceState};
use lanforge_types::update::DeviceUpdate;

pub use packet::{build_ra_packet, icmpv6_checksum};

use crate::error::NetworkError;
use lanforge_core::bus::{LanforgeEvent, NetworkEvent, SystemEvent};
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceDependency};
use rand::RngExt;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::mem::{MaybeUninit, size_of};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::ptr::{from_mut, from_ref};
use std::time::{Duration, Instant};
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tracing::{debug, info, warn};

// ICMP6_FILTER = 1 (linux/icmpv6.h — not exposed by libc crate)
const ICMP6_FILTER: libc::c_int = 1;
const ALL_NODES_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
const ALL_ROUTERS_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

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
    last_gua: Option<Ipv6Addr>,
    /// Last detected ULA
    last_ula: Option<Ipv6Addr>,
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
        current: Option<Ipv6Addr>,
        is_gua: bool,
    ) -> bool {
        let last = if is_gua { self.last_gua } else { self.last_ula };
        if current == last {
            false
        } else {
            if let Some(old) = last {
                let now = Instant::now();
                let (deprecation_end, valid_end) = if is_gua {
                    // RFC 9096: Set valid_lifetime = 0 for obsolete GUA prefix upon prefix change,
                    // and announce preferred=0 / valid=0 for 60s to ensure all LAN hosts purge it.
                    (now + Duration::from_mins(1), now)
                } else {
                    (now + Duration::from_hours(2), now + Duration::from_hours(2))
                };
                if !self.deprecated_prefixes.iter().any(|(ip, _, _)| *ip == old) {
                    self.deprecated_prefixes
                        .push((old, deprecation_end, valid_end));
                }
            }
            let prefix_type = if is_gua { "GUA" } else { "ULA" };
            debug!("RA: Internal {prefix_type} prefix state updated: {current:?}");
            if is_gua {
                self.last_gua = current;
            } else {
                self.last_ula = current;
            }
            true
        }
    }
}

#[lanforge_macros::lanforge_service(
    id = "ra",
    name = "RA Server",
    critical = true,
    retries = 0,
    base_backoff = 2,
    max_backoff = 30
)]
#[derive(Clone)]
pub struct RaService {
    cfg: RaConfig,
    ctx: LanforgeContext,
}

impl RaService {
    #[must_use]
    pub const fn new(cfg: RaConfig, ctx: LanforgeContext) -> Self {
        Self { cfg, ctx }
    }

    async fn resolve_interface_resources(
        &self,
        iface_index: u32,
    ) -> Result<([u8; 6], AsyncFd<Socket>), CoreError> {
        // Parallel optimization: Wait for interface data ONLY if not already present
        if self
            .ctx
            .get_interface_state(iface_index)
            .link_local
            .is_none()
        {
            info!(
                "RA: Waiting for interface discovery on '{}'...",
                self.cfg.iface
            );
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
                    .and_then(|ll| lanforge_core::utils::mac_from_eui64_link_local(&ll))
            })
            .ok_or_else(|| {
                CoreError::Generic(format!(
                    "MAC address for interface index {iface_index} is not resolved"
                ))
            })?
            .0;

        let socket = create_ra_socket(&self.cfg.iface, iface_index)
            .map_err(|e| CoreError::Generic(e.to_string()))?;
        socket.set_nonblocking(true).map_err(CoreError::Io)?;
        let async_socket = AsyncFd::new(socket).map_err(CoreError::Io)?;

        Ok((mac, async_socket))
    }

    async fn wait_for_config_change_or_shutdown(&self) -> Result<RunResult, CoreError> {
        let mut handle = self.ctx.service_handle_network();
        loop {
            let event = handle.next_event().await;
            let Some(timed_event) = event else {
                return Ok(RunResult::Shutdown);
            };
            if matches!(
                timed_event.event,
                LanforgeEvent::System(SystemEvent::ConfigRaChanged)
            ) {
                return Ok(RunResult::ConfigChanged);
            }
        }
    }

    async fn run_server(&self, current_cfg: RaConfig) -> Result<RunResult, CoreError> {
        current_cfg
            .validate()
            .map_err(|e| CoreError::Generic(e.to_string()))?;

        info!(
            iface = %current_cfg.iface,
            managed = u8::from(current_cfg.managed),
            other_config = u8::from(current_cfg.other_config),
            max_interval_secs = current_cfg.max_interval.as_secs(),
            router_lifetime_secs = current_cfg.effective_router_lifetime().as_secs(),
            "RA: Server active"
        );

        let iface_index = self.ctx.target_ifindex().ok_or_else(|| {
            CoreError::Generic("Target interface index is not configured in context".to_string())
        })?;

        let (mac, async_socket) = self.resolve_interface_resources(iface_index).await?;

        let mut state = RaState::new();

        // Immediate RA on startup
        send_ra_internal(
            &self.ctx,
            &async_socket,
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
        let _ = self.ctx.apply(DeviceUpdate::RaStatusUpdated {
            status: Some(Box::new(initial_status)),
        });

        let mut buf = [0u8; 1500];
        let mut handle = self.ctx.service_handle_network();

        loop {
            let now = Instant::now();
            let sleep_duration = if next_ra_at > now {
                next_ra_at - now
            } else {
                Duration::ZERO
            };

            let ctx = RaContext {
                socket: &async_socket,
                mac,
                iface_index,
                lctx: &self.ctx,
            };

            tokio::select! {
                // 1. Periodic Advertisement & Timers
                () = tokio::time::sleep(sleep_duration) => {
                    Self::perform_periodic_ra(ctx, &current_cfg, &mut state, &mut next_ra_at);
                }

                // 2. Packet processing (RS)
                res = async_socket.readable() => {
                    self.handle_rs_packet(res, &mut buf, &current_cfg, ctx, &mut state, next_ra_at).await?;
                }

                // 3. EventBus signals
                res = handle.next_event() => {
                    let Some(timed_event) = res else {
                        return Ok(RunResult::Shutdown);
                    };
                    if matches!(
                        timed_event.event,
                        LanforgeEvent::System(SystemEvent::ConfigRaChanged)
                    ) {
                        return Ok(RunResult::ConfigChanged);
                    }
                    lanforge_core::match_event!(timed_event, {
                        LanforgeEvent::Network(NetworkEvent::PrefixChanged(..)) => {
                            info!("RA: Prefix change detected — sending immediate RA burst");
                            state.initial_sent = 0;
                            next_ra_at = Instant::now();
                        }
                        LanforgeEvent::Network(NetworkEvent::RaTriggerRequested) => {
                            info!("RA: Immediate advertisement burst requested via API");
                            state.initial_sent = 0;
                            next_ra_at = Instant::now();
                        }
                    });
                }
            }
        }
    }
}

impl AsyncService for RaService {
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[ServiceDependency::Database, ServiceDependency::Interfaces]
    }

    fn stats(&self, ctx: &LanforgeContext) -> Vec<(std::borrow::Cow<'static, str>, String)> {
        let ra_status = ctx.with_state(|state| state.interfaces.ra_status.clone());
        let if_state = ctx.get_interface_state(ctx.target_ifindex().unwrap_or(0));
        let prefixes = ctx.get_ra_prefixes();
        let mut list = vec![
            (
                std::borrow::Cow::Borrowed("iface"),
                self.cfg.iface.clone(),
            ),
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
                if_state.gua.map_or_else(|| "none".to_string(), |g| g.to_string()),
            ),
            (
                std::borrow::Cow::Borrowed("ula_prefix"),
                if_state.ula.map_or_else(|| "none".to_string(), |u| u.to_string()),
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

    async fn serve(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        loop {
            let ra_server_cfg = ctx.get_ra_server_config();
            if !ra_server_cfg.enabled {
                info!("RA: Service disabled via runtime config — server idle");
                ctx.set_service_state("ra", ServiceState::Inactive);
                let _ = ctx.apply(DeviceUpdate::RaStatusUpdated { status: None });
                match self.wait_for_config_change_or_shutdown().await? {
                    RunResult::Shutdown => break,
                    RunResult::ConfigChanged => continue,
                }
            }

            let mut current_cfg = self.cfg.clone();
            current_cfg.update_from_server_config(&ra_server_cfg);

            if current_cfg.prefixes.is_empty() {
                warn!("RA: Service enabled but no prefixes configured — server idle");
                let _ = ctx.apply(DeviceUpdate::RaStatusUpdated { status: None });
                match self.wait_for_config_change_or_shutdown().await? {
                    RunResult::Shutdown => break,
                    RunResult::ConfigChanged => continue,
                }
            }

            ctx.set_service_state("ra", ServiceState::Online);
            match self.run_server(current_cfg).await? {
                RunResult::Shutdown => break,
                RunResult::ConfigChanged => {}
            }
        }

        let _ = ctx.apply(DeviceUpdate::RaStatusUpdated { status: None });
        Ok(())
    }
}


/// Thread-safe context for Router Advertisement operations.
#[derive(Clone, Copy)]
struct RaContext<'a> {
    socket: &'a AsyncFd<Socket>,
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
            ctx.socket,
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
            let _ = ctx.lctx.apply(DeviceUpdate::RaStatusUpdated {
                status: Some(Box::new(status)),
            });
        }
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn handle_rs_packet(
        &self,
        res: io::Result<AsyncFdReadyGuard<'_, Socket>>,
        buf: &mut [u8],
        cfg: &RaConfig,
        ctx: RaContext<'_>,
        state: &mut RaState,
        next_ra_at: Instant,
    ) -> Result<(), CoreError> {
        let mut guard = res.map_err(CoreError::Io)?;
        let res = guard
            .get_inner()
            .recv_from(unsafe { &mut *from_mut(buf).cast::<[MaybeUninit<u8>; 1500]>() });

        match res {
            Ok((n, src_sa)) => {
                guard.clear_ready();
                if n > 0 {
                    let data = &buf[..n];
                    if data.first() == Some(&ICMPV6_TYPE_RS) {
                        state.record_solicitation_received();
                        let rs_src: Option<Ipv6Addr> = src_sa.as_socket().and_then(|s| match s {
                            SocketAddr::V6(v6) => Some(*v6.ip()),
                            SocketAddr::V4(_) => None,
                        });
                        debug!("RS received from {rs_src:?}");

                        // RFC 4861: Random delay before responding to RS
                        let delay_ms = rand::rng().random_range(0..MAX_RA_DELAY_TIME_MS);
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;

                        let dst = rs_src.filter(|ip| !ip.is_unspecified());
                        match dst {
                            Some(unicast_dst) if state.can_unicast_now(&unicast_dst) => {
                                if let Err(e) = send_ra_internal(
                                    ctx.lctx,
                                    ctx.socket,
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
                                    ctx.socket,
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
                        let _ = ctx.lctx.apply(DeviceUpdate::RaStatusUpdated {
                            status: Some(Box::new(status)),
                        });
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                guard.clear_ready();
            }
            Err(e) => warn!("RA socket error: {e}"),
        }
        Ok(())
    }

}

#[cfg_attr(feature = "hotpath", hotpath::measure)]
fn send_ra_internal(
    lctx: &LanforgeContext,
    socket: &AsyncFd<Socket>,
    cfg: &RaConfig,
    mac: [u8; 6],
    iface_index: u32,
    unicast_dst: Option<Ipv6Addr>,
    state: &mut RaState,
) -> Result<(), NetworkError> {
    let if_ips = lctx.get_interface_state(iface_index);

    let src_ll = if_ips
        .link_local
        .ok_or(NetworkError::NoLinkLocal(iface_index))?;
    let gua = if_ips.gua;
    let ula = if_ips.ula;

    let now = Instant::now();

    state.update_prefix_and_deprecate(gua, true);
    state.update_prefix_and_deprecate(ula, false);

    // Clean up expired deprecated prefixes
    state
        .deprecated_prefixes
        .retain(|(_, deprecation_end, _)| *deprecation_end > now);

    let deprecated_list = state.deprecated_list(now);

    let dst_ip: Ipv6Addr = unicast_dst.unwrap_or(ALL_NODES_MULTICAST);
    let dst_sa = SockAddr::from(SocketAddrV6::new(dst_ip, 0, 0, iface_index));

    let gua_info = gua
        .as_ref()
        .map(|g| (g, if_ips.gua_preferred, if_ips.gua_valid));
    let mut pkt = build_ra_packet(cfg, mac, gua_info, &deprecated_list);

    let csum = icmpv6_checksum(&src_ll, &dst_ip, &pkt);
    pkt[2] = (csum >> 8) as u8;
    pkt[3] = (csum & 0xFF) as u8;

    socket
        .get_ref()
        .send_to(&pkt, &dst_sa)
        .map_err(|e| NetworkError::Socket(format!("ICMPv6 send_to: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Raw ICMPv6 Socket Configuration
// ---------------------------------------------------------------------------

fn create_ra_socket(iface: &str, iface_index: u32) -> Result<Socket, NetworkError> {
    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).map_err(|e| {
        NetworkError::Socket(format!(
            "Failed to create raw ICMPv6 socket — CAP_NET_RAW required: {e}"
        ))
    })?;

    // Bind to the LAN interface — keeps traffic contained even on multi-homed hosts.
    sock.bind_device(Some(iface.as_bytes()))
        .map_err(|e| NetworkError::Socket(format!("SO_BINDTODEVICE({iface}): {e}")))?;

    // RFC 4861 §6.1.2: Receivers MUST discard RAs with hop limit != 255.
    sock.set_multicast_hops_v6(255)
        .map_err(|e| NetworkError::Socket(format!("IPV6_MULTICAST_HOPS=255: {e}")))?;
    set_sockopt_int(&sock, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS, 255)
        .map_err(|e| NetworkError::Socket(format!("IPV6_UNICAST_HOPS=255: {e}")))?;

    // Joins ff02::2 (all-routers) to receive Router Solicitations.
    // The kernel doesn't pass multicast traffic if the socket isn't subscribed.
    sock.join_multicast_v6(&ALL_ROUTERS_MULTICAST, iface_index)
        .map_err(|e| NetworkError::Socket(format!("join_multicast_v6(ff02::2): {e}")))?;

    // ICMP6_FILTER: tells the kernel to reject all ICMPv6 types except RS (133).
    // On RPi4, this reduces context switches and CPU usage in high-traffic NDP environments.
    set_icmp6_filter_rs_only(&sock)
        .map_err(|e| NetworkError::Socket(format!("ICMP6_FILTER: {e}")))?;

    sock.set_nonblocking(false)
        .map_err(|e| NetworkError::Socket(format!("O_NONBLOCK(false): {e}")))?;

    info!("RA: ICMPv6 raw socket active (RS only), subscribed to ff02::2");
    Ok(sock)
}

/// Configures `ICMP6_FILTER` to accept only RS (type 133), blocking everything else.
///
/// The filter is a 256-bit mask (32 bytes) processed in kernel space.
/// Crucial on `RPi4` to avoid unnecessary process wakeups.
fn set_icmp6_filter_rs_only(sock: &Socket) -> io::Result<()> {
    // All bits = 1 → block all (ICMP6_FILTER_SETBLOCKALL)
    let mut filter = [0xFFu8; 32];
    // Clear the bit for RS type → let it pass (ICMP6_FILTER_SETPASS(133))
    let t = ICMPV6_TYPE_RS as usize;
    filter[t / 8] &= !(1u8 << (t % 8));

    set_sockopt_raw(sock, libc::IPPROTO_ICMPV6, ICMP6_FILTER, &filter)
}

// ---------------------------------------------------------------------------
// setsockopt wrappers not exposed by socket2
// ---------------------------------------------------------------------------

fn set_sockopt_int(
    sock: &Socket,
    level: libc::c_int,
    opt: libc::c_int,
    val: i32,
) -> io::Result<()> {
    let v = val as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            opt,
            from_ref(&v).cast::<libc::c_void>(),
            libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap_or_default(),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn set_sockopt_raw(
    sock: &Socket,
    level: libc::c_int,
    opt: libc::c_int,
    data: &[u8],
) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            opt,
            data.as_ptr().cast::<libc::c_void>(),
            libc::socklen_t::try_from(data.len()).unwrap_or_default(),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
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
        state.last_gua = if_ips.gua;

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
        state.update_prefix_and_deprecate(if_ips.gua, true);

        // Verify that old_gua is now deprecated in state
        assert_eq!(state.deprecated_prefixes.len(), 1);
        assert_eq!(state.deprecated_prefixes[0].0, old_gua);

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
