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

pub mod config;
pub mod packet;

pub use config::*;
use lanforge_core::context::LanforgeContext;
use lanforge_types::system::{ServiceBanner, ServiceState};
pub use packet::{build_ra_packet, icmpv6_checksum};

use crate::error::NetworkError;
use lanforge_core::bus::{LanforgeEvent, NetworkEvent, SystemEvent};
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceControl, StatusProvider};
use rand::RngExt;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::mem::{MaybeUninit, size_of};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::ptr::{from_mut, from_ref};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// RFC 4861 §6.2.1 and §10 Constants
// ---------------------------------------------------------------------------

/// Maximum interval between the initial RAs during startup (§6.2.6).
/// Ensures newly connected clients don't wait for the full `MaxRtrAdvInterval`.
const MAX_INITIAL_RTR_ADVERT_INTERVAL: Duration = Duration::from_secs(16);

/// Number of initial RAs sent with a reduced interval (§6.2.6).
const MAX_INITIAL_RTR_ADVERTISEMENTS: u8 = 3;

/// Minimum delay between consecutive multicast RAs (§6.2.4).
/// Protects against RA storms when multiple clients solicit simultaneously.
const MIN_DELAY_BETWEEN_RAS: Duration = Duration::from_secs(3);

/// Maximum random delay before responding to an RS (§6.2.6), in ms.
const MAX_RA_DELAY_TIME_MS: u64 = 500;

const ICMPV6_TYPE_RS: u8 = 133;

// ICMP6_FILTER = 1 (linux/icmpv6.h — not exposed by libc crate)
const ICMP6_FILTER: libc::c_int = 1;

// ---------------------------------------------------------------------------
// Runtime State — Handles RFC-compliant timing
// ---------------------------------------------------------------------------

/// Runtime timing state for the RA service.
///
/// Tracks RFC 4861 startup burst counters, last multicast/unicast timestamps,
/// and rate limiting logic. Designed to be used independently of the service struct.
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
}

impl RaState {
    pub(crate) fn new() -> Self {
        Self {
            initial_sent: 0,
            last_multicast_ra: None,
            unicast_rl: HashMap::new(),
            last_gua: None,
            last_ula: None,
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
        self.last_multicast_ra = Some(Instant::now());
        self.initial_sent = self.initial_sent.saturating_add(1);
    }

    pub(crate) fn record_unicast(&mut self, dst: Ipv6Addr) {
        self.unicast_rl.insert(dst, Instant::now());
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
    pub fn new(cfg: RaConfig, ctx: LanforgeContext) -> Self {
        let service = Self {
            cfg,
            ctx: ctx.clone(),
        };
        ctx.register_status_provider(Arc::new(service.clone()));
        service
    }
}

impl StatusProvider for RaService {
    fn banner(&self) -> ServiceBanner {
        let stats = vec![
            ("iface", self.cfg.iface.clone()),
            ("max_interval", self.cfg.max_interval.as_secs().to_string()),
            ("managed", self.cfg.managed.to_string()),
            ("other_config", self.cfg.other_config.to_string()),
        ];
        ServiceBanner {
            name: "RA Server".to_string(),
            state: ServiceState::Online,
            uptime_secs: self.ctx.uptime_secs(),
            stats,
        }
    }
}

impl AsyncService for RaService {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        self.cfg
            .validate()
            .map_err(|e| CoreError::Generic(e.to_string()))?;

        info!(
            "RA: Starting on '{}' (M={}, O={}, MaxInterval={}s, RouterLifetime={}s)",
            self.cfg.iface,
            u8::from(self.cfg.managed),
            u8::from(self.cfg.other_config),
            self.cfg.max_interval.as_secs(),
            self.cfg.effective_router_lifetime().as_secs(),
        );

        let mut bus_rx = self.ctx.bus().subscribe();

        let iface_index =
            get_iface_index(&self.cfg.iface).map_err(|e| CoreError::Generic(e.to_string()))?;

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

        let mac = get_iface_mac(&self.cfg.iface).map_err(|e| CoreError::Generic(e.to_string()))?;

        let socket = create_ra_socket(&self.cfg.iface, iface_index)
            .map_err(|e| CoreError::Generic(e.to_string()))?;
        socket.set_nonblocking(true).map_err(CoreError::Io)?;
        let async_socket = AsyncFd::new(socket).map_err(CoreError::Io)?;

        ctrl.signal_ready();

        let mut state = RaState::new();

        // Immediate RA on startup
        send_ra_internal(
            &self.ctx,
            &async_socket,
            &self.cfg,
            mac,
            iface_index,
            None,
            &mut state,
        )
        .map_err(|e| CoreError::Generic(e.to_string()))?;
        state.record_multicast();

        let mut next_ra_at = Instant::now() + state.next_interval(&self.cfg);

        let mut buf = [0u8; 1500];

        loop {
            if !self.ctx.is_running() {
                break;
            }
            let now = Instant::now();
            let sleep_duration = if next_ra_at > now {
                next_ra_at - now
            } else {
                Duration::ZERO
            };

            tokio::select! {
                // 1. Periodic Advertisement & Timers
                () = tokio::time::sleep(sleep_duration) => {
                    self.perform_periodic_ra(&self.ctx, &async_socket, mac, iface_index, &mut state, &mut next_ra_at);
                }

                // 2. Packet processing (RS)
                res = async_socket.readable() => {
                    let ctx = RaContext {
                        socket: &async_socket,
                        mac,
                        iface_index,
                        lctx: &self.ctx,
                    };
                    self.handle_rs_packet(res, &mut buf, ctx, &mut state).await?;
                }

                // 3. EventBus signals
                res = bus_rx.recv() => {
                    match res {
                        Ok(timed_event) => {
                            lanforge_core::match_event!(timed_event, {
                                LanforgeEvent::Network(NetworkEvent::PrefixChanged { .. }) => {
                                    info!("RA: Prefix change detected — sending immediate RA burst");
                                    state.initial_sent = 0;
                                    next_ra_at = Instant::now();
                                }
                                LanforgeEvent::System(SystemEvent::Shutdown) => {
                                    info!("RA service: shutdown received");
                                    return Ok(());
                                }
                            });
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                            warn!(service = "RA Server", lost = n, "Event bus lagged");
                        }
                        Err(_) => break,
                    }
                }
            }
        }
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
        &self,
        lctx: &LanforgeContext,
        socket: &AsyncFd<Socket>,
        mac: [u8; 6],
        iface_index: u32,
        state: &mut RaState,
        next_ra_at: &mut Instant,
    ) {
        if let Err(e) = send_ra_internal(lctx, socket, &self.cfg, mac, iface_index, None, state) {
            warn!("RA periodic error: {e:?}");
        } else {
            state.record_multicast();
            let interval = state.next_interval(&self.cfg);
            *next_ra_at = Instant::now() + interval;
            debug!("Next periodic RA in {:.1}s", interval.as_secs_f64());
        }
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    async fn handle_rs_packet(
        &self,
        res: io::Result<AsyncFdReadyGuard<'_, Socket>>,
        buf: &mut [u8],
        ctx: RaContext<'_>,
        state: &mut RaState,
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
                                    &self.cfg,
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
                                    &self.cfg,
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
                            _ => debug!("RS discarded: rate limit active"),
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

    if gua != state.last_gua || ula != state.last_ula {
        info!(
            gua = ?gua,
            ula = ?ula,
            "RA: Internal prefix state updated"
        );
        state.last_gua = gua;
        state.last_ula = ula;
    }

    let dst_ip: Ipv6Addr = unicast_dst.unwrap_or_else(|| "ff02::1".parse().unwrap());
    let dst_sa = SockAddr::from(SocketAddrV6::new(dst_ip, 0, 0, iface_index));

    let mut pkt = build_ra_packet(cfg, mac, gua.as_ref());

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
    let ff02_2: Ipv6Addr = "ff02::2".parse().unwrap();
    sock.join_multicast_v6(&ff02_2, iface_index)
        .map_err(|e| NetworkError::Socket(format!("join_multicast_v6(ff02::2): {e}")))?;

    // ICMP6_FILTER: tells the kernel to reject all ICMPv6 types except RS (133).
    // On RPi4, this reduces context switches and CPU usage in high-traffic NDP environments.
    set_icmp6_filter_rs_only(&sock)
        .map_err(|e| NetworkError::Socket(format!("ICMP6_FILTER: {e}")))?;

    sock.set_nonblocking(false)
        .map_err(|e| NetworkError::Socket(format!("O_NONBLOCK(false): {e}")))?;

    info!("ICMPv6 raw socket OK — ICMP6_FILTER active (RS only), subscribed to ff02::2");
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

// ---------------------------------------------------------------------------
// Interface Helpers (sysfs — direct read without extra syscalls)
// ---------------------------------------------------------------------------

fn get_iface_index(iface: &str) -> Result<u32, NetworkError> {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .map_err(|e| NetworkError::Generic(format!("ifindex de '{iface}': {e}")))?
        .trim()
        .parse::<u32>()
        .map_err(|e| NetworkError::Generic(format!("parse ifindex: {e}")))
}

fn get_iface_mac(iface: &str) -> Result<[u8; 6], NetworkError> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .map_err(|e| NetworkError::Generic(format!("MAC de '{iface}': {e}")))?;
    let bytes: Vec<u8> = s
        .trim()
        .split(':')
        .map(|x| u8::from_str_radix(x, 16).map_err(|e| NetworkError::InvalidMac(e.to_string())))
        .collect::<Result<Vec<u8>, NetworkError>>()?;
    bytes
        .try_into()
        .map_err(|_| NetworkError::InvalidMac("MAC deve ter 6 bytes".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
