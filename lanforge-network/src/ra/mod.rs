//! Router Advertisement Service (RFC 4861 + RFC 8106).
//!
//! A generic, RFC-compliant implementation of the NDP/RA protocol.
//! Designed to run on resource-constrained hardware like the Raspberry Pi 4B.
//!
//! ## RA / RS Cycle
//!
//! ```mermaid
//! sequenceDiagram
//!     participant R as Router (Lanforge)
//!     participant C as Client
//!
//!     Note over R,C: Periodic or Startup Advertisement
//!     R->>C: 1. RA Multicast (ff02::1)
//!
//!     Note over R,C: Solicitation Phase
//!     C->>R: 2. RS Unicast/Multicast (Solicitation)
//!     Note right of R: Random Delay (0-500ms)
//!     R->>C: 3. RA Unicast/Multicast (Response)
//! ```
//!
//! # Implemented RFCs
//! - RFC 4861 — Neighbor Discovery for IPv6 (Full RA/RS support)
//! - RFC 8106 — RA Options for DNS Configuration (RDNSS + DNSSL)
//! - RFC 4191 — Default Router Preferences (Priority flags)
//! - RFC 3775 — `AdvRouterAddr` flag in Prefix Information

pub mod config;
pub mod packet;

pub use config::*;
pub use packet::{build_ra_packet, icmpv6_checksum};

use crate::error::{NetworkError, Result};
use lanforge_core::bus::{LanforgeEvent, ManagedTable};
use rand::RngExt;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};
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

/// Runtime state for the RA server.
pub struct RaState {
    /// Count of initial RAs sent (startup phase tracking).
    initial_sent: u8,
    /// Timestamp of the last multicast RA sent (applies `MIN_DELAY_BETWEEN_RAS`).
    last_multicast_ra: Option<Instant>,
    /// Unicast rate limiting: tracks the last RA sent per destination IP.
    unicast_rl: HashMap<Ipv6Addr, Instant>,
    /// Last detected GUA — used to publish `PrefixChanged` only when a change occurs.
    last_gua: Option<Ipv6Addr>,
}

impl RaState {
    pub(crate) fn new() -> Self {
        Self {
            initial_sent: 0,
            last_multicast_ra: None,
            unicast_rl: HashMap::new(),
            last_gua: None,
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

/// Shared context for RA service internal functions.
pub struct RaContext<'a> {
    pub(crate) socket: &'a Socket,
    pub(crate) cfg: &'a RaConfig,
    pub(crate) table: &'a ManagedTable,
    pub(crate) mac: &'a [u8; 6],
    pub(crate) iface_index: u32,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Main task for the RA service (Synchronous OS thread).
pub fn ra_service(
    cfg: RaConfig,
    table: Arc<ManagedTable>,
    bus_rx: std::sync::mpsc::Receiver<LanforgeEvent>,
) -> Result<()> {
    cfg.validate()?;

    info!(
        "RA: Iniciando na '{}' (M={}, O={}, MaxInterval={}s, RouterLifetime={}s)",
        cfg.iface,
        u8::from(cfg.managed),
        u8::from(cfg.other_config),
        cfg.max_interval.as_secs(),
        cfg.effective_router_lifetime().as_secs(),
    );

    let iface_index = get_iface_index(&cfg.iface)?;
    let mac = get_iface_mac(&cfg.iface)?;

    let socket = create_ra_socket(&cfg.iface, iface_index)?;
    // Set a short read timeout to allow checking the bus periodically
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .map_err(|e| NetworkError::Socket(format!("set_read_timeout: {e}")))?;

    let mut state = RaState::new();
    let ctx = RaContext {
        socket: &socket,
        cfg: &cfg,
        table: &table,
        mac: &mac,
        iface_index,
    };

    // Immediate RA on startup
    do_multicast_ra(&ctx, &mut state);

    let mut next_ra_at = Instant::now() + state.next_interval(&cfg);

    loop {
        // 1. Periodic Advertisement
        if Instant::now() >= next_ra_at {
            do_multicast_ra(&ctx, &mut state);
            let interval = state.next_interval(&cfg);
            next_ra_at = Instant::now() + interval;
            debug!("Next periodic RA in {:.1}s", interval.as_secs_f64());
        }

        // 2. Packet processing (RS)
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1500];
        match socket.recv_from(&mut buf) {
            Ok((n, src_sa)) => {
                if n > 0 {
                    let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                    if data.first() == Some(&ICMPV6_TYPE_RS) {
                        let rs_src =
                            src_sa
                                .as_socket()
                                .and_then(|s: std::net::SocketAddr| match s {
                                    std::net::SocketAddr::V6(v6) => Some(*v6.ip()),
                                    _ => None,
                                });
                        debug!("RS received from {rs_src:?}");
                        handle_rs(&ctx, rs_src, &mut state);
                    }
                }
            }
            Err(e) => {
                let kind = e.kind();
                if kind == std::io::ErrorKind::WouldBlock || kind == std::io::ErrorKind::TimedOut {
                    // Read timeout, continue to bus check
                } else {
                    warn!("RA socket error: {e}");
                }
            }
        }

        // 3. EventBus signals
        while let Ok(event) = bus_rx.try_recv() {
            if let LanforgeEvent::Shutdown = event {
                info!("RA service: shutdown recebido, encerrando...");
                return Ok(());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RS Response Logic (RFC 4861 §6.2.6)
// ---------------------------------------------------------------------------

fn handle_rs(ctx: &RaContext<'_>, rs_src: Option<Ipv6Addr>, state: &mut RaState) {
    // Random delay of 0–500ms before responding (RFC 4861 §6.2.6).
    let delay_ms = rand::rng().random_range(0..MAX_RA_DELAY_TIME_MS);
    std::thread::sleep(Duration::from_millis(delay_ms));

    // Destination: unicast to solicitant (if they have a valid address) or multicast.
    let dst = rs_src.filter(|ip| !ip.is_unspecified());

    match dst {
        Some(unicast_dst) if state.can_unicast_now(&unicast_dst) => {
            match send_ra(ctx, Some(unicast_dst), state) {
                Ok(()) => {
                    debug!("RA unicast -> {unicast_dst}");
                    state.record_unicast(unicast_dst);
                }
                Err(e) => warn!("RA unicast error: {e:?}"),
            }
        }
        None if state.can_multicast_now() => {
            do_multicast_ra(ctx, state);
        }
        _ => debug!("RS discarded: rate limit active"),
    }
}

fn do_multicast_ra(ctx: &RaContext<'_>, state: &mut RaState) {
    match send_ra(ctx, None, state) {
        Ok(()) => {
            debug!("RA multicast -> ff02::1");
            state.record_multicast();
        }
        Err(e) => warn!("RA multicast error: {e:?}"),
    }
}

/// Constructs, signs (checksum), and sends an RA.
/// `unicast_dst = None` → multicast to `ff02::1` (all-nodes).
fn send_ra(ctx: &RaContext<'_>, unicast_dst: Option<Ipv6Addr>, state: &mut RaState) -> Result<()> {
    // Addresses are read from the cached interface state in ManagedTable.
    let if_ips = ctx.table.read().get_interface_ips(ctx.iface_index);

    let src_ll = if_ips
        .link_local
        .ok_or(NetworkError::NoLinkLocal(ctx.iface_index))?;
    let gua = if_ips.gua;

    // Publish PrefixChanged on the EventBus if the GUA changed.
    if gua != state.last_gua {
        info!("GUA prefix changed: {:?} -> {:?}", state.last_gua, gua);
        state.last_gua = gua;

        // Note: in a sync thread, we might not want to publish back to the bus
        // to avoid loops, but RA is the authority for prefix changes learning
        // from the monitor, so we let the ManagedTable handle the bus event.
        // Actually, RA doesn't need to publish back anymore because the MONITOR
        // already updated the table which triggers the event!
    }

    let dst_ip: Ipv6Addr = unicast_dst.unwrap_or_else(|| "ff02::1".parse().unwrap());
    // scope_id obrigatório para destinos link-scoped (multicast e link-local)
    let dst_sa = SockAddr::from(SocketAddrV6::new(dst_ip, 0, 0, ctx.iface_index));

    let mut pkt = build_ra_packet(ctx.cfg, *ctx.mac, gua.as_ref());

    // Checksum calculado sobre o pseudo-header IPv6 + payload
    let csum = icmpv6_checksum(&src_ll, &dst_ip, &pkt);
    pkt[2] = (csum >> 8) as u8;
    pkt[3] = (csum & 0xFF) as u8;

    ctx.socket
        .send_to(&pkt, &dst_sa)
        .map_err(|e| NetworkError::Socket(format!("ICMPv6 send_to: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Raw ICMPv6 Socket Configuration
// ---------------------------------------------------------------------------

fn create_ra_socket(iface: &str, iface_index: u32) -> Result<Socket> {
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
/// Crucial on RPi4 to avoid unnecessary process wakeups.
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
            std::ptr::from_ref(&v).cast::<libc::c_void>(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap_or_default(),
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

fn get_iface_index(iface: &str) -> Result<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .map_err(|e| NetworkError::Generic(format!("ifindex de '{iface}': {e}")))?
        .trim()
        .parse::<u32>()
        .map_err(|e| NetworkError::Generic(format!("parse ifindex: {e}")))
}

fn get_iface_mac(iface: &str) -> Result<[u8; 6]> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .map_err(|e| NetworkError::Generic(format!("MAC de '{iface}': {e}")))?;
    let bytes: Vec<u8> = s
        .trim()
        .split(':')
        .map(|x| u8::from_str_radix(x, 16).map_err(|e| NetworkError::InvalidMac(e.to_string())))
        .collect::<Result<Vec<u8>>>()?;
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
