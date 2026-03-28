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
use futures::TryStreamExt;
use lanforge_core::bus::{EventBus, LanforgeEvent};
use rand::{RngExt, rng};
use rtnetlink::Handle;
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::unix::AsyncFd;
use tokio::time::{Duration, sleep};
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
    pub(crate) async_fd: &'a AsyncFd<Socket>,
    pub(crate) cfg: &'a RaConfig,
    pub(crate) handle: &'a Handle,
    pub(crate) mac: &'a [u8; 6],
    pub(crate) iface_index: u32,
    pub(crate) bus: &'a EventBus,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Main task for the RA service. Should be invoked via `tokio::spawn`.
///
/// Returns `Err` only on unrecoverable failures (permission denied, interface
/// not found, etc.). The caller is responsible for restarting with backoff.
pub async fn ra_service(cfg: RaConfig, bus: Arc<EventBus>) -> Result<()> {
    cfg.validate()?;

    info!(
        "Iniciando na interface '{}' (M={}, O={}, MaxInterval={}s, RouterLifetime={}s)",
        cfg.iface,
        u8::from(cfg.managed),
        u8::from(cfg.other_config),
        cfg.max_interval.as_secs(),
        cfg.effective_router_lifetime().as_secs(),
    );

    let (connection, handle, _) = rtnetlink::new_connection()
        .map_err(|e| NetworkError::Socket(format!("Netlink connection para RA: {e}")))?;
    tokio::spawn(connection);

    let iface_index = get_iface_index(&cfg.iface)?;
    let mac = get_iface_mac(&cfg.iface)?;

    info!(
        "ifindex={iface_index}, MAC={}",
        mac.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    );

    let socket = create_ra_socket(&cfg.iface, iface_index)?;
    let async_fd = AsyncFd::new(socket).map_err(NetworkError::Io)?;
    let mut state = RaState::new();

    let ctx = RaContext {
        async_fd: &async_fd,
        cfg: &cfg,
        handle: &handle,
        mac: &mac,
        iface_index,
        bus: &bus,
    };

    let mut bus_rx = bus.subscribe();

    // Immediate RA on startup — active clients get configured without waiting
    do_multicast_ra(&ctx, &mut state).await;

    loop {
        let next = state.next_interval(&cfg);
        debug!("Next periodic RA in {:.1}s", next.as_secs_f64());

        tokio::select! {
            // ── Periodic RA ──────────────────────────────────────────────
            () = sleep(next) => {
                do_multicast_ra(&ctx, &mut state).await;
            }

            // ── Router Solicitation Received ──────────────────────────────
            guard = async_fd.readable() => {
                let mut guard = guard?;
                let mut buf = [0u8; 1500];

                match guard.try_io(|fd| {
                    let buf_uninit = unsafe {
                        &mut *(std::ptr::from_mut::<[u8]>(&mut buf)
                            as *mut [std::mem::MaybeUninit<u8>])
                    };
                    fd.get_ref().recv_from(buf_uninit)
                }) {
                    Ok(Ok((n, src_sa))) if n > 0 => {
                        let data = &buf[..n];

                        // ICMP6_FILTER already rejects non-RS packets in the kernel;
                        // this is a secondary safety check.
                        if data.first() != Some(&ICMPV6_TYPE_RS) {
                            continue;
                        }

                        let rs_src = src_sa.as_socket_ipv6().map(|s| *s.ip());
                        debug!("RS received from {rs_src:?}");

                        handle_rs(&ctx, rs_src, &mut state).await;
                    }
                    Ok(Ok(_)) | Err(_)  => {}
                    Ok(Err(e)) => warn!("Socket read error: {e}"),
                    // WouldBlock — AsyncFd resets automatically
                }
            }

            // ── EventBus — Shutdown ──────────────────────────────────────
            event = bus_rx.recv() => {
                if let Ok(LanforgeEvent::Shutdown) = event {
                    info!("RA service: shutdown recebido, encerrando...");
                    break;
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RS Response Logic (RFC 4861 §6.2.6)
// ---------------------------------------------------------------------------

async fn handle_rs(ctx: &RaContext<'_>, rs_src: Option<Ipv6Addr>, state: &mut RaState) {
    // Random delay of 0–500ms before responding (RFC 4861 §6.2.6).
    // Prevents multiple routers from responding to the same RS simultaneously.
    let delay_ms = rng().random_range(0..MAX_RA_DELAY_TIME_MS);
    sleep(Duration::from_millis(delay_ms)).await;

    // Destination: unicast to solicitant (if they have a valid address) or multicast.
    let dst = rs_src.filter(|ip| !ip.is_unspecified());

    match dst {
        Some(unicast_dst) if state.can_unicast_now(&unicast_dst) => {
            match send_ra(ctx, Some(unicast_dst), state).await {
                Ok(()) => {
                    debug!("RA unicast -> {unicast_dst}");
                    state.record_unicast(unicast_dst);
                }
                Err(e) => warn!("RA unicast error: {e:?}"),
            }
        }
        None if state.can_multicast_now() => {
            // Solicitant with unspecified address (::) → multicast response.
            do_multicast_ra(ctx, state).await;
        }
        _ => {
            // Rate limit active — RFC 4861 §6.2.6 allows silent discard.
            debug!("RS discarded: MIN_DELAY_BETWEEN_RAS rate limit active");
        }
    }
}

async fn do_multicast_ra(ctx: &RaContext<'_>, state: &mut RaState) {
    match send_ra(ctx, None, state).await {
        Ok(()) => {
            debug!("RA multicast -> ff02::1");
            state.record_multicast();
        }
        Err(e) => warn!("RA multicast error: {e:?}"),
    }
}

/// Constructs, signs (checksum), and sends an RA.
/// `unicast_dst = None` → multicast to `ff02::1` (all-nodes).
async fn send_ra(
    ctx: &RaContext<'_>,
    unicast_dst: Option<Ipv6Addr>,
    state: &mut RaState,
) -> Result<()> {
    // Addresses are re-detected on every send: GUA may change when the ISP
    // renews prefix delegation via DHCPv6-PD, without requiring a service restart.
    let src_ll = get_link_local_addr(ctx.handle, ctx.iface_index)
        .await
        .map_err(|_| NetworkError::NoLinkLocal(ctx.iface_index))?;
    let gua_info = get_gua_prefix(ctx.handle, ctx.iface_index).await?;
    let (gua, preferred, valid) = match gua_info {
        Some((ip, p, v)) => (Some(ip), p, v),
        None => (None, 0, 0),
    };
    let prefix_bits = gua.map(|ip| (ip, preferred, valid));

    // Publish PrefixChanged on the EventBus if the GUA changed.
    if prefix_bits.as_ref().map(|(ip, _, _)| *ip) != state.last_gua {
        info!(
            "GUA prefix changed: {:?} -> {:?} (pref={}, valid={})",
            state.last_gua, gua, preferred, valid
        );
        state.last_gua = gua;
        ctx.bus.publish(LanforgeEvent::PrefixChanged {
            gua,
            preferred,
            valid,
        });
    }

    let dst_ip: Ipv6Addr = unicast_dst.unwrap_or_else(|| "ff02::1".parse().unwrap());
    // scope_id obrigatório para destinos link-scoped (multicast e link-local)
    let dst_sa = SockAddr::from(SocketAddrV6::new(dst_ip, 0, 0, ctx.iface_index));

    let mut pkt = build_ra_packet(ctx.cfg, *ctx.mac, gua.as_ref());

    // Checksum calculado sobre o pseudo-header IPv6 + payload
    let csum = icmpv6_checksum(&src_ll, &dst_ip, &pkt);
    pkt[2] = (csum >> 8) as u8;
    pkt[3] = (csum & 0xFF) as u8;

    ctx.async_fd
        .get_ref()
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

    sock.set_nonblocking(true)
        .map_err(|e| NetworkError::Socket(format!("O_NONBLOCK: {e}")))?;

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
// setsockopt wrappers not exposed by socket2 0.5
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

// ---------------------------------------------------------------------------
// Address Detection via rtnetlink (reused existing Handle)
// ---------------------------------------------------------------------------

/// Returns the link-local address (`fe80::/10`) of the interface.
/// Mandatory as the source address for all RAs (RFC 4861 §4.2).
async fn get_link_local_addr(handle: &Handle, iface_index: u32) -> Result<Ipv6Addr> {
    let mut stream = handle.address().get().execute();
    while let Some(msg) = stream.try_next().await? {
        if msg.header.index != iface_index {
            continue;
        }
        if let Some(addr) = extract_ipv6(&msg) {
            let o = addr.octets();
            if o[0] == 0xFE && (o[1] & 0xC0) == 0x80 {
                return Ok(addr);
            }
        }
    }
    Err(NetworkError::NoLinkLocal(iface_index))
}

/// Detects the GUA /64 prefix on the interface and returns it along with lifetimes.
///
/// GUA (`2000::/3)`: first byte in range [0x20, 0x3F].
/// The address on the interface (e.g. `2a01:x:y:z::1`) is masked to obtain `2a01:x:y:z::`.
/// Returns `None` if no GUA is assigned (ISP without IPv6 or pending delegation).
async fn get_gua_prefix(handle: &Handle, iface_index: u32) -> Result<Option<(Ipv6Addr, u32, u32)>> {
    let mut stream = handle.address().get().execute();
    while let Some(msg) = stream.try_next().await? {
        if msg.header.index != iface_index {
            continue;
        }

        let mut addr = None;
        let mut cache_info = None;

        for attr in &msg.attributes {
            match attr {
                AddressAttribute::Address(IpAddr::V6(v6)) => addr = Some(*v6),
                AddressAttribute::CacheInfo(info) => cache_info = Some(info),
                _ => {}
            }
        }

        if let Some(v6) = addr {
            let o = v6.octets();
            if (0x20..=0x3F).contains(&o[0]) {
                let mut masked = o;
                masked[8..].fill(0);
                let ip = Ipv6Addr::from(masked);
                let (pref, valid) = if let Some(info) = cache_info {
                    (info.ifa_preferred, info.ifa_valid)
                } else {
                    (3600, 7200) // Fallback if no cache_info is present
                };
                return Ok(Some((ip, pref, valid)));
            }
        }
    }
    Ok(None)
}

fn extract_ipv6(msg: &AddressMessage) -> Option<Ipv6Addr> {
    msg.attributes.iter().find_map(|a| {
        if let AddressAttribute::Address(IpAddr::V6(v6)) = a {
            Some(*v6)
        } else {
            None
        }
    })
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
