//! Active SLAAC Tracker for IPv6.
//!
//! Listens for device connection signals and periodically pings the All-Nodes
//! multicast address (`ff02::1`) to force devices (especially Android with
//! randomized privacy addresses) to reveal their SLAAC addresses.

pub mod packet;

use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::time::{Duration, Instant};

use crate::error::NetworkError;
use crate::ndp::utils::probe_neighbor;
use crate::slaac::packet::{ICMPV6_TYPE_ECHO_REPLY, build_echo_request};
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, LanforgeService, ServiceMeta};
use rtnetlink::Handle;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::io::unix::AsyncFd;
use tracing::{debug, info, warn};

/// Active SLAAC Tracker service.
pub struct SlaacTracker {
    handle: Handle,
    target_ifindex: u32,
    ctx: LanforgeContext,
}

impl SlaacTracker {
    #[must_use]
    pub const fn new(handle: Handle, target_ifindex: u32, ctx: LanforgeContext) -> Self {
        Self {
            handle,
            target_ifindex,
            ctx,
        }
    }
}

impl LanforgeService for SlaacTracker {
    fn meta(&self) -> ServiceMeta {
        ServiceMeta {
            id: "slaac_tracker",
            display_name: "SLAAC Tracker",
            critical: false,
            max_retries: 3,
            base_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_mins(1),
            stack_kb: 512,
        }
    }
}

impl AsyncService for SlaacTracker {
    async fn run(&mut self) -> Result<(), CoreError> {
        let mut bus_rx = self.ctx.bus().subscribe();
        let mut current_gua: Option<Ipv6Addr> = None;
        let mut current_ula: Option<Ipv6Addr> = None;

        // Create raw ICMPv6 socket for Echo Reply monitoring
        let socket = create_icmpv6_socket(self.target_ifindex)
            .map_err(|e| CoreError::Generic(e.to_string()))?;
        socket.set_nonblocking(true).map_err(CoreError::Io)?;
        let async_socket = AsyncFd::new(socket).map_err(CoreError::Io)?;

        let mut next_periodic_sweep = Instant::now() + Duration::from_secs(30);
        let mut buf = [0u8; 1500];

        info!("SLAAC Tracker: Active and listening for discovery triggers");

        loop {
            if !self.ctx.is_running() {
                break;
            }

            let now = Instant::now();
            let sleep_duration = if next_periodic_sweep > now {
                next_periodic_sweep - now
            } else {
                Duration::ZERO
            };

            tokio::select! {
                // 1. Periodic Discovery Sweep
                () = tokio::time::sleep(sleep_duration) => {
                    self.trigger_multicast_ping(current_gua, current_ula, &async_socket);
                    next_periodic_sweep = Instant::now() + Duration::from_mins(5); // 5 minutes
                }

                // 2. Event Driven Discovery
                Ok(timed_event) = bus_rx.recv() => {
                    match timed_event.event {
                        LanforgeEvent::PrefixChanged { gua, ula, .. } => {
                            current_gua = gua;
                            current_ula = ula;
                        }
                        LanforgeEvent::DeviceUpdated { mac: _, hostname: _, change } => {
                            // If a device just got an IPv4 or updated its hostname,
                            // it might have IPv6 ready too. Trigger a sweep.
                            if matches!(change, lanforge_core::bus::DeviceChange::V4Assigned { .. } | lanforge_core::bus::DeviceChange::HostnameChanged { .. }) {
                                self.trigger_multicast_ping(current_gua, current_ula, &async_socket);
                            }
                        }
                        LanforgeEvent::RsReceived { .. } => {
                            // Device just asked for an RA, wait a bit for it to configure SLAAC then ping.
                            let ctx = self.ctx.clone();
                            let ifidx = self.target_ifindex;
                            let socket_fd = async_socket.as_raw_fd();
                            let gua = current_gua;
                            let ula = current_ula;
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(800)).await;
                                trigger_ping_internal(&ctx, socket_fd, ifidx, gua, ula);
                            });
                        }
                        LanforgeEvent::ScanRequested => {
                            self.trigger_multicast_ping(current_gua, current_ula, &async_socket);
                        }
                        _ => {}
                    }
                }

                // 3. Monitor Echo Replies
                res = async_socket.readable() => {
                    let mut guard = res.map_err(CoreError::Io)?;
                    let buf_uninit = unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<MaybeUninit<u8>>(), buf.len()) };
                    match guard.get_inner().recv_from(buf_uninit) {
                        Ok((n, addr)) => {
                            guard.clear_ready();
                            if n >= 8 && buf[0] == ICMPV6_TYPE_ECHO_REPLY
                                && let Some(ip) = addr.as_socket().and_then(|s| match s {
                                    SocketAddr::V6(v6) => Some(*v6.ip()),
                                    SocketAddr::V4(_) => None,
                                }) {
                                    self.handle_echo_reply(ip).await;
                                }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            guard.clear_ready();
                        }
                        Err(e) => {
                            warn!("SLAAC Tracker: Socket read error: {e}");
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl SlaacTracker {
    fn trigger_multicast_ping(
        &self,
        gua: Option<Ipv6Addr>,
        ula: Option<Ipv6Addr>,
        socket: &AsyncFd<Socket>,
    ) {
        trigger_ping_internal(&self.ctx, socket.as_raw_fd(), self.target_ifindex, gua, ula);
    }

    async fn handle_echo_reply(&self, ip: Ipv6Addr) {
        // Do we know this IP?
        if self.ctx.get_mac_by_ip(IpAddr::V6(ip)).is_none() {
            debug!(
                "SLAAC Tracker: Discovered unknown IPv6 node {}, triggering NDP probe...",
                ip
            );
            // Trigger kernel NDP resolution. NeighborMonitor will pick up the result.
            if let Err(e) =
                probe_neighbor(&self.handle, self.target_ifindex, IpAddr::V6(ip), None).await
            {
                debug!("SLAAC Tracker: Failed to probe {}: {}", ip, e);
            }
        }
    }
}

fn trigger_ping_internal(
    ctx: &LanforgeContext,
    fd: i32,
    ifindex: u32,
    gua: Option<Ipv6Addr>,
    ula: Option<Ipv6Addr>,
) {
    let if_ips = ctx.get_interface_state(ifindex);
    let Some(src_ll) = if_ips.link_local else {
        return;
    };
    let dst_all = "ff02::1".parse::<Ipv6Addr>().unwrap();
    let dst_sa = SockAddr::from(SocketAddrV6::new(dst_all, 0, 0, ifindex));

    let socket = unsafe { Socket::from_raw_fd(fd) };

    // 1. Ping from Link-Local
    send_echo(&socket, &src_ll, &dst_all, &dst_sa);

    // 2. Ping from GUA (if we have one) to tease out device GUAs
    if let Some(src_gua) = gua.or(if_ips.gua) {
        send_echo(&socket, &src_gua, &dst_all, &dst_sa);
    }

    // 3. Ping from ULA (if we have one) to tease out device ULAs
    if let Some(src_ula) = ula.or(if_ips.ula) {
        send_echo(&socket, &src_ula, &dst_all, &dst_sa);
    }

    // Don't close the socket! We are just borrowing the FD.
    std::mem::forget(socket);
}

fn send_echo(socket: &Socket, src: &Ipv6Addr, dst: &Ipv6Addr, dst_sa: &SockAddr) {
    let pkt = build_echo_request(src, dst, 0xcafe, 1);
    if let Err(e) = socket.send_to(&pkt, dst_sa) {
        debug!(
            "SLAAC Tracker: Failed to send multicast ping from {}: {}",
            src, e
        );
    }
}

fn create_icmpv6_socket(ifindex: u32) -> Result<Socket, NetworkError> {
    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
        .map_err(|e| NetworkError::Socket(format!("Failed to create ICMPv6 socket: {e}")))?;

    // We want to receive Echo Replies from everyone.
    // The host already joins ff02::1.

    // Set ICMP6_FILTER to receive only Echo Reply (129)
    let mut filter = [0xFFu8; 32];
    let t = ICMPV6_TYPE_ECHO_REPLY as usize;
    filter[t / 8] &= !(1u8 << (t % 8));

    // ICMP6_FILTER is option 1 on Linux
    unsafe {
        let ret = libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_ICMPV6,
            1, // ICMP6_FILTER
            filter.as_ptr().cast::<libc::c_void>(),
            libc::socklen_t::try_from(filter.len()).unwrap_or_default(),
        );
        if ret != 0 {
            return Err(NetworkError::Socket(format!(
                "setsockopt(ICMP6_FILTER): {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    // Bind to interface
    sock.bind_device(Some(get_iface_name(ifindex)?.as_bytes()))
        .map_err(|e| NetworkError::Socket(format!("bind_device: {e}")))?;

    Ok(sock)
}

fn get_iface_name(ifindex: u32) -> Result<String, NetworkError> {
    // This is a bit slow but only done once at startup
    for entry in
        std::fs::read_dir("/sys/class/net").map_err(|e| NetworkError::Generic(e.to_string()))?
    {
        let entry = entry.map_err(|e| NetworkError::Generic(e.to_string()))?;
        let path = entry.path().join("ifindex");
        if let Ok(idx_str) = std::fs::read_to_string(path)
            && idx_str.trim().parse::<u32>().ok() == Some(ifindex)
        {
            return Ok(entry.file_name().to_string_lossy().to_string());
        }
    }
    Err(NetworkError::Generic(format!(
        "ifindex {ifindex} not found"
    )))
}
