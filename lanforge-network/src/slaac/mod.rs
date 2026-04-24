//! Active SLAAC Tracker for IPv6.
//!
//! Listens for device connection signals and periodically pings the All-Nodes
//! multicast address (`ff02::1`) to force devices (especially Android with
//! randomized privacy addresses) to reveal their SLAAC addresses via the kernel neighbor cache.

pub mod packet;

use std::net::{Ipv6Addr, SocketAddrV6};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::NetworkError;
use crate::slaac::packet::build_echo_request;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, LanforgeService, ServiceMeta};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tracing::{debug, info, warn};

/// Active SLAAC Tracker service.
pub struct SlaacTracker {
    target_ifindex: u32,
    ctx: LanforgeContext,
    socket: Option<Arc<Socket>>,
}

impl SlaacTracker {
    /// Creates a new `SlaacTracker` for the given interface.
    #[must_use]
    pub const fn new(target_ifindex: u32, ctx: LanforgeContext) -> Self {
        Self {
            target_ifindex,
            ctx,
            socket: None,
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
        // Initialize discovery socket
        let socket = Arc::new(
            create_icmpv6_send_socket(self.target_ifindex)
                .map_err(|e| CoreError::Generic(e.to_string()))?,
        );
        self.socket = Some(Arc::clone(&socket));

        let mut bus_rx = self.ctx.bus().subscribe();
        let mut next_sweep = Instant::now(); // Immediate sweep on boot

        info!("SLAAC Tracker: Active and listening for discovery triggers");

        loop {
            if !self.ctx.is_running() {
                break;
            }

            let now = Instant::now();
            let sleep_duration = next_sweep.saturating_duration_since(now);

            tokio::select! {
                () = tokio::time::sleep(sleep_duration) => {
                    info!("SLAAC Tracker: Periodic sweep");
                    self.send_discovery_ping();
                    next_sweep = Instant::now() + Duration::from_hours(1); // 60 minutes
                }

                Ok(timed_event) = bus_rx.recv() => {
                    match timed_event.event {
                        LanforgeEvent::RsReceived { .. } => {
                            // Device requested RA, will configure SLAAC shortly.
                            let socket_clone = Arc::clone(&socket);
                            let ifindex = self.target_ifindex;
                            let ctx = self.ctx.clone();
                            tokio::spawn(async move {
                                tokio::time::sleep(Duration::from_millis(800)).await;
                                let ll = ctx.get_interface_state(ifindex).link_local;
                                if let Some(src) = ll {
                                    send_multicast_echo(&socket_clone, &src, ifindex);
                                }
                            });
                        }
                        LanforgeEvent::ScanRequested | LanforgeEvent::NeighborScanRequested => {
                            info!("SLAAC Tracker: Discovery requested, triggering sweep");
                            self.send_discovery_ping();
                        }
                        LanforgeEvent::Shutdown => break,
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
}

impl SlaacTracker {
    fn send_discovery_ping(&self) {
        let Some(ref socket) = self.socket else {
            return;
        };
        let state = self.ctx.get_interface_state(self.target_ifindex);
        let Some(src_ll) = state.link_local else {
            warn!("SLAAC Tracker: No link-local address, cannot ping");
            return;
        };
        // Only link-local as source. GUA/ULA don't help here for discovery.
        send_multicast_echo(socket, &src_ll, self.target_ifindex);
    }
}

fn send_multicast_echo(socket: &Socket, src: &Ipv6Addr, ifindex: u32) {
    let dst: Ipv6Addr = "ff02::1".parse().unwrap();
    let dst_sa = SockAddr::from(SocketAddrV6::new(dst, 0, 0, ifindex));
    let pkt = build_echo_request(src, &dst, 0xcafe, 1);
    if let Err(e) = socket.send_to(&pkt, &dst_sa) {
        debug!("SLAAC Tracker: Failed to ping ff02::1 from {src}: {e}");
    }
}

/// Creates an `ICMPv6` socket optimized for sending discovery probes.
///
/// This socket is write-only from the tracker's perspective: it blocks all
/// incoming `ICMPv6` traffic at the kernel level and disables multicast loopback.
fn create_icmpv6_send_socket(ifindex: u32) -> Result<Socket, NetworkError> {
    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
        .map_err(|e| NetworkError::Socket(format!("ICMPv6 socket creation: {e}")))?;

    // 1. Filter ALL incoming `ICMPv6` messages - we don't want to receive anything
    let filter = [0xFFu8; 32];
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

    // 2. Disable multicast loopback to avoid pinging ourselves
    sock.set_multicast_loop_v6(false)
        .map_err(|e| NetworkError::Socket(format!("set_multicast_loop_v6: {e}")))?;

    // 3. Bind to specific interface
    sock.bind_device(Some(get_iface_name(ifindex)?.as_bytes()))
        .map_err(|e| NetworkError::Socket(format!("bind_device: {e}")))?;

    Ok(sock)
}

fn get_iface_name(ifindex: u32) -> Result<String, NetworkError> {
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
