//! mDNS (Multicast DNS) prober for hostname discovery.
//!
//! Actively probes the LAN for devices by sending mDNS PTR queries and parsing
//! responses to extract hostnames. Discovered hostnames are applied to the
//! `LanforgeContext` as `DeviceUpdate::DhcpHostnameHint`.
//!
//! ## Protocol
//!
//! - Listens on `224.0.0.251:5353` (IPv4) and `[ff02::fb]:5353` (IPv6)
//! - Sends PTR queries for `_services._dns-sd._udp.local.` to discover services
//! - Sends reverse-DNS PTR queries for specific IPs (e.g., `1.0.168.192.in-addr.arpa.`)
//! - Parses PTR/SRV records from responses to extract hostnames
//!
//! ## Design
//!
//! Uses spawn-blocking `UdpSocket` listeners (non-async) because mDNS requires
//! `SO_REUSEPORT` on port 5353 — the standard async `UdpSocket` cannot share
//! this port with other processes. Commands are sent via an `mpsc` channel.
//!
//! ## Non-Critical Service
//!
//! Marked as `critical: false` — failure does not halt the daemon.

use lanforge_core::bus::{LanforgeEvent, NetworkEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::state::DeviceUpdate;
use pnet::datalink::interfaces;
use std::fmt::Write;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{debug, error, warn};

use hickory_proto::op::{Message, MessageType, OpCode, Query, UpdateMessage};
use hickory_proto::rr::{Name, RData, RecordType};

use crate::error::NetworkError;

const MDNS_PORT: u16 = 5353;
const MDNS_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_IPV6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceControl};

enum MdnsCommand {
    ProbeAll,
    ProbeIp(IpAddr),
}

/// mDNS hostname prober for IPv4 and IPv6.
///
/// Sends commands to the background worker via an `mpsc` channel.
/// The worker manages the actual socket listeners and packet processing.
#[lanforge_macros::lanforge_service(
    id = "mdns",
    name = "mDNS Prober",
    critical = false,
    retries = 0,
    base_backoff = 2,
    max_backoff = 30
)]
pub struct MdnsProber {
    tx: Sender<MdnsCommand>,
    ctx: LanforgeContext,
}

impl AsyncService for MdnsProber {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        let (tx, rx) = mpsc::channel(32);
        self.tx = tx.clone();

        ctrl.signal_ready();

        if let Err(e) = run_mdns_worker(self.ctx.clone(), rx, tx).await {
            error!("mDNS worker fatal error: {e}");
            return Err(CoreError::Generic(e.to_string()));
        }
        Ok(())
    }
}

impl MdnsProber {
    /// Creates a new `MdnsProber` (command channel is unconnected until `run()` is called).
    #[must_use]
    pub fn new(ctx: LanforgeContext) -> Self {
        let (tx, _) = mpsc::channel(32);
        Self { tx, ctx }
    }

    /// Requests a full mDNS broadcast probe across all interfaces.
    pub async fn trigger_scan(&self) {
        let _ = self.tx.send(MdnsCommand::ProbeAll).await;
    }

    /// Sends a targeted mDNS PTR query for a specific IP address.
    pub async fn probe_ip(&self, ip: IpAddr) {
        let _ = self.tx.send(MdnsCommand::ProbeIp(ip)).await;
    }
}

async fn run_mdns_worker(
    ctx: LanforgeContext,
    mut rx: Receiver<MdnsCommand>,
    tx: Sender<MdnsCommand>,
) -> Result<(), NetworkError> {
    let bus = ctx.bus();
    // We bind to a random port to SEND queries, and a fixed port to LISTEN if we want passive,
    // but on Linux, to receive multicast, we usually bind to 5353 with REUSEPORT.
    let socket_v4 = setup_multicast_socket_v4()?;
    let socket_v6 = setup_multicast_socket_v6()?;

    let (resp_tx, mut resp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100);

    // Spawn listeners
    let socket_v4_clone = socket_v4
        .try_clone()
        .map_err(|e| NetworkError::Socket(e.to_string()))?;
    socket_v4_clone
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| NetworkError::Socket(e.to_string()))?;
    let resp_tx_v4 = resp_tx.clone();

    let ctx_v4 = ctx.clone();
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        while ctx_v4.is_running() {
            match socket_v4_clone.recv_from(&mut buf) {
                Ok((n, addr)) => {
                    let _ = resp_tx_v4.blocking_send((buf[..n].to_vec(), addr));
                }
                Err(ref e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(e) => {
                    warn!("mDNS v4 listen error: {e}");
                    break;
                }
            }
        }
        debug!("mDNS v4 listener exited");
    });

    let socket_v6_clone = socket_v6
        .try_clone()
        .map_err(|e| NetworkError::Socket(e.to_string()))?;
    socket_v6_clone
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|e| NetworkError::Socket(e.to_string()))?;
    let resp_tx_v6 = resp_tx.clone();

    let ctx_v6 = ctx.clone();
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        while ctx_v6.is_running() {
            match socket_v6_clone.recv_from(&mut buf) {
                Ok((n, addr)) => {
                    let _ = resp_tx_v6.blocking_send((buf[..n].to_vec(), addr));
                }
                Err(ref e)
                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {}
                Err(e) => {
                    warn!("mDNS v6 listen error: {e}");
                    break;
                }
            }
        }
        debug!("mDNS v6 listener exited");
    });

    let mut bus_rx = bus.subscribe();

    loop {
        if !ctx.is_running() {
            break;
        }

        tokio::select! {
            event = bus_rx.recv() => {
                if let Ok(timed_event) = event {
                    handle_lanforge_event(&timed_event.event, &tx);
                }
            }
            cmd = rx.recv() => {
                if let Some(c) = cmd {
                    handle_command(&c, &socket_v4, &socket_v6);
                } else {
                    break;
                }
            }
            Some((data_vec, addr)) = resp_rx.recv() => {
                let ctx_clone = ctx.clone();
                tokio::spawn(async move {
                    handle_mdns_packet(&ctx_clone, &data_vec, addr);
                });
            }
            () = tokio::time::sleep(Duration::from_millis(500)) => {
                // Periodic flag check if idle
            }
        }
    }

    Ok(())
}

fn handle_command(cmd: &MdnsCommand, socket_v4: &UdpSocket, socket_v6: &UdpSocket) {
    match cmd {
        MdnsCommand::ProbeAll => {
            let _ = broadcast_query(socket_v4, socket_v6);
        }
        MdnsCommand::ProbeIp(ip) => {
            let _ = send_unicast_query(socket_v4, socket_v6, *ip);
        }
    }
}

fn handle_lanforge_event(event: &LanforgeEvent, tx: &Sender<MdnsCommand>) {
    if matches!(event, LanforgeEvent::Network(NetworkEvent::ScanRequested)) {
        let _ = tx.try_send(MdnsCommand::ProbeAll);
    }
}

fn setup_multicast_socket_v4() -> Result<UdpSocket, NetworkError> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| NetworkError::Socket(e.to_string()))?;

    socket
        .set_reuse_address(true)
        .map_err(|e| NetworkError::Socket(e.to_string()))?;
    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .map_err(|e| NetworkError::Socket(e.to_string()))?;

    // Bind to all interfaces on 5353
    socket
        .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MDNS_PORT).into())
        .map_err(|e| NetworkError::Socket(e.to_string()))?;

    // Join multicast on all interfaces
    let interfaces = interfaces();
    for iface in interfaces {
        if !iface.is_up() || iface.is_loopback() {
            continue;
        }
        for ip in iface.ips {
            if let IpAddr::V4(v4) = ip.ip() {
                let _ = socket.join_multicast_v4(&MDNS_IPV4, &v4);
            }
        }
    }

    Ok(socket.into())
}

fn setup_multicast_socket_v6() -> Result<UdpSocket, NetworkError> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| NetworkError::Socket(e.to_string()))?;

    socket
        .set_only_v6(true)
        .map_err(|e| NetworkError::Socket(e.to_string()))?;
    socket
        .set_reuse_address(true)
        .map_err(|e| NetworkError::Socket(e.to_string()))?;
    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .map_err(|e| NetworkError::Socket(e.to_string()))?;

    socket
        .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), MDNS_PORT).into())
        .map_err(|e| NetworkError::Socket(e.to_string()))?;

    let interfaces = interfaces();
    for iface in interfaces {
        if !iface.is_up() || iface.is_loopback() {
            continue;
        }
        let _ = socket.join_multicast_v6(&MDNS_IPV6, iface.index);
    }

    Ok(socket.into())
}

fn broadcast_query(sock4: &UdpSocket, sock6: &UdpSocket) -> Result<(), NetworkError> {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);

    // PTR query for _services._dns-sd._udp.local.
    let name = Name::from_ascii("_services._dns-sd._udp.local.")
        .map_err(|e| NetworkError::Mdns(e.to_string()))?;
    msg.add_query(Query::query(name, RecordType::PTR));

    let bytes = msg
        .to_vec()
        .map_err(|e| NetworkError::Mdns(e.to_string()))?;
    let _ = sock4.send_to(&bytes, SocketAddr::new(IpAddr::V4(MDNS_IPV4), MDNS_PORT));
    let _ = sock6.send_to(&bytes, SocketAddr::new(IpAddr::V6(MDNS_IPV6), MDNS_PORT));

    debug!("mDNS broadcast probe enviado");
    Ok(())
}

fn send_unicast_query(
    sock4: &UdpSocket,
    sock6: &UdpSocket,
    target: IpAddr,
) -> Result<(), NetworkError> {
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);

    // Most devices respond to a PTR query for their own IP.
    // Example: 1.1.168.192.in-addr.arpa.
    let name = match target {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            Name::from_ascii(format!(
                "{}.{}.{}.{}.in-addr.arpa.",
                octets[3], octets[2], octets[1], octets[0]
            ))
            .map_err(|e| NetworkError::Mdns(e.to_string()))?
        }
        IpAddr::V6(v6) => {
            let mut name_str = String::new();
            for seg in v6.octets().iter().rev() {
                let _ = write!(name_str, "{:x}.{:x}.", seg & 0xf, seg >> 4);
            }
            name_str.push_str("ip6.arpa.");
            Name::from_ascii(name_str).map_err(|e| NetworkError::Mdns(e.to_string()))?
        }
    };

    msg.add_query(Query::query(name, RecordType::PTR));
    let bytes = msg
        .to_vec()
        .map_err(|e| NetworkError::Mdns(e.to_string()))?;

    // We send to the multicast address but some devices might respond unicast if we set the QU bit.
    // For now, simple multicast.
    match target {
        IpAddr::V4(_) => {
            let _ = sock4.send_to(&bytes, SocketAddr::new(IpAddr::V4(MDNS_IPV4), MDNS_PORT));
        }
        IpAddr::V6(_) => {
            let _ = sock6.send_to(&bytes, SocketAddr::new(IpAddr::V6(MDNS_IPV6), MDNS_PORT));
        }
    }

    debug!("mDNS targeted probe enviado para {}", target);
    Ok(())
}

fn handle_mdns_packet(ctx: &LanforgeContext, data: &[u8], from: SocketAddr) {
    let Ok(msg) = Message::from_vec(data) else {
        return;
    };
    if msg.message_type != MessageType::Response {
        return;
    }

    // Passive Classification Mapping
    let classify = |name: &str| -> Option<lanforge_core::device::DeviceClass> {
        let n = name.to_lowercase();
        if n.contains("printer") || n.contains("_ipp") || n.contains("_pdl-datastream") {
            Some(lanforge_core::device::DeviceClass::Printer)
        } else if n.contains("_airplay")
            || n.contains("_googlecast")
            || n.contains("_spotify")
            || n.contains("_raop")
        {
            Some(lanforge_core::device::DeviceClass::Media)
        } else if n.contains("_hap") || n.contains("_miio") || n.contains("_homekit") {
            Some(lanforge_core::device::DeviceClass::IoT)
        } else if n.contains("_ssh") || n.contains("_smb") || n.contains("_afp") {
            Some(lanforge_core::device::DeviceClass::Computer)
        } else if n.contains("_ubnt") || n.contains("_unifi") || n.contains("_mikrotik") {
            Some(lanforge_core::device::DeviceClass::Network)
        } else {
            None
        }
    };

    // We look for PTR, SRV, or A/AAAA records that might reveal a hostname.
    // The most reliable is the "Answer" section names or SRV target.
    for record in msg.answers.iter().chain(msg.additionals().iter()) {
        let hostname = match &record.data {
            RData::PTR(name) => Some(name.to_string()),
            RData::SRV(srv) => Some(srv.target.to_string()),
            _ => None,
        };

        if let Some(h) = hostname {
            let clean_host: &str = h.trim_end_matches('.').trim_end_matches(".local");
            if clean_host.is_empty() || clean_host.contains('.') {
                // It might still be useful for classification even if not a valid hostname
                if let Some(class) = classify(&h)
                    && let Some(mac) = ctx.get_mac_by_ip(from.ip())
                {
                    let _ = ctx.apply(lanforge_core::context::state::DeviceUpdate::ClassHint {
                        mac,
                        class,
                    });
                }
                continue;
            }

            // Try to find the MAC for the sender IP
            let mac = ctx.get_mac_by_ip(from.ip());

            if let Some(mac) = mac {
                // If it has a classification hit, apply it
                if let Some(class) = classify(&h) {
                    let _ = ctx.apply(lanforge_core::context::state::DeviceUpdate::ClassHint {
                        mac,
                        class,
                    });
                }

                // If it already has a hostname, skip update to avoid useless noise
                if let Some(dev) = ctx.get_device(&mac)
                    && !dev.hostname.name.is_empty()
                {
                    continue;
                }

                debug!("mDNS descoberta: {} -> {}", from.ip(), clean_host);
                let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
                    mac,
                    hostname: clean_host.to_string(),
                });
            }
        }
    }
}
