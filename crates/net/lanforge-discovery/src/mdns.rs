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

use lanforge_macros::ServiceConfig;
use lanforge_types::device::{DeviceClass, TransientOrigin};
use lanforge_types::network::{
    DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecordType, Hostname, HostnameOrigin,
};
use lanforge_types::system::ServiceState;
use lanforge_types::update::{DeviceUpdate, TransientHostUpdate};
use serde::{Deserialize, Serialize};

use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::AsyncService;
use pnet::datalink::interfaces;
use std::fmt::Write;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{debug, error, info, warn};

use lanforge_dns_wire::{WireDecoder, WireEncoder};

use crate::error::NetworkError;

const MDNS_PORT: u16 = 5353;
const MDNS_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_IPV6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

/// Configuration for the mDNS prober.
#[derive(Debug, Clone, Serialize, Deserialize, ServiceConfig)]
#[config(key = "mdns")]
#[serde(default)]
pub struct MdnsConfig {
    /// Whether background mDNS probing is enabled.
    pub enabled: bool,
    /// Interval for periodic full network probes (seconds).
    pub probe_interval: u64,
}

impl Default for MdnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            probe_interval: 3600, // 1 hour
        }
    }
}

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
    cfg: MdnsConfig,
    tx: Sender<MdnsCommand>,
    _ctx: LanforgeContext,
}

impl AsyncService for MdnsProber {
    fn dependencies(&self) -> &'static [lanforge_core::service::ServiceDependency] {
        &[lanforge_core::service::ServiceDependency::Interfaces]
    }

    fn stats(&self, _ctx: &LanforgeContext) -> Vec<(std::borrow::Cow<'static, str>, String)> {
        vec![
            (
                std::borrow::Cow::Borrowed("enabled"),
                self.cfg.enabled.to_string(),
            ),
            (
                std::borrow::Cow::Borrowed("probe_interval_secs"),
                self.cfg.probe_interval.to_string(),
            ),
        ]
    }

    async fn serve(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        if !self.cfg.enabled {
            info!("mDNS prober is disabled in configuration.");
            ctx.set_service_state("mdns", ServiceState::Inactive);
            return Ok(());
        }

        let (tx, rx) = mpsc::channel(32);
        self.tx = tx.clone();

        if let Err(e) = run_mdns_worker(self.cfg.clone(), ctx.clone(), rx, tx).await {
            error!("mDNS worker fatal error: {e}");
            return Err(CoreError::Generic(e.to_string()));
        }
        Ok(())
    }
}

impl MdnsProber {
    /// Creates a new `MdnsProber`.
    #[must_use]
    pub fn new(cfg: MdnsConfig, ctx: LanforgeContext) -> Self {
        let (tx, _) = mpsc::channel(32);
        Self { cfg, tx, _ctx: ctx }
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
    cfg: MdnsConfig,
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

    let mut bus_rx = bus.subscribe_system();
    let mut probe_timer = tokio::time::interval(Duration::from_secs(cfg.probe_interval));

    if cfg.enabled {
        let _ = tx.try_send(MdnsCommand::ProbeAll);
    }

    loop {
        if !ctx.is_running() {
            break;
        }

        tokio::select! {
            res = bus_rx.recv() => {
                match res {
                    Ok(timed_event) => {
                        if matches!(timed_event.event, LanforgeEvent::System(SystemEvent::Shutdown)) {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(service = "mDNS", lost = n, "Event bus lagged");
                    }
                    Err(_) => break,
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
                handle_mdns_packet(&ctx, &data_vec, addr);
            }
            _ = probe_timer.tick() => {
                if cfg.enabled {
                    let _ = tx.try_send(MdnsCommand::ProbeAll);
                }
            }
        }
    }

    Ok(())
}

fn handle_command(cmd: &MdnsCommand, socket_v4: &UdpSocket, socket_v6: &UdpSocket) {
    match cmd {
        MdnsCommand::ProbeAll => {
            broadcast_query(socket_v4, socket_v6);
        }
        MdnsCommand::ProbeIp(ip) => {
            send_unicast_query(socket_v4, socket_v6, *ip);
        }
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

fn broadcast_query(sock4: &UdpSocket, sock6: &UdpSocket) {
    let mut msg = DnsMessage::new();
    msg.header.qdcount = 1;
    msg.questions.push(DnsQuestion {
        name: Arc::from("_services._dns-sd._udp.local"),
        qtype: DnsRecordType::PTR,
        qclass: DnsClass::IN,
    });

    let mut encoder = WireEncoder::new();
    let bytes = encoder.encode_message(&msg);

    let _ = sock4.send_to(&bytes, SocketAddr::new(IpAddr::V4(MDNS_IPV4), MDNS_PORT));
    let _ = sock6.send_to(&bytes, SocketAddr::new(IpAddr::V6(MDNS_IPV6), MDNS_PORT));

    debug!("mDNS broadcast probe sent");
}

fn send_unicast_query(sock4: &UdpSocket, sock6: &UdpSocket, target: IpAddr) {
    let mut msg = DnsMessage::new();
    msg.header.qdcount = 1;

    // Most devices respond to a PTR query for their own IP.
    // Example: 1.1.168.192.in-addr.arpa.
    let name = match target {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(v6) => {
            let mut name_str = String::new();
            for seg in v6.octets().iter().rev() {
                let _ = write!(name_str, "{:x}.{:x}.", seg & 0xf, seg >> 4);
            }
            name_str.push_str("ip6.arpa");
            name_str
        }
    };

    msg.questions.push(DnsQuestion {
        name: Arc::from(name),
        qtype: DnsRecordType::PTR,
        qclass: DnsClass::IN,
    });

    let mut encoder = WireEncoder::new();
    let bytes = encoder.encode_message(&msg);

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

    debug!("mDNS targeted probe sent to {}", target);
}

pub(crate) fn handle_mdns_packet(ctx: &LanforgeContext, data: &[u8], from: SocketAddr) {
    let mut decoder = WireDecoder::new(data);
    let Some(msg) = decoder.decode_message() else {
        return;
    };
    if !msg.header.qr {
        return;
    }

    // Passive Classification Mapping with zero allocations
    let classify = |name: &str| -> Option<DeviceClass> {
        fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
            haystack
                .as_bytes()
                .windows(needle.len())
                .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
        }

        if contains_ignore_ascii_case(name, "printer")
            || contains_ignore_ascii_case(name, "_ipp")
            || contains_ignore_ascii_case(name, "_pdl-datastream")
        {
            Some(DeviceClass::Printer)
        } else if contains_ignore_ascii_case(name, "_airplay")
            || contains_ignore_ascii_case(name, "_googlecast")
            || contains_ignore_ascii_case(name, "_spotify")
            || contains_ignore_ascii_case(name, "_raop")
        {
            Some(DeviceClass::Media)
        } else if contains_ignore_ascii_case(name, "_hap")
            || contains_ignore_ascii_case(name, "_miio")
            || contains_ignore_ascii_case(name, "_homekit")
        {
            Some(DeviceClass::IoT)
        } else if contains_ignore_ascii_case(name, "_ssh")
            || contains_ignore_ascii_case(name, "_smb")
            || contains_ignore_ascii_case(name, "_afp")
        {
            Some(DeviceClass::Computer)
        } else if contains_ignore_ascii_case(name, "_ubnt")
            || contains_ignore_ascii_case(name, "_unifi")
            || contains_ignore_ascii_case(name, "_mikrotik")
        {
            Some(DeviceClass::Network)
        } else {
            None
        }
    };

    let mac = ctx.get_mac_by_ip(from.ip());

    // 1. Classification pass: check both record name (e.g. "_ipp._tcp.local") and rdata
    for record in msg.answers.iter().chain(msg.additionals.iter()) {
        let rdata_str = match &record.rdata {
            DnsRData::PTR(name) => Some(name.as_ref()),
            DnsRData::SRV { target, .. } => Some(target.as_ref()),
            _ => None,
        };

        let class = classify(&record.name).or_else(|| rdata_str.and_then(classify));
        if let Some(class) = class
            && let Some(mac) = mac
        {
            let _ = ctx.apply(DeviceUpdate::ClassHint { mac, class });
        }
    }

    // 2. Hostname resolution pass: prioritize SRV records (authoritative host in DNS-SD) over PTR
    let mut srv_targets = Vec::new();
    let mut ptr_targets = Vec::new();

    for record in msg.answers.iter().chain(msg.additionals.iter()) {
        match &record.rdata {
            DnsRData::SRV { target, .. } => srv_targets.push(target.as_ref()),
            DnsRData::PTR(name) => ptr_targets.push(name.as_ref()),
            _ => {}
        }
    }

    let candidate_targets: Vec<&str> = if srv_targets.is_empty() {
        ptr_targets
    } else {
        srv_targets
    };

    for h in candidate_targets {
        let clean_host: &str = h.trim_end_matches('.').trim_end_matches(".local");
        if clean_host.is_empty() || clean_host.contains('.') {
            continue;
        }

        if let Some(mac) = mac {
            // If it doesn't have a hostname yet, apply mDNS hostname hint
            let has_hostname = ctx
                .get_device(&mac)
                .is_some_and(|dev| !dev.hostname.name.is_empty());
            if !has_hostname {
                debug!("mDNS discovery: {} -> {}", from.ip(), clean_host);
                let _ = ctx.apply(DeviceUpdate::MdnsHostnameHint {
                    mac,
                    hostname: clean_host.to_string(),
                });
            }
        }

        // Always register in transient hosts to allow immediate reverse PTR lookup
        // and automatic correlation if MAC is learned later.
        let _ = ctx.apply(DeviceUpdate::TransientHostResolved(Box::new(
            TransientHostUpdate {
                ip: from.ip(),
                hostname: Hostname::new(clean_host, HostnameOrigin::Mdns),
                origin: TransientOrigin::Mdns,
            },
        )));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_core::bus::EventBus;
    use lanforge_core::context::state::State;
    use lanforge_types::identifiers::MacAddr;
    use lanforge_types::network::DnsRecord;

    fn setup_test_context() -> LanforgeContext {
        let bus = Arc::new(EventBus::new());
        LanforgeContext::new(bus, State::new(), None)
    }

    fn build_mdns_response(records: Vec<DnsRecord>, additionals: Vec<DnsRecord>) -> Vec<u8> {
        let mut msg = DnsMessage::new();
        msg.header.qr = true;
        msg.header.ancount = u16::try_from(records.len()).unwrap_or_default();
        msg.header.arcount = u16::try_from(additionals.len()).unwrap_or_default();
        msg.answers = records;
        msg.additionals = additionals;

        let mut encoder = WireEncoder::new();
        encoder.encode_message(&msg)
    }

    #[test]
    fn test_mdns_parses_srv_and_ptr_responses() {
        let ctx = setup_test_context();
        let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let ip = Ipv4Addr::new(192, 168, 1, 50);

        // Pre-register device via ARP
        let _ = ctx.apply(DeviceUpdate::ArpSeen {
            mac,
            ip,
            is_active: true,
        });

        let answers = vec![DnsRecord {
            name: Arc::from("_ipp._tcp.local"),
            rtype: DnsRecordType::PTR,
            rclass: DnsClass::IN,
            ttl: 120,
            rdata: DnsRData::PTR(Arc::from("printer.local")),
        }];
        let additionals = vec![DnsRecord {
            name: Arc::from("printer.local"),
            rtype: DnsRecordType::SRV,
            rclass: DnsClass::IN,
            ttl: 120,
            rdata: DnsRData::SRV {
                priority: 0,
                weight: 0,
                port: 631,
                target: Arc::from("hp-laserjet.local."),
            },
        }];

        let bytes = build_mdns_response(answers, additionals);
        handle_mdns_packet(&ctx, &bytes, SocketAddr::new(IpAddr::V4(ip), 5353));

        let dev = ctx.get_device(&mac).expect("device should exist");
        assert_eq!(dev.hostname.name, "hp-laserjet");
        assert_eq!(dev.class, DeviceClass::Printer);

        let transient = ctx
            .get_transient_host(&IpAddr::V4(ip))
            .expect("transient host should exist");
        assert_eq!(transient.hostname.name, "hp-laserjet");
        assert_eq!(transient.origin, TransientOrigin::Mdns);
    }

    #[test]
    fn test_mdns_handles_unknown_mac_transient_fallback() {
        let ctx = setup_test_context();
        let ip = Ipv4Addr::new(192, 168, 1, 99);
        let mac = MacAddr([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x99]);

        // Device NOT yet registered in context (unknown MAC)
        assert!(ctx.get_mac_by_ip(IpAddr::V4(ip)).is_none());

        let answers = vec![DnsRecord {
            name: Arc::from("99.1.168.192.in-addr.arpa"),
            rtype: DnsRecordType::PTR,
            rclass: DnsClass::IN,
            ttl: 120,
            rdata: DnsRData::PTR(Arc::from("smart-tv.local.")),
        }];

        let bytes = build_mdns_response(answers, Vec::new());
        handle_mdns_packet(&ctx, &bytes, SocketAddr::new(IpAddr::V4(ip), 5353));

        // 1. Host should be saved in transient_hosts even without a known MAC
        let transient = ctx
            .get_transient_host(&IpAddr::V4(ip))
            .expect("transient host must exist");
        assert_eq!(transient.hostname.name, "smart-tv");
        assert_eq!(transient.origin, TransientOrigin::Mdns);

        // 2. When ARP is later observed, it should automatically adopt the transient mDNS hostname
        let _ = ctx.apply(DeviceUpdate::ArpSeen {
            mac,
            ip,
            is_active: true,
        });

        let dev = ctx
            .get_device(&mac)
            .expect("device should exist after ARP");
        assert_eq!(
            dev.hostname.name, "smart-tv",
            "device must adopt transient hostname upon ARP arrival"
        );
    }

    #[test]
    fn test_mdns_ignores_queries_and_malformed_packets() {
        let ctx = setup_test_context();
        let ip = Ipv4Addr::new(192, 168, 1, 10);

        // 1. Query packet (qr = false)
        let mut msg = DnsMessage::new();
        msg.header.qr = false;
        msg.answers.push(DnsRecord {
            name: Arc::from("_ipp._tcp.local"),
            rtype: DnsRecordType::PTR,
            rclass: DnsClass::IN,
            ttl: 120,
            rdata: DnsRData::PTR(Arc::from("printer.local")),
        });
        let mut encoder = WireEncoder::new();
        let query_bytes = encoder.encode_message(&msg);

        handle_mdns_packet(&ctx, &query_bytes, SocketAddr::new(IpAddr::V4(ip), 5353));
        assert!(ctx.get_transient_host(&IpAddr::V4(ip)).is_none());

        // 2. Truncated / corrupt bytes
        handle_mdns_packet(
            &ctx,
            &[0x00, 0x01, 0x02],
            SocketAddr::new(IpAddr::V4(ip), 5353),
        );
        assert!(ctx.get_transient_host(&IpAddr::V4(ip)).is_none());
    }

    #[test]
    fn test_mdns_cleans_local_domain_suffix() {
        let ctx = setup_test_context();
        let mac = MacAddr([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
        let ip = Ipv4Addr::new(192, 168, 1, 42);

        let _ = ctx.apply(DeviceUpdate::ArpSeen {
            mac,
            ip,
            is_active: true,
        });

        // Test with trailing dot and .local
        let answers = vec![DnsRecord {
            name: Arc::from("42.1.168.192.in-addr.arpa"),
            rtype: DnsRecordType::PTR,
            rclass: DnsClass::IN,
            ttl: 120,
            rdata: DnsRData::PTR(Arc::from("my-nas.local.")),
        }];

        let bytes = build_mdns_response(answers, Vec::new());
        handle_mdns_packet(&ctx, &bytes, SocketAddr::new(IpAddr::V4(ip), 5353));

        let dev = ctx.get_device(&mac).unwrap();
        assert_eq!(dev.hostname.name, "my-nas");
    }

    #[test]
    fn test_mdns_classification_mapping() {
        let test_cases = [
            ("_ipp._tcp.local", DeviceClass::Printer),
            ("_spotify-connect._tcp.local", DeviceClass::Media),
            ("_googlecast._tcp.local", DeviceClass::Media),
            ("_homekit._tcp.local", DeviceClass::IoT),
            ("_ssh._tcp.local", DeviceClass::Computer),
            ("_unifi._tcp.local", DeviceClass::Network),
        ];

        for (service_name, expected_class) in test_cases {
            let ctx = setup_test_context();
            let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11]);
            let ip = Ipv4Addr::new(192, 168, 1, 77);

            let _ = ctx.apply(DeviceUpdate::ArpSeen {
                mac,
                ip,
                is_active: true,
            });

            let answers = vec![DnsRecord {
                name: Arc::from(service_name),
                rtype: DnsRecordType::PTR,
                rclass: DnsClass::IN,
                ttl: 120,
                rdata: DnsRData::PTR(Arc::from("device-name.local")),
            }];

            let bytes = build_mdns_response(answers, Vec::new());
            handle_mdns_packet(&ctx, &bytes, SocketAddr::new(IpAddr::V4(ip), 5353));

            let dev = ctx.get_device(&mac).unwrap();
            assert_eq!(
                dev.class, expected_class,
                "Service {service_name} should classify as {expected_class:?}"
            );
        }
    }
}
