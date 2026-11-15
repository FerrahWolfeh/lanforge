//! mDNS (Multicast DNS) prober for hostname discovery.
//!
//! Listens to mDNS answers on the LAN and applies the hostnames and service types they carry to
//! the `LanforgeContext` (`DeviceUpdate::MdnsHostnameHint`, `ClassHint`).
//!
//! ## Protocol
//!
//! - Listens on `224.0.0.251:5353` and `[ff02::fb]:5353`, on the LAN interface only.
//! - Periodically asks the DNS-SD meta-query `_services._dns-sd._udp.local.` PTR (RFC 6763 §9):
//!   each responder lists its service types, which classify the device.
//! - Asks each device that has no name for the name of its address (reverse PTR such as
//!   `31.3.168.192.in-addr.arpa.`, RFC 6762 §4) when it shows up, then again after 1 min,
//!   10 min, and hourly while it stays unnamed and online.
//!
//! ## Design
//!
//! One [`UdpTransport`] bound to the LAN (`bind_link_multicast`), owned by `serve`: it closes when
//! `serve` returns, so a restart never leaves a listener behind. The service waits for the LAN
//! link (`lan_link_wait`) and is started again when it comes back.
//!
//! ## Failure Handling
//!
//! Failures are retried by the supervisor with backoff; they never halt the daemon.

use lanforge_types::config::ConfigDomain;
use lanforge_types::device::{Device, DeviceClass, DeviceStatus, IPv6State, TransientOrigin};
use lanforge_types::events::DeviceEvent;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::{
    DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecordType, Hostname, HostnameOrigin,
};
use lanforge_types::system::{DormantReason, ServiceId};
use lanforge_types::update::{DeviceUpdate, TransientHostUpdate};
use serde::{Deserialize, Serialize};

use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    Activation, AsyncService, Condition, Edge, LanforgeService, LossPolicy, RestartPolicy,
    RuntimeClass, ServiceCommand, ServiceHandle, ServiceSpec,
};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::fmt::Write;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{Instant, interval_at, sleep_until};
use tracing::{debug, info};

use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_transport::UdpTransport;

const MDNS_PORT: u16 = 5353;
const MDNS_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_IPV6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
/// RFC 6762 §17: an mDNS message fits 9000 bytes.
const MDNS_MAX_MESSAGE: usize = 9000;

/// Wait before the first reverse query: a device just seen may still be configuring its address.
const FIRST_PROBE_DELAY: Duration = Duration::from_secs(2);
/// Waits after the 1st, 2nd and later reverse queries to a device that stays unnamed (RFC 6762
/// §5.2: growing intervals, at most hourly).
const PROBE_BACKOFF: [Duration; 3] = [
    Duration::from_mins(1),
    Duration::from_mins(10),
    Duration::from_hours(1),
];

const MDNS_DEPS: &[Edge] = &[Edge::requires(ServiceId::Interfaces, LossPolicy::Continue)];

/// Configuration for the mDNS prober.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// mDNS hostname prober for IPv4 and IPv6 on the LAN.
pub struct MdnsProber {
    cfg: MdnsConfig,
    /// Injected by tests; otherwise each `serve` binds its own on the LAN.
    transport: Option<UdpTransport>,
}

impl MdnsProber {
    /// Static identifier for the service.
    pub const SERVICE_ID: ServiceId = ServiceId::Mdns;

    /// Creates a prober that binds the LAN interface when it serves.
    #[must_use]
    pub const fn new(cfg: MdnsConfig) -> Self {
        Self {
            cfg,
            transport: None,
        }
    }

    /// Creates a prober serving on `transport` (an inert one in tests).
    #[must_use]
    pub const fn with_transport(cfg: MdnsConfig, transport: UdpTransport) -> Self {
        Self {
            cfg,
            transport: Some(transport),
        }
    }
}

impl LanforgeService for MdnsProber {
    fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: Self::SERVICE_ID,
            display_name: "mDNS Prober",
            runtime: RuntimeClass::Shared,
            restart: RestartPolicy {
                base_backoff: Duration::from_secs(2),
                max_backoff: Duration::from_secs(30),
                max_retries: 0,
                healthy_uptime: Duration::from_secs(30),
            },
            shutdown_timeout: Duration::from_secs(3),
            deps: MDNS_DEPS,
            condition: Condition {
                sections: &[ConfigDomain::Interfaces],
                eval: |ctx| {
                    ctx.lan_link_wait()
                        .map_or(Activation::Active, Activation::Dormant)
                },
            },
        }
    }
}

impl AsyncService for MdnsProber {
    async fn serve(&mut self, ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        if !self.cfg.enabled {
            info!("mDNS prober is disabled in configuration.");
            h.dormant(DormantReason::disabled("mdns.enabled"));
            return Ok(());
        }

        let transport = if let Some(t) = &self.transport {
            t.clone()
        } else {
            let Some(iface) = ctx.target_interface_name() else {
                h.dormant(DormantReason::not_applicable("no LAN interface"));
                return Ok(());
            };
            UdpTransport::bind_link_multicast(&iface, MDNS_IPV4, MDNS_IPV6, MDNS_PORT)?
        };
        ctx.set_service_transports(ServiceId::Mdns, vec![transport.metrics_handle()]);

        // Subscribe first, then seed from the state: devices known before the subscription
        // produce no event.
        let mut devices = ctx.service_handle_device();
        let mut probes = NameProbes::default();
        probes.seed(ctx, Instant::now());

        let period = Duration::from_secs(self.cfg.probe_interval.max(60));
        let mut meta_timer = interval_at(Instant::now() + period, period);
        send_meta_query(&transport).await;
        h.ready();

        let mut buf = vec![0u8; MDNS_MAX_MESSAGE];
        loop {
            let next_probe = probes.next_due();
            tokio::select! {
                cmd = h.next_command() => match cmd {
                    ServiceCommand::Stop | ServiceCommand::Shutdown => break,
                    ServiceCommand::Restart => {
                        h.request_restart();
                        break;
                    }
                    _ => {}
                },
                res = transport.recv(&mut buf) => match res {
                    Ok((n, from)) => handle_mdns_packet(ctx, &buf[..n], from),
                    // The inert channel closed: nothing will ever arrive again.
                    Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                    // Counted by the transport (socket health); the next datagram may be fine.
                    Err(e) => debug!("mDNS receive error: {e}"),
                },
                _ = meta_timer.tick() => send_meta_query(&transport).await,
                event = devices.next_event() => {
                    let Some(timed) = event else { break };
                    if let LanforgeEvent::Device(event) = &timed.event {
                        probes.on_event(event, Instant::now());
                    }
                }
                () = sleep_until(next_probe.unwrap_or_else(Instant::now)), if next_probe.is_some() => {
                    for ip in probes.take_due(ctx, Instant::now()) {
                        send_reverse_query(&transport, ip).await;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Multicasts `question` (QM) to the group of `family`'s address family.
async fn send_question(transport: &UdpTransport, question: DnsQuestion, family: IpAddr) {
    let mut msg = DnsMessage::new();
    msg.header.qdcount = 1;
    msg.questions.push(question);
    let bytes = WireEncoder::new().encode_message(&msg);
    let group = match family {
        IpAddr::V4(_) => SocketAddr::from((MDNS_IPV4, MDNS_PORT)),
        IpAddr::V6(_) => SocketAddr::from((MDNS_IPV6, MDNS_PORT)),
    };
    // Counted by the transport; an unreachable family (no IPv6 on the LAN) is not fatal.
    if let Err(e) = transport.send(&bytes, &group).await {
        debug!("mDNS query to {group} not sent: {e}");
    }
}

/// The reverse name of `ip` (`d.c.b.a.in-addr.arpa`, nibbles under `ip6.arpa`).
fn reverse_name(ip: IpAddr) -> String {
    let mut name = String::with_capacity(72);
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            let _ = write!(name, "{d}.{c}.{b}.{a}.in-addr.arpa");
        }
        IpAddr::V6(v6) => {
            for byte in v6.octets().iter().rev() {
                let _ = write!(name, "{:x}.{:x}.", byte & 0xf, byte >> 4);
            }
            name.push_str("ip6.arpa");
        }
    }
    name
}

fn is_reverse_name(name: &str) -> bool {
    let name = name.trim_end_matches('.').as_bytes();
    name.len() >= 5 && name[name.len() - 5..].eq_ignore_ascii_case(b".arpa")
}

/// Whether the reverse name `name` is one of the sender's own addresses. A Bonjour Sleep Proxy
/// answers the reverse query of each sleeping host it stands in for, from its own address: such an
/// answer must not name the proxy.
fn reverse_names_sender(
    ctx: &LanforgeContext,
    name: &str,
    from: IpAddr,
    mac: Option<MacAddr>,
) -> bool {
    let name = name.trim_end_matches('.');
    let names = |ip: IpAddr| reverse_name(ip).eq_ignore_ascii_case(name);
    // An IPv6 answer comes from the link-local address: the name may be another of the sender's.
    names(from)
        || mac.is_some_and(|mac| {
            ctx.with_state(|s| {
                s.devices.get(&mac).is_some_and(|dev| {
                    dev.v4.ip().map(IpAddr::V4).is_some_and(names)
                        || dev
                            .v6
                            .iter()
                            .filter_map(IPv6State::ip)
                            .any(|ip| names(IpAddr::V6(ip)))
                })
            })
        })
}

/// Asks the owner of `ip` for its name (RFC 6762 §4: reverse address mapping).
async fn send_reverse_query(transport: &UdpTransport, ip: IpAddr) {
    let question = DnsQuestion {
        name: Arc::from(reverse_name(ip)),
        qtype: DnsRecordType::PTR,
        qclass: DnsClass::IN,
    };
    send_question(transport, question, ip).await;
    debug!("mDNS reverse query for {ip}");
}

/// When an unnamed device is next asked for its name.
struct Probe {
    due: Instant,
    sent: usize,
}

/// Devices without a name, and when each is asked next. A device leaves when it gets a name or
/// goes away.
#[derive(Default)]
struct NameProbes {
    pending: HashMap<MacAddr, Probe>,
}

impl NameProbes {
    fn seed(&mut self, ctx: &LanforgeContext, now: Instant) {
        ctx.with_state(|s| {
            for (mac, dev) in &s.devices {
                if dev.hostname.name.is_empty() {
                    self.schedule(*mac, now);
                }
            }
        });
    }

    fn schedule(&mut self, mac: MacAddr, now: Instant) {
        self.pending.entry(mac).or_insert(Probe {
            due: now + FIRST_PROBE_DELAY,
            sent: 0,
        });
    }

    fn on_event(&mut self, event: &DeviceEvent, now: Instant) {
        match event {
            DeviceEvent::Discovered { mac, hostname }
            | DeviceEvent::NetworkUpdate { mac, hostname, .. }
            | DeviceEvent::NetworkActivity { mac, hostname, .. }
            | DeviceEvent::AdminUpdate { mac, hostname, .. } => {
                if hostname.as_deref().is_some_and(|h| !h.is_empty()) {
                    self.pending.remove(mac);
                } else {
                    self.schedule(*mac, now);
                }
            }
            DeviceEvent::Expired { mac } | DeviceEvent::Purged { mac } => {
                self.pending.remove(mac);
            }
            _ => {}
        }
    }

    fn next_due(&self) -> Option<Instant> {
        self.pending.values().map(|p| p.due).min()
    }

    /// The addresses to ask now; reschedules them and drops devices named or gone since.
    fn take_due(&mut self, ctx: &LanforgeContext, now: Instant) -> SmallVec<[IpAddr; 4]> {
        let mut due = SmallVec::new();
        ctx.with_state(|s| {
            self.pending.retain(|mac, probe| {
                if probe.due > now {
                    return true;
                }
                let Some(dev) = s.devices.get(mac) else {
                    return false;
                };
                if !dev.hostname.name.is_empty() {
                    return false;
                }
                // An offline device or one without an address is looked at again soon, unasked.
                let mut wait = PROBE_BACKOFF[0];
                if dev.status != DeviceStatus::Offline
                    && let Some(ip) = probe_address(dev)
                {
                    due.push(ip);
                    wait = PROBE_BACKOFF[probe.sent.min(PROBE_BACKOFF.len() - 1)];
                    probe.sent += 1;
                }
                probe.due = now + wait;
                true
            });
        });
        due
    }
}

/// The address to ask a device's name by: its IPv4, else its first IPv6.
fn probe_address(dev: &Device) -> Option<IpAddr> {
    dev.v4
        .ip()
        .map(IpAddr::V4)
        .or_else(|| dev.v6.iter().find_map(IPv6State::ip).map(IpAddr::V6))
}

/// The DNS-SD meta-query (RFC 6763 §9): answers list each responder's service types.
async fn send_meta_query(transport: &UdpTransport) {
    for family in [IpAddr::V4(MDNS_IPV4), IpAddr::V6(MDNS_IPV6)] {
        let question = DnsQuestion {
            name: Arc::from("_services._dns-sd._udp.local"),
            qtype: DnsRecordType::PTR,
            qclass: DnsClass::IN,
        };
        send_question(transport, question, family).await;
    }
    debug!("mDNS service meta-query sent");
}

#[allow(clippy::too_many_lines)]
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
    let mut updates = SmallVec::<[DeviceUpdate; 4]>::new();

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
            updates.push(DeviceUpdate::ClassHint { mac, class });
        }
    }

    // 2. Hostname resolution pass: prioritize SRV records (authoritative host in DNS-SD) over PTR
    let mut srv_targets = SmallVec::<[&str; 8]>::new();
    let mut ptr_targets = SmallVec::<[&str; 8]>::new();

    for record in msg.answers.iter().chain(msg.additionals.iter()) {
        match &record.rdata {
            DnsRData::SRV { target, .. } => srv_targets.push(target.as_ref()),
            DnsRData::PTR(name) => {
                if is_reverse_name(&record.name)
                    && !reverse_names_sender(ctx, &record.name, from.ip(), mac)
                {
                    continue;
                }
                ptr_targets.push(name.as_ref());
            }
            _ => {}
        }
    }

    let candidate_targets: SmallVec<[&str; 8]> = if srv_targets.is_empty() {
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
            let has_hostname = ctx.with_state(|s| {
                s.devices
                    .get(&mac)
                    .is_some_and(|dev| !dev.hostname.name.is_empty())
            });
            if !has_hostname {
                debug!("mDNS discovery: {} -> {}", from.ip(), clean_host);
                updates.push(DeviceUpdate::MdnsHostnameHint {
                    mac,
                    hostname: clean_host.to_string(),
                });
            }
        }

        // Always register in transient hosts to allow immediate reverse PTR lookup
        // and automatic correlation if MAC is learned later.
        updates.push(DeviceUpdate::TransientHostResolved(Box::new(
            TransientHostUpdate {
                ip: from.ip(),
                hostname: Hostname::new(clean_host.to_string(), HostnameOrigin::Mdns),
                origin: TransientOrigin::Mdns,
            },
        )));
    }

    if !updates.is_empty() {
        let _ = ctx.apply_batch(updates);
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

        let dev = ctx.get_device(&mac).expect("device should exist after ARP");
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
