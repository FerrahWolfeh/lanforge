#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_dns::config::DnsConfig;
use lanforge_dns::error::DnsError;
use lanforge_dns::pipeline::{DnsPipelineRequest, Pipeline, middleware::*};
#[cfg(feature = "adblock")]
use lanforge_dns::resolver::AdBlocker;
use lanforge_dns::resolver::LocalResolver;
use lanforge_dns::resolver::RewriteStore;
use lanforge_dns::resolver::recursive::DnsCache;
use lanforge_dns::resolver::recursive::UpstreamStrategy;
use lanforge_dns::server::{CompiledIgnoreClients, DnsContext};
use lanforge_dns::telemetry::QueryRing;
use lanforge_dns::telemetry::stats::DnsStats;
use lanforge_dns_wire::{WireDecoder, WireEncoder, WireHeader, WireQuestion};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecord, DnsRecordType, DnsResponseCode,
    TransportProtocol,
};
use lanforge_types::system::ServiceState;
use lanforge_types::update::DeviceUpdate;
use parking_lot::{Mutex, RwLock};
use tokio::net::UdpSocket;

/// Initializes a fresh isolated `LanforgeContext` for integration testing.
#[must_use]
pub fn init_test_context() -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    LanforgeContext::new(bus, table, None)
}

/// Cooperatively polls a service until its registered state is `ServiceState::Online`.
///
/// Times out after 2 seconds to avoid test hangs.
pub async fn wait_for_service_online(
    ctx: &LanforgeContext,
    service: lanforge_types::system::ServiceId,
) {
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        if ctx.get_service_state(service) == ServiceState::Online {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("Service '{service:?}' did not reach Online state within 2 seconds");
}

#[must_use]
pub fn mock_config() -> DnsConfig {
    DnsConfig {
        search_domains: vec!["lan".to_string()],
        multi_search_labels: vec![vec![b"lan".to_vec()]],
        ..Default::default()
    }
}

pub async fn mock_dns_context(ctx: LanforgeContext, cfg: DnsConfig) -> DnsContext {
    let domain_base = cfg
        .search_domains
        .first()
        .map_or_else(|| "lan".to_string(), Clone::clone);

    let soa_zone: Arc<str> = Arc::from(domain_base.as_str());
    let soa_master_ns: Arc<str> = Arc::from(format!("ns.{domain_base}"));
    let soa_mailbox: Arc<str> = Arc::from(format!("hostmaster.{domain_base}"));

    let cfg_arc = Arc::new(cfg);
    let cache = Arc::new(DnsCache::new(cfg_arc.cache_size, 30, None));
    let recursive = Arc::new(UpstreamStrategy::new(cfg_arc.upstream_mode, Vec::new()));

    let rewrites = Arc::new(RewriteStore::new());
    if !cfg_arc.rewrites.is_empty() {
        rewrites.replace_rules(cfg_arc.rewrites.clone());
    }

    #[cfg(feature = "adblock")]
    let filter = {
        let adblocker = AdBlocker::new(cfg_arc.adblock_enabled);
        adblocker.replace_config(
            cfg_arc.blocking_mode,
            cfg_arc.blocking_ip_v4,
            cfg_arc.blocking_ip_v6,
        );
        Some(Arc::new(adblocker))
    };

    let mut pipeline = Pipeline::new();
    pipeline.push(RewriteMiddleware::new());
    pipeline.push(LocalResolverMiddleware::new());
    #[cfg(feature = "adblock")]
    pipeline.push(AdblockMiddleware::new());
    pipeline.push(CacheMiddleware::new());
    pipeline.push(UpstreamMiddleware::new());

    DnsContext {
        cfg: cfg_arc.clone(),
        stats: Arc::new(DnsStats::new()),
        bus: ctx.bus(),
        ctx: ctx.clone(),
        query_log: Some(Arc::new(QueryRing::new(100))),
        pipeline,
        local: LocalResolver::new(cfg_arc.clone(), ctx),
        recursive,
        cache,
        rewrites,
        #[cfg(feature = "adblock")]
        filter,
        soa_zone,
        soa_master_ns,
        soa_mailbox,
        reverse_managers: Arc::new(RwLock::new(HashMap::new())),
        resolving_ips: Arc::new(Mutex::new(HashSet::new())),
        compiled_ignore_clients: CompiledIgnoreClients::compile(&cfg_arc.query_log.ignore_clients),
    }
}

pub fn register_test_device(ctx: &LanforgeContext, hostname: &str, mac: MacAddr, ip: Ipv4Addr) {
    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac,
        ip,
        expires: SystemTime::now() + Duration::from_secs(3600),
    });
    if !hostname.is_empty() {
        let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
            mac,
            hostname: hostname.to_string(),
        });
    }
}

pub async fn process_query_test(
    data: &[u8],
    ctx: &DnsContext,
    src_ip: IpAddr,
    resp: &mut Vec<u8>,
) -> Result<bool, DnsError> {
    let header = WireHeader::parse(data).ok_or(DnsError::WireParseError)?;
    let question = WireQuestion::parse(data).ok_or(DnsError::WireParseError)?;
    ctx.pipeline
        .run(
            ctx,
            DnsPipelineRequest::new(data, &header, &question, src_ip, TransportProtocol::Udp),
            resp,
        )
        .await?;
    Ok(!resp.is_empty())
}

/// Fluent builder for constructing synthetic DNS queries and messages.
#[derive(Debug, Clone)]
pub struct DnsPacketBuilder {
    id: u16,
    recursion_desired: bool,
    questions: Vec<DnsQuestion>,
}

impl DnsPacketBuilder {
    /// Creates a query for a specified domain name and record type.
    #[must_use]
    pub fn query(name: &str, qtype: DnsRecordType) -> Self {
        Self {
            id: 0x1234,
            recursion_desired: true,
            questions: vec![DnsQuestion {
                name: Arc::from(name),
                qtype,
                qclass: DnsClass::IN,
            }],
        }
    }

    /// Creates a reverse PTR query for a given IPv4 or IPv6 address.
    #[must_use]
    pub fn query_ptr(ip: IpAddr) -> Self {
        let ptr_name = match ip {
            IpAddr::V4(v4) => {
                let oct = v4.octets();
                format!("{}.{}.{}.{}.in-addr.arpa", oct[3], oct[2], oct[1], oct[0])
            }
            IpAddr::V6(v6) => {
                let mut s = String::new();
                for seg in v6.octets().iter().rev() {
                    s.push_str(&format!("{:x}.{:x}.", seg & 0x0f, seg >> 4));
                }
                s.push_str("ip6.arpa");
                s
            }
        };
        Self::query(&ptr_name, DnsRecordType::PTR)
    }

    /// Sets the 16-bit DNS transaction ID.
    #[must_use]
    pub const fn with_id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    /// Sets the Recursion Desired (RD) flag.
    #[must_use]
    pub const fn with_rd(mut self, rd: bool) -> Self {
        self.recursion_desired = rd;
        self
    }

    /// Appends an additional question to the query.
    #[must_use]
    pub fn add_question(mut self, name: &str, qtype: DnsRecordType) -> Self {
        self.questions.push(DnsQuestion {
            name: Arc::from(name),
            qtype,
            qclass: DnsClass::IN,
        });
        self
    }

    /// Compiles the structured `DnsMessage`.
    #[must_use]
    pub fn build_message(&self) -> DnsMessage {
        let mut msg = DnsMessage::new();
        msg.header.id = self.id;
        msg.header.rd = self.recursion_desired;
        msg.header.qdcount = self.questions.len() as u16;
        msg.questions = self.questions.clone();
        msg
    }

    /// Encodes the message to wire bytes using `WireEncoder`.
    #[must_use]
    pub fn build_bytes(&self) -> Vec<u8> {
        let msg = self.build_message();
        let mut encoder = WireEncoder::new();
        encoder.encode_message(&msg)
    }
}

/// Decodes raw wire bytes into a `DnsMessage`.
#[must_use]
pub fn parse_response(buf: &[u8]) -> Option<DnsMessage> {
    let mut decoder = WireDecoder::new(buf);
    decoder.decode_message()
}

/// Extracts all IPv4 addresses from A records in the answer section.
#[must_use]
pub fn extract_a(msg: &DnsMessage) -> Vec<Ipv4Addr> {
    msg.answers
        .iter()
        .filter_map(|ans| {
            if let DnsRData::A(ip) = ans.rdata {
                Some(ip)
            } else {
                None
            }
        })
        .collect()
}

/// Extracts all IPv6 addresses from AAAA records in the answer section.
#[must_use]
pub fn extract_aaaa(msg: &DnsMessage) -> Vec<Ipv6Addr> {
    msg.answers
        .iter()
        .filter_map(|ans| {
            if let DnsRData::AAAA(ip) = ans.rdata {
                Some(ip)
            } else {
                None
            }
        })
        .collect()
}

/// Extracts all domain names from PTR records in the answer section.
#[must_use]
pub fn extract_ptr(msg: &DnsMessage) -> Vec<String> {
    msg.answers
        .iter()
        .filter_map(|ans| {
            if let DnsRData::PTR(ref name) = ans.rdata {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Ephemeral local UDP DNS server for testing upstream forwarding without internet access.
pub struct MockUpstreamServer {
    /// Socket address the mock upstream is bound to (on `127.0.0.1:0`).
    pub addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl MockUpstreamServer {
    /// Spawns a mock upstream server responding to queries according to a record mapping.
    pub async fn spawn(records: HashMap<String, Vec<IpAddr>>) -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind mock upstream socket");
        let addr = sock.local_addr().expect("Failed to query local address");
        let records = Arc::new(records);

        let task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok((n, client_addr)) = sock.recv_from(&mut buf).await {
                let mut decoder = WireDecoder::new(&buf[..n]);
                if let Some(req) = decoder.decode_message() {
                    let mut resp = DnsMessage::new();
                    resp.header.id = req.header.id;
                    resp.header.qr = true;
                    resp.header.rd = req.header.rd;
                    resp.header.ra = true;
                    resp.header.qdcount = req.questions.len() as u16;
                    resp.questions = req.questions.clone();

                    let mut matched = false;
                    for q in &req.questions {
                        let qname = q.name.trim_end_matches('.');
                        if let Some(ips) = records.get(qname) {
                            matched = true;
                            for ip in ips {
                                match ip {
                                    IpAddr::V4(v4) => {
                                        if q.qtype == DnsRecordType::A {
                                            resp.answers.push(DnsRecord {
                                                name: q.name.clone(),
                                                rtype: DnsRecordType::A,
                                                rclass: DnsClass::IN,
                                                ttl: 300,
                                                rdata: DnsRData::A(*v4),
                                            });
                                        }
                                    }
                                    IpAddr::V6(v6) => {
                                        if q.qtype == DnsRecordType::AAAA {
                                            resp.answers.push(DnsRecord {
                                                name: q.name.clone(),
                                                rtype: DnsRecordType::AAAA,
                                                rclass: DnsClass::IN,
                                                ttl: 300,
                                                rdata: DnsRData::AAAA(*v6),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if !matched {
                        resp.header.rcode = DnsResponseCode::NXDomain;
                    }

                    resp.header.ancount = resp.answers.len() as u16;
                    let mut encoder = WireEncoder::new();
                    let resp_bytes = encoder.encode_message(&resp);
                    let _ = sock.send_to(&resp_bytes, client_addr).await;
                }
            }
        });

        Self { addr, task }
    }

    /// Generates an `UpstreamTarget` URI referencing this mock server.
    #[must_use]
    pub fn target(&self) -> UpstreamTarget {
        format!("udp://{}", self.addr)
            .parse()
            .expect("Failed to parse mock upstream target")
    }
}

impl Drop for MockUpstreamServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
