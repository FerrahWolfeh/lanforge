pub mod service;
pub mod transport;
pub mod worker;

use crate::config::DnsConfig;
use crate::pipeline::Pipeline;
#[cfg(feature = "adblock")]
use crate::resolver::AdBlocker;
use crate::resolver::recursive::UpstreamManager;
use crate::resolver::{LocalResolver, RewriteStore, recursive::UpstreamStrategy};
use crate::telemetry::{DnsStats, QueryRing};
use lanforge_core::bus::{DnsEvent, EventBus, LanforgeEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::upstream::UpstreamTarget;
use lanforge_types::network::dns::{
    DnsRecordType, FilterMatch, QueryLogEntry, QueryResult, TransportProtocol,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Shared, immutable service state for the DNS hot path.
pub struct DnsContext {
    pub cfg: Arc<DnsConfig>,
    pub stats: Arc<DnsStats>,
    pub bus: Arc<EventBus>,
    pub ctx: LanforgeContext,
    pub query_log: Option<Arc<QueryRing>>,
    pub pipeline: Pipeline,

    // Sub-components
    pub local: LocalResolver,
    pub recursive: Arc<UpstreamStrategy>,
    pub cache: Arc<crate::resolver::recursive::DnsCache>,
    pub rewrites: Arc<RewriteStore>,
    #[cfg(feature = "adblock")]
    pub filter: Option<Arc<AdBlocker>>,

    // Pre-computed SOA names
    pub soa_zone: Arc<str>,
    pub soa_master_ns: Arc<str>,
    pub soa_mailbox: Arc<str>,

    // Reverse DNS resolution managers and lock-free tracking
    pub reverse_managers: Arc<parking_lot::RwLock<HashMap<UpstreamTarget, Arc<UpstreamManager>>>>,
    pub resolving_ips: Arc<parking_lot::Mutex<HashSet<IpAddr>>>,

    // Pre-compiled query log client ignore filters
    pub compiled_ignore_clients: CompiledIgnoreClients,
}

/// Pre-compiled ignore filter to eliminate string parsing and allocations on the DNS logging hot-path.
#[derive(Debug, Clone, Default)]
pub struct CompiledIgnoreClients {
    pub ips: smallvec::SmallVec<[IpAddr; 4]>,
    pub macs: smallvec::SmallVec<[MacAddr; 4]>,
    pub hostnames: smallvec::SmallVec<[String; 4]>,
}

impl CompiledIgnoreClients {
    #[must_use]
    pub fn compile(raw: &[String]) -> Self {
        let mut ips = smallvec::SmallVec::new();
        let mut macs = smallvec::SmallVec::new();
        let mut hostnames = smallvec::SmallVec::new();
        for item in raw {
            if let Ok(ip) = item.parse::<IpAddr>() {
                ips.push(ip);
            } else if let Some(mac) = MacAddr::parse(item) {
                macs.push(mac);
            } else {
                hostnames.push(item.to_ascii_lowercase());
            }
        }
        Self {
            ips,
            macs,
            hostnames,
        }
    }

    #[inline]
    #[must_use]
    pub fn matches(&self, ip: IpAddr, mac: Option<MacAddr>, hostname: Option<&str>) -> bool {
        if self.ips.contains(&ip) {
            return true;
        }
        if let Some(m) = mac
            && self.macs.contains(&m)
        {
            return true;
        }
        if let Some(host) = hostname
            && self.hostnames.iter().any(|h| h.eq_ignore_ascii_case(host))
        {
            return true;
        }
        false
    }
}

pub struct DnsLogEvent<'a> {
    pub src_ip: IpAddr,
    pub src_mac: Option<MacAddr>,
    pub domain: &'a str,
    pub qtype: DnsRecordType,
    pub result: QueryResult,
    pub upstream_us: u32,
    pub cached: bool,
    pub answer: Option<String>,
    pub protocol: TransportProtocol,
    pub filter: Option<Box<FilterMatch>>,
    pub coalesce_id: Option<u64>,
}

/// Checks if a domain matches an exact or wildcard pattern (e.g. `*.sonarr.tv`) without heap allocation.
#[must_use]
pub fn matches_domain_pattern(domain: &str, pattern: &str) -> bool {
    let d = domain.trim_end_matches('.');
    let p = pattern.trim_end_matches('.');
    if let Some(suffix) = p.strip_prefix("*.") {
        if d.eq_ignore_ascii_case(suffix) {
            return true;
        }
        if d.len() > suffix.len()
            && d.as_bytes().get(d.len().saturating_sub(suffix.len() + 1)) == Some(&b'.')
            && d[d.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        {
            return true;
        }
        false
    } else {
        d.eq_ignore_ascii_case(p)
    }
}

impl DnsContext {
    pub fn record_log(&self, event: DnsLogEvent<'_>) {
        if self.query_log.is_none() {
            return;
        }

        // Noise filtering
        if event.domain.is_empty() || event.domain == "." || event.domain == ":0" {
            return;
        }

        // Check if device is configured to suppress DNS logging or matches ignore_clients (zero Device clones)
        let (mac, should_ignore) = self.ctx.with_state(|state| {
            let mac = event
                .src_mac
                .or_else(|| state.get_mac_by_ip(event.src_ip));
            let dev = mac.as_ref().and_then(|m| state.devices.get(m));

            if let Some(dev) = dev {
                if dev.ignore_dns_log {
                    return (mac, true);
                }
                if !dev.ignored_log_domains.is_empty() {
                    let domain = event.domain;
                    for pattern in &dev.ignored_log_domains {
                        if matches_domain_pattern(domain, pattern) {
                            return (mac, true);
                        }
                    }
                }
            }

            let hostname = dev.map(|d| d.hostname.name.as_str());
            if self
                .compiled_ignore_clients
                .matches(event.src_ip, mac, hostname)
            {
                return (mac, true);
            }

            (mac, false)
        });

        if should_ignore {
            return;
        }

        if let Some(log) = &self.query_log {
            let entry = QueryLogEntry {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                src_ip: event.src_ip,
                domain: Arc::from(event.domain),
                qtype: event.qtype,
                result: event.result,
                upstream_us: event.upstream_us,
                cached: event.cached,
                src_mac: mac,
                answer: event.answer,
                protocol: event.protocol,
                filter: event.filter,
                coalesce_id: event.coalesce_id,
            };
            log.push(entry.clone());

            let _ = self
                .bus
                .publish(LanforgeEvent::Dns(DnsEvent::QueryResolved(std::sync::Arc::new(entry))));
        }
    }
}
