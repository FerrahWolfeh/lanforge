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
}

pub struct DnsLogEvent {
    pub src_ip: IpAddr,
    pub src_mac: Option<MacAddr>,
    pub domain: Arc<str>,
    pub qtype: DnsRecordType,
    pub result: QueryResult,
    pub upstream_us: u32,
    pub cached: bool,
    pub answer: Option<String>,
    pub protocol: TransportProtocol,
    pub filter: Option<Box<FilterMatch>>,
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
    pub fn record_log(&self, event: DnsLogEvent) {
        if self.query_log.is_none() {
            return;
        }

        // Noise filtering
        if event.domain.is_empty() || event.domain.as_ref() == "." || event.domain.as_ref() == ":0"
        {
            return;
        }

        // Check if device is configured to suppress DNS logging
        let mac = event.src_mac.or_else(|| self.ctx.get_mac_by_ip(event.src_ip));
        if let Some(mac) = mac
            && let Some(dev) = self.ctx.get_device(&mac)
        {
            if dev.ignore_dns_log {
                return;
            }
            if !dev.ignored_log_domains.is_empty() {
                let domain = event.domain.as_ref();
                for pattern in &dev.ignored_log_domains {
                    if matches_domain_pattern(domain, pattern) {
                        return;
                    }
                }
            }
        }

        // Check ignore_clients in QueryLogConfig (by IP, MAC, or hostname)
        if !self.cfg.query_log.ignore_clients.is_empty() {
            let ip_str = event.src_ip.to_string();
            let mac_str = mac.map(|m| m.to_string());
            for ignored in &self.cfg.query_log.ignore_clients {
                if ignored.eq_ignore_ascii_case(&ip_str) {
                    return;
                }
                if let Some(ref m) = mac_str
                    && ignored.eq_ignore_ascii_case(m)
                {
                    return;
                }
                if let Some(dev) = mac.and_then(|m| self.ctx.get_device(&m))
                    && ignored.eq_ignore_ascii_case(&dev.hostname.name)
                {
                    return;
                }
            }
        }

        if let Some(log) = &self.query_log {
            let entry = QueryLogEntry {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                src_ip: event.src_ip,
                domain: event.domain,
                qtype: event.qtype,
                result: event.result,
                upstream_us: event.upstream_us,
                cached: event.cached,
                src_mac: event.src_mac,
                answer: event.answer,
                protocol: event.protocol,
                filter: event.filter,
            };
            log.push(entry.clone());

            let _ = self
                .bus
                .publish(LanforgeEvent::Dns(DnsEvent::QueryResolved(std::sync::Arc::new(entry))));
        }
    }
}
