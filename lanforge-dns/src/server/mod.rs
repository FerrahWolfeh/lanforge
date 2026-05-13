pub mod service;
pub mod transport;
pub mod worker;

use crate::config::DnsConfig;
use crate::pipeline::Pipeline;
use crate::resolver::{LocalResolver, filter::AdBlocker, recursive::UpstreamStrategy};
use crate::telemetry::{DnsStats, QueryRing};
use lanforge_core::bus::{DnsEvent, LanforgeEvent};
use lanforge_core::types::{DnsRecordType, MacAddr, QueryLogEntry, QueryResult};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Shared, immutable service state for the DNS hot path.
pub struct DnsContext {
    pub cfg: Arc<DnsConfig>,
    pub stats: Arc<DnsStats>,
    pub bus: Arc<lanforge_core::bus::EventBus>,
    pub query_log: Option<Arc<QueryRing>>,
    pub pipeline: Pipeline,

    // Sub-components
    pub local: LocalResolver,
    pub recursive: Arc<UpstreamStrategy>,
    pub cache: Arc<crate::resolver::recursive::DnsCache>,
    pub filter: Option<Arc<AdBlocker>>,

    // Pre-computed SOA names
    pub soa_zone: Arc<str>,
    pub soa_master_ns: Arc<str>,
    pub soa_mailbox: Arc<str>,
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
}

impl DnsContext {
    pub fn record_log(&self, event: DnsLogEvent) {
        // Noise filtering
        if event.domain.is_empty() || event.domain.as_ref() == "." || event.domain.as_ref() == ":0"
        {
            return;
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
            };
            log.push(entry.clone());

            let _ = self
                .bus
                .publish(LanforgeEvent::Dns(DnsEvent::QueryResolved(entry)));
        }
    }
}
