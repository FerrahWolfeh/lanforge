use std::net::IpAddr;
use std::str::FromStr;

use crate::config::DnsConfig;
use crate::error::DnsError;
use crate::response::ResponseBuilder;
use crate::utils::parse_arpa;
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::PTR;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use lanforge_core::context::LanforgeContext;
use lanforge_core::device::Device;

pub struct LocalResolver<'a> {
    cfg: &'a DnsConfig,
    ctx: LanforgeContext,
}

impl<'a> LocalResolver<'a> {
    #[must_use]
    pub const fn new(cfg: &'a DnsConfig, ctx: LanforgeContext) -> Self {
        Self { cfg, ctx }
    }

    /// Resolves local A/AAAA/ANY queries.
    ///
    /// Returns a full DNS response (either `NoError` with records or `NXDomain`).
    pub fn resolve_ip(
        &self,
        query: &Message,
        hostname: &str,
        qtype: RecordType,
    ) -> Result<Vec<u8>, DnsError> {
        let rb = ResponseBuilder::new(query, self.cfg);

        if let Some(device) = self.ctx.get_by_hostname(hostname) {
            if let Some(records) = self.resolve_local(query, &device, qtype) {
                return rb.success(records);
            }
            // Host exists but has no records for the requested type (NODATA)
            return rb.empty_noerror();
        }

        rb.nxdomain()
    }

    /// Resolves reverse DNS queries (PTR).
    pub fn resolve_ptr(&self, query: &Message, qname: &Name) -> Result<Option<Vec<u8>>, DnsError> {
        let rb = ResponseBuilder::new(query, self.cfg);

        let Some(target_ip) = parse_arpa(qname) else {
            return Ok(None);
        };

        let Some(device) = self.ctx.get_by_ip(&target_ip) else {
            return Ok(None);
        };

        let question = query.queries().first().ok_or(DnsError::WireParseError)?;
        let name = question.name().clone();

        let host = if device.hostname.name.is_empty() {
            format!("host-{}", device.mac.to_string().replace(':', ""))
        } else {
            device
                .hostname
                .name
                .replace(|c: char| !c.is_ascii_alphanumeric() && c != '-', "-")
        };

        let fqdn = format!("{}.{}.", host, self.cfg.search_domain);
        let ptr_name = Name::from_str(&fqdn).unwrap_or_else(|_| Name::root());

        let record = Record::from_rdata(name, self.cfg.ttl, RData::PTR(PTR(ptr_name)));

        Ok(Some(rb.success(vec![record])?))
    }

    /// Internal logic to collect all addresses from a device and convert them into DNS records.
    #[must_use]
    pub fn resolve_local(
        &self,
        query: &Message,
        device: &Device,
        qtype: RecordType,
    ) -> Option<Vec<Record>> {
        use hickory_proto::rr::{RData, Record, RecordType};

        let question = query.queries().first()?;
        let name = question.name().clone();

        if !matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
            return None;
        }

        let ips = self.collect_device_ips(device);
        let mut records = Vec::new();

        for ip in ips {
            match ip {
                IpAddr::V4(v4) if matches!(qtype, RecordType::A | RecordType::ANY) => {
                    records.push(Record::from_rdata(
                        name.clone(),
                        self.cfg.ttl,
                        RData::A(v4.into()),
                    ));
                }
                IpAddr::V6(v6) if matches!(qtype, RecordType::AAAA | RecordType::ANY) => {
                    records.push(Record::from_rdata(
                        name.clone(),
                        self.cfg.ttl,
                        RData::AAAA(v6.into()),
                    ));
                }
                _ => {}
            }
        }

        if records.is_empty() {
            None
        } else {
            Some(records)
        }
    }

    /// Aggregates all IPs for a device (ULA, GUA, IPv4) and sorts them by priority.
    /// Data is tidied up in memory before being returned for DNS record generation.
    #[must_use]
    pub fn collect_device_ips(&self, device: &Device) -> Vec<IpAddr> {
        let (sys_gua, sys_ula) = self
            .ctx
            .target_ifindex()
            .map_or((None, None), |idx| self.ctx.get_interface_prefixes_opt(idx));

        // Fallback to configured prefixes if system hasn't learned them yet (useful for tests)
        let gua = sys_gua.or(self.cfg.gua_prefix);
        let ula = sys_ula.or(self.cfg.ula_prefix);

        // Use the core method which already handles sorting, deduplication and suffix resolution
        device.all_addresses_sorted(gua, ula)
    }
}
