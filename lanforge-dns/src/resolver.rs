use crate::error::DnsError;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use lanforge_core::device::{
    IPv6State, IpClassification, Ipv6AddrOrSuffix, Ipv6Prefix, classify_ip,
};
use lanforge_core::state::DeviceTable;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::config::DnsConfig;
use crate::response::ResponseBuilder;
use crate::utils::{combine_prefix_suffix, parse_arpa};
use lanforge_core::device::Device;

pub struct LocalResolver<'a> {
    cfg: &'a DnsConfig,
    table: &'a DeviceTable,
}

impl<'a> LocalResolver<'a> {
    pub fn new(cfg: &'a DnsConfig, table: &'a DeviceTable) -> Self {
        Self { cfg, table }
    }

    /// Resolves local A/AAAA/ANY queries.
    ///
    /// Returns a full DNS response (either NoError with records or NXDomain).
    pub fn resolve_ip(
        &self,
        query: &Message,
        hostname: &str,
        qtype: RecordType,
    ) -> Result<Vec<u8>, DnsError> {
        let rb = ResponseBuilder::new(query, self.cfg);

        if let Some(device) = self.table.get_by_hostname(hostname) {
            if let Some(records) = self.resolve_local_with_device(query, &device, qtype) {
                return rb.success(records);
            } else {
                // Host exists but has no records for the requested type (NODATA)
                return rb.empty_noerror();
            }
        }

        rb.nxdomain()
    }

    /// Resolves reverse DNS queries (PTR).
    pub fn resolve_ptr(&self, query: &Message, qname: &Name) -> Result<Option<Vec<u8>>, DnsError> {
        let rb = ResponseBuilder::new(query, self.cfg);

        let Some(target_ip) = parse_arpa(qname) else {
            return Ok(None);
        };

        let Some(device) = self.table.get_by_ip(&target_ip) else {
            return Ok(None);
        };

        let question = query.queries().first().unwrap();
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

        let record = Record::from_rdata(
            name,
            self.cfg.ttl,
            RData::PTR(hickory_proto::rr::rdata::PTR(ptr_name)),
        );

        Ok(Some(rb.success(vec![record])?))
    }

    /// Internal logic to collect all addresses from a device and convert them into DNS records.
    pub(crate) fn resolve_local_with_device(
        &self,
        _query: &Message,
        device: &Device,
        qtype: RecordType,
    ) -> Option<Vec<Record>> {
        let question = _query.queries().first().expect("Query validada");
        let name = question.name().clone();
        let mut records: Vec<Record> = Vec::new();

        if !matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
            return None;
        }

        let mut applied_prefixes = HashSet::<Ipv6Prefix>::new();
        if let Some(ula) = self.cfg.ula_prefix {
            applied_prefixes.insert(Ipv6Prefix::new(ula, IpClassification::Ula));
        }

        // 1. Collect all known absolute address prefixes (Slaac, Dynamic, and Full Static)
        // to ensure we return them and potentially apply suffixes to them if needed.
        for state in &device.v6 {
            if let Some(ip) = state.ip() {
                applied_prefixes.insert(Ipv6Prefix::from_addr(ip));
            }
        }

        // 2. Collect all potential IPs.
        let mut all_ips = Vec::new();

        // IPv4
        if let Some(ip) = device.v4.ip() {
            all_ips.push(IpAddr::V4(ip));
        }
        for ip in &device.seen_v4 {
            all_ips.push(IpAddr::V4(*ip));
        }

        // IPv6
        for state in &device.v6 {
            match state {
                IPv6State::Dynamic(lease) => all_ips.push(IpAddr::V6(lease.ip)),
                IPv6State::Slaac(ip) => all_ips.push(IpAddr::V6(*ip)),
                IPv6State::Static(suf) => match suf {
                    Ipv6AddrOrSuffix::Full(ip) => all_ips.push(IpAddr::V6(*ip)),
                    Ipv6AddrOrSuffix::Suffix(_) => {
                        for prefix in &applied_prefixes {
                            // Apply custom suffixes to both ULA and GUA prefixes.
                            // This mirrors OpenWrt's behavior, ensuring local devices can resolve GUAs
                            // generated from standard SLAAC or DHCPv6 prefixes.
                            if matches!(prefix.group, IpClassification::Ula | IpClassification::Gua)
                                && let Some(ip) = combine_prefix_suffix(&prefix.segments, suf)
                            {
                                all_ips.push(IpAddr::V6(ip));
                            }
                        }
                    }
                },
            }
        }

        // 3. De-duplicate and Sort by Priority (ULA > IPv4 > GUA).
        let mut unique = HashSet::new();
        all_ips.retain(|ip| unique.insert(*ip));
        all_ips.sort_by_cached_key(|ip| classify_ip(ip).score());

        // 4. Filter by the requested qtype and convert to Record objects.
        for ip in all_ips {
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
}
