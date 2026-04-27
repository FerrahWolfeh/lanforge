//! Local DNS resolver backed by the `LanforgeContext`.
//!
//! Resolves A, AAAA, ANY, and PTR queries by looking up devices in the
//! shared `LanforgeContext`. No network I/O is performed — all data comes
//! from the in-memory device state.

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

/// Resolves local DNS queries (A/AAAA/PTR) using the `LanforgeContext`.
///
/// This resolver performs authoritative resolution for hostnames in the
/// configured search domain. It aggregates all known IP addresses for a
/// device (IPv4, SLAAC, static V6 suffixes) into DNS records.
pub struct LocalResolver<'a> {
    cfg: &'a DnsConfig,
    ctx: LanforgeContext,
}

impl<'a> LocalResolver<'a> {
    /// Creates a new resolver bound to the given config and context.
    #[must_use]
    pub const fn new(cfg: &'a DnsConfig, ctx: LanforgeContext) -> Self {
        Self { cfg, ctx }
    }

    /// Resolves an A or AAAA query for the given hostname.
    ///
    /// Looks up the device by hostname and returns all matching IP records
    /// (A for IPv4, AAAA for IPv6). Returns a full DNS response with
    /// `NoError` (records or NODATA) or `NXDomain` if the host is unknown.
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

        // Phase 2: JIT Shadow Lookup (Trace Back)
        let threshold =
            std::time::Duration::from_secs(u64::from(self.cfg.last_seen_threshold_days) * 86400);
        if let Some(mac) = self.ctx.find_mac_by_hostname_jit(hostname, Some(threshold))
            && let Some(device) = self.ctx.get_device(&mac)
            && let Some(records) = self.resolve_local(query, &device, qtype)
        {
            return rb.success(records);
        }
        // Host promoted but has no records for the requested type
        rb.nxdomain()
    }

    /// Resolves a reverse DNS (PTR) query for an IP address.
    ///
    /// Parses the ARPA-formatted query name (e.g., `4.3.2.1.in-addr.arpa.`
    /// or `b.a.9.8...ip6.arpa.`), looks up the owning device, and returns
    /// a PTR record pointing to the device's hostname.
    ///
    /// Returns `Ok(None)` if the IP is not in the ARPA format or not found
    /// in the context.
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

    /// Collects all IP addresses for a device and converts them to DNS records.
    ///
    /// Returns `None` if no addresses match the requested query type.
    #[must_use]
    pub fn resolve_local(
        &self,
        query: &Message,
        device: &Device,
        qtype: RecordType,
    ) -> Option<Vec<Record>> {
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

    /// Collects and sorts all IP addresses for a device.
    ///
    /// Aggregates addresses from:
    /// 1. Static IPv4/V6 reservations
    /// 2. Dynamic DHCP leases
    /// 3. SLAAC-observed addresses
    /// 4. V6 suffixes combined with learned prefixes
    ///
    /// Results are sorted by priority (ULA first, then GUA, then IPv4)
    /// and deduplicated. Falls back to configured prefixes if the system
    /// hasn't learned interface prefixes yet (useful for tests).
    #[must_use]
    pub fn collect_device_ips(&self, device: &Device) -> Vec<IpAddr> {
        let (sys_gua, sys_ula) = self
            .ctx
            .target_ifindex()
            .map_or((None, None), |idx| self.ctx.get_interface_prefixes_opt(idx));

        // Fallback to configured prefixes if system hasn't learned them yet
        let gua = sys_gua.or(self.cfg.gua_prefix);
        let ula = sys_ula.or(self.cfg.ula_prefix);

        device.all_addresses_sorted(gua, ula)
    }
}
