//! Local DNS resolver backed by the `LanforgeContext`.
//!
//! Resolves A, AAAA, ANY, and PTR queries by looking up devices in the
//! shared `LanforgeContext`. No network I/O is performed — all data comes
//! from the in-memory device state.

use lanforge_core::types::Device;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::net::IpAddr;

use crate::config::DnsConfig;
use crate::error::DnsError;
use crate::utils::{extract_local_hostname, parse_arpa};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use lanforge_core::context::LanforgeContext;

/// Resolves local DNS queries (A/AAAA/PTR) using the `LanforgeContext`.
///
/// This resolver performs authoritative resolution for hostnames in the
/// configured search domain. It aggregates all known IP addresses for a
/// device (IPv4, SLAAC, static V6 suffixes) into DNS records.
pub struct LocalResolver<'a> {
    cfg: &'a DnsConfig,
    ctx: &'a LanforgeContext,
}

impl<'a> LocalResolver<'a> {
    /// Creates a new resolver bound to the given config and context.
    #[must_use]
    pub const fn new(cfg: &'a DnsConfig, ctx: &'a LanforgeContext) -> Self {
        Self { cfg, ctx }
    }

    /// Resolves an A or AAAA query for the given hostname.
    ///
    /// Looks up the device by hostname and returns all matching IP addresses.
    /// Returns `None` if the host is unknown.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    #[must_use]
    pub fn resolve_ip(&self, hostname: &str, qtype: RecordType) -> Option<SmallVec<[IpAddr; 32]>> {
        if let Some(device) = self.ctx.get_by_hostname(hostname) {
            return self.collect_device_ips_filtered(&device, qtype);
        }

        // JIT Shadow Lookup (Trace Back)
        let threshold =
            std::time::Duration::from_secs(u64::from(self.cfg.last_seen_threshold_days) * 86400);
        if let Some(mac) = self.ctx.find_mac_by_hostname_jit(hostname, Some(threshold))
            && let Some(device) = self.ctx.get_device(&mac)
        {
            return self.collect_device_ips_filtered(&device, qtype);
        }

        None
    }

    /// Resolves a reverse DNS (PTR) query for an IP address.
    pub fn resolve_ptr(&self, qname: &Name) -> Result<Option<(String, String)>, DnsError> {
        let Some(target_ip) = parse_arpa(qname) else {
            return Ok(None);
        };

        let Some(device) = self.ctx.get_by_ip(&target_ip) else {
            return Ok(None);
        };

        let (host, domain) = self.get_ptr_parts(&device);
        Ok(Some((host.into_owned(), domain.into_owned())))
    }

    /// Internal helper to get PTR parts from a device without allocating if possible.
    #[must_use]
    pub fn get_ptr_parts<'d>(&self, device: &'d Device) -> (Cow<'d, str>, Cow<'a, str>) {
        let host = if device.hostname.name.is_empty() {
            Cow::Borrowed(device.dns_fallback.as_str())
        } else {
            let name = &device.hostname.name;
            if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                Cow::Borrowed(name.as_str())
            } else {
                Cow::Owned(name.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-', "-"))
            }
        };

        let domain = self
            .cfg
            .search_domains
            .first()
            .map_or("lan", |d| d.as_str());

        (host, Cow::Borrowed(domain))
    }

    /// Internal helper to collect IPs filtered by query type.
    #[must_use]
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn collect_device_ips_filtered(
        &self,
        device: &Device,
        qtype: RecordType,
    ) -> Option<SmallVec<[IpAddr; 32]>> {
        if !matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
            return None;
        }

        let mut ips = self.collect_device_ips(device);
        ips.retain(|ip| match ip {
            IpAddr::V4(_) => matches!(qtype, RecordType::A | RecordType::ANY),
            IpAddr::V6(_) => matches!(qtype, RecordType::AAAA | RecordType::ANY),
        });

        if ips.is_empty() { None } else { Some(ips) }
    }

    /// Collects all IP addresses for a device and converts them to DNS records.
    ///
    /// Returns `None` if no addresses match the requested query type.
    /// Resolves local records for a given name and type.
    #[must_use]
    pub fn resolve_local(&self, qname: &Name, qtype: RecordType) -> Option<Vec<Record>> {
        let hostname = extract_local_hostname(qname, &self.cfg.multi_search_labels)?;
        let device = self.ctx.get_by_hostname(hostname)?;
        self.resolve_local_with_device(qname, &device, qtype)
    }

    /// Internal helper to resolve records when the device is already known.
    #[must_use]
    pub fn resolve_local_with_device(
        &self,
        qname: &Name,
        device: &Device,
        qtype: RecordType,
    ) -> Option<Vec<Record>> {
        if !matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
            return None;
        }

        let ips = self.collect_device_ips(device);
        let mut records = Vec::new();

        for ip in ips {
            match ip {
                IpAddr::V4(v4) if matches!(qtype, RecordType::A | RecordType::ANY) => {
                    records.push(Record::from_rdata(
                        qname.clone(),
                        self.cfg.ttl,
                        RData::A(v4.into()),
                    ));
                }
                IpAddr::V6(v6) if matches!(qtype, RecordType::AAAA | RecordType::ANY) => {
                    records.push(Record::from_rdata(
                        qname.clone(),
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
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn collect_device_ips(&self, device: &Device) -> SmallVec<[IpAddr; 32]> {
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
