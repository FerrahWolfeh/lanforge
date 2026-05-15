//! Local DNS resolver backed by the `LanforgeContext`.

use lanforge_types::device::Device;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::DnsConfig;
use crate::error::DnsError;
use crate::resolver::builder::ResponseBuilder;
use crate::utils::{
    extract_local_hostname, extract_local_hostname_wire, fast_lowercase, parse_arpa,
    parse_arpa_wire,
};
use crate::wire::{PtrResponseArgs, WireHeader, WireOptScanner, WireQuestion, WireResponseWriter};
use lanforge_core::context::LanforgeContext;
use lanforge_types::network::dns::{DnsClass, DnsRData, DnsRecord, DnsRecordType};

/// Resolves local DNS queries (A/AAAA/PTR) using the `LanforgeContext`.
pub struct LocalResolver {
    pub cfg: Arc<DnsConfig>,
    pub ctx: LanforgeContext,
}

impl LocalResolver {
    #[must_use]
    pub fn new(cfg: Arc<DnsConfig>, ctx: LanforgeContext) -> Self {
        Self { cfg, ctx }
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    #[must_use]
    pub fn resolve_ip(
        &self,
        hostname: &str,
        qtype: DnsRecordType,
    ) -> Option<SmallVec<[IpAddr; 32]>> {
        if let Some(device) = self.ctx.get_by_hostname(hostname) {
            return self.collect_device_ips_filtered(&device, qtype);
        }

        // JIT Shadow Lookup
        let threshold =
            std::time::Duration::from_secs(u64::from(self.cfg.last_seen_threshold_days) * 86400);
        if let Some(mac) = self.ctx.find_mac_by_hostname_jit(hostname, Some(threshold))
            && let Some(device) = self.ctx.get_device(&mac)
        {
            return self.collect_device_ips_filtered(&device, qtype);
        }

        None
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn resolve_ptr(&self, qname: &str) -> Result<Option<(String, String)>, DnsError> {
        let Some(target_ip) = parse_arpa(qname) else {
            return Ok(None);
        };

        let Some(device) = self.ctx.get_by_ip(&target_ip) else {
            return Ok(None);
        };

        let (host, domain) = self.get_ptr_parts(&device);
        Ok(Some((host.into_owned(), domain.into_owned())))
    }

    #[must_use]
    pub fn get_ptr_parts<'d>(&self, device: &'d Device) -> (Cow<'d, str>, Cow<'_, str>) {
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

    #[must_use]
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn collect_device_ips_filtered(
        &self,
        device: &Device,
        qtype: DnsRecordType,
    ) -> Option<SmallVec<[IpAddr; 32]>> {
        if !matches!(
            qtype,
            DnsRecordType::A | DnsRecordType::AAAA | DnsRecordType::ANY
        ) {
            return None;
        }

        let mut ips = self.collect_device_ips(device);
        ips.retain(|ip| match ip {
            IpAddr::V4(_) => matches!(qtype, DnsRecordType::A | DnsRecordType::ANY),
            IpAddr::V6(_) => matches!(qtype, DnsRecordType::AAAA | DnsRecordType::ANY),
        });

        if ips.is_empty() { None } else { Some(ips) }
    }

    #[must_use]
    pub fn resolve_local(&self, qname: &str, qtype: DnsRecordType) -> Option<Vec<DnsRecord>> {
        let hostname = extract_local_hostname(qname, &self.cfg.multi_search_labels)?;
        let device = self.ctx.get_by_hostname(hostname)?;
        self.resolve_local_with_device(qname, &device, qtype)
    }

    #[must_use]
    pub fn resolve_local_with_device(
        &self,
        qname: &str,
        device: &Device,
        qtype: DnsRecordType,
    ) -> Option<Vec<DnsRecord>> {
        if !matches!(
            qtype,
            DnsRecordType::A | DnsRecordType::AAAA | DnsRecordType::ANY
        ) {
            return None;
        }

        let ips = self.collect_device_ips(device);
        let mut records = Vec::new();
        let qname_arc: Arc<str> = Arc::from(qname);

        for ip in ips {
            match ip {
                IpAddr::V4(v4) if matches!(qtype, DnsRecordType::A | DnsRecordType::ANY) => {
                    records.push(DnsRecord {
                        name: qname_arc.clone(),
                        rtype: DnsRecordType::A,
                        rclass: DnsClass::IN,
                        ttl: self.cfg.ttl,
                        rdata: DnsRData::A(v4),
                    });
                }
                IpAddr::V6(v6) if matches!(qtype, DnsRecordType::AAAA | DnsRecordType::ANY) => {
                    records.push(DnsRecord {
                        name: qname_arc.clone(),
                        rtype: DnsRecordType::AAAA,
                        rclass: DnsClass::IN,
                        ttl: self.cfg.ttl,
                        rdata: DnsRData::AAAA(v6),
                    });
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

    #[must_use]
    pub fn collect_device_ips(&self, device: &Device) -> SmallVec<[IpAddr; 32]> {
        let (sys_gua, sys_ula) = self
            .ctx
            .target_ifindex()
            .map_or((None, None), |idx| self.ctx.get_interface_prefixes_opt(idx));
        let gua = sys_gua.or(self.cfg.gua_prefix);
        let ula = sys_ula.or(self.cfg.ula_prefix);
        device.all_addresses_sorted(gua, ula)
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn resolve_local_wire(
        &self,
        data: &[u8],
        header: &WireHeader,
        question: &WireQuestion<'_>,
        has_upstreams: bool,
        resp: &mut Vec<u8>,
    ) -> bool {
        let qtype = DnsRecordType::from(question.qtype());

        match qtype {
            DnsRecordType::A | DnsRecordType::AAAA | DnsRecordType::ANY => {
                let mut labels = question.labels();
                if let Some(hostname_slice) =
                    extract_local_hostname_wire(&mut labels, &self.cfg.multi_search_labels)
                {
                    let safe_hostname = fast_lowercase(hostname_slice);
                    let edns = WireOptScanner::scan(data, header, question);

                    if let Some(ips) = self.resolve_ip(&safe_hostname, qtype) {
                        WireResponseWriter::write_ip_response(
                            data,
                            question,
                            &ips,
                            self.cfg.ttl,
                            edns,
                            has_upstreams,
                            resp,
                        );
                        return true;
                    } else if self.ctx.get_by_hostname(&safe_hostname).is_some() {
                        WireResponseWriter::write_error_response(
                            data,
                            question,
                            0, // NOERROR (but no data)
                            edns,
                            has_upstreams,
                            resp,
                        );
                        return true;
                    } else {
                        WireResponseWriter::write_error_response(
                            data,
                            question,
                            3, // NXDOMAIN
                            edns,
                            has_upstreams,
                            resp,
                        );
                        return true;
                    }
                }
            }
            DnsRecordType::PTR => {
                if let Some(target_ip) = parse_arpa_wire(question.labels()) {
                    let edns = WireOptScanner::scan(data, header, question);

                    if let Some(device) = self.ctx.get_by_ip(&target_ip) {
                        let (host, domain) = self.get_ptr_parts(&device);
                        WireResponseWriter::write_ptr_response(
                            PtrResponseArgs {
                                query_data: data,
                                question,
                                host: &host,
                                domain: &domain,
                                ttl: self.cfg.ttl,
                                edns,
                                ra: has_upstreams,
                            },
                            resp,
                        );
                        return true;
                    }
                }
            }
            _ => {}
        }
        false
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn resolve_local_fallback(
        &self,
        rb: &ResponseBuilder,
        qname: &str,
        qtype: DnsRecordType,
        resp: &mut Vec<u8>,
    ) -> Result<bool, DnsError> {
        if matches!(
            qtype,
            DnsRecordType::A | DnsRecordType::AAAA | DnsRecordType::ANY
        ) {
            if let Some(hostname_slice) =
                extract_local_hostname(qname, &self.cfg.multi_search_labels)
            {
                let safe_hostname = fast_lowercase(hostname_slice);
                if let Some(ips) = self.resolve_ip(&safe_hostname, qtype) {
                    resp.clear();
                    resp.extend_from_slice(&rb.success_ips(ips)?);
                    return Ok(true);
                } else if self.ctx.get_by_hostname(&safe_hostname).is_some() {
                    resp.clear();
                    resp.extend_from_slice(&rb.empty_noerror()?);
                    return Ok(true);
                }
            }
        } else if qtype == DnsRecordType::PTR
            && let Some((host, domain)) = self.resolve_ptr(qname)?
        {
            resp.clear();
            resp.extend_from_slice(&rb.success_ptr(&host, &domain)?);
            return Ok(true);
        }
        Ok(false)
    }
}
