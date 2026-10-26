//! Local DNS resolver backed by the `LanforgeContext`.

use lanforge_types::device::Device;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::config::DnsConfig;
use crate::error::DnsError;
use crate::resolver::builder::ResponseBuilder;
use crate::utils::{
    extract_local_hostname, extract_local_hostname_wire, fast_lowercase, parse_arpa,
    parse_arpa_wire,
};
use lanforge_core::context::LanforgeContext;
use lanforge_dns_wire::{
    PtrResponseArgs, WireHeader, WireOptScanner, WireQuestion, WireResponseWriter,
};
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
    ) -> Option<SmallVec<[IpAddr; 8]>> {
        self.resolve_ip_status(hostname, qtype).0
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    #[must_use]
    pub fn resolve_ip_status(
        &self,
        hostname: &str,
        qtype: DnsRecordType,
    ) -> (Option<SmallVec<[IpAddr; 8]>>, bool) {
        if !matches!(
            qtype,
            DnsRecordType::A | DnsRecordType::AAAA | DnsRecordType::ANY
        ) {
            return (None, false);
        }

        let parsed_mac = lanforge_types::identifiers::MacAddr::parse(hostname);
        let resolved_mac = self.ctx.with_state(|state| {
            if let Some(ref mac) = parsed_mac
                && state.devices.contains_key(mac)
            {
                return Some(*mac);
            }
            if let Some(mac) = state.indices.name_index.get(hostname).copied() {
                return Some(mac);
            }
            None
        });

        let mac = match resolved_mac {
            Some(m) => Some(m),
            None => {
                let threshold =
                    Duration::from_secs(u64::from(self.cfg.last_seen_threshold_days) * 86400);
                self.ctx.find_mac_by_hostname_jit(hostname, Some(threshold))
            }
        };

        if let Some(mac) = mac {
            let target_idx = self.ctx.target_ifindex();
            return self.ctx.with_state(|state| {
                if let Some(device) = state.devices.get(&mac) {
                    let (sys_gua, sys_ula) = if let Some(idx) = target_idx {
                        let ips = state.get_interface_ips(idx);
                        (ips.gua, ips.ula)
                    } else {
                        (None, None)
                    };
                    let gua = sys_gua.or(self.cfg.gua_prefix);
                    let ula = sys_ula.or(self.cfg.ula_prefix);
                    let mut ips = device.all_addresses_sorted(gua, ula);
                    ips.retain(|ip| match ip {
                        IpAddr::V4(_) => matches!(qtype, DnsRecordType::A | DnsRecordType::ANY),
                        IpAddr::V6(_) => matches!(qtype, DnsRecordType::AAAA | DnsRecordType::ANY),
                    });
                    let ret = if ips.is_empty() { None } else { Some(ips) };
                    (ret, true)
                } else {
                    (None, false)
                }
            });
        }

        (None, false)
    }

    #[must_use]
    pub fn resolve_device(
        &self,
        id: &lanforge_types::identifiers::DeviceIdentifier,
        qtype: DnsRecordType,
    ) -> Option<SmallVec<[IpAddr; 8]>> {
        match id {
            lanforge_types::identifiers::DeviceIdentifier::Mac(mac) => {
                if let Some(device) = self.ctx.get_device(mac) {
                    self.collect_device_ips_filtered(&device, qtype)
                } else {
                    None
                }
            }
            lanforge_types::identifiers::DeviceIdentifier::Name(name) => {
                self.resolve_ip(name, qtype)
            }
        }
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn resolve_ptr(&self, qname: &str) -> Result<Option<(String, String)>, DnsError> {
        let Some(target_ip) = parse_arpa(qname) else {
            return Ok(None);
        };

        let result = self.ctx.with_state(|state| {
            let mac = state.get_mac_by_ip(target_ip)?;
            let device = state.devices.get(&mac)?;
            let (host, domain) = self.get_ptr_parts(device);
            Some((host.into_owned(), domain.into_owned()))
        });

        Ok(result)
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
    ) -> Option<SmallVec<[IpAddr; 8]>> {
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
        self.ctx.with_state(|state| {
            let mac = state.indices.name_index.get(hostname)?;
            let device = state.devices.get(mac)?;
            self.resolve_local_with_device(qname, device, qtype)
        })
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
    pub fn collect_device_ips(&self, device: &Device) -> SmallVec<[IpAddr; 8]> {
        let (sys_gua, sys_ula) = if let Some(idx) = self.ctx.target_ifindex() {
            self.ctx.with_state(|state| {
                let ips = state.get_interface_ips(idx);
                (ips.gua, ips.ula)
            })
        } else {
            (None, None)
        };
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

                    let (ips, device_exists) = self.resolve_ip_status(&safe_hostname, qtype);
                    if let Some(ips) = ips {
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
                    } else if device_exists {
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

                    let ptr_res = self.ctx.with_state(|state| {
                        let mac = state.get_mac_by_ip(target_ip)?;
                        let device = state.devices.get(&mac)?;
                        let (host, domain) = self.get_ptr_parts(device);
                        Some((host.into_owned(), domain.into_owned()))
                    });

                    if let Some((host, domain)) = ptr_res {
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
                let (ips, device_exists) = self.resolve_ip_status(&safe_hostname, qtype);
                if let Some(ips) = ips {
                    resp.clear();
                    resp.extend_from_slice(&rb.success_ips(ips)?);
                    return Ok(true);
                } else if device_exists {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{init_test_context, mock_config};
    use lanforge_types::identifiers::MacAddr;
    use lanforge_types::update::DeviceUpdate;
    use std::net::Ipv4Addr;
    use std::time::{Duration, SystemTime};

    #[test]
    fn should_resolve_device_by_hostname_and_mac() {
        let ctx = init_test_context();
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11]);
        let ip = Ipv4Addr::new(10, 0, 0, 42);

        let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
            mac,
            ip,
            expires: SystemTime::now() + Duration::from_secs(3600),
        });
        let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
            mac,
            hostname: "printer".to_string(),
        });

        let resolver = LocalResolver::new(Arc::new(mock_config()), ctx);

        // Resolve by hostname
        let ips = resolver
            .resolve_ip("printer", DnsRecordType::A)
            .expect("Must resolve printer");
        assert_eq!(ips.as_slice(), &[IpAddr::V4(ip)]);

        // Resolve by MAC string
        let mac_str = mac.to_string();
        let ips_mac = resolver
            .resolve_ip(&mac_str, DnsRecordType::A)
            .expect("Must resolve MAC");
        assert_eq!(ips_mac.as_slice(), &[IpAddr::V4(ip)]);

        // Unknown device
        assert!(resolver.resolve_ip("unknown", DnsRecordType::A).is_none());
    }

    #[test]
    fn should_resolve_ptr_for_known_ip() {
        let ctx = init_test_context();
        let mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x22]);
        let ip = Ipv4Addr::new(10, 0, 0, 99);

        let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
            mac,
            ip,
            expires: SystemTime::now() + Duration::from_secs(3600),
        });
        let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
            mac,
            hostname: "nas-box".to_string(),
        });

        let resolver = LocalResolver::new(Arc::new(mock_config()), ctx);

        let ptr_query = "99.0.0.10.in-addr.arpa";
        let (host, domain) = resolver
            .resolve_ptr(ptr_query)
            .unwrap()
            .expect("Must resolve PTR");
        assert_eq!(host, "nas-box");
        assert_eq!(domain, "lan");
    }
}
