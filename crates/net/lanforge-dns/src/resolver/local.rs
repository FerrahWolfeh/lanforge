//! Local DNS resolver backed by the `LanforgeContext`.

use arc_swap::{ArcSwap, Guard};
use lanforge_types::device::Device;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::config::DnsConfig;
use crate::error::DnsError;
use crate::utils::{extract_local_hostname, fast_lowercase, parse_arpa, parse_arpa_wire};
use lanforge_core::context::LanforgeContext;
use lanforge_dns_wire::{
    PtrResponseArgs, WireHeader, WireLabelIter, WireOptScanner, WireQuestion, WireResponseWriter,
};
use lanforge_types::network::dns::{DnsClass, DnsRData, DnsRecord, DnsRecordType};

/// The site's domains as the hot path uses them: wire labels to match names under them, and the
/// first one, which PTR answers name hosts in. Swapped whole when the site's domains change.
#[derive(Debug)]
pub struct LocalZone {
    pub domains: Vec<String>,
    pub labels: Vec<Vec<Vec<u8>>>,
    pub primary: Arc<str>,
}

impl LocalZone {
    /// The zone of `domains`; none given means `lan`.
    #[must_use]
    pub fn new(domains: &[String]) -> Self {
        let domains = if domains.is_empty() {
            vec!["lan".to_string()]
        } else {
            domains.to_vec()
        };
        let labels = domains
            .iter()
            .map(|d| d.split('.').map(|l| l.as_bytes().to_vec()).collect())
            .collect();
        Self {
            primary: Arc::from(domains[0].as_str()),
            labels,
            domains,
        }
    }
}

/// Where a query name sits relative to the site's domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SitePlace<'a> {
    /// A site domain itself (`lan`).
    Apex,
    /// One label under a site domain (`archie.lan`): a LAN host name.
    Host(&'a [u8]),
    /// Deeper under a site domain (`x.archie.lan`): the LAN serves no such names.
    Deeper,
    /// Not under any site domain.
    Outside,
}

impl LocalZone {
    /// Where the name of `labels` sits relative to the site's domains.
    #[must_use]
    pub fn place<'a>(&self, labels: WireLabelIter<'a>) -> SitePlace<'a> {
        let name: SmallVec<[&[u8]; 8]> = labels.collect();
        for domain in &self.labels {
            let Some(below) = name.len().checked_sub(domain.len()) else {
                continue;
            };
            let under = name[below..]
                .iter()
                .zip(domain)
                .all(|(a, b)| a.eq_ignore_ascii_case(b));
            if under {
                return match below {
                    0 => SitePlace::Apex,
                    1 => SitePlace::Host(name[0]),
                    _ => SitePlace::Deeper,
                };
            }
        }
        SitePlace::Outside
    }
}

/// Resolves local DNS queries (A/AAAA/PTR) using the `LanforgeContext`.
pub struct LocalResolver {
    pub cfg: Arc<DnsConfig>,
    pub ctx: LanforgeContext,
    zone: ArcSwap<LocalZone>,
}

impl LocalResolver {
    /// A resolver for `cfg.search_domains`; [`Self::set_domains`] changes them in place.
    #[must_use]
    pub fn new(cfg: Arc<DnsConfig>, ctx: LanforgeContext) -> Self {
        let zone = ArcSwap::from_pointee(LocalZone::new(&cfg.search_domains));
        Self { cfg, ctx, zone }
    }

    /// The site's domains in use now.
    #[must_use]
    pub fn zone(&self) -> Guard<Arc<LocalZone>> {
        self.zone.load()
    }

    /// Answers for `domains` from the next query on; queries in flight finish with the old ones.
    pub fn set_domains(&self, domains: &[String]) {
        self.zone.store(Arc::new(LocalZone::new(domains)));
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

        let domain = self.zone().primary.to_string();
        (host, Cow::Owned(domain))
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
        let zone = self.zone();
        let hostname = extract_local_hostname(qname, &zone.labels)?;
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
                        name: Arc::clone(&qname_arc),
                        rtype: DnsRecordType::A,
                        rclass: DnsClass::IN,
                        ttl: self.cfg.ttl,
                        rdata: DnsRData::A(v4),
                    });
                }
                IpAddr::V6(v6) if matches!(qtype, DnsRecordType::AAAA | DnsRecordType::ANY) => {
                    records.push(DnsRecord {
                        name: Arc::clone(&qname_arc),
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

    /// Answers what the router owns, whatever the type; `false` sends the query on.
    ///
    /// Names under the site's domains never leave the router (dnsmasq's `local=/lan/`): a host
    /// the LAN knows answers its addresses, or NODATA for any other type; a host it does not
    /// know, or a deeper name, is NXDOMAIN; the domain itself is NODATA (an NXDOMAIN there
    /// would deny every name under it, RFC 8020). A dotless name is looked up as a LAN host and
    /// never forwarded either (dnsmasq's `domain-needed`) — an IoT device looping on `:0` is
    /// answered here — except the root and TLD delegation lookups (NS/SOA/DS/DNSKEY of a name
    /// that is not a LAN host, e.g. `. NS`, `com. DS`). Reverse names (PTR) of LAN addresses
    /// are answered when known, else forwarded.
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
        let reply = |rcode: u8, resp: &mut Vec<u8>| {
            WireResponseWriter::write_error_response(
                data,
                question,
                rcode,
                WireOptScanner::scan(data, header, question),
                has_upstreams,
                resp,
            );
            true
        };

        let place = self.zone().place(question.labels());
        let host = match place {
            SitePlace::Apex => return reply(0, resp),
            SitePlace::Deeper => return reply(3, resp),
            SitePlace::Host(label) => label,
            SitePlace::Outside => {
                let mut labels = question.labels();
                match (labels.next(), labels.next()) {
                    (Some(label), None) => label,
                    _ => {
                        return qtype == DnsRecordType::PTR
                            && self.reply_ptr(data, header, question, has_upstreams, resp);
                    }
                }
            }
        };
        let raw = String::from_utf8_lossy(host);
        let host = fast_lowercase(&raw);

        if matches!(
            qtype,
            DnsRecordType::A | DnsRecordType::AAAA | DnsRecordType::ANY
        ) {
            let (ips, device_exists) = self.resolve_ip_status(&host, qtype);
            if let Some(ips) = ips {
                WireResponseWriter::write_ip_response(
                    data,
                    question,
                    &ips,
                    self.cfg.ttl,
                    WireOptScanner::scan(data, header, question),
                    has_upstreams,
                    resp,
                );
                return true;
            }
            return reply(if device_exists { 0 } else { 3 }, resp);
        }

        let (ips, device_exists) = self.resolve_ip_status(&host, DnsRecordType::A);
        let known = ips.is_some() || device_exists;
        let delegation = matches!(
            qtype,
            DnsRecordType::NS
                | DnsRecordType::SOA
                | DnsRecordType::Unknown(43) // DS
                | DnsRecordType::Unknown(48) // DNSKEY
        );
        if place == SitePlace::Outside && delegation && !known {
            return false;
        }
        reply(if known { 0 } else { 3 }, resp)
    }

    /// The PTR answer for a reverse name of a LAN address, when the router knows it.
    fn reply_ptr(
        &self,
        data: &[u8],
        header: &WireHeader,
        question: &WireQuestion<'_>,
        has_upstreams: bool,
        resp: &mut Vec<u8>,
    ) -> bool {
        let Some(target_ip) = parse_arpa_wire(question.labels()) else {
            return false;
        };
        let ptr_res = self.ctx.with_state(|state| {
            let mac = state.get_mac_by_ip(target_ip)?;
            let device = state.devices.get(&mac)?;
            let (host, domain) = self.get_ptr_parts(device);
            Some((host.into_owned(), domain.into_owned()))
        });
        let Some((host, domain)) = ptr_res else {
            return false;
        };
        WireResponseWriter::write_ptr_response(
            PtrResponseArgs {
                query_data: data,
                question,
                host: &host,
                domain: &domain,
                ttl: self.cfg.ttl,
                edns: WireOptScanner::scan(data, header, question),
                ra: has_upstreams,
            },
            resp,
        );
        true
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

    /// The site's domains change in place: the PTR domain follows the first one, and
    /// an empty list falls back to `lan`.
    #[test]
    fn set_domains_swaps_the_zone() {
        let resolver = LocalResolver::new(Arc::new(mock_config()), init_test_context());
        assert_eq!(&*resolver.zone().primary, "lan");

        resolver.set_domains(&["home.arpa".to_string(), "lan".to_string()]);
        let zone = resolver.zone();
        assert_eq!(&*zone.primary, "home.arpa");
        assert_eq!(zone.labels[0], [b"home".to_vec(), b"arpa".to_vec()]);

        resolver.set_domains(&[]);
        assert_eq!(resolver.zone().domains, ["lan"]);
    }
}
