use anyhow::Result;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use lanforge_core::device::{IPv6State, Ipv6AddrOrSuffix, classify_ip};
use lanforge_core::state::DeviceTable;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::dns::config::DnsConfig;
use crate::dns::response::ResponseBuilder;
use crate::dns::utils::{combine_prefix_suffix, parse_arpa};
use lanforge_core::device::Device;

pub struct LocalResolver<'a> {
    cfg: &'a DnsConfig,
    table: &'a DeviceTable,
}

impl<'a> LocalResolver<'a> {
    pub fn new(cfg: &'a DnsConfig, table: &'a DeviceTable) -> Self {
        Self { cfg, table }
    }

    /// Resolve queries para nomes locais A/AAAA/ANY.
    /// Retorna uma resposta completa (NoError com registros ou NXDomain).
    pub fn resolve_ip(
        &self,
        query: &Message,
        hostname: &str,
        qtype: RecordType,
    ) -> Result<Vec<u8>> {
        let rb = ResponseBuilder::new(query, self.cfg);

        if let Some(device) = self.table.get_by_hostname(hostname) {
            if let Some(records) = self.resolve_local_with_device(query, device, qtype) {
                return rb.success(records);
            } else {
                // Host existe mas não tem registros do tipo pedido (NODATA)
                return rb.empty_noerror();
            }
        }

        rb.nxdomain()
    }

    /// Resolve queries reversas (PTR).
    pub fn resolve_ptr(&self, query: &Message, qname: &Name) -> Result<Option<Vec<u8>>> {
        let rb = ResponseBuilder::new(query, self.cfg);

        let Some(target_ip) = parse_arpa(qname) else {
            return Ok(None);
        };

        let Some(device) = self.table.get_by_ip(&target_ip) else {
            return Ok(None);
        };

        let question = query.queries().first().unwrap();
        let name = question.name().clone();

        let host = if device.hostname.is_empty() {
            format!("host-{}", device.mac.to_string().replace(':', ""))
        } else {
            device.hostname.clone()
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

    /// Lógica interna para coletar endereços de um dispositivo e converter em registros DNS.
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

        let mut ula_prefix_segs = None;
        if let Some(ula) = self.cfg.ula_prefix {
            let segs = ula.segments();
            ula_prefix_segs = Some([segs[0], segs[1], segs[2], segs[3]]);
        }

        let mut applied_prefixes = HashSet::<[u16; 4]>::new();
        if let Some(p) = ula_prefix_segs {
            applied_prefixes.insert(p);
        }

        // 1. Coleta prefixos de endereços SLAAC para aplicar aos sufixos estáticos depois
        for state in &device.v6 {
            if let IPv6State::Slaac(ip) = state {
                let segs = ip.segments();
                applied_prefixes.insert([segs[0], segs[1], segs[2], segs[3]]);
            }
        }

        // 2. Coleta todos os IPs potenciais
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
                            if let Some(ip) = combine_prefix_suffix(prefix, suf) {
                                all_ips.push(IpAddr::V6(ip));
                            }
                        }
                    }
                },
            }
        }

        // 3. De-duplicação e Ordenação por Prioridade (ULA > IPv4 > GUA)
        let mut unique = HashSet::new();
        all_ips.retain(|ip| unique.insert(*ip));
        all_ips.sort_by_cached_key(|ip| classify_ip(ip).score());

        // 4. Filtra por qtype e converte em Records
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
