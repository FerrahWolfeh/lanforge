use anyhow::Result;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::device::Device;
use crate::dns::config::DnsConfig;
use crate::dns::response::{base_response, empty_noerror_response};
use crate::dns::utils::{combine_prefix_suffix, parse_arpa};
use crate::state::DeviceTable;

pub fn resolve_local(
    query: &Message,
    device: &Device,
    qtype: RecordType,
    cfg: &DnsConfig,
) -> Result<Option<Vec<u8>>> {
    let question = query.queries().first().expect("Query validada");

    let name = question.name().clone();
    let mut records: Vec<Record> = Vec::new();

    if matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY) {
        let mut ula_prefix_segs = None;
        if let Some(ula) = cfg.ula_prefix {
            let segs = ula.segments();
            ula_prefix_segs = Some([segs[0], segs[1], segs[2], segs[3]]);
        }

        let mut applied_prefixes = HashSet::<[u16; 4]>::new();
        if let Some(p) = ula_prefix_segs {
            applied_prefixes.insert(p);
        }

        // 1. Collect prefixes from SLAAC addresses to apply to suffixes later
        for state in &device.v6 {
            if let crate::device::IPv6State::Slaac(ip) = state {
                let segs = ip.segments();
                applied_prefixes.insert([segs[0], segs[1], segs[2], segs[3]]);
            }
        }

        // 2. Collect all potential addresses (including those with suffixes)
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
                crate::device::IPv6State::Dynamic(lease) => all_ips.push(IpAddr::V6(lease.ip)),
                crate::device::IPv6State::Slaac(ip) => all_ips.push(IpAddr::V6(*ip)),
                crate::device::IPv6State::Static(suf) => match suf {
                    crate::device::Ipv6AddrOrSuffix::Full(ip) => all_ips.push(IpAddr::V6(*ip)),
                    crate::device::Ipv6AddrOrSuffix::Suffix(_) => {
                        for prefix in &applied_prefixes {
                            if let Some(ip) = combine_prefix_suffix(prefix, suf) {
                                all_ips.push(IpAddr::V6(ip));
                            }
                        }
                    }
                },
            }
        }

        // 3. De-duplicate and Sort by Priority (ULA > IPv4 > GUA)
        let mut unique = HashSet::new();
        all_ips.retain(|ip| unique.insert(*ip));
        all_ips.sort_by_cached_key(|ip| crate::device::classify_ip(ip).score());

        // 4. Filter by qtype and Convert to Records
        for ip in all_ips {
            match ip {
                IpAddr::V4(v4) if matches!(qtype, RecordType::A | RecordType::ANY) => {
                    records.push(Record::from_rdata(
                        name.clone(),
                        cfg.ttl,
                        RData::A(v4.into()),
                    ));
                }
                IpAddr::V6(v6) if matches!(qtype, RecordType::AAAA | RecordType::ANY) => {
                    records.push(Record::from_rdata(
                        name.clone(),
                        cfg.ttl,
                        RData::AAAA(v6.into()),
                    ));
                }
                _ => {}
            }
        }
    }

    if records.is_empty() {
        return Ok(Some(empty_noerror_response(query, cfg)?));
    }

    let mut resp = base_response(query, cfg);
    resp.set_response_code(ResponseCode::NoError)
        .add_answers(records);

    Ok(Some(resp.to_bytes()?))
}

pub fn resolve_ptr(
    query: &Message,
    qname: &str,
    cfg: &DnsConfig,
    table: &DeviceTable,
) -> Result<Option<Vec<u8>>> {
    let Some(target_ip) = parse_arpa(qname) else {
        return Ok(None);
    };

    let Some(&mac) = table.ip_index.get(&target_ip) else {
        return Ok(None);
    };

    let device = table
        .devices
        .get(&mac)
        .expect("Índice corrompido: MAC não encontrado");

    let question = query.queries().first().unwrap();
    let name = question.name().clone();

    let host = if device.hostname.is_empty() {
        format!("host-{}", device.mac.to_string().replace(':', ""))
    } else {
        device.hostname.clone()
    };

    let fqdn = format!("{}.{}.", host, cfg.search_domain);
    let ptr_name = Name::from_str(&fqdn).unwrap_or_else(|_| Name::root());

    let record = Record::from_rdata(
        name,
        cfg.ttl,
        RData::PTR(hickory_proto::rr::rdata::PTR(ptr_name)),
    );

    let mut resp = base_response(query, cfg);
    resp.set_response_code(ResponseCode::NoError)
        .add_answers(vec![record]);

    Ok(Some(resp.to_bytes()?))
}
