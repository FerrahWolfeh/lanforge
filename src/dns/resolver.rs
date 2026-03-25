use anyhow::Result;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use std::collections::HashSet;
use std::net::Ipv6Addr;
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
    table: &DeviceTable,
) -> Result<Option<Vec<u8>>> {
    let question = query.queries().first().expect("Query validada");

    let name = question.name().clone();
    let mut records: Vec<Record> = Vec::new();

    let _static_entry = table.static_entries.get(&device.mac);

    if matches!(qtype, RecordType::A | RecordType::ANY)
        && let Some(ip) = device.v4.ip()
    {
        records.push(Record::from_rdata(
            name.clone(),
            cfg.ttl,
            RData::A(ip.into()),
        ));
    }

    if matches!(qtype, RecordType::AAAA | RecordType::ANY) {
        let mut ulas = Vec::new();
        let mut others = Vec::new();

        let mut classify_and_push = |ip: Ipv6Addr| {
            if (ip.segments()[0] & 0xfe00) == 0xfc00 {
                ulas.push(ip);
            } else {
                others.push(ip);
            }
        };

        let mut applied_prefixes = HashSet::<[u16; 4]>::new();
        let mut ula_prefix = None;

        if let Some(ula) = cfg.ula_prefix {
            let segs = ula.segments();
            let p = [segs[0], segs[1], segs[2], segs[3]];
            ula_prefix = Some(p);
            applied_prefixes.insert(p);
        }

        // 1. Collect prefixes from SLAAC addresses to apply to suffixes later
        for state in &device.v6 {
            if let crate::device::IPv6State::Slaac(ip) = state {
                let segs = ip.segments();
                applied_prefixes.insert([segs[0], segs[1], segs[2], segs[3]]);
            }
        }

        // 2. Process all states
        for state in &device.v6 {
            match state {
                crate::device::IPv6State::Dynamic(lease) => classify_and_push(lease.ip),
                crate::device::IPv6State::Slaac(ip) => classify_and_push(*ip),
                crate::device::IPv6State::Static(suf) => match suf {
                    crate::device::Ipv6AddrOrSuffix::Full(ip) => classify_and_push(*ip),
                    crate::device::Ipv6AddrOrSuffix::Suffix(_) => {
                        // Apply suffix to all learned prefixes
                        for prefix in &applied_prefixes {
                            if let Some(ip) = combine_prefix_suffix(prefix, suf) {
                                classify_and_push(ip);
                            }
                        }
                        // Also apply to ULA prefix if not already in applied_prefixes (redundant but safe)
                        if let Some(p) = &ula_prefix
                            && !applied_prefixes.contains(p)
                            && let Some(ip) = combine_prefix_suffix(p, suf)
                        {
                            classify_and_push(ip);
                        }
                    }
                },
            }
        }

        let mut unique = HashSet::new();
        for ip in ulas.into_iter().chain(others.into_iter()) {
            if unique.insert(ip) {
                records.push(Record::from_rdata(
                    name.clone(),
                    cfg.ttl,
                    RData::AAAA(ip.into()),
                ));
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
