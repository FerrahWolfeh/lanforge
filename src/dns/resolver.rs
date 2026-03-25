use anyhow::Result;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::str::FromStr;

use crate::dns::config::DnsConfig;
use crate::dns::response::{base_response, empty_noerror_response};
use crate::dns::utils::{combine_prefix_suffix, parse_arpa};
use crate::state::{Device, DeviceTable};

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

    let static_entry = table.static_entries.get(&device.mac);

    if matches!(qtype, RecordType::A | RecordType::ANY) {
        let v4_ip = static_entry
            .and_then(|e| e.v4_ip)
            .or(device.v4_static)
            .or_else(|| device.v4.as_ref().map(|l| l.ip));

        if let Some(ip) = v4_ip {
            records.push(Record::from_rdata(
                name.clone(),
                cfg.ttl,
                RData::A(ip.into()),
            ));
        }
    }

    if matches!(qtype, RecordType::AAAA | RecordType::ANY) {
        let mut ulas = Vec::new();
        let mut others = Vec::new();

        let mut classify_ip = |ip: Ipv6Addr| {
            if (ip.segments()[0] & 0xfe00) == 0xfc00 {
                ulas.push(ip);
            } else {
                others.push(ip);
            }
        };

        if let Some(v6) = &device.v6 {
            classify_ip(v6.ip);
        }

        let v6_suffix = static_entry
            .and_then(|e| e.v6_suffix.as_ref())
            .or(device.v6_suffix.as_ref());

        if let Some(suffix) = v6_suffix {
            if suffix.starts_with("::") {
                let mut applied_prefixes = HashSet::<[u16; 4]>::new();

                if let Some(ula) = cfg.ula_prefix {
                    let segments = ula.segments();
                    let ula_prefix = [segments[0], segments[1], segments[2], segments[3]];
                    if applied_prefixes.insert(ula_prefix)
                        && let Some(ip) = combine_prefix_suffix(&ula_prefix, suffix)
                    {
                        classify_ip(ip);
                    }
                }

                for slaac_ip in &device.slaac {
                    let segments = slaac_ip.segments();
                    let prefix = [segments[0], segments[1], segments[2], segments[3]];
                    if applied_prefixes.insert(prefix)
                        && let Some(ip) = combine_prefix_suffix(&prefix, suffix)
                    {
                        classify_ip(ip);
                    }
                }
            } else if let Ok(ip) = suffix.parse::<Ipv6Addr>() {
                classify_ip(ip);
            }
        }

        for ip in &device.slaac {
            classify_ip(*ip);
        }

        for ip in ulas.into_iter().chain(others.into_iter()) {
            records.push(Record::from_rdata(
                name.clone(),
                cfg.ttl,
                RData::AAAA(ip.into()),
            ));
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
