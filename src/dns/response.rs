use anyhow::Result;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{Name, RData, Record, rdata::SOA},
    serialize::binary::BinEncodable,
};
use std::str::FromStr;

use crate::dns::config::DnsConfig;

pub fn base_response(query: &Message, cfg: &DnsConfig) -> Message {
    let mut resp = Message::new();
    resp.set_id(query.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_authoritative(true)
        .set_recursion_available(cfg.upstream.is_some())
        .add_queries(query.queries().to_vec());

    if let Some(edns) = query.extensions() {
        if let Some(ext) = resp.extensions_mut() {
            *ext = edns.clone();
        } else {
            let ext = resp.extensions_mut();
            *ext = Some(edns.clone());
        }
    }
    resp
}

pub fn add_soa(resp: &mut Message, cfg: &DnsConfig) {
    let name = Name::from_str(&format!("{}.", cfg.search_domain)).unwrap_or_else(|_| Name::root());
    let mname =
        Name::from_str(&format!("ns.{}.", cfg.search_domain)).unwrap_or_else(|_| Name::root());
    let rname = Name::from_str(&format!("hostmaster.{}.", cfg.search_domain))
        .unwrap_or_else(|_| Name::root());
    let soa = SOA::new(mname, rname, 1, 7200, 3600, 1209600, 3600);
    resp.add_name_server(Record::from_rdata(name, 3600, RData::SOA(soa)));
}

pub fn nxdomain_response(query: &Message, cfg: &DnsConfig) -> Result<Vec<u8>> {
    let mut resp = base_response(query, cfg);
    resp.set_response_code(ResponseCode::NXDomain);
    add_soa(&mut resp, cfg);
    Ok(resp.to_bytes()?)
}

pub fn refused_response(query: &Message, cfg: &DnsConfig) -> Result<Vec<u8>> {
    let mut resp = base_response(query, cfg);
    resp.set_response_code(ResponseCode::Refused);
    Ok(resp.to_bytes()?)
}

pub fn empty_noerror_response(query: &Message, cfg: &DnsConfig) -> Result<Vec<u8>> {
    let mut resp = base_response(query, cfg);
    resp.set_response_code(ResponseCode::NoError);
    add_soa(&mut resp, cfg);
    Ok(resp.to_bytes()?)
}

pub fn formerr_response(query: &Message, cfg: &DnsConfig) -> Result<Vec<u8>> {
    let mut resp = base_response(query, cfg);
    resp.set_response_code(ResponseCode::FormErr);
    Ok(resp.to_bytes()?)
}
