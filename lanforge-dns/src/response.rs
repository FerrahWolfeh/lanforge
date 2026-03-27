use crate::error::DnsError;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{Name, RData, Record, rdata::SOA},
    serialize::binary::BinEncodable,
};
use std::str::FromStr;

use crate::config::DnsConfig;

pub struct ResponseBuilder<'a> {
    query: &'a Message,
    cfg: &'a DnsConfig,
}

impl<'a> ResponseBuilder<'a> {
    pub fn new(query: &'a Message, cfg: &'a DnsConfig) -> Self {
        Self { query, cfg }
    }

    pub fn base(&self) -> Message {
        let mut resp = Message::new();
        resp.set_id(self.query.id())
            .set_message_type(MessageType::Response)
            .set_op_code(OpCode::Query)
            .set_authoritative(true)
            .set_recursion_available(self.cfg.upstream.is_some())
            .add_queries(self.query.queries().to_vec());

        if let Some(edns) = self.query.extensions() {
            if let Some(ext) = resp.extensions_mut() {
                *ext = edns.clone();
            } else {
                let ext = resp.extensions_mut();
                *ext = Some(edns.clone());
            }
        }
        resp
    }

    pub fn add_soa(&self, resp: &mut Message) {
        let name = Name::from_str(&format!("{}.", self.cfg.search_domain))
            .unwrap_or_else(|_| Name::root());
        let mname = Name::from_str(&format!("ns.{}.", self.cfg.search_domain))
            .unwrap_or_else(|_| Name::root());
        let rname = Name::from_str(&format!("hostmaster.{}.", self.cfg.search_domain))
            .unwrap_or_else(|_| Name::root());
        let soa = SOA::new(mname, rname, 1, 7200, 3600, 1209600, 3600);
        resp.add_name_server(Record::from_rdata(name, 3600, RData::SOA(soa)));
    }

    pub fn nxdomain(&self) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.set_response_code(ResponseCode::NXDomain);
        self.add_soa(&mut resp);
        Ok(resp.to_bytes()?)
    }

    pub fn refused(&self) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.set_response_code(ResponseCode::Refused);
        Ok(resp.to_bytes()?)
    }

    pub fn empty_noerror(&self) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.set_response_code(ResponseCode::NoError);
        self.add_soa(&mut resp);
        Ok(resp.to_bytes()?)
    }

    pub fn formerr(&self) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.set_response_code(ResponseCode::FormErr);
        Ok(resp.to_bytes()?)
    }

    pub fn success(&self, answers: Vec<Record>) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.set_response_code(ResponseCode::NoError)
            .add_answers(answers);
        Ok(resp.to_bytes()?)
    }
}
