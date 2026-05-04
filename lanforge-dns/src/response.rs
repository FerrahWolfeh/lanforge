//! DNS response message builder.
//!
//! Constructs DNS response messages using Hickory-DNS `Message` for
//! correctness and EDNS compatibility.

use crate::error::DnsError;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{Name, RData, Record, rdata::SOA},
    serialize::binary::BinEncodable,
};
use std::str::FromStr;

use crate::config::DnsConfig;

/// Builder for DNS response messages.
///
/// Wraps a query message and configuration to produce properly formatted
/// DNS responses with correct flags, EDNS preservation, and SOA records
/// for NXDOMAIN/NODATA responses.
pub struct ResponseBuilder<'a> {
    query: &'a Message,
    cfg: &'a DnsConfig,
}

impl<'a> ResponseBuilder<'a> {
    /// Creates a new response builder from the given query and config.
    #[must_use]
    pub const fn new(query: &'a Message, cfg: &'a DnsConfig) -> Self {
        Self { query, cfg }
    }

    /// Constructs the base response message with standard flags.
    ///
    /// Sets:
    /// - QR = 1 (response)
    /// - Authoritative = true
    /// - Recursion Available (if upstream is configured)
    /// - Copies query section and EDNS extensions
    #[must_use]
    pub fn base(&self) -> Message {
        let mut resp = Message::new(self.query.metadata.id, MessageType::Response, OpCode::Query);
        resp.metadata.authoritative = true;
        resp.metadata.recursion_available = !self.cfg.upstreams.is_empty();
        resp.add_queries(self.query.queries.iter().cloned());

        if let Some(edns) = &self.query.edns {
            resp.set_edns(edns.clone());
        }
        resp
    }

    /// Adds an SOA (Start of Authority) record to the authority section.
    ///
    /// Required for NXDOMAIN and NODATA responses per RFC 1035.
    pub fn add_soa(&self, resp: &mut Message) {
        let domain = self
            .cfg
            .search_domains
            .first()
            .map_or("lan", |d| d.as_str());
        let name = Name::from_str(&format!("{domain}.")).unwrap_or_else(|_| Name::root());
        let mname = Name::from_str(&format!("ns.{domain}.")).unwrap_or_else(|_| Name::root());
        let rname =
            Name::from_str(&format!("hostmaster.{domain}.")).unwrap_or_else(|_| Name::root());
        let soa = SOA::new(mname, rname, 1, 7200, 3600, 1_209_600, 3600);
        resp.authorities
            .push(Record::from_rdata(name, 3600, RData::SOA(soa)));
    }

    /// Builds an NXDOMAIN response (domain does not exist).
    pub fn nxdomain(&self) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.metadata.response_code = ResponseCode::NXDomain;
        self.add_soa(&mut resp);
        Ok(resp.to_bytes()?)
    }

    /// Builds a REFUSED response (server refuses to answer).
    pub fn refused(&self) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.metadata.response_code = ResponseCode::Refused;
        Ok(resp.to_bytes()?)
    }

    /// Builds a NODATA response (domain exists but no records for the requested type).
    ///
    /// RCODE = `NoError`, but with zero answer records and an SOA in the authority section.
    pub fn empty_noerror(&self) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.metadata.response_code = ResponseCode::NoError;
        self.add_soa(&mut resp);
        Ok(resp.to_bytes()?)
    }

    /// Builds a FORMERR response (malformed query).
    pub fn formerr(&self) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.metadata.response_code = ResponseCode::FormErr;
        Ok(resp.to_bytes()?)
    }

    /// Builds a successful response with the given answer records.
    pub fn success(&self, answers: Vec<Record>) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.metadata.response_code = ResponseCode::NoError;
        resp.add_answers(answers);
        Ok(resp.to_bytes()?)
    }
}
