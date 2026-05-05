//! DNS response message builder.
//!
//! Constructs DNS response messages using Hickory-DNS `Message` for
//! correctness and EDNS compatibility.

use crate::{error::DnsError, wire::WireOptScanner};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::SOA},
    serialize::binary::BinEncodable,
};

use crate::server::DnsContext;

/// Metadata required to construct a DNS response.
#[derive(Clone)]
pub enum QueryMetadata<'a> {
    Full(&'a Message),
    Wire {
        id: u16,
        qname: Name,
        qtype: RecordType,
        edns: Option<WireOptScanner>,
    },
}

/// Builder for DNS response messages.
///
/// Wraps a query message or its metadata and configuration to produce properly
/// formatted DNS responses with correct flags, EDNS preservation, and SOA records.
#[derive(Clone)]
pub struct ResponseBuilder<'a> {
    query: QueryMetadata<'a>,
    ctx: &'a DnsContext,
}

impl<'a> ResponseBuilder<'a> {
    /// Creates a new response builder from the given query and config.
    #[must_use]
    pub const fn new(query: &'a Message, ctx: &'a DnsContext) -> Self {
        Self {
            query: QueryMetadata::Full(query),
            ctx,
        }
    }

    /// Creates a new response builder from wire-parsed metadata.
    #[must_use]
    pub const fn from_wire(
        id: u16,
        qname: Name,
        qtype: RecordType,
        edns: Option<WireOptScanner>,
        ctx: &'a DnsContext,
    ) -> Self {
        Self {
            query: QueryMetadata::Wire {
                id,
                qname,
                qtype,
                edns,
            },
            ctx,
        }
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
        match &self.query {
            QueryMetadata::Full(query) => {
                let mut resp =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                resp.metadata.authoritative = true;
                resp.metadata.recursion_available = !self.ctx.upstreams.is_empty();
                resp.add_queries(query.queries.iter().cloned());
                if let Some(edns) = &query.edns {
                    resp.set_edns(edns.clone());
                }
                resp
            }
            QueryMetadata::Wire {
                id,
                qname,
                qtype,
                edns,
            } => {
                let mut resp = Message::new(*id, MessageType::Response, OpCode::Query);
                resp.metadata.authoritative = true;
                resp.metadata.recursion_available = !self.ctx.upstreams.is_empty();
                resp.add_query(Query::query(qname.clone(), *qtype));
                if let Some(scanner) = edns {
                    let mut opt = Edns::new();
                    opt.set_max_payload(scanner.max_payload);
                    resp.set_edns(opt);
                }
                resp
            }
        }
    }

    /// Adds an SOA (Start of Authority) record to the authority section.
    ///
    /// Required for NXDOMAIN and NODATA responses per RFC 1035.
    pub fn add_soa(&self, resp: &mut Message) {
        resp.authorities.push(Record::from_rdata(
            self.ctx.soa_zone.clone(),
            3600,
            RData::SOA(SOA::new(
                self.ctx.soa_master_ns.clone(),
                self.ctx.soa_mailbox.clone(),
                1,
                7200,
                3600,
                1_209_600,
                3600,
            )),
        ));
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

    /// Returns the QNAME of the query.
    #[must_use]
    pub fn qname(&self) -> &Name {
        match &self.query {
            QueryMetadata::Full(query) => query
                .queries
                .first()
                .map(Query::name)
                .expect("Malformed query: no question section"),
            QueryMetadata::Wire { qname, .. } => qname,
        }
    }
}
