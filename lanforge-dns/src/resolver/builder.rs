//! DNS response message builder.

use crate::error::DnsError;
use crate::server::DnsContext;
use crate::wire::{WireEncoder, WireOptScanner};
use lanforge_types::network::dns::{
    DnsClass, DnsMessage, DnsQuestion, DnsRData, DnsRecord, DnsRecordType, DnsResponseCode,
};
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Clone)]
pub enum QueryMetadata<'a> {
    Full(&'a DnsMessage),
    Wire {
        id: u16,
        qname: Arc<str>,
        qtype: DnsRecordType,
        edns: Option<WireOptScanner>,
    },
}

#[derive(Clone)]
pub struct ResponseBuilder<'a> {
    query: QueryMetadata<'a>,
    ctx: &'a DnsContext,
}

impl<'a> ResponseBuilder<'a> {
    #[must_use]
    pub const fn new(query: &'a DnsMessage, ctx: &'a DnsContext) -> Self {
        Self {
            query: QueryMetadata::Full(query),
            ctx,
        }
    }

    #[must_use]
    pub fn from_wire(
        id: u16,
        qname: Arc<str>,
        qtype: DnsRecordType,
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

    #[must_use]
    pub fn base(&self) -> DnsMessage {
        match &self.query {
            QueryMetadata::Full(query) => {
                let mut resp = DnsMessage::new();
                resp.header = query.header.clone();
                resp.header.qr = true;
                resp.header.aa = true;
                resp.header.ra = !self.ctx.recursive.is_empty();
                resp.header.ancount = 0;
                resp.header.nscount = 0;
                resp.header.arcount = 0;
                resp.questions = query.questions.clone();

                // Carry over EDNS if present
                if let Some(opt) = query
                    .additionals
                    .iter()
                    .find(|r| r.rtype == DnsRecordType::OPT)
                {
                    resp.additionals.push(opt.clone());
                    resp.header.arcount = 1;
                }

                resp
            }
            QueryMetadata::Wire {
                id,
                qname,
                qtype,
                edns,
            } => {
                let mut resp = DnsMessage::new();
                resp.header.id = *id;
                resp.header.qr = true;
                resp.header.aa = true;
                resp.header.ra = !self.ctx.recursive.is_empty();
                resp.header.qdcount = 1;
                resp.questions.push(DnsQuestion {
                    name: qname.clone(),
                    qtype: *qtype,
                    qclass: DnsClass::IN,
                });

                if let Some(scanner) = edns {
                    resp.additionals.push(DnsRecord {
                        name: Arc::from(""),
                        rtype: DnsRecordType::OPT,
                        rclass: DnsClass::Unknown(scanner.max_payload),
                        ttl: 0,
                        rdata: DnsRData::OPT {
                            options: Vec::new(),
                        },
                    });
                    resp.header.arcount = 1;
                }
                resp
            }
        }
    }

    pub fn add_soa(&self, resp: &mut DnsMessage) {
        resp.authorities.push(DnsRecord {
            name: self.ctx.soa_zone.clone(),
            rtype: DnsRecordType::SOA,
            rclass: DnsClass::IN,
            ttl: 3600,
            rdata: DnsRData::SOA {
                mname: self.ctx.soa_master_ns.clone(),
                rname: self.ctx.soa_mailbox.clone(),
                serial: 1,
                refresh: 7200,
                retry: 3600,
                expire: 1_209_600,
                minimum: 3600,
            },
        });
        resp.header.nscount += 1;
    }

    pub fn nxdomain(&self) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.header.rcode = DnsResponseCode::NXDomain;
        self.add_soa(&mut resp);
        let mut encoder = WireEncoder::new();
        Ok(encoder.encode_message(&resp))
    }

    pub fn refused(&self) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.header.rcode = DnsResponseCode::Refused;
        let mut encoder = WireEncoder::new();
        Ok(encoder.encode_message(&resp))
    }

    pub fn empty_noerror(&self) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.header.rcode = DnsResponseCode::NoError;
        self.add_soa(&mut resp);
        let mut encoder = WireEncoder::new();
        Ok(encoder.encode_message(&resp))
    }

    pub fn formerr(&self) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.header.rcode = DnsResponseCode::FormErr;
        let mut encoder = WireEncoder::new();
        Ok(encoder.encode_message(&resp))
    }

    pub fn success_ips(&self, ips: impl IntoIterator<Item = IpAddr>) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        let qname = self.qname();
        for ip in ips {
            let (rtype, rdata) = match ip {
                IpAddr::V4(v4) => (DnsRecordType::A, DnsRData::A(v4)),
                IpAddr::V6(v6) => (DnsRecordType::AAAA, DnsRData::AAAA(v6)),
            };
            resp.answers.push(DnsRecord {
                name: qname.clone(),
                rtype,
                rclass: DnsClass::IN,
                ttl: self.ctx.cfg.ttl,
                rdata,
            });
            resp.header.ancount += 1;
        }
        let mut encoder = WireEncoder::new();
        Ok(encoder.encode_message(&resp))
    }

    pub fn success_ptr(&self, host: &str, domain: &str) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        let qname = self.qname();
        let fqdn = format!("{host}.{domain}");
        resp.answers.push(DnsRecord {
            name: qname.clone(),
            rtype: DnsRecordType::PTR,
            rclass: DnsClass::IN,
            ttl: self.ctx.cfg.ttl,
            rdata: DnsRData::PTR(Arc::from(fqdn)),
        });
        resp.header.ancount += 1;
        let mut encoder = WireEncoder::new();
        Ok(encoder.encode_message(&resp))
    }

    pub fn success_cname(&self, target: &str) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        let qname = self.qname();
        resp.answers.push(DnsRecord {
            name: qname.clone(),
            rtype: DnsRecordType::CNAME,
            rclass: DnsClass::IN,
            ttl: self.ctx.cfg.ttl,
            rdata: DnsRData::CNAME(Arc::from(target)),
        });
        resp.header.ancount += 1;
        let mut encoder = WireEncoder::new();
        Ok(encoder.encode_message(&resp))
    }

    pub fn success(&self, answers: Vec<DnsRecord>) -> Result<Vec<u8>, DnsError> {
        let mut resp = self.base();
        resp.header.rcode = DnsResponseCode::NoError;
        resp.header.ancount = answers.len() as u16;
        resp.answers = answers;
        let mut encoder = WireEncoder::new();
        Ok(encoder.encode_message(&resp))
    }

    #[must_use]
    pub fn qname(&self) -> Arc<str> {
        match &self.query {
            QueryMetadata::Full(query) => query
                .questions
                .first()
                .map(|q| q.name.clone())
                .expect("Malformed query"),
            QueryMetadata::Wire { qname, .. } => qname.clone(),
        }
    }
}
