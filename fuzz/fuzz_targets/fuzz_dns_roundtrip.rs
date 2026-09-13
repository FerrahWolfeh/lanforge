#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::sync::Arc;
use std::net::{Ipv4Addr, Ipv6Addr};
use lanforge_dns_wire::{WireEncoder, WireDecoder};
use lanforge_types::network::{
    DnsClass, DnsHeader, DnsMessage, DnsQuestion, DnsRData, DnsRecord, DnsRecordType,
    DnsResponseCode, DnsSoaData, DnsSvcbData,
};

#[derive(Arbitrary, Debug)]
struct FuzzDnsHeader {
    id: u16,
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    z: bool,
    ad: bool,
    cd: bool,
    rcode: FuzzDnsResponseCode,
}

#[derive(Arbitrary, Debug)]
enum FuzzDnsResponseCode {
    NoError, FormErr, ServFail, NXDomain, NotImp, Refused, YXDomain, YXRRSet, NXRRSet, NotAuth, NotZone, BADVERS, Unknown(u8)
}

impl From<FuzzDnsResponseCode> for DnsResponseCode {
    fn from(val: FuzzDnsResponseCode) -> Self {
        match val {
            FuzzDnsResponseCode::NoError => DnsResponseCode::NoError,
            FuzzDnsResponseCode::FormErr => DnsResponseCode::FormErr,
            FuzzDnsResponseCode::ServFail => DnsResponseCode::ServFail,
            FuzzDnsResponseCode::NXDomain => DnsResponseCode::NXDomain,
            FuzzDnsResponseCode::NotImp => DnsResponseCode::NotImp,
            FuzzDnsResponseCode::Refused => DnsResponseCode::Refused,
            FuzzDnsResponseCode::YXDomain => DnsResponseCode::YXDomain,
            FuzzDnsResponseCode::YXRRSet => DnsResponseCode::YXRRSet,
            FuzzDnsResponseCode::NXRRSet => DnsResponseCode::NXRRSet,
            FuzzDnsResponseCode::NotAuth => DnsResponseCode::NotAuth,
            FuzzDnsResponseCode::NotZone => DnsResponseCode::NotZone,
            FuzzDnsResponseCode::BADVERS => DnsResponseCode::BADVERS,
            FuzzDnsResponseCode::Unknown(v) => DnsResponseCode::Unknown(v),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum FuzzDnsRecordType {
    A, NS, CNAME, SOA, PTR, HINFO, MX, TXT, AAAA, SRV, OPT, SVCB, HTTPS, ANY, Unknown(u16)
}

impl From<FuzzDnsRecordType> for DnsRecordType {
    fn from(val: FuzzDnsRecordType) -> Self {
        match val {
            FuzzDnsRecordType::A => DnsRecordType::A,
            FuzzDnsRecordType::NS => DnsRecordType::NS,
            FuzzDnsRecordType::CNAME => DnsRecordType::CNAME,
            FuzzDnsRecordType::SOA => DnsRecordType::SOA,
            FuzzDnsRecordType::PTR => DnsRecordType::PTR,
            FuzzDnsRecordType::HINFO => DnsRecordType::HINFO,
            FuzzDnsRecordType::MX => DnsRecordType::MX,
            FuzzDnsRecordType::TXT => DnsRecordType::TXT,
            FuzzDnsRecordType::AAAA => DnsRecordType::AAAA,
            FuzzDnsRecordType::SRV => DnsRecordType::SRV,
            FuzzDnsRecordType::OPT => DnsRecordType::OPT,
            FuzzDnsRecordType::SVCB => DnsRecordType::SVCB,
            FuzzDnsRecordType::HTTPS => DnsRecordType::HTTPS,
            FuzzDnsRecordType::ANY => DnsRecordType::ANY,
            FuzzDnsRecordType::Unknown(v) => DnsRecordType::Unknown(v),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum FuzzDnsClass {
    IN, CS, CH, HS, ANY, Unknown(u16)
}

impl From<FuzzDnsClass> for DnsClass {
    fn from(val: FuzzDnsClass) -> Self {
        match val {
            FuzzDnsClass::IN => DnsClass::IN,
            FuzzDnsClass::CS => DnsClass::CS,
            FuzzDnsClass::CH => DnsClass::CH,
            FuzzDnsClass::HS => DnsClass::HS,
            FuzzDnsClass::ANY => DnsClass::ANY,
            FuzzDnsClass::Unknown(v) => DnsClass::Unknown(v),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum FuzzDnsRData {
    A([u8; 4]),
    AAAA([u8; 16]),
    CNAME(String),
    PTR(String),
    MX {
        preference: u16,
        exchange: String,
    },
    NS(String),
    TXT(Vec<String>),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    OPT {
        options: Vec<(u16, Vec<u8>)>,
    },
    HTTPS {
        svc_priority: u16,
        svc_domain: String,
        params: Vec<(u16, Vec<u8>)>,
    },
    SVCB {
        svc_priority: u16,
        svc_domain: String,
        params: Vec<(u16, Vec<u8>)>,
    },
    Unknown(Vec<u8>),
}

impl From<FuzzDnsRData> for DnsRData {
    fn from(val: FuzzDnsRData) -> Self {
        match val {
            FuzzDnsRData::A(ip) => DnsRData::A(Ipv4Addr::from(ip)),
            FuzzDnsRData::AAAA(ip) => DnsRData::AAAA(Ipv6Addr::from(ip)),
            FuzzDnsRData::CNAME(s) => DnsRData::CNAME(Arc::from(s)),
            FuzzDnsRData::PTR(s) => DnsRData::PTR(Arc::from(s)),
            FuzzDnsRData::MX { preference, exchange } => DnsRData::MX {
                preference,
                exchange: Arc::from(exchange),
            },
            FuzzDnsRData::NS(s) => DnsRData::NS(Arc::from(s)),
            FuzzDnsRData::TXT(list) => DnsRData::TXT(list.into_iter().map(Arc::from).collect()),
            FuzzDnsRData::SOA { mname, rname, serial, refresh, retry, expire, minimum } => DnsRData::SOA(Box::new(DnsSoaData {
                mname: Arc::from(mname),
                rname: Arc::from(rname),
                serial,
                refresh,
                retry,
                expire,
                minimum,
            })),
            FuzzDnsRData::SRV { priority, weight, port, target } => DnsRData::SRV {
                priority,
                weight,
                port,
                target: Arc::from(target),
            },
            FuzzDnsRData::OPT { options } => DnsRData::OPT { options },
            FuzzDnsRData::HTTPS { svc_priority, svc_domain, params } => DnsRData::HTTPS(Box::new(DnsSvcbData {
                svc_priority,
                svc_domain: Arc::from(svc_domain),
                params,
            })),
            FuzzDnsRData::SVCB { svc_priority, svc_domain, params } => DnsRData::SVCB(Box::new(DnsSvcbData {
                svc_priority,
                svc_domain: Arc::from(svc_domain),
                params,
            })),
            FuzzDnsRData::Unknown(bytes) => DnsRData::Unknown(bytes),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzDnsQuestion {
    name: String,
    qtype: FuzzDnsRecordType,
    qclass: FuzzDnsClass,
}

impl From<FuzzDnsQuestion> for DnsQuestion {
    fn from(val: FuzzDnsQuestion) -> Self {
        DnsQuestion {
            name: Arc::from(val.name),
            qtype: DnsRecordType::from(val.qtype),
            qclass: DnsClass::from(val.qclass),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzDnsRecord {
    name: String,
    rtype: FuzzDnsRecordType,
    rclass: FuzzDnsClass,
    ttl: u32,
    rdata: FuzzDnsRData,
}

impl From<FuzzDnsRecord> for DnsRecord {
    fn from(val: FuzzDnsRecord) -> Self {
        DnsRecord {
            name: Arc::from(val.name),
            rtype: DnsRecordType::from(val.rtype),
            rclass: DnsClass::from(val.rclass),
            ttl: val.ttl,
            rdata: DnsRData::from(val.rdata),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzDnsMessage {
    header: FuzzDnsHeader,
    questions: Vec<FuzzDnsQuestion>,
    answers: Vec<FuzzDnsRecord>,
    authorities: Vec<FuzzDnsRecord>,
    additionals: Vec<FuzzDnsRecord>,
}

fuzz_target!(|msg: FuzzDnsMessage| {
    // Construct the actual DnsMessage
    let dns_msg = DnsMessage {
        header: DnsHeader {
            id: msg.header.id,
            qr: msg.header.qr,
            opcode: msg.header.opcode & 0x0F, // only 4 bits
            aa: msg.header.aa,
            tc: msg.header.tc,
            rd: msg.header.rd,
            ra: msg.header.ra,
            z: msg.header.z,
            ad: msg.header.ad,
            cd: msg.header.cd,
            rcode: DnsResponseCode::from(msg.header.rcode),
            qdcount: u16::try_from(msg.questions.len()).unwrap_or(u16::MAX),
            ancount: u16::try_from(msg.answers.len()).unwrap_or(u16::MAX),
            nscount: u16::try_from(msg.authorities.len()).unwrap_or(u16::MAX),
            arcount: u16::try_from(msg.additionals.len()).unwrap_or(u16::MAX),
        },
        questions: msg.questions.into_iter().map(DnsQuestion::from).collect(),
        answers: msg.answers.into_iter().map(DnsRecord::from).collect(),
        authorities: msg.authorities.into_iter().map(DnsRecord::from).collect(),
        additionals: msg.additionals.into_iter().map(DnsRecord::from).collect(),
    };

    // Encode to wire format
    let mut encoder = WireEncoder::new();
    let encoded_bytes = encoder.encode_message(&dns_msg);

    // Decode from wire format
    let mut decoder = WireDecoder::new(&encoded_bytes);
    let decoded_msg = decoder.decode_message();

    if let Some(_decoded) = decoded_msg {
        // Successful roundtrip
    }
});
