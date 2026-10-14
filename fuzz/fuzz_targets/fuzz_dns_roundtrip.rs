#![no_main]
#![allow(clippy::upper_case_acronyms)]

use arbitrary::Arbitrary;
use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::network::dns::{DnsSoaData, DnsSvcbData};
use lanforge_types::network::{
    DnsClass, DnsHeader, DnsMessage, DnsQuestion, DnsRData, DnsRecord, DnsRecordType,
    DnsResponseCode,
};
use libfuzzer_sys::fuzz_target;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

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
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    YXDomain,
    YXRRSet,
    NXRRSet,
    NotAuth,
    NotZone,
    BADVERS,
    Unknown(u8),
}

impl From<FuzzDnsResponseCode> for DnsResponseCode {
    fn from(val: FuzzDnsResponseCode) -> Self {
        match val {
            FuzzDnsResponseCode::NoError => Self::NoError,
            FuzzDnsResponseCode::FormErr => Self::FormErr,
            FuzzDnsResponseCode::ServFail => Self::ServFail,
            FuzzDnsResponseCode::NXDomain => Self::NXDomain,
            FuzzDnsResponseCode::NotImp => Self::NotImp,
            FuzzDnsResponseCode::Refused => Self::Refused,
            FuzzDnsResponseCode::YXDomain => Self::YXDomain,
            FuzzDnsResponseCode::YXRRSet => Self::YXRRSet,
            FuzzDnsResponseCode::NXRRSet => Self::NXRRSet,
            FuzzDnsResponseCode::NotAuth => Self::NotAuth,
            FuzzDnsResponseCode::NotZone => Self::NotZone,
            FuzzDnsResponseCode::BADVERS => Self::BADVERS,
            FuzzDnsResponseCode::Unknown(v) => Self::Unknown(v),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum FuzzDnsRecordType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    HINFO,
    MX,
    TXT,
    AAAA,
    SRV,
    OPT,
    SVCB,
    HTTPS,
    ANY,
    Unknown(u16),
}

impl From<FuzzDnsRecordType> for DnsRecordType {
    fn from(val: FuzzDnsRecordType) -> Self {
        match val {
            FuzzDnsRecordType::A => Self::A,
            FuzzDnsRecordType::NS => Self::NS,
            FuzzDnsRecordType::CNAME => Self::CNAME,
            FuzzDnsRecordType::SOA => Self::SOA,
            FuzzDnsRecordType::PTR => Self::PTR,
            FuzzDnsRecordType::HINFO => Self::HINFO,
            FuzzDnsRecordType::MX => Self::MX,
            FuzzDnsRecordType::TXT => Self::TXT,
            FuzzDnsRecordType::AAAA => Self::AAAA,
            FuzzDnsRecordType::SRV => Self::SRV,
            FuzzDnsRecordType::OPT => Self::OPT,
            FuzzDnsRecordType::SVCB => Self::SVCB,
            FuzzDnsRecordType::HTTPS => Self::HTTPS,
            FuzzDnsRecordType::ANY => Self::ANY,
            FuzzDnsRecordType::Unknown(v) => Self::Unknown(v),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum FuzzDnsClass {
    IN,
    CS,
    CH,
    HS,
    ANY,
    Unknown(u16),
}

impl From<FuzzDnsClass> for DnsClass {
    fn from(val: FuzzDnsClass) -> Self {
        match val {
            FuzzDnsClass::IN => Self::IN,
            FuzzDnsClass::CS => Self::CS,
            FuzzDnsClass::CH => Self::CH,
            FuzzDnsClass::HS => Self::HS,
            FuzzDnsClass::ANY => Self::ANY,
            FuzzDnsClass::Unknown(v) => Self::Unknown(v),
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
            FuzzDnsRData::A(ip) => Self::A(Ipv4Addr::from(ip)),
            FuzzDnsRData::AAAA(ip) => Self::AAAA(Ipv6Addr::from(ip)),
            FuzzDnsRData::CNAME(s) => Self::CNAME(Arc::from(s)),
            FuzzDnsRData::PTR(s) => Self::PTR(Arc::from(s)),
            FuzzDnsRData::MX {
                preference,
                exchange,
            } => Self::MX {
                preference,
                exchange: Arc::from(exchange),
            },
            FuzzDnsRData::NS(s) => Self::NS(Arc::from(s)),
            FuzzDnsRData::TXT(list) => Self::TXT(list.into_iter().map(Arc::from).collect()),
            FuzzDnsRData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => Self::SOA(Box::new(DnsSoaData {
                mname: Arc::from(mname),
                rname: Arc::from(rname),
                serial,
                refresh,
                retry,
                expire,
                minimum,
            })),
            FuzzDnsRData::SRV {
                priority,
                weight,
                port,
                target,
            } => Self::SRV {
                priority,
                weight,
                port,
                target: Arc::from(target),
            },
            FuzzDnsRData::OPT { options } => Self::OPT { options },
            FuzzDnsRData::HTTPS {
                svc_priority,
                svc_domain,
                params,
            } => Self::HTTPS(Box::new(DnsSvcbData {
                svc_priority,
                svc_domain: Arc::from(svc_domain),
                params,
            })),
            FuzzDnsRData::SVCB {
                svc_priority,
                svc_domain,
                params,
            } => Self::SVCB(Box::new(DnsSvcbData {
                svc_priority,
                svc_domain: Arc::from(svc_domain),
                params,
            })),
            FuzzDnsRData::Unknown(bytes) => Self::Unknown(bytes),
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
        Self {
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
        Self {
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
    if let Some(decoded_msg) = decoder.decode_message() {
        let owned = decoded_msg.to_owned();
        // Re-encode decoded message: ensures encoder never panics on valid decoded messages
        let mut re_encoder = WireEncoder::new();
        let _re_encoded = re_encoder.encode_message(&owned);
    }
});
