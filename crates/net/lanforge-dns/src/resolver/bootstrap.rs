//! Upstreams given by host name (`tls://dns.google`) are looked up through the bootstrap
//! resolvers (`[dns] bootstrap`): plain DNS over UDP, never through the system resolver, which can
//! be this DNS itself.

use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use lanforge_dns_wire::{WireDecoder, WireEncoder};
use lanforge_types::network::dns::{
    DnsClass, DnsHeader, DnsMessage, DnsQuestion, DnsRData, DnsRecordType,
};
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout_at};

use crate::error::DnsError;

/// How long one bootstrap resolver gets to answer both queries before the next is tried.
const PER_SERVER: Duration = Duration::from_millis(1500);

/// The addresses `name` has, IPv4 first, from the first bootstrap resolver that answers with
/// any.
pub async fn lookup(name: &str, servers: &[SocketAddr]) -> Result<Vec<IpAddr>, DnsError> {
    let mut last = DnsError::Generic("no bootstrap resolver configured".into());
    for &server in servers {
        match lookup_at(name, server).await {
            Ok(addrs) if !addrs.is_empty() => return Ok(addrs),
            Ok(_) => last = DnsError::Generic(format!("{server} has no address for {name}")),
            Err(e) => last = DnsError::Generic(format!("bootstrap {server}: {e}")),
        }
    }
    Err(last)
}

fn query(id: u16, name: &str, qtype: DnsRecordType) -> Vec<u8> {
    WireEncoder::new().encode_message(&DnsMessage {
        header: DnsHeader {
            id,
            rd: true,
            qdcount: 1,
            ..DnsHeader::default()
        },
        questions: vec![DnsQuestion {
            name: Arc::from(name),
            qtype,
            qclass: DnsClass::IN,
        }],
        ..DnsMessage::default()
    })
}

/// Asks `server` for `name`'s A and AAAA records at once and waits for both answers.
async fn lookup_at(name: &str, server: SocketAddr) -> Result<Vec<IpAddr>, DnsError> {
    let bind: SocketAddr = if server.is_ipv4() {
        (IpAddr::from([0u8; 4]), 0).into()
    } else {
        (IpAddr::from([0u16; 8]), 0).into()
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(server).await?;
    // Unpredictable IDs on a random source port: an off-path answer must guess both.
    let id = (RandomState::new().hash_one(name) & 0xfffe) as u16;
    socket.send(&query(id, name, DnsRecordType::A)).await?;
    socket
        .send(&query(id | 1, name, DnsRecordType::AAAA))
        .await?;

    let deadline = Instant::now() + PER_SERVER;
    let (mut v4, mut v6) = (None::<Vec<IpAddr>>, None::<Vec<IpAddr>>);
    let mut buf = [0u8; 1500];
    while v4.is_none() || v6.is_none() {
        let len = timeout_at(deadline, socket.recv(&mut buf))
            .await
            .map_err(|_| DnsError::UpstreamTimeout)??;
        let Some(msg) = WireDecoder::new(&buf[..len]).decode_message() else {
            continue;
        };
        let asked = msg
            .questions
            .first()
            .is_some_and(|q| q.name.trim_end_matches('.').eq_ignore_ascii_case(name));
        if !msg.header.qr || msg.header.id & 0xfffe != id || !asked {
            continue;
        }
        let addrs = msg
            .answers
            .iter()
            .filter_map(|r| match r.rdata {
                DnsRData::A(ip) => Some(IpAddr::V4(ip)),
                DnsRData::AAAA(ip) => Some(IpAddr::V6(ip)),
                _ => None,
            })
            .collect();
        if msg.header.id == id {
            v4 = Some(addrs);
        } else {
            v6 = Some(addrs);
        }
    }
    Ok(v4.into_iter().chain(v6).flatten().collect())
}
