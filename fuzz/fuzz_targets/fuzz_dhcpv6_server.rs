#![no_main]
#![allow(clippy::field_reassign_with_default)]

use arbitrary::Arbitrary;
use dhcproto::v6::{DhcpOption, Message, MessageType};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_dhcp::v6::config::Dhcpv6Config;
use lanforge_dhcp::v6::pool::Ipv6Pool;
use lanforge_dhcp::v6::server::{Dhcpv6Server, HandleResult};
use lanforge_types::identifiers::{Duid, MacAddr};
use libfuzzer_sys::fuzz_target;
use std::net::Ipv6Addr;
use std::sync::Arc;

#[derive(Arbitrary, Debug)]
enum FuzzDhcpv6MessageType {
    Solicit,
    Request,
    Confirm,
    Renew,
    Rebind,
    Release,
    Decline,
    InformationRequest,
    RelayForward,
    Unknown(u8),
}

impl From<FuzzDhcpv6MessageType> for MessageType {
    fn from(val: FuzzDhcpv6MessageType) -> Self {
        match val {
            FuzzDhcpv6MessageType::Solicit => Self::Solicit,
            FuzzDhcpv6MessageType::Request => Self::Request,
            FuzzDhcpv6MessageType::Confirm => Self::Confirm,
            FuzzDhcpv6MessageType::Renew => Self::Renew,
            FuzzDhcpv6MessageType::Rebind => Self::Rebind,
            FuzzDhcpv6MessageType::Release => Self::Release,
            FuzzDhcpv6MessageType::Decline => Self::Decline,
            FuzzDhcpv6MessageType::InformationRequest => Self::InformationRequest,
            FuzzDhcpv6MessageType::RelayForward => Self::RelayForw,
            FuzzDhcpv6MessageType::Unknown(v) => Self::Unknown(v),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzStructuredV6Packet {
    msg_type: FuzzDhcpv6MessageType,
    xid: [u8; 3],
    client_duid: Vec<u8>,
    server_duid: Option<Vec<u8>>,
    elapsed_time: Option<u16>,
    rapid_commit: bool,
}

#[derive(Arbitrary, Debug)]
enum FuzzV6InputPacket {
    Raw(Vec<u8>),
    Structured(FuzzStructuredV6Packet),
}

#[derive(Arbitrary, Debug)]
struct FuzzDhcpv6ServerInput {
    client_mac: Option<[u8; 6]>,
    peer_ip: [u8; 16],
    packets: Vec<FuzzV6InputPacket>,
}

fuzz_target!(|input: FuzzDhcpv6ServerInput| {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus, state, None);

    let ula_prefix = Ipv6Addr::new(0xfd00, 0x1234, 0x5678, 0x0001, 0, 0, 0, 0);
    let mut cfg = Dhcpv6Config::default();
    cfg.ula_prefix = Some(ula_prefix);
    cfg.ula_prefix_len = 64;

    let pool = Ipv6Pool::new(&cfg.pools, cfg.ula_prefix, cfg.ula_prefix_len);
    let server_mac = [0x02, 0x00, 0x00, 0x11, 0x22, 0x33];
    let server_duid = Duid::generate_ll_from_mac(&server_mac);

    let mut server = Dhcpv6Server::new(cfg, pool, server_duid, ctx);
    let peer_addr = Ipv6Addr::from(input.peer_ip);
    let resolved_mac = input.client_mac.map(MacAddr);

    let mut resp_vec = Vec::with_capacity(1024);

    for pkt in input.packets {
        resp_vec.clear();
        match pkt {
            FuzzV6InputPacket::Raw(bytes) => {
                if let Ok(msg) = Message::decode(&mut Decoder::new(&bytes)) {
                    let handle_res =
                        server.handle_packet(&msg, peer_addr, resolved_mac, &mut resp_vec);
                    if let HandleResult::Reply(reply_bytes, ..) = handle_res {
                        // Ensure generated reply is valid decodable wire DHCPv6
                        let _ = Message::decode(&mut Decoder::new(reply_bytes));
                    }
                }
            }
            FuzzV6InputPacket::Structured(s) => {
                let mut msg = Message::default();
                msg.set_msg_type(MessageType::from(s.msg_type));
                msg.set_xid(s.xid);

                let opts = msg.opts_mut();
                if !s.client_duid.is_empty() {
                    opts.insert(DhcpOption::ClientId(s.client_duid));
                }
                if let Some(s_duid) = s.server_duid {
                    opts.insert(DhcpOption::ServerId(s_duid));
                }
                if let Some(elapsed) = s.elapsed_time {
                    opts.insert(DhcpOption::ElapsedTime(elapsed));
                }
                if s.rapid_commit {
                    opts.insert(DhcpOption::RapidCommit);
                }

                // Encode message to wire bytes
                let mut encoded = Vec::new();
                let mut enc = Encoder::new(&mut encoded);
                if msg.encode(&mut enc).is_ok() {
                    let handle_res =
                        server.handle_packet(&msg, peer_addr, resolved_mac, &mut resp_vec);
                    if let HandleResult::Reply(reply_bytes, ..) = handle_res {
                        let _ = Message::decode(&mut Decoder::new(reply_bytes));
                    }
                }
            }
        }
    }
});
