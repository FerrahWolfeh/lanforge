#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use lanforge_core::bus::EventBus;
use lanforge_core::context::state::State;
use lanforge_core::context::LanforgeContext;
use lanforge_dhcp::v4::config::Dhcpv4Config;
use lanforge_dhcp::v4::server::{DhcpServer, HandleResult};

use dhcproto::v4::{self, DhcpOption, HType, Message, MessageType, Opcode, UnknownOption};
use dhcproto::Encodable;

#[derive(Arbitrary, Debug)]
enum FuzzMessageType {
    Discover,
    Request,
    Release,
    Decline,
    Inform,
    Nak,
    Offer,
    Ack,
    ForceRenew,
    Unknown(u8),
}

impl From<FuzzMessageType> for MessageType {
    fn from(val: FuzzMessageType) -> Self {
        match val {
            FuzzMessageType::Discover => MessageType::Discover,
            FuzzMessageType::Request => MessageType::Request,
            FuzzMessageType::Release => MessageType::Release,
            FuzzMessageType::Decline => MessageType::Decline,
            FuzzMessageType::Inform => MessageType::Inform,
            FuzzMessageType::Nak => MessageType::Nak,
            FuzzMessageType::Offer => MessageType::Offer,
            FuzzMessageType::Ack => MessageType::Ack,
            FuzzMessageType::ForceRenew => MessageType::ForceRenew,
            FuzzMessageType::Unknown(v) => MessageType::Unknown(v),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum FuzzOpcode {
    BootRequest,
    BootReply,
    Unknown(u8),
}

impl From<FuzzOpcode> for Opcode {
    fn from(val: FuzzOpcode) -> Self {
        match val {
            FuzzOpcode::BootRequest => Opcode::BootRequest,
            FuzzOpcode::BootReply => Opcode::BootReply,
            FuzzOpcode::Unknown(v) => Opcode::Unknown(v),
        }
    }
}

#[derive(Arbitrary, Debug)]
struct FuzzDhcpOption {
    code: u8,
    data: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct FuzzDhcpPacket {
    opcode: FuzzOpcode,
    htype: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: [u8; 4],
    yiaddr: [u8; 4],
    siaddr: [u8; 4],
    giaddr: [u8; 4],
    chaddr: Vec<u8>,
    sname: String,
    file: String,
    msg_type: FuzzMessageType,
    req_ip: Option<[u8; 4]>,
    server_id: Option<[u8; 4]>,
    custom_options: Vec<FuzzDhcpOption>,
}

#[derive(Arbitrary, Debug)]
struct FuzzDhcpServerInput {
    lease_time: u32,
    range_start: [u8; 4],
    range_end: [u8; 4],
    router: [u8; 4],
    dns: Vec<[u8; 4]>,
    subnet_mask: [u8; 4],
    server_id: [u8; 4],
    packets: Vec<FuzzDhcpPacket>,
}

fuzz_target!(|input: FuzzDhcpServerInput| {
    // 1. Setup events, state, context
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus, state, None);

    // 2. Setup config
    let cfg = Dhcpv4Config {
        enabled: true,
        iface: "eth0".to_string(),
        server_id: Ipv4Addr::from(input.server_id),
        range_start: Some(Ipv4Addr::from(input.range_start)),
        range_end: Some(Ipv4Addr::from(input.range_end)),
        pools: Vec::new(),
        lease_time: input.lease_time,
        router: Ipv4Addr::from(input.router),
        dns: input.dns.into_iter().map(Ipv4Addr::from).collect(),
        subnet_mask: Ipv4Addr::from(input.subnet_mask),
        domain_name: Some("lanforge.local".to_string()),
        search_domains: vec!["lanforge.local".to_string()],
        port: 67,
        tftp_server: None,
        boot_file: None,
        options: HashMap::new(),
    };

    let mut server = DhcpServer::new(cfg, ctx);

    // 3. Process packets
    for fuzz_pkt in input.packets {
        // Build dhcproto::v4::Message
        let mut msg = Message::default();
        msg.set_opcode(Opcode::from(fuzz_pkt.opcode));
        msg.set_htype(match fuzz_pkt.htype % 2 {
            0 => HType::Eth,
            _ => HType::Unknown(fuzz_pkt.htype),
        });
        msg.set_xid(fuzz_pkt.xid);
        msg.set_secs(fuzz_pkt.secs);
        msg.set_flags(dhcproto::v4::Flags::from(fuzz_pkt.flags));
        msg.set_ciaddr(Ipv4Addr::from(fuzz_pkt.ciaddr));
        msg.set_yiaddr(Ipv4Addr::from(fuzz_pkt.yiaddr));
        msg.set_siaddr(Ipv4Addr::from(fuzz_pkt.siaddr));
        msg.set_giaddr(Ipv4Addr::from(fuzz_pkt.giaddr));
        msg.set_chaddr(&fuzz_pkt.chaddr);
        msg.set_sname(fuzz_pkt.sname.as_bytes());
        // msg.set_file(fuzz_pkt.file);

        let opts = msg.opts_mut();
        opts.insert(DhcpOption::MessageType(MessageType::from(
            fuzz_pkt.msg_type,
        )));

        if let Some(req) = fuzz_pkt.req_ip {
            opts.insert(DhcpOption::RequestedIpAddress(Ipv4Addr::from(req)));
        }
        if let Some(sid) = fuzz_pkt.server_id {
            opts.insert(DhcpOption::ServerIdentifier(Ipv4Addr::from(sid)));
        }

        for opt in fuzz_pkt.custom_options {
            opts.insert(DhcpOption::Unknown(UnknownOption::new(
                opt.code.into(),
                opt.data,
            )));
        }

        // Encode Message to raw bytes
        let mut encoded = Vec::new();
        let mut enc = dhcproto::Encoder::new(&mut encoded);
        if msg.encode(&mut enc).is_ok() {
            // Feed to server
            let _ = server.handle_packet(&encoded, None);
        }
    }
});
