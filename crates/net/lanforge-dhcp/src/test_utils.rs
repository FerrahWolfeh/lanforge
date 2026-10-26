use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use dhcproto::v4::{
    DhcpOption as Dhcpv4Option, Message as MessageV4, MessageType as MessageTypeV4,
};
use dhcproto::v6::{
    DhcpOption as Dhcpv6Option, DhcpOptions as Dhcpv6Options, IANA, Message as MessageV6,
    MessageType as MessageTypeV6,
};
use dhcproto::{Encodable, Encoder};
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_types::identifiers::{Duid, MacAddr};
use lanforge_types::network::dhcp::{Dhcpv4Pool, Dhcpv6Pool};
use lanforge_types::update::{DeviceUpdate, InterfaceState};

use crate::v4::Dhcpv4Config;
use crate::v6::Dhcpv6Config;

/// Initializes a fresh isolated `LanforgeContext` for testing.
#[must_use]
pub fn init_test_context() -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    LanforgeContext::new(bus, table, None)
}

/// Initializes an isolated `LanforgeContext` with interface state configured.
#[must_use]
pub fn init_test_context_with_interface(
    ifindex: u32,
    iface_name: &str,
    mac: MacAddr,
) -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    let ctx = LanforgeContext::new(bus, table, Some(ifindex));
    ctx.set_target_interface_name(iface_name.to_string());

    let ula = "fd97:f00d:cafe:3731::".parse::<Ipv6Addr>().unwrap();

    let state = InterfaceState {
        v4: Some((Ipv4Addr::new(192, 168, 1, 1), 24)),
        link_local: Some("fe80::1".parse().unwrap()),
        gua: None,
        ula: Some(ula),
        gua_preferred: 3600,
        gua_valid: 3600,
        mac: Some(mac),
    };

    let _ = ctx.apply(DeviceUpdate::InterfaceIpsChanged {
        ifindex,
        state: Box::new(state),
    });
    ctx
}

/// Returns a standard test configuration for `Dhcpv4Service`.
#[must_use]
pub fn create_test_v4_config() -> Dhcpv4Config {
    Dhcpv4Config {
        enabled: true,
        iface: "lan0".into(),
        server_id: Ipv4Addr::new(192, 168, 1, 1),
        lease_time: 3600,
        router: Ipv4Addr::new(192, 168, 1, 1),
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        dns: vec![Ipv4Addr::new(192, 168, 1, 1)],
        domain_name: Some("lan".to_string()),
        pools: vec![Dhcpv4Pool {
            name: Some("Primary LAN Scope".to_string()),
            range_start: Ipv4Addr::new(192, 168, 1, 100),
            range_end: Ipv4Addr::new(192, 168, 1, 200),
            lease_time: Some(3600),
            router: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns_servers: vec![Ipv4Addr::new(192, 168, 1, 1)],
            domain_name: Some("lan".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// Returns a standard test configuration for `Dhcpv6Service`.
#[must_use]
pub fn create_test_v6_config() -> Dhcpv6Config {
    let ula = "fd97:f00d:cafe:3731::".parse::<Ipv6Addr>().unwrap();
    let start = "fd97:f00d:cafe:3731::100".parse::<Ipv6Addr>().unwrap();
    let end = "fd97:f00d:cafe:3731::200".parse::<Ipv6Addr>().unwrap();

    Dhcpv6Config {
        enabled: true,
        iface: "lan0".to_string(),
        lease_time: 86400,
        ula_prefix: Some(ula),
        ula_prefix_len: 64,
        port: 547,
        pools: vec![Dhcpv6Pool {
            name: Some("Primary IPv6 Scope".to_string()),
            range_start: Some(lanforge_types::device::Ipv6AddrOrSuffix::Full(start)),
            range_end: Some(lanforge_types::device::Ipv6AddrOrSuffix::Full(end)),
            ..Default::default()
        }],
        dns_servers: vec![ula],
        search_domains: vec!["lan".to_string()],
        boot_file: None,
        options: std::collections::HashMap::new(),
        ntp_servers: Vec::new(),
    }
}

/// Fluent builder for constructing synthetic `DHCPv4` client packets.
#[derive(Debug, Clone)]
pub struct Dhcpv4PacketBuilder {
    msg_type: MessageTypeV4,
    mac: MacAddr,
    ciaddr: Ipv4Addr,
    requested_ip: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
    hostname: Option<String>,
    broadcast: bool,
}

impl Dhcpv4PacketBuilder {
    #[must_use]
    pub fn discover(mac: MacAddr) -> Self {
        Self {
            msg_type: MessageTypeV4::Discover,
            mac,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            requested_ip: None,
            server_id: None,
            hostname: None,
            broadcast: false,
        }
    }

    #[must_use]
    pub fn request(mac: MacAddr, requested_ip: Ipv4Addr, server_id: Ipv4Addr) -> Self {
        Self {
            msg_type: MessageTypeV4::Request,
            mac,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            requested_ip: Some(requested_ip),
            server_id: Some(server_id),
            hostname: None,
            broadcast: false,
        }
    }

    #[must_use]
    pub fn decline(mac: MacAddr, declined_ip: Ipv4Addr, server_id: Ipv4Addr) -> Self {
        Self {
            msg_type: MessageTypeV4::Decline,
            mac,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            requested_ip: Some(declined_ip),
            server_id: Some(server_id),
            hostname: None,
            broadcast: false,
        }
    }

    #[must_use]
    pub fn release(mac: MacAddr, client_ip: Ipv4Addr, server_id: Ipv4Addr) -> Self {
        Self {
            msg_type: MessageTypeV4::Release,
            mac,
            ciaddr: client_ip,
            requested_ip: None,
            server_id: Some(server_id),
            hostname: None,
            broadcast: false,
        }
    }

    #[must_use]
    pub fn with_hostname(mut self, hostname: &str) -> Self {
        self.hostname = Some(hostname.to_string());
        self
    }

    #[must_use]
    pub const fn with_ciaddr(mut self, ciaddr: Ipv4Addr) -> Self {
        self.ciaddr = ciaddr;
        self
    }

    #[must_use]
    pub const fn with_broadcast(mut self, broadcast: bool) -> Self {
        self.broadcast = broadcast;
        self
    }

    #[must_use]
    pub fn build_message(&self) -> MessageV4 {
        let mut msg = MessageV4::new(
            self.ciaddr,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            &self.mac.0,
        );
        if self.broadcast {
            msg.set_flags(dhcproto::v4::Flags::default().set_broadcast());
        }
        msg.opts_mut()
            .insert(Dhcpv4Option::MessageType(self.msg_type));

        if let Some(req_ip) = self.requested_ip {
            msg.opts_mut()
                .insert(Dhcpv4Option::RequestedIpAddress(req_ip));
        }
        if let Some(srv) = self.server_id {
            msg.opts_mut().insert(Dhcpv4Option::ServerIdentifier(srv));
        }
        if let Some(ref host) = self.hostname {
            msg.opts_mut().insert(Dhcpv4Option::Hostname(host.clone()));
        }

        msg
    }

    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let msg = self.build_message();
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        msg.encode(&mut enc)
            .expect("Failed to encode DHCPv4 test message");
        buf
    }
}

/// Fluent builder for constructing synthetic `DHCPv6` client packets.
#[derive(Debug, Clone)]
pub struct Dhcpv6PacketBuilder {
    msg_type: MessageTypeV6,
    client_duid: Duid,
    server_duid: Option<Duid>,
    ia_na: Option<(u32, Option<Ipv6Addr>)>,
    rapid_commit: bool,
}

impl Dhcpv6PacketBuilder {
    #[must_use]
    pub const fn solicit(client_duid: Duid) -> Self {
        Self {
            msg_type: MessageTypeV6::Solicit,
            client_duid,
            server_duid: None,
            ia_na: Some((1, None)),
            rapid_commit: false,
        }
    }

    #[must_use]
    pub const fn request(client_duid: Duid, server_duid: Duid) -> Self {
        Self {
            msg_type: MessageTypeV6::Request,
            client_duid,
            server_duid: Some(server_duid),
            ia_na: Some((1, None)),
            rapid_commit: false,
        }
    }

    #[must_use]
    pub const fn release(client_duid: Duid, server_duid: Duid) -> Self {
        Self {
            msg_type: MessageTypeV6::Release,
            client_duid,
            server_duid: Some(server_duid),
            ia_na: Some((1, None)),
            rapid_commit: false,
        }
    }

    #[must_use]
    pub const fn with_ia_na(mut self, iaid: u32, ip: Option<Ipv6Addr>) -> Self {
        self.ia_na = Some((iaid, ip));
        self
    }

    #[must_use]
    pub const fn with_rapid_commit(mut self, rapid_commit: bool) -> Self {
        self.rapid_commit = rapid_commit;
        self
    }

    #[must_use]
    pub fn build_message(&self) -> MessageV6 {
        let mut msg = MessageV6::new(self.msg_type);
        msg.opts_mut()
            .insert(Dhcpv6Option::ClientId(self.client_duid.as_bytes().to_vec()));

        if let Some(ref srv) = self.server_duid {
            msg.opts_mut()
                .insert(Dhcpv6Option::ServerId(srv.as_bytes().to_vec()));
        }

        if let Some((iaid, maybe_ip)) = self.ia_na {
            let mut opts = Dhcpv6Options::new();
            if let Some(ip) = maybe_ip {
                opts.insert(Dhcpv6Option::IAAddr(dhcproto::v6::IAAddr {
                    addr: ip,
                    preferred_life: 0,
                    valid_life: 0,
                    opts: Dhcpv6Options::new(),
                }));
            }
            msg.opts_mut().insert(Dhcpv6Option::IANA(IANA {
                id: iaid,
                t1: 0,
                t2: 0,
                opts,
            }));
        }

        if self.rapid_commit {
            msg.opts_mut().insert(Dhcpv6Option::RapidCommit);
        }

        msg
    }

    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let msg = self.build_message();
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        msg.encode(&mut enc)
            .expect("Failed to encode DHCPv6 test message");
        buf
    }
}
