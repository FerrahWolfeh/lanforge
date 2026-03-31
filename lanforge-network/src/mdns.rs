use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use lanforge_core::bus::ManagedTable;
use lanforge_core::bus::{EventBus, LanforgeEvent};
use lanforge_core::state::update::DeviceUpdate;

use crate::error::{NetworkError, Result};

const MDNS_PORT: u16 = 5353;
const MDNS_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_IPV6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

pub struct MdnsProber {
    tx: mpsc::Sender<MdnsCommand>,
}

enum MdnsCommand {
    ProbeAll,
    ProbeIp(IpAddr),
}

impl MdnsProber {
    pub fn new(bus: Arc<EventBus>, table: Arc<ManagedTable>) -> Self {
        let (tx, rx) = mpsc::channel(32);
        let bus_clone = bus.clone();
        let table_clone = table.clone();
        let tx_clone = tx.clone();

        tokio::spawn(async move {
            if let Err(e) = run_mdns_worker(bus_clone, table_clone, rx, tx_clone).await {
                error!("mDNS worker fatal error: {e}");
            }
        });

        Self { tx }
    }

    pub async fn trigger_scan(&self) {
        let _ = self.tx.send(MdnsCommand::ProbeAll).await;
    }

    pub async fn probe_ip(&self, ip: IpAddr) {
        let _ = self.tx.send(MdnsCommand::ProbeIp(ip)).await;
    }
}

async fn run_mdns_worker(
    bus: Arc<EventBus>,
    table: Arc<ManagedTable>,
    mut rx: mpsc::Receiver<MdnsCommand>,
    tx: mpsc::Sender<MdnsCommand>,
) -> Result<()> {
    // We bind to a random port to SEND queries, and a fixed port to LISTEN if we want passive,
    // but on Linux, to receive multicast, we usually bind to 5353 with REUSEPORT.
    let socket_v4 = setup_multicast_socket_v4()?;
    let socket_v6 = setup_multicast_socket_v6()?;

    let (resp_tx, mut resp_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100);

    // Spawn listeners
    let socket_v4_clone = socket_v4
        .try_clone()
        .map_err(|e| NetworkError::Socket(e.to_string()))?;
    let resp_tx_v4 = resp_tx.clone();
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            match socket_v4_clone.recv_from(&mut buf) {
                Ok((n, addr)) => {
                    let _ = resp_tx_v4.blocking_send((buf[..n].to_vec(), addr));
                }
                Err(e) => {
                    warn!("mDNS v4 listen error: {e}");
                    break;
                }
            }
        }
    });

    let socket_v6_clone = socket_v6
        .try_clone()
        .map_err(|e| NetworkError::Socket(e.to_string()))?;
    let resp_tx_v6 = resp_tx.clone();
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 4096];
        loop {
            match socket_v6_clone.recv_from(&mut buf) {
                Ok((n, addr)) => {
                    let _ = resp_tx_v6.blocking_send((buf[..n].to_vec(), addr));
                }
                Err(e) => {
                    warn!("mDNS v6 listen error: {e}");
                    break;
                }
            }
        }
    });

    info!("mDNS prober ativo (v4/v6)");

    let mut bus_rx = bus.subscribe();

    loop {
        tokio::select! {
            event = bus_rx.recv() => {
                if let Ok(LanforgeEvent::ScanRequested) = event {
                    let _ = tx.send(MdnsCommand::ProbeAll).await;
                }
            }
            cmd = rx.recv() => {
                match cmd {
                    Some(MdnsCommand::ProbeAll) => {
                        let _ = broadcast_query(&socket_v4, &socket_v6);
                    }
                    Some(MdnsCommand::ProbeIp(ip)) => {
                        let _ = send_unicast_query(&socket_v4, &socket_v6, ip);
                    }
                    None => break,
                }
            }
            resp = resp_rx.recv() => {
                if let Some((data, addr)) = resp {
                    let bus = bus.clone();
                    let table = table.clone();
                    tokio::spawn(async move {
                        handle_mdns_packet(&bus, &table, &data, addr).await;
                    });
                }
            }
        }
    }

    Ok(())
}

fn setup_multicast_socket_v4() -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| NetworkError::Socket(e.to_string()))?;

    socket
        .set_reuse_address(true)
        .map_err(|e| NetworkError::Socket(e.to_string()))?;
    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .map_err(|e| NetworkError::Socket(e.to_string()))?;

    // Bind to all interfaces on 5353
    socket
        .bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MDNS_PORT).into())
        .map_err(|e| NetworkError::Socket(e.to_string()))?;

    // Join multicast on all interfaces
    let interfaces = pnet::datalink::interfaces();
    for iface in interfaces {
        if !iface.is_up() || iface.is_loopback() {
            continue;
        }
        for ip in iface.ips {
            if let IpAddr::V4(v4) = ip.ip() {
                let _ = socket.join_multicast_v4(&MDNS_IPV4, &v4);
            }
        }
    }

    Ok(socket.into())
}

fn setup_multicast_socket_v6() -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| NetworkError::Socket(e.to_string()))?;

    socket
        .set_only_v6(true)
        .map_err(|e| NetworkError::Socket(e.to_string()))?;
    socket
        .set_reuse_address(true)
        .map_err(|e| NetworkError::Socket(e.to_string()))?;
    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .map_err(|e| NetworkError::Socket(e.to_string()))?;

    socket
        .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), MDNS_PORT).into())
        .map_err(|e| NetworkError::Socket(e.to_string()))?;

    let interfaces = pnet::datalink::interfaces();
    for iface in interfaces {
        if !iface.is_up() || iface.is_loopback() {
            continue;
        }
        let _ = socket.join_multicast_v6(&MDNS_IPV6, iface.index);
    }

    Ok(socket.into())
}

fn broadcast_query(sock4: &UdpSocket, sock6: &UdpSocket) -> Result<()> {
    let mut msg = Message::new();
    msg.set_id(0); // mDNS standard
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false);

    // PTR query for _services._dns-sd._udp.local.
    let name = Name::from_ascii("_services._dns-sd._udp.local.")
        .map_err(|e| NetworkError::Mdns(e.to_string()))?;
    msg.add_query(Query::query(name, RecordType::PTR));

    let bytes = msg
        .to_vec()
        .map_err(|e| NetworkError::Mdns(e.to_string()))?;
    let _ = sock4.send_to(&bytes, SocketAddr::new(IpAddr::V4(MDNS_IPV4), MDNS_PORT));
    let _ = sock6.send_to(&bytes, SocketAddr::new(IpAddr::V6(MDNS_IPV6), MDNS_PORT));

    debug!("mDNS broadcast probe enviado");
    Ok(())
}

fn send_unicast_query(sock4: &UdpSocket, sock6: &UdpSocket, target: IpAddr) -> Result<()> {
    let mut msg = Message::new();
    msg.set_id(0);
    msg.set_message_type(MessageType::Query);

    // Most devices respond to a PTR query for their own IP.
    // Example: 1.1.168.192.in-addr.arpa.
    let name = match target {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            Name::from_ascii(format!(
                "{}.{}.{}.{}.in-addr.arpa.",
                octets[3], octets[2], octets[1], octets[0]
            ))
            .map_err(|e| NetworkError::Mdns(e.to_string()))?
        }
        IpAddr::V6(v6) => {
            let mut name_str = String::new();
            for seg in v6.octets().iter().rev() {
                name_str.push_str(&format!("{:x}.{:x}.", seg & 0xf, seg >> 4));
            }
            name_str.push_str("ip6.arpa.");
            Name::from_ascii(name_str).map_err(|e| NetworkError::Mdns(e.to_string()))?
        }
    };

    msg.add_query(Query::query(name, RecordType::PTR));
    let bytes = msg
        .to_vec()
        .map_err(|e| NetworkError::Mdns(e.to_string()))?;

    // We send to the multicast address but some devices might respond unicast if we set the QU bit.
    // For now, simple multicast.
    match target {
        IpAddr::V4(_) => {
            let _ = sock4.send_to(&bytes, SocketAddr::new(IpAddr::V4(MDNS_IPV4), MDNS_PORT));
        }
        IpAddr::V6(_) => {
            let _ = sock6.send_to(&bytes, SocketAddr::new(IpAddr::V6(MDNS_IPV6), MDNS_PORT));
        }
    }

    debug!("mDNS targeted probe enviado para {}", target);
    Ok(())
}

async fn handle_mdns_packet(_bus: &EventBus, table: &ManagedTable, data: &[u8], from: SocketAddr) {
    let Ok(msg) = Message::from_vec(data) else {
        return;
    };
    if msg.message_type() != MessageType::Response {
        return;
    }

    // We look for PTR, SRV, or A/AAAA records that might reveal a hostname.
    // The most reliable is the "Answer" section names or SRV target.
    for record in msg.answers().iter().chain(msg.additionals().iter()) {
        let hostname = match record.data() {
            RData::PTR(name) => Some(name.to_string()),
            RData::SRV(srv) => Some(srv.target().to_string()),
            _ => None,
        };

        if let Some(h) = hostname {
            let clean_host: &str = h.trim_end_matches('.').trim_end_matches(".local");
            if clean_host.is_empty() || clean_host.contains('.') {
                continue;
            }

            // Try to find the MAC for the sender IP
            let mac = {
                let t = table.read();
                t.get_mac_by_ip(from.ip())
            };

            if let Some(mac) = mac {
                // If it already has a hostname, skip update to avoid useless noise
                {
                    let t = table.read();
                    if let Some(dev) = t.get_device(&mac)
                        && !dev.hostname.name.is_empty()
                    {
                        continue;
                    }
                }

                debug!("mDNS descoberta: {} -> {}", from.ip(), clean_host);
                table.update(DeviceUpdate::MdnsHostnameHint {
                    mac,
                    hostname: clean_host.to_string(),
                });
            }
        }
    }
}
