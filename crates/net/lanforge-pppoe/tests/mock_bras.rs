use lanforge_pppoe::discovery::frame::{
    CODE_PADI, CODE_PADO, CODE_PADR, CODE_PADS, CODE_PADT, PppoeDiscoveryFrame, TAG_AC_COOKIE,
    TAG_AC_NAME, TAG_HOST_UNIQ, TAG_SERVICE_NAME, Tag,
};
use lanforge_transport::PppoeInertHandle;
use lanforge_types::identifiers::MacAddr;
use smallvec::{SmallVec, smallvec};
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep_until};

#[derive(Debug, Clone)]
pub struct MockBrasConfig {
    pub ac_mac: MacAddr,
    pub ac_name: String,
    pub session_id: u16,
    pub local_ip: Ipv4Addr,
    pub peer_ip: Ipv4Addr,
    pub dns: Vec<Ipv4Addr>,
    pub auth_ok: bool,
    pub fail_discovery: bool,
    pub send_echo_replies: bool,
    /// Send an LCP Terminate-Request this long after the session comes up (flapping concentrator).
    pub terminate_after: Option<Duration>,
    /// Send a PADT (discovery stage) this long after the session comes up (ISP-side hangup).
    pub padt_after: Option<Duration>,
}

impl Default for MockBrasConfig {
    fn default() -> Self {
        Self {
            ac_mac: MacAddr([0x02, 0x00, 0x00, 0xac, 0x00, 0x01]),
            ac_name: "lanforge-bras".to_string(),
            session_id: 0x0042,
            local_ip: Ipv4Addr::new(100, 64, 0, 2),
            peer_ip: Ipv4Addr::new(100, 64, 0, 1),
            dns: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)],
            auth_ok: true,
            fail_discovery: false,
            send_echo_replies: true,
            terminate_after: None,
            padt_after: None,
        }
    }
}

pub fn spawn_mock_bras(handle: PppoeInertHandle, cfg: MockBrasConfig) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut terminate_at: Option<Instant> = None;
        let mut padt_at: Option<Instant> = None;
        let mut client_mac = MacAddr([0; 6]);
        // Discovery phase
        loop {
            tokio::select! {
                () = async {
                    match terminate_at {
                        Some(at) => sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                } => {
                    terminate_at = None;
                    handle.inject_session(vec![0xc0, 0x21, 0x05, 0x99, 0x00, 0x04]).await;
                }
                () = async {
                    match padt_at {
                        Some(at) => sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                } => {
                    padt_at = None;
                    let padt = PppoeDiscoveryFrame {
                        dst_mac: client_mac,
                        src_mac: cfg.ac_mac,
                        code: CODE_PADT,
                        session_id: cfg.session_id,
                        tags: smallvec![],
                    };
                    handle.inject_discovery(padt.encode().to_vec()).await;
                }
                disc_opt = handle.recv_discovery() => {
                    let Some(bytes) = disc_opt else { break; };
                    if let Some(frame) = PppoeDiscoveryFrame::parse(&bytes) {
                        if frame.code == CODE_PADI {
                            if cfg.fail_discovery {
                                continue;
                            }
                            let host_uniq = frame.tags.iter().find(|t| t.tag_type == TAG_HOST_UNIQ);
                            let mut tags: SmallVec<[Tag; 8]> = smallvec![
                                Tag {
                                    tag_type: TAG_AC_NAME,
                                    value: cfg.ac_name.as_bytes(),
                                },
                                Tag {
                                    tag_type: TAG_AC_COOKIE,
                                    value: &[0x11, 0x22, 0x33, 0x44],
                                },
                            ];
                            if let Some(hu) = host_uniq {
                                tags.push(*hu);
                            }
                            let pado = PppoeDiscoveryFrame {
                                dst_mac: frame.src_mac,
                                src_mac: cfg.ac_mac,
                                code: CODE_PADO,
                                session_id: 0,
                                tags,
                            };
                            handle.inject_discovery(pado.encode().to_vec()).await;
                        } else if frame.code == CODE_PADR {
                            client_mac = frame.src_mac;
                            let host_uniq = frame.tags.iter().find(|t| t.tag_type == TAG_HOST_UNIQ);
                            let mut tags: SmallVec<[Tag; 8]> = smallvec![
                                Tag {
                                    tag_type: TAG_SERVICE_NAME,
                                    value: b"",
                                },
                            ];
                            if let Some(hu) = host_uniq {
                                tags.push(*hu);
                            }
                            let pads = PppoeDiscoveryFrame {
                                dst_mac: frame.src_mac,
                                src_mac: cfg.ac_mac,
                                code: CODE_PADS,
                                session_id: cfg.session_id,
                                tags,
                            };
                            handle.inject_discovery(pads.encode().to_vec()).await;
                        } else if frame.code == CODE_PADT {
                            // Client disconnected
                        }
                    }
                }
                sess_opt = handle.recv_session() => {
                    let Some(bytes) = sess_opt else { break; };
                    if bytes.len() < 4 {
                        continue;
                    }
                    let proto = u16::from_be_bytes([bytes[0], bytes[1]]);
                    let code = bytes[2];
                    let id = bytes[3];

                    match proto {
                        0xc021 => { // LCP
                            match code {
                                1 => { // Conf-Req
                                    // Ack client options
                                    let mut ack = bytes.clone();
                                    ack[2] = 2; // Conf-Ack
                                    handle.inject_session(ack).await;

                                    // Send BRAS Conf-Req proposing CHAP-MD5
                                    let bras_req = vec![
                                        0xc0, 0x21, // PPP_LCP
                                        0x01,       // Conf-Req
                                        0x01,       // id: 1
                                        0x00, 0x13, // len: 19 (4 header + 4 MRU + 5 Auth + 6 Magic)
                                        0x01, 0x04, 0x05, 0xd4, // MRU: 1492
                                        0x03, 0x05, 0xc2, 0x23, 0x05, // Auth: CHAP MD5 (0xc223, 0x05)
                                        0x05, 0x06, 0x87, 0x65, 0x43, 0x21, // Magic: 0x87654321
                                    ];
                                    handle.inject_session(bras_req).await;
                                }
                                2 => { // Conf-Ack
                                    // Client accepted our LCP options, initiate CHAP challenge
                                    let challenge = vec![
                                        0xc2, 0x23, // PPP_CHAP
                                        0x01,       // Challenge
                                        0x01,       // id: 1
                                        0x00, 0x1b, // len: 27
                                        0x10,       // val_len: 16
                                        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                                        b'l', b'a', b'n', b'f', b'o', b'r', // Name: "lanfor"
                                    ];
                                    handle.inject_session(challenge).await;
                                }
                                3 => { // Conf-Nak
                                    // Client requested PAP instead of CHAP
                                    let bras_req = vec![
                                        0xc0, 0x21, // PPP_LCP
                                        0x01,       // Conf-Req
                                        id.wrapping_add(1),
                                        0x00, 0x12, // len: 18 (4 header + 4 MRU + 4 Auth + 6 Magic)
                                        0x01, 0x04, 0x05, 0xd4, // MRU: 1492
                                        0x03, 0x04, 0xc0, 0x23, // Auth: PAP
                                        0x05, 0x06, 0x87, 0x65, 0x43, 0x21, // Magic
                                    ];
                                    handle.inject_session(bras_req).await;
                                }
                                9 => { // Echo-Req
                                    if cfg.send_echo_replies {
                                        let rep = vec![
                                            0xc0, 0x21, // PPP_LCP
                                            0x0a,       // Echo-Reply
                                            id,
                                            0x00, 0x08,
                                            0x87, 0x65, 0x43, 0x21,
                                        ];
                                        handle.inject_session(rep).await;
                                    }
                                }
                                5 => { // Term-Req
                                    let ack = vec![0xc0, 0x21, 0x06, id, 0x00, 0x04];
                                    handle.inject_session(ack).await;
                                }
                                _ => {}
                            }
                        }
                        0xc223 => { // CHAP
                            if code == 2 { // Response
                                if cfg.auth_ok {
                                    let succ = vec![
                                        0xc2, 0x23,
                                        0x03, // Success
                                        id,
                                        0x00, 0x04,
                                    ];
                                    handle.inject_session(succ).await;
                                } else {
                                    let reason = b"PAP/CHAP authentication failed: invalid credentials";
                                    let len = 4 + reason.len();
                                    let mut fail = vec![
                                        0xc2, 0x23,
                                        0x04, // Failure
                                        id,
                                        (len >> 8) as u8, (len & 0xff) as u8,
                                    ];
                                    fail.extend_from_slice(reason);
                                    handle.inject_session(fail).await;
                                }
                            }
                        }
                        0xc023 => { // PAP
                            if code == 1 { // Authenticate-Request
                                if cfg.auth_ok {
                                    // Auth-Ack
                                    let ack = vec![
                                        0xc0, 0x23, // PPP_PAP
                                        0x02,       // Auth-Ack
                                        id,
                                        0x00, 0x05, // len: 5
                                        0x00,       // msg len: 0
                                    ];
                                    handle.inject_session(ack).await;
                                } else {
                                    // Auth-Nak
                                    let reason = b"PAP/CHAP authentication failed: invalid credentials";
                                    let len = 5 + reason.len();
                                    let mut nak = vec![
                                        0xc0, 0x23,
                                        0x03, // Auth-Nak
                                        id,
                                        (len >> 8) as u8, (len & 0xff) as u8,
                                        reason.len() as u8,
                                    ];
                                    nak.extend_from_slice(reason);
                                    handle.inject_session(nak).await;
                                }
                            }
                        }
                        0x8057 => { // IPv6CP
                            if code == 1 { // Conf-Req
                                let mut rej = bytes.clone();
                                rej[2] = 0x04; // Conf-Rej
                                handle.inject_session(rej).await;
                            }
                        }
                        0x8021 if code == 1 => { // IPCP Conf-Req
                            // Check if client requested 0.0.0.0
                                let ip_opt = bytes.windows(6).find(|w| w[0] == 0x03 && w[1] == 0x06);
                                if let Some(opt) = ip_opt && opt[2..6] == [0, 0, 0, 0] {
                                    // Nak with assigned IP and DNS
                                    let ip_octets = cfg.local_ip.octets();
                                    let dns1_octets = cfg.dns.first().copied().unwrap_or(Ipv4Addr::new(1, 1, 1, 1)).octets();
                                    let dns2_octets = cfg.dns.get(1).copied().unwrap_or(Ipv4Addr::new(1, 0, 0, 1)).octets();
                                    let nak = vec![
                                        0x80, 0x21,
                                        0x03, // Conf-Nak
                                        id,
                                        0x00, 0x16, // len: 22
                                        0x03, 0x06, ip_octets[0], ip_octets[1], ip_octets[2], ip_octets[3],
                                        0x81, 0x06, dns1_octets[0], dns1_octets[1], dns1_octets[2], dns1_octets[3],
                                        0x83, 0x06, dns2_octets[0], dns2_octets[1], dns2_octets[2], dns2_octets[3],
                                    ];
                                    handle.inject_session(nak).await;
                                } else {
                                    // Client accepted our IP or already requested it: Ack!
                                    let mut ack = bytes.clone();
                                    ack[2] = 0x02; // Conf-Ack
                                    handle.inject_session(ack).await;
                                    terminate_at = cfg.terminate_after.map(|d| Instant::now() + d);
                                    padt_at = cfg.padt_after.map(|d| Instant::now() + d);

                                    // Send BRAS IPCP Conf-Req with peer IP
                                    let peer_octets = cfg.peer_ip.octets();
                                    let req = vec![
                                        0x80, 0x21,
                                        0x01, // Conf-Req
                                        0x01, // id: 1
                                        0x00, 0x0a, // len: 10
                                        0x03, 0x06, peer_octets[0], peer_octets[1], peer_octets[2], peer_octets[3],
                                    ];
                                    handle.inject_session(req).await;
                                }
                            }
                        _ => {}
                    }
                }
            }
        }
    })
}
