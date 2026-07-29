use crate::config::AuthMethod;
use crate::error::PppoeError;
use crate::session::PppoeSession;
use std::time::Duration;
use tracing::debug;

pub const PPP_LCP: u16 = 0xc021;
pub const PPP_PAP: u16 = 0xc023;
pub const PPP_CHAP: u16 = 0xc223;
pub const CHAP_ALG_MD5: u8 = 0x05;

pub const LCP_CONF_REQ: u8 = 0x01;
pub const LCP_CONF_ACK: u8 = 0x02;
pub const LCP_CONF_NAK: u8 = 0x03;
pub const LCP_CONF_REJ: u8 = 0x04;
pub const LCP_TERM_REQ: u8 = 0x05;
pub const LCP_TERM_ACK: u8 = 0x06;
pub const LCP_ECHO_REQ: u8 = 0x09;
pub const LCP_ECHO_REP: u8 = 0x0a;

pub const LCP_OPT_MRU: u8 = 1;
pub const LCP_OPT_AUTH: u8 = 3;
pub const LCP_OPT_MAGIC: u8 = 5;

#[derive(Debug, Clone)]
pub struct LcpOption {
    pub opt_type: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct LcpPacket {
    pub code: u8,
    pub id: u8,
    pub options: Vec<LcpOption>,
}

impl LcpPacket {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut opts_buf = Vec::new();
        for opt in &self.options {
            opts_buf.push(opt.opt_type);
            #[allow(clippy::cast_possible_truncation)]
            let len = (opt.data.len() + 2) as u8;
            opts_buf.push(len);
            opts_buf.extend_from_slice(&opt.data);
        }

        let mut pkt = Vec::with_capacity(6 + opts_buf.len());
        pkt.extend_from_slice(&PPP_LCP.to_be_bytes());
        pkt.push(self.code);
        pkt.push(self.id);
        #[allow(clippy::cast_possible_truncation)]
        let len = (4 + opts_buf.len()) as u16;
        pkt.extend_from_slice(&len.to_be_bytes());
        pkt.extend_from_slice(&opts_buf);
        pkt
    }

    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let data = if bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0x03 {
            &bytes[2..]
        } else {
            bytes
        };

        if data.len() < 6 {
            return None;
        }

        let proto = u16::from_be_bytes([data[0], data[1]]);
        if proto != PPP_LCP {
            return None;
        }

        let code = data[2];
        let id = data[3];
        let len = u16::from_be_bytes([data[4], data[5]]) as usize;

        if data.len() < 2 + len {
            return None;
        }

        let mut options = Vec::new();
        let mut offset = 6;
        let end = 2 + len;

        while offset + 2 <= end {
            let opt_type = data[offset];
            let opt_len = data[offset + 1] as usize;
            if opt_len < 2 || offset + opt_len > end {
                break;
            }

            options.push(LcpOption {
                opt_type,
                data: data[offset + 2..offset + opt_len].to_vec(),
            });
            offset += opt_len;
        }

        Some(Self { code, id, options })
    }
}

#[derive(Debug)]
pub struct LcpNegotiated {
    pub mru: u16,
    pub local_magic: u32,
    pub peer_magic: u32,
    pub auth_method: AuthMethod,
}

pub async fn negotiate_lcp(
    session: &PppoeSession,
    desired_mru: u16,
    _desired_auth: AuthMethod,
) -> Result<LcpNegotiated, PppoeError> {
    let local_magic: u32 = rand::random();
    let mut req_id = 1u8;

    let mut my_ack_received = false;
    let mut peer_ack_sent = false;

    let mut peer_magic = 0u32;
    let mut negotiated_mru = desired_mru;
    let mut negotiated_auth = AuthMethod::None;

    let mut req_packet = build_conf_req(req_id, desired_mru, local_magic);

    session.send_ppp_frame(&req_packet.encode()).await?;

    let timeout = Duration::from_secs(10);
    let start = tokio::time::Instant::now();
    let mut buf = [0u8; 1500];

    while start.elapsed() < timeout {
        if my_ack_received && peer_ack_sent {
            debug!("LCP negotiation complete!");
            return Ok(LcpNegotiated {
                mru: negotiated_mru,
                local_magic,
                peer_magic,
                auth_method: negotiated_auth,
            });
        }

        let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(1), session.recv_ppp_frame(&mut buf)).await
        else {
            // Timeout, retransmit
            req_id = req_id.wrapping_add(1);
            req_packet = build_conf_req(req_id, negotiated_mru, local_magic);
            session.send_ppp_frame(&req_packet.encode()).await?;
            continue;
        };

        let Some(packet) = LcpPacket::parse(&buf[..n]) else {
            continue;
        };

        match packet.code {
            LCP_CONF_ACK => {
                if packet.id == req_id {
                    my_ack_received = true;
                    debug!("LCP Configure-Ack received from peer");
                }
            }
            LCP_CONF_REJ => {
                if packet.id == req_id {
                    for opt in packet.options {
                        if opt.opt_type == LCP_OPT_AUTH {
                            negotiated_auth = AuthMethod::None;
                        }
                    }
                }
            }
            LCP_CONF_NAK => {
                if packet.id == req_id {
                    handle_conf_nak(&packet, &mut negotiated_mru);
                    req_id = req_id.wrapping_add(1);
                    req_packet = build_conf_req(req_id, negotiated_mru, local_magic);
                    session.send_ppp_frame(&req_packet.encode()).await?;
                }
            }
            LCP_CONF_REQ => {
                if handle_conf_req(packet, session, &mut peer_magic, &mut negotiated_auth).await? {
                    peer_ack_sent = true;
                }
            }
            LCP_TERM_REQ => {
                let ack = LcpPacket {
                    code: LCP_TERM_ACK,
                    id: packet.id,
                    options: vec![],
                };
                session.send_ppp_frame(&ack.encode()).await?;
                return Err(PppoeError::LcpFailed("Peer terminated LCP".into()));
            }
            _ => {}
        }
    }

    Err(PppoeError::LcpFailed("LCP negotiation timed out".into()))
}

fn build_conf_req(id: u8, mru: u16, local_magic: u32) -> LcpPacket {
    LcpPacket {
        code: LCP_CONF_REQ,
        id,
        options: vec![
            LcpOption {
                opt_type: LCP_OPT_MRU,
                data: mru.to_be_bytes().to_vec(),
            },
            LcpOption {
                opt_type: LCP_OPT_MAGIC,
                data: local_magic.to_be_bytes().to_vec(),
            },
        ],
    }
}

fn handle_conf_nak(packet: &LcpPacket, negotiated_mru: &mut u16) {
    for opt in &packet.options {
        if opt.opt_type == LCP_OPT_MRU && opt.data.len() == 2 {
            *negotiated_mru = u16::from_be_bytes([opt.data[0], opt.data[1]]);
        }
    }
}

async fn handle_conf_req(
    packet: LcpPacket,
    session: &PppoeSession,
    peer_magic: &mut u32,
    negotiated_auth: &mut AuthMethod,
) -> Result<bool, PppoeError> {
    let mut ack_opts = Vec::new();
    let mut rej_opts = Vec::new();

    for opt in packet.options {
        match opt.opt_type {
            LCP_OPT_MAGIC => {
                if opt.data.len() == 4 {
                    *peer_magic =
                        u32::from_be_bytes([opt.data[0], opt.data[1], opt.data[2], opt.data[3]]);
                    ack_opts.push(opt);
                }
            }
            LCP_OPT_AUTH => {
                if opt.data.len() >= 2 {
                    let proto = u16::from_be_bytes([opt.data[0], opt.data[1]]);
                    if proto == PPP_PAP {
                        *negotiated_auth = AuthMethod::Pap;
                        ack_opts.push(opt);
                    } else if proto == PPP_CHAP
                        && opt.data.len() >= 3
                        && opt.data[2] == CHAP_ALG_MD5
                    {
                        *negotiated_auth = AuthMethod::ChapMd5;
                        ack_opts.push(opt);
                    } else {
                        rej_opts.push(opt);
                    }
                }
            }
            LCP_OPT_MRU => {
                ack_opts.push(opt);
            }
            _ => {
                rej_opts.push(opt);
            }
        }
    }

    if rej_opts.is_empty() {
        let ack = LcpPacket {
            code: LCP_CONF_ACK,
            id: packet.id,
            options: ack_opts,
        };
        session.send_ppp_frame(&ack.encode()).await?;
        debug!("Sent LCP Configure-Ack to peer");
        Ok(true)
    } else {
        let rej = LcpPacket {
            code: LCP_CONF_REJ,
            id: packet.id,
            options: rej_opts,
        };
        session.send_ppp_frame(&rej.encode()).await?;
        Ok(false)
    }
}
