use crate::config::AuthMethod;
use crate::error::PppoeError;
use crate::ipcp::PacketBuf;
use crate::session::PppoeSession;
use rand::random;
use smallvec::{SmallVec, smallvec};
use std::time::Duration;
use tokio::time::{Instant, timeout_at};
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

/// RFC 1661 §4.6 Restart timer default.
const RESTART_TIMER: Duration = Duration::from_secs(3);
/// Max-Configure (10) × Restart timer, as `pppd` does.
const LCP_DEADLINE: Duration = Duration::from_secs(30);
/// Bound on frames kept for the authentication phase.
const MAX_EARLY_FRAMES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LcpOption<'a> {
    pub opt_type: u8,
    pub data: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LcpPacket<'a> {
    pub code: u8,
    pub id: u8,
    pub options: SmallVec<[LcpOption<'a>; 8]>,
}

impl<'a> LcpPacket<'a> {
    #[must_use]
    pub fn encode(&self) -> PacketBuf<128> {
        let opts_len: usize = self.options.iter().map(|o| 2 + o.data.len()).sum();
        let mut pkt = PacketBuf::<128>::new();
        pkt.extend_from_slice(&PPP_LCP.to_be_bytes());
        pkt.push(self.code);
        pkt.push(self.id);
        #[allow(clippy::cast_possible_truncation)]
        let len = (4 + opts_len) as u16;
        pkt.extend_from_slice(&len.to_be_bytes());

        for opt in &self.options {
            pkt.push(opt.opt_type);
            #[allow(clippy::cast_possible_truncation)]
            let l = (opt.data.len() + 2) as u8;
            pkt.push(l);
            pkt.extend_from_slice(opt.data);
        }
        pkt
    }

    #[must_use]
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
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

        let mut options = SmallVec::new();
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
                data: &data[offset + 2..offset + opt_len],
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
    /// Non-LCP frames (in practice the CHAP Challenge) received before LCP completed on our side.
    /// The peer may reach Opened first and challenge right away; dropping that frame leaves the
    /// authentication phase waiting for a Challenge the peer will not repeat.
    pub early_frames: Vec<Vec<u8>>,
}

#[allow(clippy::too_many_lines)]
pub async fn negotiate_lcp(
    session: &PppoeSession,
    desired_mru: u16,
    desired_auth: AuthMethod,
) -> Result<LcpNegotiated, PppoeError> {
    let local_magic: u32 = random();
    let mut req_id = 1u8;

    let mut my_ack_received = false;
    let mut peer_ack_sent = false;

    let mut peer_magic = 0u32;
    let mut negotiated_mru = desired_mru;
    let mut negotiated_auth = AuthMethod::None;
    let mut early_frames = Vec::new();

    let mut mru_bytes = desired_mru.to_be_bytes();
    let magic_bytes = local_magic.to_be_bytes();

    session
        .send_ppp_frame(&build_conf_req(req_id, &mru_bytes, &magic_bytes).encode())
        .await?;

    let deadline = Instant::now() + LCP_DEADLINE;
    let mut retransmit_at = Instant::now() + RESTART_TIMER;
    let mut buf = [0u8; 1500];

    while Instant::now() < deadline {
        if my_ack_received && peer_ack_sent {
            debug!(
                mru = negotiated_mru,
                auth = ?negotiated_auth,
                "LCP negotiation complete!"
            );
            return Ok(LcpNegotiated {
                mru: negotiated_mru,
                local_magic,
                peer_magic,
                auth_method: negotiated_auth,
                early_frames,
            });
        }

        let wait = retransmit_at.min(deadline);
        let Ok(recv) = timeout_at(wait, session.recv_ppp_frame(&mut buf)).await else {
            // RFC 1661 §5.1: a retransmission MAY keep its Identifier. Keeping it lets a late
            // Ack for this very request still count. Once acked, only the peer's request is
            // missing: re-sending ours would make an Opened peer renegotiate.
            if !my_ack_received {
                session
                    .send_ppp_frame(&build_conf_req(req_id, &mru_bytes, &magic_bytes).encode())
                    .await?;
            }
            retransmit_at = Instant::now() + RESTART_TIMER;
            continue;
        };
        let n = recv?;

        let Some(packet) = LcpPacket::parse(&buf[..n]) else {
            if is_auth_frame(&buf[..n]) && early_frames.len() < MAX_EARLY_FRAMES {
                early_frames.push(buf[..n].to_vec());
            }
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
                    mru_bytes = negotiated_mru.to_be_bytes();
                    req_id = req_id.wrapping_add(1);
                    session
                        .send_ppp_frame(&build_conf_req(req_id, &mru_bytes, &magic_bytes).encode())
                        .await?;
                    retransmit_at = Instant::now() + RESTART_TIMER;
                }
            }
            LCP_CONF_REQ => {
                if handle_conf_req(
                    packet,
                    session,
                    desired_auth,
                    &mut peer_magic,
                    &mut negotiated_auth,
                )
                .await?
                {
                    peer_ack_sent = true;
                }
            }
            LCP_TERM_REQ => {
                let ack = LcpPacket {
                    code: LCP_TERM_ACK,
                    id: packet.id,
                    options: smallvec![],
                };
                session.send_ppp_frame(&ack.encode()).await?;
                return Err(PppoeError::LcpFailed("Peer terminated LCP".into()));
            }
            _ => {}
        }
    }

    Err(PppoeError::LcpFailed("LCP negotiation timed out".into()))
}

fn is_auth_frame(bytes: &[u8]) -> bool {
    let data = if bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0x03 {
        &bytes[2..]
    } else {
        bytes
    };
    data.len() >= 2 && matches!(u16::from_be_bytes([data[0], data[1]]), PPP_CHAP | PPP_PAP)
}

fn build_conf_req<'a>(id: u8, mru_bytes: &'a [u8; 2], magic_bytes: &'a [u8; 4]) -> LcpPacket<'a> {
    LcpPacket {
        code: LCP_CONF_REQ,
        id,
        options: smallvec![
            LcpOption {
                opt_type: LCP_OPT_MRU,
                data: mru_bytes,
            },
            LcpOption {
                opt_type: LCP_OPT_MAGIC,
                data: magic_bytes,
            },
        ],
    }
}

fn handle_conf_nak(packet: &LcpPacket<'_>, negotiated_mru: &mut u16) {
    for opt in &packet.options {
        if opt.opt_type == LCP_OPT_MRU && opt.data.len() == 2 {
            *negotiated_mru = u16::from_be_bytes([opt.data[0], opt.data[1]]);
        }
    }
}

async fn handle_conf_req(
    packet: LcpPacket<'_>,
    session: &PppoeSession,
    desired_auth: AuthMethod,
    peer_magic: &mut u32,
    negotiated_auth: &mut AuthMethod,
) -> Result<bool, PppoeError> {
    let mut nak_options: SmallVec<[LcpOption<'_>; 8]> = SmallVec::new();
    let mut rej_options: SmallVec<[LcpOption<'_>; 8]> = SmallVec::new();
    let mut ack_options: SmallVec<[LcpOption<'_>; 8]> = SmallVec::new();

    for opt in &packet.options {
        match opt.opt_type {
            LCP_OPT_MAGIC => {
                if opt.data.len() == 4 {
                    *peer_magic =
                        u32::from_be_bytes([opt.data[0], opt.data[1], opt.data[2], opt.data[3]]);
                    ack_options.push(*opt);
                } else {
                    rej_options.push(*opt);
                }
            }
            LCP_OPT_MRU => {
                if opt.data.len() == 2 {
                    ack_options.push(*opt);
                } else {
                    rej_options.push(*opt);
                }
            }
            LCP_OPT_AUTH if opt.data.len() >= 2 => {
                let proto = u16::from_be_bytes([opt.data[0], opt.data[1]]);
                if proto == PPP_PAP && desired_auth == AuthMethod::Pap {
                    *negotiated_auth = AuthMethod::Pap;
                    ack_options.push(*opt);
                } else if proto == PPP_CHAP
                    && opt.data.len() >= 3
                    && opt.data[2] == CHAP_ALG_MD5
                    && desired_auth == AuthMethod::ChapMd5
                {
                    *negotiated_auth = AuthMethod::ChapMd5;
                    ack_options.push(*opt);
                } else if desired_auth == AuthMethod::ChapMd5 {
                    let chap_nak_data: &'static [u8] = &[0xc2, 0x23, 0x05];
                    nak_options.push(LcpOption {
                        opt_type: LCP_OPT_AUTH,
                        data: chap_nak_data,
                    });
                } else if desired_auth == AuthMethod::Pap {
                    let pap_nak_data: &'static [u8] = &[0xc0, 0x23];
                    nak_options.push(LcpOption {
                        opt_type: LCP_OPT_AUTH,
                        data: pap_nak_data,
                    });
                } else {
                    rej_options.push(*opt);
                }
            }
            _ => {
                rej_options.push(*opt);
            }
        }
    }

    if !rej_options.is_empty() {
        let resp = LcpPacket {
            code: LCP_CONF_REJ,
            id: packet.id,
            options: rej_options,
        };
        session.send_ppp_frame(&resp.encode()).await?;
        Ok(false)
    } else if !nak_options.is_empty() {
        let resp = LcpPacket {
            code: LCP_CONF_NAK,
            id: packet.id,
            options: nak_options,
        };
        session.send_ppp_frame(&resp.encode()).await?;
        Ok(false)
    } else {
        let resp = LcpPacket {
            code: LCP_CONF_ACK,
            id: packet.id,
            options: ack_options,
        };
        session.send_ppp_frame(&resp.encode()).await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lcp_packet_encode_parse() {
        let mru = 1492u16.to_be_bytes();
        let magic = 0x1234_5678u32.to_be_bytes();
        let pkt = build_conf_req(1, &mru, &magic);
        let encoded = pkt.encode();

        let parsed = LcpPacket::parse(&encoded).expect("parse encoded LCP packet");
        assert_eq!(parsed.code, LCP_CONF_REQ);
        assert_eq!(parsed.id, 1);
        assert_eq!(parsed.options.len(), 2);
        assert_eq!(parsed.options[0].opt_type, LCP_OPT_MRU);
        assert_eq!(parsed.options[0].data, &mru);
        assert_eq!(parsed.options[1].opt_type, LCP_OPT_MAGIC);
        assert_eq!(parsed.options[1].data, &magic);
    }

    #[test]
    fn test_lcp_handle_conf_nak() {
        let new_mru = 1400u16.to_be_bytes();
        let pkt = LcpPacket {
            code: LCP_CONF_NAK,
            id: 2,
            options: smallvec![LcpOption {
                opt_type: LCP_OPT_MRU,
                data: &new_mru,
            }],
        };
        let mut negotiated = 1492;
        handle_conf_nak(&pkt, &mut negotiated);
        assert_eq!(negotiated, 1400);
    }
}
