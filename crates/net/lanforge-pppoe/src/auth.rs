//! PPP authentication phase: PAP (RFC 1334) and CHAP-MD5 (RFC 1994).
//!
//! Invariants:
//! - The phase has one overall deadline; individual packets never end it early. A slow RADIUS
//!   behind the concentrator routinely takes several seconds.
//! - PAP: the peer drives retransmission. Authenticate-Request is re-sent on a restart timer with
//!   a new Identifier until Authenticate-Ack/Nak (RFC 1334 §2.2.1).
//! - CHAP: the authenticator drives retransmission. Every Challenge is answered, including a
//!   re-sent one after a lost Response (RFC 1994 §4.1); only a Success/Failure matching the last
//!   answered Identifier ends the phase.
//! - LCP is Opened: Echo-Request is answered and Terminate-Request acknowledged (RFC 1661 §5).
//! - An explicit reject (`AuthFailed`) is reported apart from silence (`AuthTimeout`).

use crate::config::{AuthMethod, PppoeCredentials};
use crate::error::PppoeError;
use crate::lcp::{
    LCP_ECHO_REP, LCP_ECHO_REQ, LCP_TERM_ACK, LCP_TERM_REQ, LcpNegotiated, PPP_CHAP, PPP_LCP,
    PPP_PAP,
};
use crate::session::PppoeSession;
use md5::{Digest, Md5};
use std::time::Duration;
use tokio::time::{Instant, timeout_at};
use tracing::debug;

/// Overall authentication deadline: well above a slow RADIUS round trip (several seconds), short
/// enough that a concentrator still holding the previous session is retried soon.
const AUTH_DEADLINE: Duration = Duration::from_secs(20);
/// PAP restart timer (RFC 1334 suggests the LCP default of 3 s).
const PAP_RESTART_TIMER: Duration = Duration::from_secs(3);

const PAP_AUTH_REQ: u8 = 0x01;
const PAP_AUTH_ACK: u8 = 0x02;
const PAP_AUTH_NAK: u8 = 0x03;
const CHAP_CHALLENGE: u8 = 0x01;
const CHAP_RESPONSE: u8 = 0x02;
const CHAP_SUCCESS: u8 = 0x03;
const CHAP_FAILURE: u8 = 0x04;

pub async fn authenticate(
    session: &PppoeSession,
    creds: &PppoeCredentials,
    lcp: &LcpNegotiated,
) -> Result<(), PppoeError> {
    if creds.auth == AuthMethod::None {
        debug!("No authentication requested by peer, skipping auth phase");
        return Ok(());
    }

    let deadline = Instant::now() + AUTH_DEADLINE;
    let mut early = lcp.early_frames.iter();
    let mut buf = [0u8; 1500];

    // PAP: Identifier of the outstanding Authenticate-Request and when to re-send it.
    let mut pap_id = 0u8;
    let mut pap_resend_at = Instant::now();
    // CHAP: Identifier of the last Challenge we answered.
    let mut chap_answered: Option<u8> = None;

    loop {
        // Checked every iteration: a peer that keeps sending frames must not extend the phase.
        if Instant::now() >= deadline {
            return Err(PppoeError::AuthTimeout(timeout_reason(
                creds.auth,
                chap_answered,
            )));
        }
        if creds.auth == AuthMethod::Pap && Instant::now() >= pap_resend_at {
            pap_id = pap_id.wrapping_add(1);
            send_pap_request(session, creds, pap_id).await?;
            pap_resend_at = Instant::now() + PAP_RESTART_TIMER;
        }

        let frame = if let Some(f) = early.next() {
            f.as_slice()
        } else {
            let wake = if creds.auth == AuthMethod::Pap {
                pap_resend_at.min(deadline)
            } else {
                deadline
            };
            match timeout_at(wake, session.recv_ppp_frame(&mut buf)).await {
                Ok(res) => &buf[..res?],
                Err(_) if Instant::now() >= deadline => {
                    return Err(PppoeError::AuthTimeout(timeout_reason(
                        creds.auth,
                        chap_answered,
                    )));
                }
                Err(_) => continue,
            }
        };

        let data = strip_hdlc(frame);
        if data.len() < 6 {
            continue;
        }
        let (proto, code, id) = (u16::from_be_bytes([data[0], data[1]]), data[2], data[3]);

        match proto {
            PPP_LCP => handle_lcp(session, data, lcp.local_magic).await?,
            PPP_PAP if creds.auth == AuthMethod::Pap && id == pap_id => match code {
                PAP_AUTH_ACK => {
                    debug!("PAP authentication successful");
                    return Ok(());
                }
                PAP_AUTH_NAK => return Err(PppoeError::AuthFailed("PAP Auth-Nak".into())),
                _ => {}
            },
            PPP_CHAP if creds.auth == AuthMethod::ChapMd5 => match code {
                CHAP_CHALLENGE => {
                    if send_chap_response(session, creds, data).await? {
                        chap_answered = Some(id);
                    }
                }
                CHAP_SUCCESS if chap_answered == Some(id) => {
                    debug!("CHAP-MD5 authentication successful");
                    return Ok(());
                }
                CHAP_FAILURE if chap_answered == Some(id) => {
                    return Err(PppoeError::AuthFailed("CHAP Failure received".into()));
                }
                _ => {}
            },
            _ => {}
        }
    }
}

fn timeout_reason(auth: AuthMethod, chap_answered: Option<u8>) -> String {
    match (auth, chap_answered) {
        (AuthMethod::Pap, _) => "no PAP Authenticate-Ack/Nak".into(),
        (_, None) => "no CHAP Challenge".into(),
        (_, Some(_)) => "no CHAP Success/Failure".into(),
    }
}

#[inline]
fn strip_hdlc(bytes: &[u8]) -> &[u8] {
    if bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0x03 {
        &bytes[2..]
    } else {
        bytes
    }
}

/// Answers the LCP packets an Opened peer may send while authenticating.
async fn handle_lcp(
    session: &PppoeSession,
    data: &[u8],
    local_magic: u32,
) -> Result<(), PppoeError> {
    match data[2] {
        LCP_ECHO_REQ => {
            let rep = [
                data[0],
                data[1],
                LCP_ECHO_REP,
                data[3],
                0x00,
                0x08,
                local_magic.to_be_bytes()[0],
                local_magic.to_be_bytes()[1],
                local_magic.to_be_bytes()[2],
                local_magic.to_be_bytes()[3],
            ];
            session.send_ppp_frame(&rep).await
        }
        LCP_TERM_REQ => {
            let ack = [data[0], data[1], LCP_TERM_ACK, data[3], 0x00, 0x04];
            session.send_ppp_frame(&ack).await?;
            Err(PppoeError::Terminated(
                "LCP Terminate-Request during authentication".into(),
            ))
        }
        _ => Ok(()),
    }
}

async fn send_pap_request(
    session: &PppoeSession,
    creds: &PppoeCredentials,
    id: u8,
) -> Result<(), PppoeError> {
    let u_bytes = creds.username.as_bytes();
    let p_bytes = creds.password.as_bytes();
    let u_len = u_bytes.len().min(255);
    let p_len = p_bytes.len().min(255);
    let total_len = 6 + 1 + u_len + 1 + p_len;

    let mut pkt = [0u8; 520];
    pkt[0..2].copy_from_slice(&PPP_PAP.to_be_bytes());
    pkt[2] = PAP_AUTH_REQ;
    pkt[3] = id;
    #[allow(clippy::cast_possible_truncation)]
    let len_field = (4 + 1 + u_len + 1 + p_len) as u16;
    pkt[4..6].copy_from_slice(&len_field.to_be_bytes());

    #[allow(clippy::cast_possible_truncation)]
    let u_len_u8 = u_len as u8;
    #[allow(clippy::cast_possible_truncation)]
    let p_len_u8 = p_len as u8;

    pkt[6] = u_len_u8;
    pkt[7..7 + u_len].copy_from_slice(&u_bytes[..u_len]);

    let p_offset = 7 + u_len;
    pkt[p_offset] = p_len_u8;
    pkt[p_offset + 1..p_offset + 1 + p_len].copy_from_slice(&p_bytes[..p_len]);

    session.send_ppp_frame(&pkt[..total_len]).await
}

/// Answers a CHAP Challenge; returns `false` for a malformed one (left unanswered).
async fn send_chap_response(
    session: &PppoeSession,
    creds: &PppoeCredentials,
    data: &[u8],
) -> Result<bool, PppoeError> {
    if data.len() < 7 {
        return Ok(false);
    }
    let id = data[3];
    let val_len = data[6] as usize;
    if data.len() < 7 + val_len {
        return Ok(false);
    }
    let challenge_val = &data[7..7 + val_len];

    // CHAP-MD5 response = MD5(id || password || challenge)
    let mut hasher = Md5::new();
    hasher.update([id]);
    hasher.update(creds.password.as_bytes());
    hasher.update(challenge_val);
    let response_hash = hasher.finalize();

    let u_bytes = creds.username.as_bytes();
    let u_len = u_bytes.len().min(255);
    let total_len = 6 + 1 + 16 + u_len;

    let mut resp_pkt = [0u8; 512];
    resp_pkt[0..2].copy_from_slice(&PPP_CHAP.to_be_bytes());
    resp_pkt[2] = CHAP_RESPONSE;
    resp_pkt[3] = id;
    #[allow(clippy::cast_possible_truncation)]
    let len_field = (4 + 1 + 16 + u_len) as u16;
    resp_pkt[4..6].copy_from_slice(&len_field.to_be_bytes());

    resp_pkt[6] = 16; // MD5 length
    resp_pkt[7..23].copy_from_slice(&response_hash);
    resp_pkt[23..23 + u_len].copy_from_slice(&u_bytes[..u_len]);

    session.send_ppp_frame(&resp_pkt[..total_len]).await?;
    Ok(true)
}
