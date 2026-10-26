//! LCP → CHAP handshake against a scripted access concentrator (RFC 1661, RFC 1994).
//!
//! Owner logs (ISP BRAS, right after a lanforge restart): `CHAP Challenge timeout` and
//! `CHAP result timeout`, then a successful retry. Each test models one way a real, slow or lossy
//! concentrator behaves; the client must authenticate in all of them.

use std::time::Duration;

use lanforge_pppoe::auth::authenticate;
use lanforge_pppoe::lcp::negotiate_lcp;
use lanforge_pppoe::session::PppoeSession;
use lanforge_pppoe::{AuthMethod, PppoeCredentials, PppoeError, PppoeTransport};
use lanforge_transport::PppoeInertHandle;
use lanforge_types::identifiers::MacAddr;
use tokio::time::sleep;

const LCP: [u8; 2] = [0xc0, 0x21];
const CHAP: [u8; 2] = [0xc2, 0x23];

/// How the scripted concentrator misbehaves.
#[derive(Clone, Copy, Default)]
struct Bras {
    /// Delay before answering each frame (busy BRAS after a reconnect storm).
    latency: Duration,
    /// One stall before the first answer; the BRAS then works through its queue promptly.
    initial_stall: Duration,
    /// Delay between the CHAP Response and Success (slow RADIUS).
    radius_delay: Duration,
    /// Ignore the first CHAP Response, then re-send a fresh Challenge (lost Response).
    drop_first_response: bool,
    /// Send an LCP Echo-Request once Opened and only challenge after it is answered.
    echo_before_challenge: bool,
    /// Negotiate PAP instead of CHAP and silently drop the first Authenticate-Request.
    pap_drop_first: bool,
}

fn bras_conf_req(pap: bool) -> Vec<u8> {
    if pap {
        return vec![
            0xc0, 0x21, 0x01, 0x01, 0x00, 0x12, // Conf-Req id 1, len 18
            0x01, 0x04, 0x05, 0xd4, // MRU 1492
            0x03, 0x04, 0xc0, 0x23, // Auth: PAP
            0x05, 0x06, 0x87, 0x65, 0x43, 0x21, // Magic
        ];
    }
    vec![
        0xc0, 0x21, 0x01, 0x01, 0x00, 0x13, // Conf-Req id 1, len 19
        0x01, 0x04, 0x05, 0xd4, // MRU 1492
        0x03, 0x05, 0xc2, 0x23, 0x05, // Auth: CHAP-MD5
        0x05, 0x06, 0x87, 0x65, 0x43, 0x21, // Magic
    ]
}

fn challenge(id: u8) -> Vec<u8> {
    let mut c = vec![0xc2, 0x23, 0x01, id, 0x00, 0x1b, 0x10];
    c.extend((1..=16).map(|b| b ^ id));
    c.extend_from_slice(b"bras00");
    c
}

/// Plays the concentrator side. A Configure-Request received once Opened renegotiates LCP
/// (RFC 1661: Ack + own Configure-Request again), but the authenticator keeps waiting for the
/// Response to the Challenge it already sent and does not challenge again. A client that drops
/// that Challenge completes LCP and then waits for nothing.
async fn run_bras(h: PppoeInertHandle, b: Bras) {
    let mut acked_client = false;
    let mut got_ack = false;
    // Concentrators usually open with their own Configure-Request.
    h.inject_session(bras_conf_req(b.pap_drop_first)).await;
    let mut sent_req = true;
    let mut stalled = false;
    let mut opened = false;
    let mut challenge_id = 1u8;
    let mut responses = 0u32;
    let mut pap_requests = 0u32;

    while let Some(f) = h.recv_session().await {
        if f.len() < 6 {
            continue;
        }
        if !stalled {
            stalled = true;
            sleep(b.initial_stall).await;
        }
        sleep(b.latency).await;
        let (proto, code, id) = ([f[0], f[1]], f[2], f[3]);
        match (proto, code) {
            (LCP, 0x01) => {
                let mut ack = f.clone();
                ack[2] = 0x02;
                h.inject_session(ack).await;
                acked_client = true;
                if !sent_req || opened {
                    sent_req = true;
                    h.inject_session(bras_conf_req(b.pap_drop_first)).await;
                }
            }
            (LCP, 0x02) if id == 0x01 => got_ack = true,
            (LCP, 0x0a) if opened && b.echo_before_challenge => {
                h.inject_session(challenge(challenge_id)).await;
            }
            ([0xc0, 0x23], 0x01) => {
                pap_requests += 1;
                if pap_requests > 1 {
                    h.inject_session(vec![0xc0, 0x23, 0x02, id, 0x00, 0x05, 0x00]).await;
                }
            }
            (CHAP, 0x02) => {
                responses += 1;
                if b.drop_first_response && responses == 1 {
                    sleep(Duration::from_secs(3)).await;
                    challenge_id += 1;
                    h.inject_session(challenge(challenge_id)).await;
                    continue;
                }
                if id == challenge_id {
                    sleep(b.radius_delay).await;
                    h.inject_session(vec![0xc2, 0x23, 0x03, id, 0x00, 0x04])
                        .await;
                }
            }
            _ => {}
        }

        if !opened && acked_client && got_ack {
            opened = true;
            if b.pap_drop_first {
                continue;
            }
            if b.echo_before_challenge {
                h.inject_session(vec![
                    0xc0, 0x21, 0x09, 0x07, 0x00, 0x08, 0x87, 0x65, 0x43, 0x21,
                ])
                .await;
            } else {
                h.inject_session(challenge(challenge_id)).await;
            }
        }
    }
}

async fn handshake(b: Bras) -> Result<(), PppoeError> {
    let auth = if b.pap_drop_first {
        AuthMethod::Pap
    } else {
        AuthMethod::ChapMd5
    };
    let (handle, transport) = PppoeTransport::inert();
    let session = PppoeSession::connect(transport, "wan0", MacAddr([2, 0, 0, 0xac, 0, 1]), 0x42)?;
    let bras = tokio::spawn(run_bras(handle, b));

    let creds = PppoeCredentials {
        username: "user".into(),
        password: "secret".into(),
        auth,
    };
    let lcp = negotiate_lcp(&session, 1492, auth).await?;
    assert_eq!(lcp.auth_method, auth);
    let res = authenticate(&session, &creds, &lcp).await;
    bras.abort();
    res
}

#[tokio::test(start_paused = true)]
async fn chap_succeeds_against_a_prompt_bras() {
    handshake(Bras::default())
        .await
        .expect("baseline handshake");
}

/// `CHAP Challenge timeout` (owner, 09:34 / 09:51): the BRAS stalls ~1.2 s before its first
/// answer. A 1 s LCP retransmit bumps the request id, so the late Ack for the old id is ignored;
/// the BRAS is already Opened and challenges, the Challenge is discarded as "not LCP", LCP then
/// completes on the retransmit, and the client waits for a Challenge that never comes again.
#[tokio::test(start_paused = true)]
async fn chap_keeps_a_challenge_sent_before_lcp_completes() {
    handshake(Bras {
        initial_stall: Duration::from_millis(1200),
        ..Bras::default()
    })
    .await
    .expect("stalled BRAS must still authenticate");
}

/// RFC 1661 §4.6: the restart timer defaults to 3 s. With a 1 s timer, a BRAS that takes 1.5 s per
/// answer always acks a request id the client has already replaced, and LCP times out.
#[tokio::test(start_paused = true)]
async fn lcp_survives_a_bras_slower_than_one_second() {
    handshake(Bras {
        latency: Duration::from_millis(1500),
        ..Bras::default()
    })
    .await
    .expect("slow BRAS must still complete LCP");
}

/// `CHAP result timeout` (owner, 14:01): RADIUS answers after 7 s.
#[tokio::test(start_paused = true)]
async fn chap_waits_for_a_slow_radius() {
    handshake(Bras {
        radius_delay: Duration::from_secs(7),
        ..Bras::default()
    })
    .await
    .expect("slow RADIUS must still authenticate");
}

/// RFC 1994 §2.2: the authenticator retransmits a Challenge when the Response is lost; the peer
/// must answer every Challenge.
#[tokio::test(start_paused = true)]
async fn chap_answers_a_retransmitted_challenge() {
    handshake(Bras {
        drop_first_response: true,
        ..Bras::default()
    })
    .await
    .expect("re-sent Challenge must be answered");
}

/// RFC 1661 §5.8: Echo-Request in the Opened state must be answered, authentication phase included.
#[tokio::test(start_paused = true)]
async fn lcp_echo_is_answered_during_authentication() {
    handshake(Bras {
        echo_before_challenge: true,
        ..Bras::default()
    })
    .await
    .expect("Echo-Request during auth must be answered");
}

/// RFC 1334 §2.2.1: the PAP peer retransmits Authenticate-Request until Ack/Nak; one dropped
/// request must not fail the session.
#[tokio::test(start_paused = true)]
async fn pap_retransmits_a_dropped_request() {
    handshake(Bras {
        pap_drop_first: true,
        ..Bras::default()
    })
    .await
    .expect("PAP must retransmit");
}
