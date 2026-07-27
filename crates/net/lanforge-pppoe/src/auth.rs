use crate::config::{AuthMethod, PppoeCredentials};
use crate::error::PppoeError;
use crate::lcp::{PPP_CHAP, PPP_PAP};
use crate::session::PppoeSession;
use md5::{Digest, Md5};
use std::time::Duration;
use tracing::debug;

pub async fn authenticate(
    session: &PppoeSession,
    creds: &PppoeCredentials,
) -> Result<(), PppoeError> {
    match creds.auth {
        AuthMethod::None => {
            debug!("No authentication requested by peer, skipping auth phase");
            Ok(())
        }
        AuthMethod::Pap => authenticate_pap(session, creds).await,
        AuthMethod::ChapMd5 => authenticate_chap(session, creds).await,
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

async fn authenticate_pap(
    session: &PppoeSession,
    creds: &PppoeCredentials,
) -> Result<(), PppoeError> {
    let mut payload = Vec::new();
    #[allow(clippy::cast_possible_truncation)]
    let user_len = creds.username.len() as u8;
    payload.push(user_len);
    payload.extend_from_slice(creds.username.as_bytes());

    #[allow(clippy::cast_possible_truncation)]
    let pass_len = creds.password.len() as u8;
    payload.push(pass_len);
    payload.extend_from_slice(creds.password.as_bytes());

    let req_id = 1u8;
    let mut pkt = Vec::with_capacity(6 + payload.len());
    pkt.extend_from_slice(&PPP_PAP.to_be_bytes());
    pkt.push(0x01); // Auth-Request
    pkt.push(req_id);
    #[allow(clippy::cast_possible_truncation)]
    let len = (4 + payload.len()) as u16;
    pkt.extend_from_slice(&len.to_be_bytes());
    pkt.extend_from_slice(&payload);

    session.send_ppp_frame(&pkt).await?;

    let timeout = Duration::from_secs(10);
    let start = tokio::time::Instant::now();
    let mut buf = [0u8; 1500];

    while start.elapsed() < timeout {
        let remaining = timeout.saturating_sub(start.elapsed());
        let Ok(Ok(n)) = tokio::time::timeout(remaining, session.recv_ppp_frame(&mut buf)).await
        else {
            return Err(PppoeError::AuthFailed("PAP auth response timeout".into()));
        };

        let data = strip_hdlc(&buf[..n]);
        if data.len() >= 6 {
            let proto = u16::from_be_bytes([data[0], data[1]]);
            if proto == PPP_PAP {
                let code = data[2];
                let id = data[3];
                if id == req_id {
                    match code {
                        0x02 => {
                            debug!("PAP authentication successful");
                            return Ok(());
                        }
                        0x03 => return Err(PppoeError::AuthFailed("PAP Auth-Nak".into())),
                        _ => {}
                    }
                }
            }
        }
    }

    Err(PppoeError::AuthFailed("PAP timed out".into()))
}

async fn authenticate_chap(
    session: &PppoeSession,
    creds: &PppoeCredentials,
) -> Result<(), PppoeError> {
    let timeout = Duration::from_secs(10);
    let start = tokio::time::Instant::now();
    let mut buf = [0u8; 1500];

    while start.elapsed() < timeout {
        let remaining = timeout.saturating_sub(start.elapsed());
        let Ok(Ok(n)) = tokio::time::timeout(remaining, session.recv_ppp_frame(&mut buf)).await
        else {
            return Err(PppoeError::AuthFailed("CHAP Challenge timeout".into()));
        };

        let data = strip_hdlc(&buf[..n]);
        if data.len() >= 2 {
            let proto = u16::from_be_bytes([data[0], data[1]]);
            debug!(
                proto = format_args!("{:#06x}", proto),
                len = data.len(),
                "Received PPP frame during CHAP"
            );
            if proto == PPP_CHAP && data.len() >= 6 {
                let code = data[2];
                let id = data[3];
                if code == 0x01 && data.len() >= 7 {
                    // Challenge
                    let val_len = data[6] as usize;
                    if data.len() >= 7 + val_len {
                        let challenge_val = &data[7..7 + val_len];

                        // Calculate CHAP-MD5 response = MD5(id || password || challenge)
                        let mut hasher = Md5::new();
                        hasher.update([id]);
                        hasher.update(creds.password.as_bytes());
                        hasher.update(challenge_val);
                        let response_hash = hasher.finalize();

                        let mut resp_payload = Vec::new();
                        resp_payload.push(16u8); // MD5 hash length is 16
                        resp_payload.extend_from_slice(&response_hash);
                        resp_payload.extend_from_slice(creds.username.as_bytes());

                        let mut resp_pkt = Vec::with_capacity(6 + resp_payload.len());
                        resp_pkt.extend_from_slice(&PPP_CHAP.to_be_bytes());
                        resp_pkt.push(0x02); // Response
                        resp_pkt.push(id);
                        #[allow(clippy::cast_possible_truncation)]
                        let len = (4 + resp_payload.len()) as u16;
                        resp_pkt.extend_from_slice(&len.to_be_bytes());
                        resp_pkt.extend_from_slice(&resp_payload);

                        session.send_ppp_frame(&resp_pkt).await?;

                        // Wait for CHAP Success / Failure
                        let resp_timeout = Duration::from_secs(5);
                        let resp_start = tokio::time::Instant::now();

                        while resp_start.elapsed() < resp_timeout {
                            let resp_rem = resp_timeout.saturating_sub(resp_start.elapsed());
                            if let Ok(Ok(n_res)) =
                                tokio::time::timeout(resp_rem, session.recv_ppp_frame(&mut buf))
                                    .await
                            {
                                let res_data = strip_hdlc(&buf[..n_res]);
                                if res_data.len() >= 6 {
                                    let p = u16::from_be_bytes([res_data[0], res_data[1]]);
                                    if p == PPP_CHAP && res_data[3] == id {
                                        if res_data[2] == 0x03 {
                                            debug!("CHAP-MD5 authentication successful");
                                            return Ok(());
                                        } else if res_data[2] == 0x04 {
                                            return Err(PppoeError::AuthFailed(
                                                "CHAP Failure received".into(),
                                            ));
                                        }
                                    }
                                }
                            }
                        }

                        return Err(PppoeError::AuthFailed("CHAP result timeout".into()));
                    }
                }
            }
        }
    }

    Err(PppoeError::AuthFailed("CHAP negotiation timed out".into()))
}
