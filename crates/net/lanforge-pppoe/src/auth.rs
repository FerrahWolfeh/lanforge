use crate::config::{AuthMethod, PppoeCredentials};
use crate::error::PppoeError;
use crate::lcp::{PPP_CHAP, PPP_PAP};
use crate::session::PppoeSession;
use md5::{Digest, Md5};
use std::time::Duration;
use tokio::time::{Instant, timeout};
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
    let u_bytes = creds.username.as_bytes();
    let p_bytes = creds.password.as_bytes();
    let u_len = u_bytes.len().min(255);
    let p_len = p_bytes.len().min(255);
    let total_len = 6 + 1 + u_len + 1 + p_len;

    let mut pkt = [0u8; 512];
    pkt[0..2].copy_from_slice(&PPP_PAP.to_be_bytes());
    pkt[2] = 0x01; // Auth-Request
    pkt[3] = 1; // Req ID
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

    session.send_ppp_frame(&pkt[..total_len]).await?;

    let auth_timeout = Duration::from_secs(10);
    let start = Instant::now();
    let mut buf = [0u8; 1500];

    while start.elapsed() < auth_timeout {
        let remaining = auth_timeout.saturating_sub(start.elapsed());
        let Ok(Ok(n)) = timeout(remaining, session.recv_ppp_frame(&mut buf)).await else {
            return Err(PppoeError::AuthFailed("PAP auth response timeout".into()));
        };

        let data = strip_hdlc(&buf[..n]);
        if data.len() >= 6 {
            let proto = u16::from_be_bytes([data[0], data[1]]);
            if proto == PPP_PAP && data[3] == 1 {
                match data[2] {
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

    Err(PppoeError::AuthFailed("PAP timed out".into()))
}

async fn authenticate_chap(
    session: &PppoeSession,
    creds: &PppoeCredentials,
) -> Result<(), PppoeError> {
    let auth_timeout = Duration::from_secs(10);
    let start = Instant::now();
    let mut buf = [0u8; 1500];

    while start.elapsed() < auth_timeout {
        let remaining = auth_timeout.saturating_sub(start.elapsed());
        let Ok(Ok(n)) = timeout(remaining, session.recv_ppp_frame(&mut buf)).await else {
            return Err(PppoeError::AuthFailed("CHAP Challenge timeout".into()));
        };

        let data = strip_hdlc(&buf[..n]);
        if data.len() >= 7 {
            let proto = u16::from_be_bytes([data[0], data[1]]);
            let code = data[2];
            let id = data[3];

            if proto == PPP_CHAP && code == 0x01 {
                // Challenge received
                let val_len = data[6] as usize;
                if data.len() >= 7 + val_len {
                    let challenge_val = &data[7..7 + val_len];

                    // Calculate CHAP-MD5 response = MD5(id || password || challenge)
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
                    resp_pkt[2] = 0x02; // Response
                    resp_pkt[3] = id;
                    #[allow(clippy::cast_possible_truncation)]
                    let len_field = (4 + 1 + 16 + u_len) as u16;
                    resp_pkt[4..6].copy_from_slice(&len_field.to_be_bytes());

                    resp_pkt[6] = 16; // MD5 length
                    resp_pkt[7..23].copy_from_slice(&response_hash);
                    resp_pkt[23..23 + u_len].copy_from_slice(&u_bytes[..u_len]);

                    session.send_ppp_frame(&resp_pkt[..total_len]).await?;

                    // Wait for CHAP Success / Failure
                    let resp_timeout = Duration::from_secs(5);
                    let resp_start = Instant::now();

                    while resp_start.elapsed() < resp_timeout {
                        let resp_rem = resp_timeout.saturating_sub(resp_start.elapsed());
                        if let Ok(Ok(n_res)) =
                            timeout(resp_rem, session.recv_ppp_frame(&mut buf)).await
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

    Err(PppoeError::AuthFailed("CHAP negotiation timed out".into()))
}
