use crate::config::PppoeConfig;
use crate::discovery::frame::{CODE_PADT, PppoeDiscoveryFrame};
use crate::error::PppoeError;
use crate::lcp::{LCP_CONF_REQ, LCP_ECHO_REP, LCP_ECHO_REQ, LCP_TERM_ACK, LCP_TERM_REQ, PPP_LCP};
use crate::service::SystemInterrupt;
use crate::session::PppoeSession;
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::{ConfigSubscription, LanforgeContext};
use lanforge_transport::{ArpProber, PppoeTransport};
use lanforge_types::config::ChangeImpact;
use lanforge_types::identifiers::MacAddr;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{Instant, Interval, interval_at, timeout_at};
use tracing::{debug, info, warn};

pub const PPP_IP: u16 = 0x0021;
pub const PPP_IPV6: u16 = 0x0057;

/// The discovery-stage identity of the live session, to recognise the concentrator's PADT.
#[derive(Clone, Copy)]
pub(crate) struct PadtWatch<'a> {
    pub transport: &'a PppoeTransport,
    pub ac_mac: MacAddr,
    pub session_id: u16,
}

impl PadtWatch<'_> {
    fn matches(&self, frame: &[u8]) -> bool {
        PppoeDiscoveryFrame::parse(frame).is_some_and(|f| {
            f.code == CODE_PADT && f.session_id == self.session_id && f.src_mac == self.ac_mac
        })
    }
}

/// The LCP echo timer: first tick one period from now (an immediate tick would count a missed
/// echo before the peer could answer). `0` (echo off) still ticks every second, sending nothing.
fn echo_timer(interval_secs: u64) -> Interval {
    let period = Duration::from_secs(interval_secs.max(1));
    interval_at(Instant::now() + period, period)
}

/// Watches the live session. `config_sub` is the service's own subscription: a change seen here
/// counts as applied for the service too, and a change that arrived while the session was being
/// negotiated is still pending here (a fresh subscription would have missed it).
#[allow(clippy::too_many_lines)]
pub(crate) async fn run_keepalive(
    session: &PppoeSession,
    ctx: &LanforgeContext,
    local_magic: u32,
    peer_magic: u32,
    config_sub: &mut ConfigSubscription<PppoeConfig>,
    prober: Option<(&ArpProber, Ipv4Addr, Option<Ipv4Addr>, Duration)>,
    padt: PadtWatch<'_>,
) -> Result<Option<SystemInterrupt>, PppoeError> {
    let mut echo_id: u8 = 0;
    let mut disc_buf = [0u8; 1500];
    let mut watch_padt = true;
    let mut failed_echoes: u32 = 0;

    let applied = config_sub.current();
    let mut interval_secs = applied.lcp_echo_interval_secs;
    let mut max_failures = applied.lcp_echo_max_failures;
    let mut interval_timer = echo_timer(interval_secs);

    let mut bus_rx = ctx.bus().subscribe_system();
    let mut read_buf = [0u8; 1500];

    loop {
        if !ctx.is_running() {
            debug!("Lanforge context stopped, exiting keepalive loop");
            return Ok(Some(SystemInterrupt::Shutdown));
        }

        tokio::select! {
            delta_opt = config_sub.next() => {
                // The subscription only closes with the context: the daemon is going away.
                let Some(delta) = delta_opt else { return Ok(Some(SystemInterrupt::Shutdown)); };
                if !delta.new.enabled {
                    info!("PPPoE disabled during keepalive; terminating session");
                    return Ok(Some(SystemInterrupt::ConfigDisabled));
                }
                match delta.impact {
                    ChangeImpact::None => {}
                    ChangeImpact::Hot => {
                        if delta.new.lcp_echo_interval_secs != interval_secs
                            || delta.new.lcp_echo_max_failures != max_failures
                        {
                            interval_secs = delta.new.lcp_echo_interval_secs;
                            max_failures = delta.new.lcp_echo_max_failures;
                            interval_timer = echo_timer(interval_secs);
                            info!(interval_secs, max_failures, "PPPoE LCP echo timers updated in place");
                        }
                    }
                    ChangeImpact::Reconnect | ChangeImpact::Rebind => {
                        info!("PPPoE keepalive received config change requiring reconnect; terminating session to reconnect");
                        return Ok(Some(SystemInterrupt::ConfigUpdated));
                    }
                }
            }
            _ = interval_timer.tick() => {
                if interval_secs > 0 {
                    echo_id = echo_id.wrapping_add(1);
                    if let Err(e) = send_echo_request(
                        session,
                        echo_id,
                        local_magic,
                    ).await {
                        warn!(error = %e, "Failed to send LCP Echo-Request");
                    }

                    failed_echoes += 1;
                    if failed_echoes > 1 {
                        warn!(
                            missed = failed_echoes,
                            max = max_failures,
                            "Missing LCP Echo-Reply from ISP Access Concentrator"
                        );
                    }
                    if max_failures > 0 && failed_echoes > max_failures {
                        warn!(
                            missed = failed_echoes,
                            max = max_failures,
                            "LCP keepalive failure threshold exceeded, disconnecting PPPoE session"
                        );
                        if let Some((arp, target_ip, sender_ip, timeout)) = prober {
                            if let Ok(Some(reply)) = arp.probe(target_ip, sender_ip, timeout).await {
                                info!(
                                    target_ip = %target_ip,
                                    rtt_ms = reply.rtt.as_secs_f64() * 1000.0,
                                    "Terminal responded to probe: local hardware underlay is intact, failure is upstream with ISP/optical link"
                                );
                                return Err(PppoeError::KeepAliveTimeout);
                            }
                            warn!(
                                target_ip = %target_ip,
                                "Terminal failed to respond to probe: local hardware/terminal crash or cable disconnected"
                            );
                            return Err(PppoeError::TerminalUnreachable(target_ip, "wan".into()));
                        }
                        return Err(PppoeError::KeepAliveTimeout);
                    }
                }
            }

            read_res = session.recv_ppp_frame(&mut read_buf) => {
                match read_res {
                    Ok(n) if n > 0 => {
                        let action = handle_incoming_frame(
                            session,
                            &read_buf[..n],
                            local_magic,
                            peer_magic,
                            &mut failed_echoes,
                        ).await;
                        if action == KeepaliveAction::PeerTerminated {
                            return Err(PppoeError::LcpFailed(
                                "Peer terminated session (LCP Terminate-Request)".into(),
                            ));
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!(error = %e, "PPPoE channel read error during keepalive");
                        return Err(e);
                    }
                }
            }

            // RFC 2516 §5.5: the concentrator may end the session at any time with a PADT.
            disc_res = padt.transport.recv_discovery(&mut disc_buf), if watch_padt => match disc_res {
                Ok(n) if padt.matches(&disc_buf[..n]) => {
                    warn!(session_id = padt.session_id, "Access concentrator terminated the session (PADT)");
                    return Err(PppoeError::PadtReceived);
                }
                Ok(_) => {}
                Err(e) => {
                    // LCP echo still detects a dead session; do not spin on a broken socket.
                    warn!(error = %e, "Discovery socket error; no longer watching for PADT");
                    watch_padt = false;
                }
            },
            event_res = bus_rx.recv() => match event_res {
                Ok(timed) if matches!(timed.event, LanforgeEvent::System(SystemEvent::Shutdown)) => {
                    info!("PPPoE keepalive received system shutdown");
                    return Ok(Some(SystemInterrupt::Shutdown));
                }
                Err(RecvError::Closed) => return Ok(Some(SystemInterrupt::Shutdown)),
                // A lagged receiver only missed notifications; the session is fine.
                Ok(_) | Err(RecvError::Lagged(_)) => {}
            },
        }
    }
}

/// Echo-Requests sent to confirm a session taken over from a previous process, one per second.
const TAKEOVER_ECHOES: u8 = 3;

/// Whether the concentrator still answers on a session taken over from a previous process: an
/// Echo-Reply within [`TAKEOVER_ECHOES`] seconds. Frames queued while no process served the
/// session (the concentrator's own Echo-Requests) are answered on the way.
pub(crate) async fn confirm_alive(
    session: &PppoeSession,
    local_magic: u32,
    peer_magic: u32,
) -> bool {
    let mut buf = [0u8; 1500];
    for id in 1..=TAKEOVER_ECHOES {
        if let Err(e) = send_echo_request(session, id, local_magic).await {
            warn!(error = %e, "Cannot send LCP Echo-Request on the kept session");
            return false;
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let n = match timeout_at(deadline, session.recv_ppp_frame(&mut buf)).await {
                Err(_) => break,
                Ok(Err(e)) => {
                    warn!(error = %e, "PPPoE channel read error on the kept session");
                    return false;
                }
                Ok(Ok(n)) => n,
            };
            // Set to 0 by an Echo-Reply.
            let mut unanswered = 1;
            let action =
                handle_incoming_frame(session, &buf[..n], local_magic, peer_magic, &mut unanswered)
                    .await;
            if action == KeepaliveAction::PeerTerminated {
                return false;
            }
            if unanswered == 0 {
                return true;
            }
        }
    }
    false
}

async fn send_echo_request(session: &PppoeSession, id: u8, magic: u32) -> Result<(), PppoeError> {
    let mut pkt = [0u8; 10];
    pkt[0..2].copy_from_slice(&PPP_LCP.to_be_bytes());
    pkt[2] = LCP_ECHO_REQ;
    pkt[3] = id;
    pkt[4..6].copy_from_slice(&8u16.to_be_bytes());
    pkt[6..10].copy_from_slice(&magic.to_be_bytes());

    session.send_ppp_frame(&pkt).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepaliveAction {
    Continue,
    PeerTerminated,
}

async fn handle_incoming_frame(
    session: &PppoeSession,
    frame: &[u8],
    local_magic: u32,
    _peer_magic: u32,
    failed_echoes: &mut u32,
) -> KeepaliveAction {
    let data = if frame.len() >= 2 && frame[0] == 0xff && frame[1] == 0x03 {
        &frame[2..]
    } else {
        frame
    };

    if data.len() < 2 {
        return KeepaliveAction::Continue;
    }

    let proto = u16::from_be_bytes([data[0], data[1]]);
    if proto == PPP_LCP {
        handle_lcp_frame(session, &data[2..], local_magic, failed_echoes).await
    } else if proto == PPP_IP || proto == PPP_IPV6 {
        debug!(
            proto = format_args!("{proto:#06x}"),
            len = data.len(),
            "Data plane packet received on control channel"
        );
        KeepaliveAction::Continue
    } else {
        debug!(
            proto = format_args!("{proto:#06x}"),
            "Unknown PPP protocol received, sending Protocol-Reject"
        );
        send_protocol_reject(session, proto, data).await;
        KeepaliveAction::Continue
    }
}

async fn handle_lcp_frame(
    session: &PppoeSession,
    lcp_data: &[u8],
    local_magic: u32,
    failed_echoes: &mut u32,
) -> KeepaliveAction {
    if lcp_data.len() < 4 {
        return KeepaliveAction::Continue;
    }

    let code = lcp_data[0];
    let id = lcp_data[1];
    let len = u16::from_be_bytes([lcp_data[2], lcp_data[3]]) as usize;

    if lcp_data.len() < len || len < 4 {
        return KeepaliveAction::Continue;
    }

    let payload = &lcp_data[4..len];

    match code {
        LCP_ECHO_REP => {
            if *failed_echoes > 1 {
                info!(
                    id,
                    missed = *failed_echoes,
                    "LCP keepalive recovered, received Echo-Reply from ISP Access Concentrator"
                );
            }
            *failed_echoes = 0;
            debug!(id, "Received LCP Echo-Reply from BRAS");
            KeepaliveAction::Continue
        }
        LCP_ECHO_REQ => {
            let mut rep = [0u8; 512];
            let rep_len = 6 + payload.len().min(500);
            rep[0..2].copy_from_slice(&PPP_LCP.to_be_bytes());
            rep[2] = LCP_ECHO_REP;
            rep[3] = id;
            #[allow(clippy::cast_possible_truncation)]
            let l = (4 + payload.len().min(500)) as u16;
            rep[4..6].copy_from_slice(&l.to_be_bytes());

            if payload.len() >= 4 {
                rep[6..10].copy_from_slice(&local_magic.to_be_bytes());
                if payload.len() > 4 {
                    let extra = (payload.len() - 4).min(496);
                    rep[10..10 + extra].copy_from_slice(&payload[4..4 + extra]);
                }
            }
            let _ = session.send_ppp_frame(&rep[..rep_len]).await;
            KeepaliveAction::Continue
        }
        LCP_TERM_REQ => {
            info!(id, "Peer sent LCP Terminate-Request, sending Terminate-Ack");
            let mut ack = [0u8; 6];
            ack[0..2].copy_from_slice(&PPP_LCP.to_be_bytes());
            ack[2] = LCP_TERM_ACK;
            ack[3] = id;
            ack[4..6].copy_from_slice(&4u16.to_be_bytes());
            let _ = session.send_ppp_frame(&ack).await;
            KeepaliveAction::PeerTerminated
        }
        LCP_TERM_ACK => {
            debug!(id, "Peer acknowledged LCP termination");
            KeepaliveAction::Continue
        }
        LCP_CONF_REQ => {
            debug!(id, "Peer renegotiating LCP in active session");
            KeepaliveAction::Continue
        }
        _ => {
            debug!(code, id, "Unhandled LCP packet in keepalive phase");
            KeepaliveAction::Continue
        }
    }
}

async fn send_protocol_reject(session: &PppoeSession, rejected_proto: u16, original_data: &[u8]) {
    let mut rej = [0u8; 512];
    let extra_len = original_data.len().min(500);
    let total_len = 6 + 2 + extra_len;

    rej[0..2].copy_from_slice(&PPP_LCP.to_be_bytes());
    rej[2] = 0x08; // Protocol-Reject
    rej[3] = 1; // ID
    #[allow(clippy::cast_possible_truncation)]
    let len = (4 + 2 + extra_len) as u16;
    rej[4..6].copy_from_slice(&len.to_be_bytes());
    rej[6..8].copy_from_slice(&rejected_proto.to_be_bytes());
    rej[8..8 + extra_len].copy_from_slice(&original_data[..extra_len]);

    let _ = session.send_ppp_frame(&rej[..total_len]).await;
}
