use crate::config::PppoeConfig;
use crate::error::PppoeError;
use crate::lcp::{LCP_CONF_REQ, LCP_ECHO_REP, LCP_ECHO_REQ, LCP_TERM_ACK, LCP_TERM_REQ, PPP_LCP};
use crate::service::SystemInterrupt;
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_transport::ArpProber;
use lanforge_types::config::ChangeImpact;
use lanforge_types::system::ServiceAction;
use nix::unistd::{read, write};
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::time::interval;
use tracing::{debug, info, warn};

pub const PPP_IP: u16 = 0x0021;
pub const PPP_IPV6: u16 = 0x0057;

#[allow(clippy::too_many_lines)]
pub(crate) async fn run_keepalive(
    chan_fd: &OwnedFd,
    ctx: &LanforgeContext,
    local_magic: u32,
    peer_magic: u32,
    mut interval_secs: u64,
    mut max_failures: u32,
    prober: Option<(&ArpProber, Ipv4Addr, Option<Ipv4Addr>, Duration)>,
) -> Result<Option<SystemInterrupt>, PppoeError> {
    let async_chan_fd = unsafe { AsyncFd::register(chan_fd.try_clone()?)? };
    let mut echo_id: u8 = 0;
    let mut failed_echoes: u32 = 0;

    let check_interval = Duration::from_secs(interval_secs.max(1));
    let mut interval_timer = interval(check_interval);

    let mut bus_rx = ctx.bus().subscribe_system();
    let mut config_sub = ctx.config_subscription::<PppoeConfig>();
    let mut read_buf = [0u8; 1500];

    loop {
        if !ctx.is_running() {
            debug!("Lanforge context stopped, exiting keepalive loop");
            return Ok(Some(SystemInterrupt::Shutdown));
        }

        tokio::select! {
            delta_opt = config_sub.next() => {
                let Some(delta) = delta_opt else { return Ok(None); };
                if !delta.new.enabled {
                    info!("PPPoE disabled during keepalive; terminating session");
                    return Ok(Some(SystemInterrupt::Stop));
                }
                match delta.impact {
                    ChangeImpact::None => {}
                    ChangeImpact::Hot => {
                        info!("PPPoE keepalive updated timers in-place");
                        interval_secs = delta.new.lcp_echo_interval_secs;
                        max_failures = delta.new.lcp_echo_max_failures;
                        interval_timer = interval(Duration::from_secs(interval_secs.max(1)));
                    }
                    ChangeImpact::Reconnect | ChangeImpact::Rebind => {
                        info!("PPPoE keepalive received config change requiring reconnect; terminating session to reconnect");
                        return Ok(Some(SystemInterrupt::Restart));
                    }
                }
            }
            _ = interval_timer.tick() => {
                if interval_secs > 0 {
                    echo_id = echo_id.wrapping_add(1);
                    if let Err(e) = send_echo_request(
                        chan_fd,
                        echo_id,
                        local_magic,
                    ) {
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

            guard_res = async_chan_fd.readable() => {
                let mut guard = guard_res?;
                match read(chan_fd, &mut read_buf) {
                    Ok(n) if n > 0 => {
                        guard.clear_ready();
                        let action = handle_incoming_frame(
                            chan_fd,
                            &read_buf[..n],
                            local_magic,
                            peer_magic,
                            &mut failed_echoes,
                        );
                        if action == KeepaliveAction::PeerTerminated {
                            return Err(PppoeError::LcpFailed(
                                "Peer terminated session (LCP Terminate-Request)".into(),
                            ));
                        }
                    }
                    Ok(_) | Err(nix::errno::Errno::EWOULDBLOCK) => {
                        guard.clear_ready();
                    }
                    Err(e) => {
                        warn!(error = %e, "PPPoE channel read error during keepalive");
                        return Err(PppoeError::Nix(e));
                    }
                }
            }

            res = bus_rx.recv() => {
                let Ok(event) = res else { continue; };
                match event.event {
                    LanforgeEvent::System(SystemEvent::Shutdown) => {
                        info!("PPPoE keepalive received daemon shutdown, disconnecting session");
                        return Ok(Some(SystemInterrupt::Shutdown));
                    }
                    LanforgeEvent::System(SystemEvent::ServiceControl { ref id, ref action })
                        if *id == lanforge_types::system::ServiceId::Pppoe =>
                    {
                        match action {
                            ServiceAction::Stop => {
                                info!("PPPoE keepalive received service stop");
                                return Ok(Some(SystemInterrupt::Stop));
                            }
                            ServiceAction::Restart => {
                                info!("PPPoE keepalive received service restart");
                                return Ok(Some(SystemInterrupt::Restart));
                            }
                            ServiceAction::Start => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn send_echo_request(fd: &OwnedFd, id: u8, magic: u32) -> Result<(), PppoeError> {
    let mut pkt = [0u8; 10];
    pkt[0..2].copy_from_slice(&PPP_LCP.to_be_bytes());
    pkt[2] = LCP_ECHO_REQ;
    pkt[3] = id;
    pkt[4..6].copy_from_slice(&8u16.to_be_bytes());
    pkt[6..10].copy_from_slice(&magic.to_be_bytes());

    let n = write(fd, &pkt)?;
    if n != 10 {
        return Err(PppoeError::NegotiationFailed(
            "Short write on LCP Echo-Request".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepaliveAction {
    Continue,
    PeerTerminated,
}

fn handle_incoming_frame(
    fd: &OwnedFd,
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
        handle_lcp_frame(fd, &data[2..], local_magic, failed_echoes)
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
        send_protocol_reject(fd, proto, data);
        KeepaliveAction::Continue
    }
}

fn handle_lcp_frame(
    fd: &OwnedFd,
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
            let _ = write(fd, &rep[..rep_len]);
            KeepaliveAction::Continue
        }
        LCP_TERM_REQ => {
            info!(id, "Peer sent LCP Terminate-Request, sending Terminate-Ack");
            let mut ack = [0u8; 6];
            ack[0..2].copy_from_slice(&PPP_LCP.to_be_bytes());
            ack[2] = LCP_TERM_ACK;
            ack[3] = id;
            ack[4..6].copy_from_slice(&4u16.to_be_bytes());
            let _ = write(fd, &ack);
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

fn send_protocol_reject(fd: &OwnedFd, rejected_proto: u16, original_data: &[u8]) {
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

    let _ = write(fd, &rej[..total_len]);
}
