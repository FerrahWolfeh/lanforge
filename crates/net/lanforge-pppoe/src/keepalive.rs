use crate::error::PppoeError;
use crate::lcp::{LCP_ECHO_REP, LCP_ECHO_REQ, LCP_TERM_ACK, LCP_TERM_REQ, PPP_LCP};
use lanforge_core::bus::{LanforgeEvent, PppoeEvent, SystemEvent};

use lanforge_core::context::LanforgeContext;
use std::os::fd::OwnedFd;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::time::MissedTickBehavior;
use tracing::{debug, warn};

pub async fn run_keepalive(
    control_fd: &OwnedFd,
    ctx: &LanforgeContext,
    local_magic: u32,
    _peer_magic: u32,
    echo_interval_secs: u64,
    max_failures: u32,
) -> Result<(), PppoeError> {
    let chan_fd_clone = control_fd.try_clone()?;
    let async_chan_fd = AsyncFd::new(chan_fd_clone)?;
    let mut bus_rx = ctx.bus().subscribe();

    let mut req_id = 1u8;
    let mut consecutive_failures = 0u32;
    let mut interval_timer = tokio::time::interval(Duration::from_secs(echo_interval_secs));
    interval_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Skip initial immediate tick so first Echo-Request is sent after the full interval
    interval_timer.tick().await;

    debug!(
        echo_interval_secs,
        max_failures,
        "Keepalive monitoring loop initialized, waiting for first interval tick"
    );

    let mut buf = [0u8; 1500];

    loop {
        if !ctx.is_running() {
            return Ok(());
        }

        tokio::select! {
            _ = interval_timer.tick() => {
                send_echo_request(
                    ctx,
                    &async_chan_fd,
                    &mut req_id,
                    &mut consecutive_failures,
                    local_magic,
                    max_failures,
                ).await?;
            }

            _ = async_chan_fd.readable() => {
                if let Some(err) = process_readable_chan_fd(
                    ctx,
                    &async_chan_fd,
                    &mut buf,
                    local_magic,
                    &mut consecutive_failures,
                ).await? {
                    return Err(err);
                }
            }


            res = bus_rx.recv() => {
                let Ok(event) = res else { continue; };
                match event.event {
                    LanforgeEvent::System(SystemEvent::Shutdown) => {
                        debug!("Shutdown received during keepalive loop");
                        return Ok(());
                    }
                    LanforgeEvent::System(SystemEvent::ServiceControl { ref id, ref action })
                        if id == "pppoe"
                            && matches!(
                                action,
                                lanforge_types::system::ServiceAction::Stop
                                    | lanforge_types::system::ServiceAction::Restart
                            ) =>
                    {
                        debug!("ServiceControl {:?} received during keepalive loop", action);
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn send_echo_request(
    ctx: &LanforgeContext,
    async_chan_fd: &AsyncFd<OwnedFd>,
    req_id: &mut u8,
    consecutive_failures: &mut u32,
    local_magic: u32,
    max_failures: u32,
) -> Result<(), PppoeError> {
    *consecutive_failures += 1;
    if *consecutive_failures > 1 {
        let _ = ctx
            .bus()
            .publish(LanforgeEvent::Pppoe(PppoeEvent::KeepaliveWarning {
                consecutive_failures: *consecutive_failures,
                max_failures,
            }));
    }
    if *consecutive_failures > max_failures {
        warn!(
            failures = *consecutive_failures,
            max_failures,
            "LCP echo keepalive timed out (no Echo-Reply from peer), link considered dead"
        );
        return Err(PppoeError::KeepAliveTimeout);
    }

    *req_id = req_id.wrapping_add(1);
    // RFC 1661 Sec 5.8: LCP Echo-Request format (10 bytes total: 2-byte PPP proto + 4-byte LCP header + 4-byte magic)
    let mut pkt_bytes = Vec::with_capacity(10);
    pkt_bytes.extend_from_slice(&PPP_LCP.to_be_bytes());
    pkt_bytes.push(LCP_ECHO_REQ);
    pkt_bytes.push(*req_id);
    pkt_bytes.extend_from_slice(&8u16.to_be_bytes());
    pkt_bytes.extend_from_slice(&local_magic.to_be_bytes());

    let mut guard = async_chan_fd.writable().await?;
    match nix::unistd::write(async_chan_fd.get_ref(), &pkt_bytes) {
        Ok(n) => {
            debug!(
                req_id = *req_id,
                failures = *consecutive_failures,
                bytes_written = n,
                "Sent LCP Echo-Request to peer"
            );
        }
        Err(e) => {
            warn!(error = %e, "Failed to write LCP Echo-Request to ppp_chan_fd");
        }
    }
    guard.clear_ready();
    Ok(())
}

async fn process_readable_chan_fd(
    ctx: &LanforgeContext,
    async_chan_fd: &AsyncFd<OwnedFd>,
    buf: &mut [u8],
    local_magic: u32,
    consecutive_failures: &mut u32,
) -> Result<Option<PppoeError>, PppoeError> {
    let Ok(mut guard) = async_chan_fd.readable().await else {
        return Ok(None);
    };
    let n = match nix::unistd::read(async_chan_fd.get_ref(), buf) {
        Ok(n) => n,
        Err(e) => {
            warn!(error = %e, "Error reading from ppp_chan_fd");
            guard.clear_ready();
            return Ok(None);
        }
    };
    guard.clear_ready();

    if n == 0 {
        warn!("ppp_chan_fd returned EOF (0 bytes read). PPPoE channel disconnected!");
        return Ok(Some(PppoeError::KeepAliveTimeout));
    }

    handle_lcp_frame(
        ctx,
        async_chan_fd,
        &buf[..n],
        local_magic,
        consecutive_failures,
    )
    .await
}

async fn send_protocol_reject(
    async_chan_fd: &AsyncFd<OwnedFd>,
    proto: u16,
    data: &[u8],
) {
    if (proto & 0x8000) != 0 && proto != 0x8021 && proto != 0x8057 {
        let mut rej = Vec::with_capacity(6 + data.len());
        rej.extend_from_slice(&PPP_LCP.to_be_bytes());
        rej.push(8 /* LCP_PROT_REJ */);
        rej.push(1 /* id */);
        #[allow(clippy::cast_possible_truncation)]
        let rej_len = (4 + data.len()) as u16;
        rej.extend_from_slice(&rej_len.to_be_bytes());
        rej.extend_from_slice(data);
        if let Ok(mut wguard) = async_chan_fd.writable().await {
            let _ = nix::unistd::write(async_chan_fd.get_ref(), &rej);
            wguard.clear_ready();
            debug!(
                proto = %format!("0x{proto:04x}"),
                "Sent LCP Protocol-Reject for unsupported protocol"
            );
        }
    }
}

struct LcpPacket<'a> {
    code: u8,
    id: u8,
    len: usize,
    data: &'a [u8],
}

async fn handle_lcp_code(
    ctx: &LanforgeContext,
    async_chan_fd: &AsyncFd<OwnedFd>,
    pkt: &LcpPacket<'_>,
    local_magic: u32,
    consecutive_failures: &mut u32,
) -> Result<Option<PppoeError>, PppoeError> {
    match pkt.code {
        LCP_ECHO_REP => {
            if *consecutive_failures > 0 {
                let _ = ctx
                    .bus()
                    .publish(LanforgeEvent::Pppoe(PppoeEvent::KeepaliveRestored));
            }
            *consecutive_failures = 0;
            debug!(id = pkt.id, "Received LCP Echo-Reply from peer");
        }
        LCP_ECHO_REQ => {
            let mut reply = Vec::with_capacity(2 + pkt.len);
            reply.extend_from_slice(&PPP_LCP.to_be_bytes());
            reply.push(LCP_ECHO_REP);
            reply.push(pkt.id);
            #[allow(clippy::cast_possible_truncation)]
            reply.extend_from_slice(&(pkt.len as u16).to_be_bytes());
            reply.extend_from_slice(&local_magic.to_be_bytes());
            if pkt.len > 8 {
                reply.extend_from_slice(&pkt.data[10..2 + pkt.len]);
            }

            if let Ok(mut wguard) = async_chan_fd.writable().await {
                let _ = nix::unistd::write(async_chan_fd.get_ref(), &reply);
                wguard.clear_ready();
                debug!(id = pkt.id, "Received LCP Echo-Request from peer, sent Echo-Reply");
            }
        }
        LCP_TERM_REQ => {
            let mut ack = Vec::with_capacity(6);
            ack.extend_from_slice(&PPP_LCP.to_be_bytes());
            ack.push(LCP_TERM_ACK);
            ack.push(pkt.id);
            ack.extend_from_slice(&4u16.to_be_bytes());

            if let Ok(mut wguard) = async_chan_fd.writable().await {
                let _ = nix::unistd::write(async_chan_fd.get_ref(), &ack);
                wguard.clear_ready();
            }
            warn!(id = pkt.id, "Peer sent LCP Terminate-Request!");
            return Ok(Some(PppoeError::LcpFailed(
                "Peer terminated LCP session".into(),
            )));
        }
        _ => {
            debug!(code = pkt.code, id = pkt.id, len = pkt.len, "Received other LCP frame code");
        }
    }

    Ok(None)
}

async fn handle_lcp_frame(
    ctx: &LanforgeContext,
    async_chan_fd: &AsyncFd<OwnedFd>,
    raw_buf: &[u8],
    local_magic: u32,
    consecutive_failures: &mut u32,
) -> Result<Option<PppoeError>, PppoeError> {
    let data = if raw_buf.len() >= 2 && raw_buf[0] == 0xff && raw_buf[1] == 0x03 {
        &raw_buf[2..]
    } else {
        raw_buf
    };

    if data.len() < 2 {
        tracing::trace!(len = raw_buf.len(), "Read short packet from ppp_chan_fd");
        return Ok(None);
    }

    let proto = u16::from_be_bytes([data[0], data[1]]);
    if proto != PPP_LCP {
        debug!(
            proto = %format!("0x{proto:04x}"),
            len = raw_buf.len(),
            "Received non-LCP PPP frame on chan_fd"
        );
        send_protocol_reject(async_chan_fd, proto, data).await;
        return Ok(None);
    }

    if data.len() < 6 {
        debug!(len = data.len(), "Received truncated LCP frame");
        return Ok(None);
    }

    let code = data[2];
    let id = data[3];
    let len = u16::from_be_bytes([data[4], data[5]]) as usize;

    if data.len() < 2 + len {
        debug!(
            code,
            id,
            len,
            actual = data.len() - 2,
            "Received LCP frame with incomplete length"
        );
        return Ok(None);
    }

    let pkt = LcpPacket {
        code,
        id,
        len,
        data,
    };

    handle_lcp_code(
        ctx,
        async_chan_fd,
        &pkt,
        local_magic,
        consecutive_failures,
    )
    .await
}
