pub mod frame;

use crate::error::PppoeError;
use crate::ipcp::PacketBuf;
use frame::{
    CODE_PADI, CODE_PADO, CODE_PADR, CODE_PADS, CODE_PADT, PppoeDiscoveryFrame, TAG_AC_COOKIE,
    TAG_AC_NAME, TAG_HOST_UNIQ, TAG_SERVICE_NAME, Tag,
};
use lanforge_transport::PppoeTransport;
use lanforge_types::identifiers::MacAddr;
use smallvec::{SmallVec, smallvec};
use std::str;
use std::time::Duration;
use tokio::time::{self, Instant, sleep};
use tracing::{debug, info, warn};

pub struct DiscoveryResult {
    pub ac_mac: MacAddr,
    pub ac_name: Option<String>,
    pub session_id: u16,
}

pub struct PppoeDiscovery {
    ifindex: u32,
    local_mac: MacAddr,
    padi_retries: u32,
    padi_timeout_secs: u64,
    service_name: Option<String>,
    ac_name: Option<String>,
}

impl PppoeDiscovery {
    #[must_use]
    pub const fn new(
        ifindex: u32,
        local_mac: MacAddr,
        padi_retries: u32,
        padi_timeout_secs: u64,
        service_name: Option<String>,
        ac_name: Option<String>,
    ) -> Self {
        Self {
            ifindex,
            local_mac,
            padi_retries,
            padi_timeout_secs,
            service_name,
            ac_name,
        }
    }

    #[allow(clippy::similar_names)]
    pub async fn run_with_transport(
        &self,
        transport: &PppoeTransport,
    ) -> Result<DiscoveryResult, PppoeError> {
        let host_uniq: [u8; 4] = rand::random();

        // 1. Send PADI and wait for PADO
        let (ac_mac, ac_name, ac_cookie) = exchange_padi(
            transport,
            self.local_mac,
            &host_uniq,
            self.padi_retries,
            self.padi_timeout_secs,
            self.service_name.as_deref(),
            self.ac_name.as_deref(),
        )
        .await?;

        // 2. Send PADR and wait for PADS
        let session_id = exchange_padr(
            transport,
            self.local_mac,
            ac_mac,
            ac_cookie.as_deref(),
            &host_uniq,
            self.service_name.as_deref(),
        )
        .await?;

        Ok(DiscoveryResult {
            ac_mac,
            ac_name,
            session_id,
        })
    }

    /// Whether a concentrator answers right now: one PADI, one timeout, no session. A PADO commits
    /// the concentrator to nothing (RFC 2516 §5.2), so this is cheap to repeat while the WAN is
    /// dark.
    ///
    /// # Errors
    /// The PADI cannot be sent.
    pub async fn probe(&self, transport: &PppoeTransport) -> Result<bool, PppoeError> {
        let host_uniq: [u8; 4] = rand::random();
        let padi = padi_frame(self.local_mac, host_uniq, self.service_name.as_deref());
        transport
            .send_discovery(&padi)
            .await
            .map_err(|e| PppoeError::NegotiationFailed(e.to_string()))?;
        let timeout = Duration::from_secs(self.padi_timeout_secs);
        Ok(
            await_pado(transport, &host_uniq, timeout, self.ac_name.as_deref())
                .await
                .is_some(),
        )
    }

    pub async fn run(&self) -> Result<DiscoveryResult, PppoeError> {
        let transport = PppoeTransport::bind(self.ifindex)
            .map_err(|e| PppoeError::NegotiationFailed(e.to_string()))?;
        self.run_with_transport(&transport).await
    }
}

/// What a matching PADO offers: the concentrator's MAC, its name and its cookie.
type Pado = (MacAddr, Option<String>, Option<SmallVec<[u8; 64]>>);

fn padi_frame(
    local_mac: MacAddr,
    host_uniq: [u8; 4],
    service_name: Option<&str>,
) -> PacketBuf<256> {
    PppoeDiscoveryFrame {
        dst_mac: MacAddr([0xff; 6]),
        src_mac: local_mac,
        code: CODE_PADI,
        session_id: 0,
        tags: smallvec![
            Tag {
                tag_type: TAG_SERVICE_NAME,
                value: service_name.map_or(&[], str::as_bytes),
            },
            Tag {
                tag_type: TAG_HOST_UNIQ,
                value: &host_uniq,
            },
        ],
    }
    .encode()
}

/// Waits up to `timeout` for a PADO answering `host_uniq` from an acceptable concentrator.
async fn await_pado(
    transport: &PppoeTransport,
    host_uniq: &[u8; 4],
    timeout: Duration,
    ac_name_filter: Option<&str>,
) -> Option<Pado> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        let remaining = timeout.saturating_sub(start.elapsed());
        let mut buf = [0u8; 2048];
        if let Ok(Ok(n)) = time::timeout(remaining, transport.recv_discovery(&mut buf)).await
            && let Some(frame) = PppoeDiscoveryFrame::parse(&buf[..n])
            && frame.code == CODE_PADO
        {
            // Verify host_uniq
            let matches_uniq = frame
                .tags
                .iter()
                .any(|t| t.tag_type == TAG_HOST_UNIQ && t.value == host_uniq);
            if matches_uniq {
                let mut frame_ac_name = None;
                let mut frame_ac_cookie = None;
                for tag in &frame.tags {
                    if tag.tag_type == TAG_AC_COOKIE {
                        frame_ac_cookie = Some(SmallVec::from_slice(tag.value));
                    } else if tag.tag_type == TAG_AC_NAME {
                        frame_ac_name = str::from_utf8(tag.value).ok().map(ToString::to_string);
                    }
                }

                if let Some(filter) = ac_name_filter
                    && frame_ac_name.as_deref() != Some(filter)
                {
                    debug!(
                        expected = filter,
                        actual = ?frame_ac_name,
                        "Ignoring PADO from non-matching Access Concentrator"
                    );
                    continue;
                }

                debug!("Received valid PPPoE PADO frame");
                return Some((frame.src_mac, frame_ac_name, frame_ac_cookie));
            }
        }
    }
    None
}

async fn exchange_padi(
    transport: &PppoeTransport,
    local_mac: MacAddr,
    host_uniq: &[u8; 4],
    padi_retries: u32,
    padi_timeout_secs: u64,
    service_name: Option<&str>,
    ac_name_filter: Option<&str>,
) -> Result<Pado, PppoeError> {
    let padi_bytes = padi_frame(local_mac, *host_uniq, service_name);
    let timeout = Duration::from_secs(padi_timeout_secs);

    for attempt in 0..padi_retries {
        debug!(attempt, "Sending PPPoE PADI frame...");
        transport
            .send_discovery(&padi_bytes)
            .await
            .map_err(|e| PppoeError::NegotiationFailed(e.to_string()))?;

        if let Some(pado) = await_pado(transport, host_uniq, timeout, ac_name_filter).await {
            return Ok(pado);
        }
    }

    Err(PppoeError::NoConcentrator)
}

async fn exchange_padr(
    transport: &PppoeTransport,
    local_mac: MacAddr,
    ac_mac: MacAddr,
    ac_cookie: Option<&[u8]>,
    host_uniq: &[u8; 4],
    service_name: Option<&str>,
) -> Result<u16, PppoeError> {
    let service_name_bytes = service_name.map_or_else(|| &[] as &[u8], str::as_bytes);
    let mut padr_tags = smallvec![
        Tag {
            tag_type: TAG_SERVICE_NAME,
            value: service_name_bytes,
        },
        Tag {
            tag_type: TAG_HOST_UNIQ,
            value: host_uniq,
        },
    ];
    if let Some(cookie) = ac_cookie {
        padr_tags.push(Tag {
            tag_type: TAG_AC_COOKIE,
            value: cookie,
        });
    }

    let padr_frame = PppoeDiscoveryFrame {
        dst_mac: ac_mac,
        src_mac: local_mac,
        code: CODE_PADR,
        session_id: 0,
        tags: padr_tags,
    };
    let padr_bytes = padr_frame.encode();

    let mut session_id = None;

    for attempt in 0..3 {
        debug!(attempt, "Sending PPPoE PADR frame...");
        transport
            .send_discovery(&padr_bytes)
            .await
            .map_err(|e| PppoeError::NegotiationFailed(e.to_string()))?;

        // Wait for PADS
        let timeout = Duration::from_secs(3);
        let start = Instant::now();

        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            let mut buf = [0u8; 2048];
            if let Ok(Ok(n)) = time::timeout(remaining, transport.recv_discovery(&mut buf)).await
                && let Some(frame) = PppoeDiscoveryFrame::parse(&buf[..n])
                && frame.code == CODE_PADS
            {
                let matches_uniq = frame
                    .tags
                    .iter()
                    .any(|t| t.tag_type == TAG_HOST_UNIQ && t.value == host_uniq);
                if matches_uniq {
                    session_id = Some(frame.session_id);
                    debug!(session_id = frame.session_id, "Received PPPoE PADS frame");
                    break;
                }
            }
        }

        if session_id.is_some() {
            break;
        }
    }

    session_id.ok_or(PppoeError::DiscoveryTimeout)
}

pub async fn send_padt(
    transport: &PppoeTransport,
    ifname: &str,
    wan_mac: MacAddr,
    ac_mac: MacAddr,
    session_id: u16,
) -> Result<(), PppoeError> {
    let frame = PppoeDiscoveryFrame {
        dst_mac: ac_mac,
        src_mac: wan_mac,
        code: CODE_PADT,
        session_id,
        tags: smallvec![],
    };

    let bytes = frame.encode();
    for i in 0..3 {
        if let Err(e) = transport.send_discovery(&bytes).await {
            warn!(
                attempt = i + 1,
                error = %e,
                "Failed to transmit PPPoE PADT frame"
            );
        }
        sleep(Duration::from_millis(10)).await;
    }

    info!(
        session_id,
        wan_iface = ifname,
        ac_mac = %ac_mac,
        "Transmitted PPPoE PADT termination frames to BRAS"
    );
    Ok(())
}
