use crate::error::PppoeError;
use lanforge_transport::PppoeTransport;
use lanforge_types::identifiers::MacAddr;
use std::os::fd::{OwnedFd, RawFd};

pub struct PppoeSession {
    transport: PppoeTransport,
}

impl PppoeSession {
    pub fn connect(
        transport: PppoeTransport,
        ifname: &str,
        ac_mac: MacAddr,
        session_id: u16,
    ) -> Result<Self, PppoeError> {
        transport
            .connect_session(ifname, ac_mac.0, session_id)
            .map_err(|e| PppoeError::NegotiationFailed(e.to_string()))?;
        Ok(Self { transport })
    }

    pub async fn send_ppp_frame(&self, frame: &[u8]) -> Result<(), PppoeError> {
        self.transport
            .send_session(frame)
            .await
            .map_err(|e| PppoeError::NegotiationFailed(e.to_string()))?;
        Ok(())
    }

    pub async fn recv_ppp_frame(&self, buf: &mut [u8]) -> Result<usize, PppoeError> {
        self.transport
            .recv_session(buf)
            .await
            .map_err(|e| PppoeError::NegotiationFailed(e.to_string()))
    }

    #[must_use]
    pub fn is_inert(&self) -> bool {
        self.transport.is_inert()
    }

    pub fn try_clone_session_fd(&self) -> Result<Option<OwnedFd>, PppoeError> {
        self.transport
            .try_clone_session_fd()
            .map_err(|e| PppoeError::NegotiationFailed(e.to_string()))
    }

    pub fn attach_kernel_channel(&self, chan_fd: OwnedFd) -> Result<(), PppoeError> {
        self.transport
            .attach_kernel_channel(chan_fd)
            .map_err(|e| PppoeError::NegotiationFailed(e.to_string()))
    }

    #[must_use]
    pub fn session_raw_fd(&self) -> Option<RawFd> {
        self.transport.session_raw_fd()
    }
}

impl Drop for PppoeSession {
    fn drop(&mut self) {
        self.transport.close_session();
    }
}
