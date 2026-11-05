//! What the `PPPoE` service needs from the machine it runs on, injected like its transport:
//! [`KernelHost`] in production, a stand-in in rootless tests. The service itself holds no
//! simulation branches.

use crate::error::PppoeError;
use crate::ipcp::IpcpNegotiated;
use crate::kernel::{KernelSession, configure_interface, handoff_to_kernel};
use crate::lcp::LcpNegotiated;
use crate::session::PppoeSession;
use lanforge_transport::{Icmp6Transport, sys};
use lanforge_types::identifiers::MacAddr;
use std::future::Future;
use std::io::Read;
use std::path::Path;
use tracing::{debug, info, warn};

/// The host operations of a `PPPoE` session: interface lookup, link state, and the kernel side
/// of bringing the PPP link up.
pub trait PppoeHost: Send + Sync + 'static {
    /// Kernel index and MAC address of interface `name`; `None` if it does not exist.
    fn interface(&self, name: &str) -> Option<(u32, MacAddr)>;

    /// Carrier of interface `name`: `Some(true)` when the link is up, `None` when unknown.
    fn carrier(&self, name: &str) -> Option<bool>;

    /// Whether the kernel PPP driver (`/dev/ppp`) is available.
    fn ppp_available(&self) -> bool;

    /// Hands the negotiated session to the kernel and configures the PPP interface. Returns the
    /// interface name and the kernel session, which must live as long as the link.
    fn bring_up(
        &self,
        session: &PppoeSession,
        lcp: &LcpNegotiated,
        ipcp: &IpcpNegotiated,
    ) -> impl Future<Output = Result<(String, Option<KernelSession>), PppoeError>> + Send;

    /// A passive listener for the Router Advertisements the ISP sends on `interface`.
    fn ra_listener(&self, interface: &str) -> Option<Icmp6Transport>;
}

/// The real host: sysfs, `/dev/ppp`, ioctls and rtnetlink.
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelHost;

impl PppoeHost for KernelHost {
    fn interface(&self, name: &str) -> Option<(u32, MacAddr)> {
        let ifindex = sys::if_name_to_index(name)?;
        let mac = sys::if_hwaddr(name)?;
        Some((ifindex, MacAddr(mac)))
    }

    fn carrier(&self, name: &str) -> Option<bool> {
        if !Path::new("/sys/class/net").exists() {
            debug!(
                name,
                "No /sys/class/net: carrier unknown, assuming the link is up"
            );
            return Some(true);
        }
        read_carrier(name)
    }

    fn ppp_available(&self) -> bool {
        Path::new("/dev/ppp").exists()
    }

    async fn bring_up(
        &self,
        session: &PppoeSession,
        lcp: &LcpNegotiated,
        ipcp: &IpcpNegotiated,
    ) -> Result<(String, Option<KernelSession>), PppoeError> {
        info!("Performing kernel ppp_generic handoff...");
        let session_fd = session.try_clone_session_fd()?.ok_or_else(|| {
            PppoeError::NegotiationFailed("No session fd available for kernel handoff".into())
        })?;
        let kernel_session = handoff_to_kernel(session_fd, lcp.mru)?;
        session.attach_kernel_channel(kernel_session.ppp_chan_fd.try_clone()?)?;
        configure_interface(
            &kernel_session.interface_name,
            ipcp.local_ip,
            ipcp.peer_ip,
            ipcp.local_v6_ll,
            ipcp.peer_v6_ll,
            lcp.mru,
        )
        .await?;
        Ok((kernel_session.interface_name.clone(), Some(kernel_session)))
    }

    fn ra_listener(&self, interface: &str) -> Option<Icmp6Transport> {
        Icmp6Transport::bind_ra_listener(interface)
            .inspect_err(|e| {
                warn!(interface, error = %e, "Cannot listen for the ISP's RAs; IPv6 resolvers not followed");
            })
            .ok()
    }
}

/// Extracts the base physical device name from a potential VLAN interface (e.g. "eth0.10" -> "eth0").
#[must_use]
pub fn resolve_parent_iface(iface: &str) -> &str {
    iface.split('.').next().unwrap_or(iface)
}

/// Reads the sysfs carrier status of the given network interface or its parent device.
#[must_use]
pub fn read_carrier(iface: &str) -> Option<bool> {
    let check = |name: &str| -> Option<bool> {
        let mut path_buf = [0u8; 64];
        let prefix = b"/sys/class/net/";
        let suffix = b"/carrier";
        let name_bytes = name.as_bytes();
        let total_len = prefix.len() + name_bytes.len() + suffix.len();
        if total_len > path_buf.len() {
            return None;
        }
        path_buf[..prefix.len()].copy_from_slice(prefix);
        path_buf[prefix.len()..prefix.len() + name_bytes.len()].copy_from_slice(name_bytes);
        path_buf[prefix.len() + name_bytes.len()..total_len].copy_from_slice(suffix);
        let path = std::str::from_utf8(&path_buf[..total_len]).ok()?;

        let mut buf = [0u8; 8];
        let mut file = std::fs::File::open(path).ok()?;
        let n = file.read(&mut buf).ok()?;
        let s = std::str::from_utf8(&buf[..n]).ok()?.trim();
        match s {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        }
    };

    if let Some(c) = check(iface) {
        return Some(c);
    }
    let parent = resolve_parent_iface(iface);
    if parent != iface {
        return check(parent);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_parent_iface() {
        assert_eq!(resolve_parent_iface("eth0.10"), "eth0");
        assert_eq!(resolve_parent_iface("wan0.35"), "wan0");
        assert_eq!(resolve_parent_iface("eth0"), "eth0");
        assert_eq!(resolve_parent_iface("wan0"), "wan0");
        assert_eq!(resolve_parent_iface("enp1s0.100"), "enp1s0");
    }

    #[test]
    fn test_read_carrier_nonexistent() {
        assert_eq!(read_carrier("nonexistent_iface_xyz_123"), None);
    }
}
