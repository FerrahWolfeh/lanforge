use std::collections::HashSet;
use std::time::Duration;

use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    AsyncService, Condition, LanforgeService, RestartPolicy, RuntimeClass, ServiceCommand,
    ServiceHandle, ServiceSpec,
};
use lanforge_types::network::snapshot::{InterfaceSnapshot, LinkInfo};
use lanforge_types::network::subnet::IpSubnet;
use lanforge_types::system::{DegradedReason, ServiceId};
use pnet::datalink;
use rtnetlink::packet_core::NetlinkPayload;
use rtnetlink::packet_route::RouteNetlinkMessage;
use tokio::sync::broadcast::{self, error::RecvError};

use crate::bootstrap::NetlinkRawMessage;
use smallvec::SmallVec;
use tracing::{debug, info, warn};

/// Synthetic node monitoring OS network interfaces.
///
/// Discovers link states and addresses, publishes `InterfaceSnapshot`,
/// and reports `Online` once all configured links (LAN, WAN, traffic)
/// exist by name in the OS network stack.
pub struct InterfacesService {
    lan_iface: String,
    /// Kernel link and address notifications: a rescan runs on each, instead of polling.
    netlink: broadcast::Receiver<NetlinkRawMessage>,
}

impl InterfacesService {
    /// Creates a new `InterfacesService` instance fed by the netlink dispatcher.
    #[must_use]
    pub const fn new(lan_iface: String, netlink: broadcast::Receiver<NetlinkRawMessage>) -> Self {
        Self { lan_iface, netlink }
    }

    /// Whether a netlink message can change the snapshot (a link or an address came or went);
    /// neighbour churn, the bulk of the traffic, cannot.
    const fn touches_links(msg: &NetlinkRawMessage) -> bool {
        matches!(
            msg.0.payload,
            NetlinkPayload::InnerMessage(
                RouteNetlinkMessage::NewLink(_)
                    | RouteNetlinkMessage::DelLink(_)
                    | RouteNetlinkMessage::NewAddress(_)
                    | RouteNetlinkMessage::DelAddress(_)
            )
        )
    }

    /// Scans the host network stack for all network interfaces and IP addresses.
    #[must_use]
    pub fn scan_interfaces(generation: u64) -> InterfaceSnapshot {
        let mut links = SmallVec::new();
        for iface in datalink::interfaces() {
            let mut addrs = SmallVec::new();
            for ipnet in &iface.ips {
                addrs.push(IpSubnet {
                    addr: ipnet.ip(),
                    prefix_len: ipnet.prefix(),
                });
            }

            let carrier = iface.is_up();
            links.push(LinkInfo {
                ifindex: iface.index,
                name: iface.name,
                carrier,
                addrs,
            });
        }

        InterfaceSnapshot { links, generation }
    }

    /// Returns the set of interface names required by configuration.
    fn required_ifaces(&self, ctx: &LanforgeContext) -> HashSet<String> {
        let mut required = HashSet::new();
        if !self.lan_iface.is_empty() {
            required.insert(self.lan_iface.clone());
        }

        if let Some(wan) = ctx.effective_wan_iface()
            && !wan.is_empty()
        {
            required.insert(wan);
        }

        if let Some(traffic) = ctx.get_traffic_config()
            && traffic.sqm.enabled
            && !traffic.sqm.interface.is_empty()
            && traffic.sqm.interface != "auto"
        {
            required.insert(traffic.sqm.interface);
        }

        required
    }
}

impl LanforgeService for InterfacesService {
    fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: ServiceId::Interfaces,
            display_name: "Network Interfaces Observer",
            runtime: RuntimeClass::Shared,
            restart: RestartPolicy::default(),
            shutdown_timeout: Duration::from_secs(2),
            deps: &[],
            condition: Condition::ALWAYS,
        }
    }
}

impl AsyncService for InterfacesService {
    async fn serve(&mut self, ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        let mut generation = 1u64;
        let mut snapshot = Self::scan_interfaces(generation);
        ctx.set_interfaces_snapshot(snapshot.clone());

        let required = self.required_ifaces(ctx);
        let missing: Vec<_> = required
            .iter()
            .filter(|name| !snapshot.has_link(name))
            .cloned()
            .collect();

        if missing.is_empty() {
            info!(links = snapshot.links.len(), "All configured links present");
            h.ready();
        } else {
            warn!(
                missing = ?missing,
                "Configured links missing from OS, entering degraded wait"
            );
            h.degraded(DegradedReason::custom("waiting for configured links"));
        }

        loop {
            tokio::select! {
                cmd = h.next_command() => {
                    match cmd {
                        ServiceCommand::Stop | ServiceCommand::Shutdown => {
                            debug!("Interfaces observer received stop/shutdown command");
                            break;
                        }
                        _ => {}
                    }
                }
                msg = self.netlink.recv() => {
                    match msg {
                        Ok(msg) if Self::touches_links(&msg) => {}
                        Ok(_) => continue,
                        // Missed notifications: the rescan below catches up.
                        Err(RecvError::Lagged(_)) => {}
                        Err(RecvError::Closed) => {
                            warn!("Netlink dispatcher closed; interfaces observer stops");
                            break;
                        }
                    }
                    let new_snapshot = Self::scan_interfaces(generation + 1);
                    if new_snapshot.links != snapshot.links {
                        generation += 1;
                        snapshot = new_snapshot;
                        snapshot.generation = generation;
                        ctx.set_interfaces_snapshot(snapshot.clone());

                        let required = self.required_ifaces(ctx);
                        if required.iter().all(|name| snapshot.has_link(name)) {
                            h.ready();
                        } else {
                            h.degraded(DegradedReason::custom("waiting for configured links"));
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
