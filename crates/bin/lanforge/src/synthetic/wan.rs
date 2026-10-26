use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use lanforge_core::bus::{LanforgeEvent, NetworkEvent, PppoeEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    AsyncService, Condition, Edge, LanforgeService, RestartPolicy, RuntimeClass, ServiceCommand,
    ServiceHandle, ServiceSpec,
};
use lanforge_types::network::snapshot::{InterfaceSnapshot, Ipv6Net, WanSnapshot, WanState};
use lanforge_types::system::ServiceId;
use smallvec::SmallVec;
use tracing::{debug, info};

static WAN_DEPS: &[Edge] = &[
    Edge::wants(ServiceId::Pppoe),
    Edge::wants(ServiceId::Interfaces),
];

/// Synthetic node observing WAN layer-3 operational state.
///
/// Derives WAN connectivity, address assignments, and IPv6 prefixes from
/// `PPPoE` session state or OS Netlink interface properties.
#[derive(Clone, Default)]
pub struct WanService;

impl WanService {
    /// Creates a new `WanService` instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Evaluates WAN state for an OS-managed WAN interface without `PPPoE`.
    fn evaluate_os_wan(
        if_snapshot: &InterfaceSnapshot,
        effective_wan: Option<&str>,
        generation_idx: u64,
    ) -> WanSnapshot {
        let Some(wan_name) = effective_wan else {
            return WanSnapshot {
                state: WanState::Down,
                ifindex: None,
                ifname: None,
                v4: None,
                v6_prefixes: SmallVec::new(),
                generation: generation_idx,
            };
        };

        let Some(link) = if_snapshot.find_by_name(wan_name) else {
            return WanSnapshot {
                state: WanState::Down,
                ifindex: None,
                ifname: Some(wan_name.to_string()),
                v4: None,
                v6_prefixes: SmallVec::new(),
                generation: generation_idx,
            };
        };

        let mut v4_addr: Option<(Ipv4Addr, u8)> = None;
        let mut v6_prefixes: SmallVec<[Ipv6Net; 2]> = SmallVec::new();

        for subnet in &link.addrs {
            match subnet.addr {
                IpAddr::V4(v4) => {
                    if !v4.is_loopback() && !v4.is_link_local() && v4_addr.is_none() {
                        v4_addr = Some((v4, subnet.prefix_len));
                    }
                }
                IpAddr::V6(v6) => {
                    let octets = v6.octets();
                    // Global Unicast Address range 2000::/3
                    if (0x20..=0x3F).contains(&octets[0]) {
                        v6_prefixes.push(Ipv6Net::new(v6, subnet.prefix_len));
                    }
                }
            }
        }

        let is_up = link.carrier && (v4_addr.is_some() || !v6_prefixes.is_empty());
        let state = if is_up { WanState::Up } else { WanState::Down };

        WanSnapshot {
            state,
            ifindex: Some(link.ifindex),
            ifname: Some(wan_name.to_string()),
            v4: v4_addr,
            v6_prefixes,
            generation: generation_idx,
        }
    }
}

impl LanforgeService for WanService {
    fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: ServiceId::Wan,
            display_name: "WAN Connectivity Observer",
            runtime: RuntimeClass::Shared,
            restart: RestartPolicy::default(),
            shutdown_timeout: Duration::from_secs(2),
            deps: WAN_DEPS,
            condition: Condition::ALWAYS,
        }
    }
}

impl AsyncService for WanService {
    #[allow(clippy::too_many_lines)]
    async fn serve(&mut self, ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        let mut generation = 1u64;
        let pppoe_enabled = ctx.get_pppoe_config().is_some_and(|p| p.enabled);

        let mut current_snapshot = if pppoe_enabled {
            WanSnapshot {
                state: WanState::Down,
                ifindex: None,
                ifname: None,
                v4: None,
                v6_prefixes: SmallVec::new(),
                generation,
            }
        } else {
            let if_snap = ctx.interfaces_snapshot();
            let wan_iface = ctx.effective_wan_iface();
            Self::evaluate_os_wan(&if_snap, wan_iface.as_deref(), generation)
        };

        ctx.set_wan_snapshot(current_snapshot.clone());
        info!(
            state = ?current_snapshot.state,
            generation = current_snapshot.generation,
            "Initial state evaluated"
        );
        h.ready();

        let mut pppoe_rx = ctx.bus().subscribe_pppoe();
        let mut net_rx = ctx.bus().subscribe_network();
        let mut if_rx = ctx.watch_interfaces();

        loop {
            tokio::select! {
                cmd = h.next_command() => {
                    match cmd {
                        ServiceCommand::Stop | ServiceCommand::Shutdown => {
                            debug!("WAN observer received stop/shutdown command");
                            break;
                        }
                        _ => {}
                    }
                }

                pppoe_res = pppoe_rx.recv() => {
                    if let Ok(timed_event) = pppoe_res {
                        match timed_event.event {
                            LanforgeEvent::Pppoe(PppoeEvent::SessionUp(up)) => {
                                generation += 1;
                                let ifindex = pnet::datalink::interfaces()
                                    .into_iter()
                                    .find(|i| i.name == up.interface)
                                    .map(|i| i.index);

                                current_snapshot = WanSnapshot {
                                    state: WanState::Up,
                                    ifindex,
                                    ifname: Some(up.interface.clone()),
                                    v4: up.ipv4.map(|ip| (ip, 32)),
                                    v6_prefixes: current_snapshot.v6_prefixes.clone(),
                                    generation,
                                };
                                ctx.set_wan_snapshot(current_snapshot.clone());
                                info!(
                                    ifindex = ?ifindex,
                                    iface = %up.interface,
                                    v4 = ?up.ipv4,
                                    generation,
                                    "PPPoE session connected"
                                );
                            }
                            LanforgeEvent::Pppoe(PppoeEvent::SessionDown { .. }) => {
                                generation += 1;
                                current_snapshot = WanSnapshot {
                                    state: WanState::Down,
                                    ifindex: None,
                                    ifname: None,
                                    v4: None,
                                    v6_prefixes: SmallVec::new(),
                                    generation,
                                };
                                ctx.set_wan_snapshot(current_snapshot.clone());
                                info!(generation, "PPPoE session dropped");
                            }
                            _ => {}
                        }
                    }
                }

                net_res = net_rx.recv() => {
                    if let Ok(timed_event) = net_res
                        && let LanforgeEvent::Network(NetworkEvent::PrefixChanged(ref details)) = timed_event.event
                        // Only the WAN link's own addresses; the LAN (delegated) prefix is not WAN state.
                        && current_snapshot.ifindex == Some(details.ifindex)
                        && let Some(gua_prefix) = details.gua
                    {
                        let new_net = Ipv6Net::from(gua_prefix);
                        if current_snapshot.v6_prefixes.first() != Some(&new_net) {
                            generation += 1;
                            let mut new_prefixes = current_snapshot.v6_prefixes.clone();
                            new_prefixes.clear();
                            new_prefixes.push(new_net);
                            current_snapshot.v6_prefixes = new_prefixes;
                            current_snapshot.generation = generation;
                            ctx.set_wan_snapshot(current_snapshot.clone());
                            info!(
                                prefix = %gua_prefix,
                                generation,
                                "IPv6 GUA prefix updated"
                            );
                        }
                    }
                }

                Ok(()) = if_rx.changed() => {
                    let is_pppoe = ctx.get_pppoe_config().is_some_and(|p| p.enabled);
                    if !is_pppoe {
                        let if_snap = if_rx.borrow().clone();
                        let wan_iface = ctx.effective_wan_iface();
                        let evaluated = Self::evaluate_os_wan(&if_snap, wan_iface.as_deref(), generation + 1);

                        if evaluated.state != current_snapshot.state
                            || evaluated.ifindex != current_snapshot.ifindex
                            || evaluated.v4 != current_snapshot.v4
                            || evaluated.v6_prefixes != current_snapshot.v6_prefixes
                        {
                            generation += 1;
                            current_snapshot = evaluated;
                            current_snapshot.generation = generation;
                            ctx.set_wan_snapshot(current_snapshot.clone());
                            info!(
                                state = ?current_snapshot.state,
                                generation,
                                "OS-managed WAN state changed"
                            );
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
