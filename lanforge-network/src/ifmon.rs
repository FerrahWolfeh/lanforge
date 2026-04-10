//! Interface configuration monitor.
//!
//! This service is responsible for tracking the IP addresses (Link-Local, GUA, ULA)
//! assigned to the local network interfaces. It provides a synchronous bootstrap
//! mechanism to ensure networking is ready before other services start.

use futures::stream::TryStreamExt;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, LanforgeService, ServiceMeta};
use lanforge_core::state::{DeviceUpdate, InterfaceState};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::Handle;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::address::AddressAttribute;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use netlink_sys::SocketAddr;

use crate::error::NetworkError;

pub type NetlinkStream = broadcast::Receiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>;

pub struct InterfaceMonitor {
    handle: Handle,
    messages: NetlinkStream,
    target_ifindex: u32,
    ctx: LanforgeContext,
}

impl InterfaceMonitor {
    #[must_use]
    pub const fn new(
        handle: Handle,
        messages: NetlinkStream,
        target_ifindex: u32,
        ctx: LanforgeContext,
    ) -> Self {
        Self {
            handle,
            messages,
            target_ifindex,
            ctx,
        }
    }

    /// Performs a full refresh of all addresses for the target interface.
    ///
    /// This is typically called during bootstrap or in response to a netlink address event.
    pub async fn refresh_interface(&self, ifindex: u32) -> Result<InterfaceState, NetworkError> {
        let mut stream = self
            .handle
            .address()
            .get()
            .set_link_index_filter(ifindex)
            .execute();

        let mut state = InterfaceState::default();

        while let Some(msg) = stream.try_next().await? {
            for attr in &msg.attributes {
                match attr {
                    AddressAttribute::Address(IpAddr::V4(v4)) => {
                        state.v4 = Some((*v4, msg.header.prefix_len));
                    }
                    AddressAttribute::Address(IpAddr::V6(v6)) => {
                        let o = v6.octets();
                        if o[0] == 0xFE && (o[1] & 0xC0) == 0x80 {
                            state.link_local = Some(*v6);
                        } else if (0x20..=0x3F).contains(&o[0]) {
                            let mut masked = o;
                            masked[8..].fill(0);
                            state.gua = Some(Ipv6Addr::from(masked));
                        } else if o[0] == 0xFD {
                            let mut masked = o;
                            masked[8..].fill(0);
                            state.ula = Some(Ipv6Addr::from(masked));
                        }
                    }
                    AddressAttribute::CacheInfo(info) => {
                        state.gua_preferred = info.ifa_preferred;
                        state.gua_valid = info.ifa_valid;
                    }
                    _ => {}
                }
            }
        }

        // Update global table
        // Update table via injected context
        let _ = self.ctx.apply(&DeviceUpdate::InterfaceIpsChanged {
            ifindex,
            state: state.clone(),
        });

        Ok(state)
    }

    /// Synchronous bootstrap — queries all interfaces once.
    ///
    /// This ensures the global state is seeded before services like RA/DHCP start.
    pub async fn initial_scan(&self) -> Result<InterfaceState, NetworkError> {
        info!("InterfaceMonitor: Starting initial interface scan...");

        // We focus on the target interface for the return value,
        // but we could refresh others if needed.
        let state = self.refresh_interface(self.target_ifindex).await?;

        info!("InterfaceMonitor: Initial scan complete.");
        Ok(state)
    }
}

impl LanforgeService for InterfaceMonitor {
    fn meta(&self) -> ServiceMeta {
        ServiceMeta {
            id: "ifmon",
            display_name: "Interface Monitor",
            critical: true,
            max_retries: 0,
            base_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(30),
            stack_kb: 256,
        }
    }

    fn describe(&self) -> String {
        format!("Interface Monitor (ifindex: {})", self.target_ifindex)
    }

    fn on_shutdown(&mut self) -> Result<(), CoreError> {
        Ok(())
    }
}

impl AsyncService for InterfaceMonitor {
    async fn run(&mut self) -> Result<(), CoreError> {
        let mut bus_rx = self.ctx.bus().subscribe();

        loop {
            if !self.ctx.is_running() {
                break;
            }

            tokio::select! {
                res = self.messages.recv() => {
                    let Ok((msg, _addr)) = res else {
                        if matches!(res, Err(broadcast::error::RecvError::Lagged(_))) {
                            warn!("InterfaceMonitor: Netlink broadcast lagged, skipping catch-up");
                            continue;
                        }
                        break;
                    };

                    if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr) |
                    RouteNetlinkMessage::DelAddress(addr)) = &msg.payload
                        && addr.header.index == self.target_ifindex {
                            debug!("InterfaceMonitor: Address event on ifindex {}, refreshing...", addr.header.index);
                            if let Err(e) = self.refresh_interface(addr.header.index).await {
                                warn!("InterfaceMonitor: Failed to refresh interface {}: {e}", addr.header.index);
                            }
                        }
                }

                Ok(event) = bus_rx.recv() => {
                    if matches!(event.event, LanforgeEvent::Shutdown) {
                        break;
                    }
                }

                else => break,
            }
        }

        Ok(())
    }
}
