//! Interface configuration monitor.
//!
//! This service is responsible for tracking the IP addresses (Link-Local, GUA, ULA)
//! assigned to the local network interfaces. It provides a synchronous bootstrap
//! mechanism to ensure networking is ready before other services start.

use crate::error::Result;
use futures::StreamExt;
use futures::channel::mpsc::UnboundedReceiver;
use futures::stream::TryStreamExt;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, LanforgeService};
use lanforge_core::state::InterfaceState;
use lanforge_core::state::update::DeviceUpdate;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::Handle;
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::address::AddressAttribute;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use netlink_sys::SocketAddr;

pub type NetlinkStream = UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>;

pub struct InterfaceMonitor {
    handle: Handle,
    messages: Arc<Mutex<NetlinkStream>>,
    target_ifindex: u32,
}

impl InterfaceMonitor {
    #[must_use]
    pub fn new(handle: Handle, messages: Arc<Mutex<NetlinkStream>>, target_ifindex: u32) -> Self {
        Self {
            handle,
            messages,
            target_ifindex,
        }
    }

    /// Performs a full refresh of all addresses for the target interface.
    ///
    /// This is typically called during bootstrap or in response to a netlink address event.
    pub async fn refresh_interface(&self, ifindex: u32) -> Result<InterfaceState> {
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
        let table = LanforgeContext::table();
        let _ = table.update(&DeviceUpdate::InterfaceIpsChanged {
            ifindex,
            link_local: state.link_local,
            gua: state.gua,
            ula: state.ula,
            preferred: state.gua_preferred,
            valid: state.gua_valid,
        });

        Ok(state)
    }

    /// Synchronous bootstrap — queries all interfaces once.
    ///
    /// This ensures the global state is seeded before services like RA/DHCP start.
    pub async fn initial_scan(&self) -> Result<InterfaceState> {
        info!("InterfaceMonitor: Starting initial interface scan...");

        // We focus on the target interface for the return value,
        // but we could refresh others if needed.
        let state = self.refresh_interface(self.target_ifindex).await?;

        info!("InterfaceMonitor: Initial scan complete.");
        Ok(state)
    }
}

impl LanforgeService for InterfaceMonitor {
    fn name(&self) -> &str {
        "InterfaceMonitor"
    }

    fn on_shutdown(&mut self) -> std::result::Result<(), CoreError> {
        info!("InterfaceMonitor: Deinitializing Service");
        Ok(())
    }
}

impl AsyncService for InterfaceMonitor {
    async fn run(&mut self) -> std::result::Result<(), CoreError> {
        let mut bus_rx = LanforgeContext::bus().subscribe();

        info!("InterfaceMonitor: Service started (reactive mode)");

        let _ = LanforgeContext::bus().publish(LanforgeEvent::ServiceReady {
            name: "ifmon".to_string(),
        });

        let mut rx = self.messages.lock().await;

        loop {
            if !LanforgeContext::is_running() {
                break;
            }

            tokio::select! {
                res = rx.next() => {
                    let Some((msg, _addr)) = res else { break };

                    if let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(addr))
                    | NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelAddress(addr)) = &msg.payload
                        && addr.header.index == self.target_ifindex {
                            debug!("InterfaceMonitor: Address event on ifindex {}, refreshing...", addr.header.index);
                            if let Err(e) = self.refresh_interface(addr.header.index).await {
                                warn!("InterfaceMonitor: Failed to refresh interface {}: {e}", addr.header.index);
                            }
                        }
                }

                Ok(event) = bus_rx.recv() => {
                    if matches!(event, LanforgeEvent::Shutdown) {
                        break;
                    }
                }

                else => break,
            }
        }

        info!("InterfaceMonitor: Service stopped");
        Ok(())
    }
}
