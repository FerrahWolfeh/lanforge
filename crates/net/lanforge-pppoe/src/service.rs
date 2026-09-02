use crate::auth::authenticate;
use crate::config::{PppoeConfig, PppoeCredentials};
use crate::discovery::{send_padt, PppoeDiscovery};
use crate::ebpf::EbpfSession;
use crate::error::PppoeError;
use crate::ipcp::negotiate_ipcp;
use crate::keepalive::run_keepalive;
use crate::kernel::{configure_interface, deconfigure_interface, handoff_to_kernel};
use crate::lcp::negotiate_lcp;
use crate::nftables::{apply_nftables_tuning, cleanup_nftables_tuning};
use crate::session::PppoeSession;
use lanforge_core::bus::{LanforgeEvent, PppoeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceDependency};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::pppoe::{PppoeDataplane, PppoeNftablesConfig};
use lanforge_types::system::{PppoeSessionState, PppoeStatusResponse, ServiceAction};
use lanforge_types::update::DeviceUpdate;
use pnet::datalink::interfaces;
use std::borrow::Cow;
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

#[lanforge_macros::lanforge_service(
    id = "pppoe",
    name = "PPPoE Client",
    critical = false,
    retries = 0,
    base_backoff = 5,
    max_backoff = 10,
    shutdown_timeout = 10,
    describe = format!("PPPoE on {} (user: {})", self.cfg.wan_iface, self.cfg.username)
)]
pub struct PppoeService {
    cfg: PppoeConfig,
    ctx: LanforgeContext,
    attempt: u32,
    active_session: Option<(MacAddr, MacAddr, u16)>,
}

impl PppoeService {
    #[must_use]
    pub const fn new(cfg: PppoeConfig, ctx: LanforgeContext) -> Self {
        Self {
            cfg,
            ctx,
            attempt: 0,
            active_session: None,
        }
    }

    fn get_interface_details(&self) -> Result<(u32, MacAddr), PppoeError> {
        let ifaces = interfaces();
        for iface in ifaces {
            if iface.name == self.cfg.wan_iface
                && let Some(mac) = iface.mac
            {
                return Ok((iface.index, MacAddr(mac.octets())));
            }
        }
        Err(PppoeError::NegotiationFailed(format!(
            "Interface {} not found or has no MAC address",
            self.cfg.wan_iface
        )))
    }

    #[allow(clippy::too_many_lines)]
    async fn run_session_flow(&mut self) -> Result<(), PppoeError> {
        let (ifindex, mac) = self.get_interface_details()?;

        // 1. Discovery
        info!("PPPoE: Starting discovery on {}", self.cfg.wan_iface);
        let discovery = PppoeDiscovery::new(
            ifindex,
            mac,
            self.cfg.discovery_padi_retries,
            self.cfg.discovery_padi_timeout_secs,
            self.cfg.service_name.clone(),
            self.cfg.ac_name.clone(),
        );
        let disc_res = discovery.run().await?;
        self.active_session = Some((mac, disc_res.ac_mac, disc_res.session_id));
        info!(
            ac_mac = %disc_res.ac_mac,
            ac_name = disc_res.ac_name.as_deref().unwrap_or("unknown"),
            session_id = disc_res.session_id,
            "PPPoE discovery complete"
        );

        // 2. Open Session Socket & Execute Session Flow
        let flow_res = async {
            let session =
                PppoeSession::connect(&self.cfg.wan_iface, disc_res.ac_mac, disc_res.session_id)?;

            // 3. Negotiate LCP
            info!("Negotiating LCP...");
            let lcp_res = negotiate_lcp(&session, self.cfg.mru, self.cfg.auth).await?;
            info!(
                mru = lcp_res.mru,
                auth = ?lcp_res.auth_method,
                "LCP negotiation succeeded"
            );

            // 4. Authenticate
            info!("Authenticating via {:?}...", lcp_res.auth_method);
            let creds = PppoeCredentials {
                username: self.cfg.username.clone(),
                password: self.cfg.password.clone(),
                auth: lcp_res.auth_method,
            };
            if let Err(e) = authenticate(&session, &creds).await {
                let _ = self
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::Pppoe(PppoeEvent::AuthFailed {
                        reason: e.to_string(),
                    }));
                return Err(e);
            }
            info!("Authentication successful");

            // 5. Negotiate IPCP / IPv6CP
            info!("Negotiating IPCP / IPv6CP...");
            let ipcp_res = negotiate_ipcp(&session, mac).await?;
            info!(
                ipv4 = ?ipcp_res.local_ip,
                peer = ?ipcp_res.peer_ip,
                dns_count = ipcp_res.dns.len(),
                ipv6_link_local = ipcp_res.local_v6_ll.is_some(),
                "IPCP negotiation succeeded"
            );

            // 6. Handoff to data plane & Configure network interface
            let (interface_name, control_fd, _ebpf_session, _kernel_session) =
                if self.cfg.dataplane == PppoeDataplane::Ebpf {
                    info!(
                        wan_iface = %self.cfg.wan_iface,
                        "Attaching eBPF Generic XDP + TC fast-path data plane"
                    );
                    let ebpf_sess = EbpfSession::attach(
                        ifindex,
                        &self.cfg.wan_iface,
                        disc_res.session_id,
                        disc_res.ac_mac.0,
                        mac.0,
                        ipcp_res.local_ip,
                        ipcp_res.peer_ip,
                        lcp_res.mru,
                    )?;
                    configure_interface(
                        &self.cfg.wan_iface,
                        ipcp_res.local_ip,
                        ipcp_res.peer_ip,
                        Some(disc_res.ac_mac.0),
                        ipcp_res.local_v6_ll,
                        ipcp_res.peer_v6_ll,
                        lcp_res.mru,
                    )
                    .await?;
                    (
                        self.cfg.wan_iface.clone(),
                        session.session_fd().try_clone()?,
                        Some(ebpf_sess),
                        None,
                    )
                } else {
                    info!("Performing kernel ppp_generic handoff...");
                    let kernel_session = handoff_to_kernel(session.session_fd(), lcp_res.mru)?;
                    configure_interface(
                        &kernel_session.interface_name,
                        ipcp_res.local_ip,
                        ipcp_res.peer_ip,
                        None,
                        ipcp_res.local_v6_ll,
                        ipcp_res.peer_v6_ll,
                        lcp_res.mru,
                    )
                    .await?;
                    let chan_fd = kernel_session.ppp_chan_fd.try_clone()?;
                    (
                        kernel_session.interface_name.clone(),
                        chan_fd,
                        None,
                        Some(kernel_session),
                    )
                };

            // Apply nftables router performance tuning rules if enabled
            if self.cfg.nftables.enabled {
                let configured_lan = self.ctx.get_status().map(|s| s.lan_iface);
                let all_ifaces: Vec<String> = interfaces().into_iter().map(|i| i.name).collect();
                let lan_ifaces = resolve_lan_ifaces(
                    &self.cfg.nftables,
                    configured_lan.as_deref(),
                    &self.cfg.wan_iface,
                    &all_ifaces,
                );

                if let Err(e) = apply_nftables_tuning(
                    &self.cfg.nftables,
                    &interface_name,
                    &lan_ifaces,
                )
                .await
                {
                    warn!(error = %e, "Failed to apply nftables performance tuning rules");
                }
            }

            // Update core State with connected PPPoE status
            let pppoe_status = PppoeStatusResponse {
                enabled: true,
                dataplane: Some(self.cfg.dataplane),
                state: PppoeSessionState::Connected,
                interface: Some(interface_name.clone()),
                wan_iface: Some(self.cfg.wan_iface.clone()),
                local_ip: ipcp_res.local_ip,
                peer_ip: ipcp_res.peer_ip,
                ac_mac: Some(disc_res.ac_mac),
                ac_name: disc_res.ac_name.clone(),
                session_id: Some(disc_res.session_id),
                mru: Some(lcp_res.mru),
                dns_servers: ipcp_res.dns.clone(),
                uptime_secs: Some(0),
                reconnect_attempts: self.attempt,
                last_error: None,
                auth: Some(lcp_res.auth_method),
            };

            let _ = self.ctx.apply(DeviceUpdate::PppoeStatusUpdated {
                status: Some(pppoe_status),
            });

            // 7. Publish SessionUp event and signal service readiness
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::Pppoe(PppoeEvent::SessionUp {
                    interface: interface_name.clone(),
                    ac_mac: Some(disc_res.ac_mac),
                    ac_name: disc_res.ac_name.clone(),
                    session_id: disc_res.session_id,
                    mru: lcp_res.mru,
                    ipv4: ipcp_res.local_ip,
                    ipv4_peer: ipcp_res.peer_ip,
                    dns: ipcp_res.dns,
                    ipv6_link_local: ipcp_res.local_v6_ll.is_some(),
                }));

            // Signal supervisor that PPPoE WAN interface is UP and ready
            self.ctx.set_pppoe_ready(true);

            // Reset attempt counter on clean connection
            self.attempt = 0;

            // 8. Run keepalive / monitoring loop
            info!(
                interface = %interface_name,
                dataplane = ?self.cfg.dataplane,
                "PPPoE session established, entering keepalive monitoring loop"
            );

            run_keepalive(
                &control_fd,
                &self.ctx,
                lcp_res.local_magic,
                lcp_res.peer_magic,
                self.cfg.lcp_echo_interval_secs,
                self.cfg.lcp_echo_max_failures,
            )
            .await
        }
        .await;

        if self.cfg.nftables.enabled {
            cleanup_nftables_tuning(&self.cfg.nftables.table_name).await;
        }

        deconfigure_interface(
            &self.cfg.wan_iface,
            self.cfg.dataplane == PppoeDataplane::Ebpf,
            None,
        )
        .await;

        if let Some((wan_mac, ac_mac, session_id)) = self.active_session.take()
            && self.cfg.send_padt_on_shutdown
        {
            let _ = send_padt(
                &self.cfg.wan_iface,
                wan_mac,
                ac_mac,
                session_id,
            );
        }

        let reason = match &flow_res {
            Ok(()) => "Graceful shutdown".to_string(),
            Err(e) => e.to_string(),
        };

        self.ctx.set_pppoe_ready(false);
        let _ = self
            .ctx
            .apply(DeviceUpdate::PppoeStatusUpdated { status: None });

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Pppoe(PppoeEvent::SessionDown { reason }));

        flow_res
    }
}

fn is_shutdown_or_stop_event(event: &LanforgeEvent) -> bool {
    match event {
        LanforgeEvent::System(SystemEvent::Shutdown) => true,
        LanforgeEvent::System(SystemEvent::ServiceControl { id, action })
            if id == "pppoe"
                && matches!(
                    action,
                    ServiceAction::Stop | ServiceAction::Restart
                ) =>
        {
            true
        }
        _ => false,
    }
}

impl AsyncService for PppoeService {
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[ServiceDependency::Interfaces]
    }

    fn stats(&self, ctx: &LanforgeContext) -> Vec<(Cow<'static, str>, String)> {
        let (state_str, local_ip, ppp_iface) = ctx.with_state(|state| {
            state.interfaces.pppoe_status.as_ref().map_or_else(
                || {
                    (
                        "disconnected".to_string(),
                        "none".to_string(),
                        "none".to_string(),
                    )
                },
                |p| (
                    format!("{:?}", p.state),
                    p.local_ip.map_or_else(|| "none".to_string(), |ip| ip.to_string()),
                    p.interface.clone().unwrap_or_else(|| "none".to_string()),
                ),
            )
        });
        vec![
            (Cow::Borrowed("wan_iface"), self.cfg.wan_iface.clone()),
            (Cow::Borrowed("username"), self.cfg.username.clone()),
            (Cow::Borrowed("state"), state_str),
            (Cow::Borrowed("local_ip"), local_ip),
            (Cow::Borrowed("ppp_interface"), ppp_iface),
            (
                Cow::Borrowed("reconnect_attempts"),
                self.attempt.to_string(),
            ),
        ]
    }

    async fn serve(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        if self.cfg.dataplane == PppoeDataplane::Kernel
            && !Path::new("/dev/ppp").exists()
        {
            warn!(
                service = "PPPoE",
                "/dev/ppp device unavailable (ppp_generic kernel module missing). Disabling PPPoE service."
            );
            let _ = ctx
                .bus()
                .publish(LanforgeEvent::Pppoe(PppoeEvent::SessionDown {
                    reason: "/dev/ppp device unavailable".into(),
                }));
            ctx.set_pppoe_ready(true);
            return Ok(());
        }

        let mut bus_rx = ctx.bus().subscribe_system();

        'main_loop: loop {
            if !ctx.is_running() {
                break 'main_loop;
            }

            tokio::select! {
                biased;
                event_res = bus_rx.recv() => {
                    if let Ok(timed) = event_res && is_shutdown_or_stop_event(&timed.event) {
                        info!("PPPoE service received shutdown/stop event, exiting serve loop");
                        break 'main_loop;
                    }
                }
                flow_res = self.run_session_flow() => {
                    match flow_res {
                        Ok(()) => {
                            info!("PPPoE service session finished cleanly");
                            break 'main_loop;
                        }
                        Err(e) => {
                            if !ctx.is_running() {
                                break 'main_loop;
                            }
                            self.attempt += 1;
                            warn!(
                                attempt = self.attempt,
                                error = %e,
                                delay_secs = self.cfg.reconnect_delay_secs,
                                "PPPoE session error, scheduling reconnection"
                            );

                            let _ =
                                ctx
                                    .bus()
                                    .publish(LanforgeEvent::Pppoe(PppoeEvent::Reconnecting {
                                        attempt: self.attempt,
                                        next_retry_secs: self.cfg.reconnect_delay_secs,
                                    }));

                            let delay = Duration::from_secs(self.cfg.reconnect_delay_secs);
                            tokio::select! {
                                () = sleep(delay) => {}
                                res = bus_rx.recv() => {
                                    if let Ok(timed) = res
                                        && is_shutdown_or_stop_event(&timed.event)
                                    {
                                        info!("PPPoE service received shutdown during reconnect delay");
                                        break 'main_loop;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn cleanup(&mut self, ctx: &LanforgeContext) -> Result<(), CoreError> {
        ctx.set_pppoe_ready(false);
        if let Some((wan_mac, ac_mac, session_id)) = self.active_session.take()
            && self.cfg.send_padt_on_shutdown
        {
            info!(
                wan_iface = %self.cfg.wan_iface,
                session_id,
                "Sending PPPoE PADT frame during service cleanup"
            );
            let _ = send_padt(
                &self.cfg.wan_iface,
                wan_mac,
                ac_mac,
                session_id,
            );
        }
        if self.cfg.nftables.enabled {
            cleanup_nftables_tuning(&self.cfg.nftables.table_name).await;
        }
        deconfigure_interface(
            &self.cfg.wan_iface,
            self.cfg.dataplane == PppoeDataplane::Ebpf,
            None,
        )
        .await;
        let _ = ctx.apply(DeviceUpdate::PppoeStatusUpdated { status: None });
        Ok(())
    }
}

/// Checks if an interface name represents a virtual, container, or tunnel device.
fn is_virtual_or_tunnel_iface(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.starts_with("docker")
        || lower.starts_with("podman")
        || lower.starts_with("cni")
        || lower.starts_with("flannel")
        || lower.starts_with("calico")
        || lower.starts_with("virbr")
        || lower.starts_with("lxdbr")
        || lower.starts_with("veth")
        || lower.starts_with("tun")
        || lower.starts_with("tap")
        || lower.starts_with("wg")
        || lower.starts_with("tailscale")
        || lower.starts_with("dummy")
        || lower.starts_with("macvlan")
        || lower.starts_with("ipvlan")
        || lower.starts_with("br-")
}

/// Resolves the LAN interface names to include in the flowtable ruleset.
///
/// Priority:
/// 1. Explicitly configured `nftables.lan_ifaces`
/// 2. Primary LAN interface reported by `LanforgeContext` system status
/// 3. Filtered physical interfaces from the host (excluding loopback, WAN, PPP, tunnels, containers)
#[must_use]
pub(crate) fn resolve_lan_ifaces(
    nft_cfg: &PppoeNftablesConfig,
    configured_lan: Option<&str>,
    wan_iface: &str,
    available_ifaces: &[String],
) -> Vec<String> {
    if !nft_cfg.lan_ifaces.is_empty() {
        return nft_cfg.lan_ifaces.clone();
    }
    if let Some(lan) = configured_lan {
        let trimmed = lan.trim();
        if !trimmed.is_empty() {
            return vec![trimmed.to_string()];
        }
    }
    available_ifaces
        .iter()
        .filter(|name| {
            let n = name.as_str();
            n != "lo"
                && n != wan_iface
                && !n.starts_with("ppp")
                && !is_virtual_or_tunnel_iface(n)
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_lan_ifaces_explicit() {
        let mut nft_cfg = PppoeNftablesConfig::default();
        nft_cfg.lan_ifaces = vec!["enp2s0".to_string()];
        let available = vec!["enp1s0".to_string(), "enp2s0".to_string(), "podman1".to_string()];
        let resolved = resolve_lan_ifaces(&nft_cfg, Some("eth99"), "enp1s0", &available);
        assert_eq!(resolved, vec!["enp2s0"]);
    }

    #[test]
    fn test_resolve_lan_ifaces_from_context() {
        let nft_cfg = PppoeNftablesConfig::default();
        let available = vec!["enp1s0".to_string(), "enp2s0".to_string(), "podman1".to_string()];
        let resolved = resolve_lan_ifaces(&nft_cfg, Some("enp2s0"), "enp1s0", &available);
        assert_eq!(resolved, vec!["enp2s0"]);
    }

    #[test]
    fn test_resolve_lan_ifaces_fallback_filters_virtual() {
        let nft_cfg = PppoeNftablesConfig::default();
        let available = vec![
            "lo".to_string(),
            "enp1s0".to_string(),
            "ppp0".to_string(),
            "enp2s0".to_string(),
            "podman1".to_string(),
            "tailscale0".to_string(),
            "veth1234".to_string(),
            "docker0".to_string(),
            "wg0".to_string(),
        ];
        let resolved = resolve_lan_ifaces(&nft_cfg, None, "enp1s0", &available);
        assert_eq!(resolved, vec!["enp2s0"]);
    }
}

