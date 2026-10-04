use crate::auth::authenticate;
use crate::config::{PppoeConfig, PppoeCredentials};
use crate::discovery::{PppoeDiscovery, send_padt};
#[cfg(feature = "ebpf")]
use crate::ebpf::EbpfSession;
use crate::error::PppoeError;
use crate::ipcp::negotiate_ipcp;
use crate::keepalive::run_keepalive;
use crate::kernel::{configure_interface, deconfigure_interface, handoff_to_kernel};
use crate::lcp::negotiate_lcp;
use crate::session::PppoeSession;
use lanforge_core::bus::{LanforgeEvent, PppoeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceDependency};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::pppoe::PppoeDataplane;
use lanforge_types::system::{
    PppoeSessionState, PppoeStatusResponse, ServiceAction, ServiceState,
};
use lanforge_types::update::DeviceUpdate;
use pnet::datalink::interfaces;
use std::borrow::Cow;
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn};

#[cfg(feature = "ebpf")]
type EbpfSessionHandle = Option<crate::ebpf::EbpfSession>;
#[cfg(not(feature = "ebpf"))]
type EbpfSessionHandle = Option<()>;

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
    pub fn new(mut cfg: PppoeConfig, ctx: LanforgeContext) -> Self {
        if let Some(dynamic_cfg) = ctx.get_pppoe_config() {
            cfg = dynamic_cfg;
        }
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

    async fn perform_discovery(
        &mut self,
        ifindex: u32,
        mac: MacAddr,
    ) -> Result<crate::discovery::DiscoveryResult, PppoeError> {
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
        Ok(disc_res)
    }

    async fn negotiate_session(
        &self,
        disc_res: &crate::discovery::DiscoveryResult,
        mac: MacAddr,
    ) -> Result<(PppoeSession, crate::lcp::LcpNegotiated, crate::ipcp::IpcpNegotiated), PppoeError> {
        let session =
            PppoeSession::connect(&self.cfg.wan_iface, disc_res.ac_mac, disc_res.session_id)?;

        info!("Negotiating LCP...");
        let lcp_res = negotiate_lcp(&session, self.cfg.mru, self.cfg.auth).await?;
        info!(
            mru = lcp_res.mru,
            auth = ?lcp_res.auth_method,
            "LCP negotiation succeeded"
        );

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

        info!("Negotiating IPCP / IPv6CP...");
        let ipcp_res = negotiate_ipcp(&session, mac).await?;
        info!(
            ipv4 = ?ipcp_res.local_ip,
            peer = ?ipcp_res.peer_ip,
            dns_count = ipcp_res.dns.len(),
            ipv6_link_local = ipcp_res.local_v6_ll.is_some(),
            "IPCP negotiation succeeded"
        );

        Ok((session, lcp_res, ipcp_res))
    }

    async fn setup_dataplane(
        &self,
        session: &PppoeSession,
        _disc_res: &crate::discovery::DiscoveryResult,
        mac: MacAddr,
        ifindex: u32,
        lcp_res: &crate::lcp::LcpNegotiated,
        ipcp_res: &crate::ipcp::IpcpNegotiated,
    ) -> Result<
        (
            String,
            std::os::fd::OwnedFd,
            EbpfSessionHandle,
            Option<crate::kernel::KernelSession>,
        ),
        PppoeError,
    > {
        if self.cfg.dataplane == PppoeDataplane::Ebpf {
            #[cfg(feature = "ebpf")]
            {
                info!(
                    wan_iface = %self.cfg.wan_iface,
                    "Attaching eBPF Generic XDP + TC fast-path data plane"
                );
                let ebpf_sess = EbpfSession::attach(
                    ifindex,
                    &self.cfg.wan_iface,
                    _disc_res.session_id,
                    _disc_res.ac_mac.0,
                    mac.0,
                    ipcp_res.local_ip,
                    ipcp_res.peer_ip,
                    lcp_res.mru,
                )?;
                configure_interface(
                    &self.cfg.wan_iface,
                    ipcp_res.local_ip,
                    ipcp_res.peer_ip,
                    Some(_disc_res.ac_mac.0),
                    ipcp_res.local_v6_ll,
                    ipcp_res.peer_v6_ll,
                    lcp_res.mru,
                )
                .await?;
                Ok((
                    self.cfg.wan_iface.clone(),
                    session.session_fd().try_clone()?,
                    Some(ebpf_sess),
                    None,
                ))
            }
            #[cfg(not(feature = "ebpf"))]
            {
                let _ = (ifindex, mac);
                Err(PppoeError::NegotiationFailed(
                    "eBPF dataplane support is not compiled into this binary (compile with --features ebpf)".into(),
                ))
            }
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
            Ok((
                kernel_session.interface_name.clone(),
                chan_fd,
                None,
                Some(kernel_session),
            ))
        }
    }

    fn publish_connected_status(
        &mut self,
        interface_name: &str,
        disc_res: &crate::discovery::DiscoveryResult,
        lcp_res: &crate::lcp::LcpNegotiated,
        ipcp_res: &crate::ipcp::IpcpNegotiated,
    ) {
        let pppoe_status = PppoeStatusResponse {
            enabled: true,
            dataplane: Some(self.cfg.dataplane),
            state: PppoeSessionState::Connected,
            interface: Some(interface_name.to_string()),
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
            status: Some(Box::new(pppoe_status)),
        });

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Pppoe(PppoeEvent::SessionUp(Box::new(
                lanforge_types::events::PppoeSessionUp {
                    interface: interface_name.to_string(),
                    ac_mac: Some(disc_res.ac_mac),
                    ac_name: disc_res.ac_name.clone(),
                    session_id: disc_res.session_id,
                    mru: lcp_res.mru,
                    ipv4: ipcp_res.local_ip,
                    ipv4_peer: ipcp_res.peer_ip,
                    dns: ipcp_res.dns.clone(),
                    ipv6_link_local: ipcp_res.local_v6_ll.is_some(),
                },
            ))));

        self.ctx.set_pppoe_ready(true);
        self.attempt = 0;
    }

    async fn run_session_flow(&mut self) -> Result<(), PppoeError> {
        let (ifindex, mac) = self.get_interface_details()?;
        let disc_res = self.perform_discovery(ifindex, mac).await?;

        let flow_res = async {
            let (session, lcp_res, ipcp_res) = self.negotiate_session(&disc_res, mac).await?;
            let (interface_name, control_fd, _ebpf_session, _kernel_session) = self
                .setup_dataplane(&session, &disc_res, mac, ifindex, &lcp_res, &ipcp_res)
                .await?;

            self.publish_connected_status(&interface_name, &disc_res, &lcp_res, &ipcp_res);

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

        if let Some((wan_mac, ac_mac, session_id)) = self.active_session.take()
            && self.cfg.send_padt_on_shutdown
        {
            let _ = send_padt(&self.cfg.wan_iface, wan_mac, ac_mac, session_id);
        }

        deconfigure_interface(
            &self.cfg.wan_iface,
            self.cfg.dataplane == PppoeDataplane::Ebpf,
            None,
        )
        .await;

        let reason = match &flow_res {
            Ok(()) => "Graceful shutdown".to_string(),
            Err(e) => e.to_string(),
        };

        if flow_res.is_err() {
            warn!(
                wan_iface = %self.cfg.wan_iface,
                error = %reason,
                "PPPoE session disconnected due to error or carrier loss"
            );
        } else {
            info!(
                wan_iface = %self.cfg.wan_iface,
                reason = %reason,
                "PPPoE session disconnected cleanly"
            );
        }

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
            if id == "pppoe" && matches!(action, ServiceAction::Stop | ServiceAction::Restart) =>
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
                |p| {
                    (
                        format!("{:?}", p.state),
                        p.local_ip
                            .map_or_else(|| "none".to_string(), |ip| ip.to_string()),
                        p.interface.clone().unwrap_or_else(|| "none".to_string()),
                    )
                },
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
        if let Some(dynamic_cfg) = ctx.get_pppoe_config() {
            self.cfg = dynamic_cfg;
        }

        if !self.cfg.enabled {
            info!("PPPoE service is disabled in configuration.");
            ctx.set_service_state("pppoe", ServiceState::Inactive);
            ctx.set_pppoe_ready(true);
            return Ok(());
        }

        if self.cfg.dataplane == PppoeDataplane::Kernel && !Path::new("/dev/ppp").exists() {
            warn!(
                service = "PPPoE",
                "/dev/ppp device unavailable (ppp_generic kernel module missing). Disabling PPPoE service."
            );
            let _ = ctx
                .bus()
                .publish(LanforgeEvent::Pppoe(PppoeEvent::SessionDown {
                    reason: "/dev/ppp device unavailable".into(),
                }));
            ctx.set_service_state("pppoe", ServiceState::Error);
            ctx.set_pppoe_ready(true);
            return Ok(());
        }

        #[cfg(not(feature = "ebpf"))]
        if self.cfg.dataplane == PppoeDataplane::Ebpf {
            warn!(
                service = "PPPoE",
                "eBPF dataplane requested but not compiled into this binary (compile with --features ebpf). Disabling PPPoE service."
            );
            let _ = ctx
                .bus()
                .publish(LanforgeEvent::Pppoe(PppoeEvent::SessionDown {
                    reason: "eBPF dataplane not compiled in".into(),
                }));
            ctx.set_service_state("pppoe", ServiceState::Error);
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
            let _ = send_padt(&self.cfg.wan_iface, wan_mac, ac_mac, session_id);
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
