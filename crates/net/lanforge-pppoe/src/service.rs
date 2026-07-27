use crate::auth::authenticate;
use crate::config::{PppoeConfig, PppoeCredentials};
use crate::discovery::{self, PppoeDiscovery};
use crate::error::PppoeError;
use crate::ipcp::negotiate_ipcp;
use crate::keepalive::run_keepalive;
use crate::kernel::{configure_interface, handoff_to_kernel};
use crate::lcp::negotiate_lcp;
use crate::session::PppoeSession;
use lanforge_core::bus::{LanforgeEvent, PppoeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::error::CoreError;
use lanforge_core::service::{AsyncService, ServiceControl};
use std::time::Duration;
use tracing::{info, warn};

#[lanforge_macros::lanforge_service(
    id = "pppoe",
    name = "PPPoE Client",
    critical = false,
    retries = 0,
    base_backoff = 10,
    max_backoff = 10,
    describe = format!("PPPoE on {} (user: {})", self.cfg.wan_iface, self.cfg.username)
)]
pub struct PppoeService {
    cfg: PppoeConfig,
    ctx: LanforgeContext,
    attempt: u32,
}

impl PppoeService {
    #[must_use]
    pub const fn new(cfg: PppoeConfig, ctx: LanforgeContext) -> Self {
        Self {
            cfg,
            ctx,
            attempt: 0,
        }
    }

    fn get_interface_details(&self) -> Result<(u32, [u8; 6]), PppoeError> {
        let ifaces = pnet::datalink::interfaces();
        for iface in ifaces {
            if iface.name == self.cfg.wan_iface
                && let Some(mac) = iface.mac
            {
                return Ok((iface.index, mac.octets()));
            }
        }
        Err(PppoeError::NegotiationFailed(format!(
            "Interface {} not found or has no MAC address",
            self.cfg.wan_iface
        )))
    }

    async fn run_session_flow(&mut self, ctrl: &ServiceControl) -> Result<(), PppoeError> {
        let (ifindex, mac) = self.get_interface_details()?;

        // 1. Discovery
        info!("Starting PPPoE discovery on {}", self.cfg.wan_iface);
        let discovery = PppoeDiscovery::new(ifindex, mac);
        let disc_res = discovery.run().await?;
        info!(
            ac_mac = %format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                disc_res.ac_mac[0], disc_res.ac_mac[1], disc_res.ac_mac[2],
                disc_res.ac_mac[3], disc_res.ac_mac[4], disc_res.ac_mac[5]),
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
            authenticate(&session, &creds).await?;
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

            // 6. Handoff to kernel ppp_generic & Configure network interface
            info!("Performing kernel ppp_generic handoff...");
            let kernel_session = handoff_to_kernel(session.session_fd(), lcp_res.mru)?;
            configure_interface(
                &kernel_session.interface_name,
                ipcp_res.local_ip,
                ipcp_res.peer_ip,
                ipcp_res.local_v6_ll,
                ipcp_res.peer_v6_ll,
                lcp_res.mru,
            )
            .await?;

            // 7. Publish SessionUp event and signal service readiness
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::Pppoe(PppoeEvent::SessionUp {
                    interface: kernel_session.interface_name.clone(),
                    ipv4: ipcp_res.local_ip,
                    ipv4_peer: ipcp_res.peer_ip,
                    dns: ipcp_res.dns,
                    ipv6_link_local: ipcp_res.local_v6_ll.is_some(),
                }));

            // Signal supervisor that PPPoE WAN interface is UP and ready
            ctrl.signal_ready();

            // Reset attempt counter on clean connection
            self.attempt = 0;

            // 8. Run keepalive / monitoring loop
            info!(
                interface = %kernel_session.interface_name,
                "PPPoE session established, entering keepalive monitoring loop"
            );

            run_keepalive(
                &kernel_session,
                &self.ctx,
                lcp_res.local_magic,
                lcp_res.peer_magic,
                self.cfg.lcp_echo_interval_secs,
                self.cfg.lcp_echo_max_failures,
            )
            .await
        }
        .await;

        let _ = discovery::send_padt(
            &self.cfg.wan_iface,
            mac,
            disc_res.ac_mac,
            disc_res.session_id,
        );

        let reason = match &flow_res {
            Ok(()) => "Graceful shutdown".to_string(),
            Err(e) => e.to_string(),
        };

        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::Pppoe(PppoeEvent::SessionDown { reason }));

        flow_res
    }
}

impl AsyncService for PppoeService {
    async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
        if !std::path::Path::new("/dev/ppp").exists() {
            warn!(
                service = "PPPoE",
                "/dev/ppp device unavailable (ppp_generic kernel module missing). Disabling PPPoE service."
            );
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::Pppoe(PppoeEvent::SessionDown {
                    reason: "/dev/ppp device unavailable".into(),
                }));
            ctrl.signal_ready();
            return Ok(());
        }

        let mut bus_rx = self.ctx.bus().subscribe();

        loop {
            if !self.ctx.is_running() {
                break;
            }

            match self.run_session_flow(&ctrl).await {
                Ok(()) => {
                    info!("PPPoE service session finished cleanly");
                    break;
                }
                Err(e) => {
                    self.attempt += 1;
                    warn!(
                        attempt = self.attempt,
                        error = %e,
                        delay_secs = self.cfg.reconnect_delay_secs,
                        "PPPoE session error, scheduling reconnection"
                    );

                    let _ =
                        self.ctx
                            .bus()
                            .publish(LanforgeEvent::Pppoe(PppoeEvent::Reconnecting {
                                attempt: self.attempt,
                                next_retry_secs: self.cfg.reconnect_delay_secs,
                            }));

                    let delay = Duration::from_secs(self.cfg.reconnect_delay_secs);
                    tokio::select! {
                        () = tokio::time::sleep(delay) => {}
                        res = bus_rx.recv() => {
                            if let Ok(timed) = res
                                && matches!(timed.event, LanforgeEvent::System(SystemEvent::Shutdown)) {
                                    break;
                                }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
