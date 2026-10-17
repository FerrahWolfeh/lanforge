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
use lanforge_transport::ArpProber;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::pppoe::PppoeDataplane;
use lanforge_types::system::{
    PppoeSessionState, PppoeStatusResponse, ServiceAction, ServiceState,
};
use lanforge_types::update::DeviceUpdate;
use pnet::datalink::interfaces;
use std::borrow::Cow;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Extracts the base physical device name from a potential VLAN interface (e.g. "eth0.10" -> "eth0").
#[must_use]
pub fn resolve_parent_iface(iface: &str) -> &str {
    iface.split('.').next().unwrap_or(iface)
}

/// Reads the sysfs carrier status of the given network interface or its parent device.
#[must_use]
pub fn read_carrier(iface: &str) -> Option<bool> {
    let check = |name: &str| -> Option<bool> {
        let path = format!("/sys/class/net/{name}/carrier");
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

    check(iface).or_else(|| {
        let parent = resolve_parent_iface(iface);
        if parent == iface {
            None
        } else {
            check(parent)
        }
    })
}

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
    inert: bool,
    prober: Option<ArpProber>,
    terminal_status: Option<(bool, Option<MacAddr>, Option<u32>)>,
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
            inert: false,
            prober: None,
            terminal_status: None,
        }
    }

    /// Creates an inert instance of `PppoeService` for rootless simulation and testing.
    #[must_use]
    pub fn inert(mut cfg: PppoeConfig, ctx: LanforgeContext) -> Self {
        if let Some(dynamic_cfg) = ctx.get_pppoe_config() {
            cfg = dynamic_cfg;
        }
        Self {
            cfg,
            ctx,
            attempt: 0,
            active_session: None,
            inert: true,
            prober: None,
            terminal_status: None,
        }
    }

    #[must_use]
    pub fn with_prober(mut self, prober: ArpProber) -> Self {
        self.prober = Some(prober);
        self
    }

    #[must_use]
    pub const fn with_inert(mut self, inert: bool) -> Self {
        self.inert = inert;
        self
    }

    #[must_use]
    pub const fn is_inert(&self) -> bool {
        self.inert
    }

    async fn teardown_active_session(&mut self, reason: String) {
        let had_session = self.active_session.is_some() || self.ctx.is_pppoe_ready();
        if let Some((wan_mac, ac_mac, session_id)) = self.active_session.take()
            && self.cfg.send_padt_on_shutdown
            && !self.inert
        {
            info!(
                wan_iface = %self.cfg.wan_iface,
                session_id,
                "Sending PPPoE PADT frame during session teardown"
            );
            let _ = send_padt(&self.cfg.wan_iface, wan_mac, ac_mac, session_id);
        }

        if !self.inert {
            deconfigure_interface(
                &self.cfg.wan_iface,
                self.cfg.dataplane == PppoeDataplane::Ebpf,
                None,
            )
            .await;
        }

        self.ctx.set_pppoe_ready(false);
        let _ = self
            .ctx
            .apply(DeviceUpdate::PppoeStatusUpdated { status: None });

        if had_session {
            warn!(
                wan_iface = %self.cfg.wan_iface,
                reason = %reason,
                "PPPoE session disconnected, publishing SessionDown"
            );
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::Pppoe(PppoeEvent::SessionDown { reason }));
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn run_inert_session_flow(&mut self) -> Result<(), PppoeError> {
        if self.cfg.username == "fail_auth" {
            sleep(Duration::from_millis(10)).await;
            let reason = "PAP/CHAP authentication failed: invalid credentials".to_string();
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::Pppoe(PppoeEvent::AuthFailed {
                    reason: reason.clone(),
                }));
            return Err(PppoeError::AuthFailed(reason));
        }

        if self.cfg.username == "discovery_timeout" {
            sleep(Duration::from_millis(10)).await;
            return Err(PppoeError::DiscoveryTimeout);
        }

        let ac_mac = MacAddr([0x02, 0x00, 0x00, 0xac, 0x00, 0x01]);
        let wan_mac = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
        let session_id = 0x0042;
        self.active_session = Some((wan_mac, ac_mac, session_id));

        let disc_res = crate::discovery::DiscoveryResult {
            ac_mac,
            ac_name: Some("lanforge-bras".into()),
            session_id,
        };
        let lcp_res = crate::lcp::LcpNegotiated {
            mru: self.cfg.mru,
            auth_method: self.cfg.auth,
            local_magic: 0x1234_5678,
            peer_magic: 0x8765_4321,
        };
        let local_ip = Ipv4Addr::new(100, 64, 0, 2);
        let peer_ip = Ipv4Addr::new(100, 64, 0, 1);
        let ipcp_res = crate::ipcp::IpcpNegotiated {
            local_ip: Some(local_ip),
            peer_ip: Some(peer_ip),
            dns: vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            ],
            local_v6_ll: None,
            peer_v6_ll: None,
        };

        if self.cfg.terminal_probe.enabled {
            if let Some(ref prober) = self.prober {
                let target = self.cfg.terminal_probe.target_ip;
                let sender = self.cfg.terminal_probe.sender_ip;
                let timeout = Duration::from_millis(self.cfg.terminal_probe.timeout_ms);
                match prober.probe(target, sender, timeout).await {
                    Ok(Some(reply)) => {
                        let rtt_us = u32::try_from(reply.rtt.as_micros()).unwrap_or(u32::MAX);
                        self.terminal_status = Some((true, Some(MacAddr(reply.mac)), Some(rtt_us)));
                    }
                    _ => {
                        self.terminal_status = Some((false, None, None));
                    }
                }
            } else if self.cfg.username == "terminal_unreachable" {
                self.terminal_status = Some((false, None, None));
            } else {
                self.terminal_status = Some((
                    true,
                    Some(MacAddr([0x3c, 0x84, 0x6a, 0xbc, 0x8c, 0xe5])),
                    Some(800),
                ));
            }
        } else {
            self.terminal_status = None;
        }

        let interface_name = if self.cfg.dataplane == PppoeDataplane::Ebpf {
            self.cfg.wan_iface.clone()
        } else {
            "ppp0".to_string()
        };

        self.publish_connected_status(&interface_name, &disc_res, &lcp_res, &ipcp_res);
        self.ctx.set_service_state("pppoe", ServiceState::Online);

        if self.cfg.username == "carrier_drop" {
            sleep(Duration::from_millis(30)).await;
            self.teardown_active_session("LCP Keepalive Echo timeout (carrier loss)".into())
                .await;
            return Err(PppoeError::KeepAliveTimeout);
        }

        let mut bus_rx = self.ctx.bus().subscribe_system();
        loop {
            tokio::select! {
                event_res = bus_rx.recv() => {
                    match event_res {
                        Ok(timed) => match timed.event {
                            LanforgeEvent::System(SystemEvent::Shutdown) => {
                                info!("PPPoE inert keepalive received shutdown");
                                self.teardown_active_session("Graceful shutdown".into()).await;
                                return Ok(());
                            }
                            LanforgeEvent::System(SystemEvent::ServiceControl { id, action }) if id == "pppoe" => {
                                info!(action = ?action, "PPPoE inert keepalive received service control");
                                self.teardown_active_session(format!("Service control {action:?}")).await;
                                return Ok(());
                            }
                            LanforgeEvent::System(SystemEvent::ConfigPppoeChanged) => {
                                info!("PPPoE inert keepalive received ConfigPppoeChanged");
                                self.teardown_active_session("Configuration updated".into()).await;
                                return Ok(());
                            }
                            _ => {}
                        },
                        Err(_) => break,
                    }
                }
            }
        }

        self.teardown_active_session("Channel closed".into()).await;
        Ok(())
    }

    fn find_interface_details(iface_name: &str) -> Option<(u32, MacAddr)> {
        interfaces().into_iter().find_map(|iface| {
            if iface.name == iface_name {
                iface.mac.map(|mac| (iface.index, MacAddr(mac.octets())))
            } else {
                None
            }
        })
    }

    fn get_interface_details(&self) -> Result<(u32, MacAddr), PppoeError> {
        Self::find_interface_details(&self.cfg.wan_iface).ok_or_else(|| {
            PppoeError::NegotiationFailed(format!(
                "Interface {} not found or has no MAC address",
                self.cfg.wan_iface
            ))
        })
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

    pub fn publish_connected_status(
        &mut self,
        interface_name: &str,
        disc_res: &crate::discovery::DiscoveryResult,
        lcp_res: &crate::lcp::LcpNegotiated,
        ipcp_res: &crate::ipcp::IpcpNegotiated,
    ) {
        let (terminal_reachable, terminal_mac, terminal_rtt_us) =
            self.terminal_status.map_or((None, None, None), |(r, m, rtt)| (Some(r), m, rtt));

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
            terminal_reachable,
            terminal_mac,
            terminal_rtt_us,
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

    pub fn publish_session_state(
        &self,
        state: PppoeSessionState,
        last_error: Option<String>,
    ) {
        let (terminal_reachable, terminal_mac, terminal_rtt_us) =
            self.terminal_status.map_or((None, None, None), |(r, m, rtt)| (Some(r), m, rtt));

        let pppoe_status = PppoeStatusResponse {
            enabled: true,
            dataplane: Some(self.cfg.dataplane),
            state,
            interface: None,
            wan_iface: Some(self.cfg.wan_iface.clone()),
            local_ip: None,
            peer_ip: None,
            ac_mac: None,
            ac_name: None,
            session_id: None,
            mru: Some(self.cfg.mru),
            dns_servers: Vec::new(),
            uptime_secs: None,
            reconnect_attempts: self.attempt,
            last_error,
            auth: Some(self.cfg.auth),
            terminal_reachable,
            terminal_mac,
            terminal_rtt_us,
        };

        let _ = self.ctx.apply(DeviceUpdate::PppoeStatusUpdated {
            status: Some(Box::new(pppoe_status)),
        });
    }

    async fn wait_for_carrier(&mut self) -> Result<(), PppoeError> {
        if !Path::new("/sys/class/net").exists() {
            info!(
                wan_iface = %self.cfg.wan_iface,
                "Sysfs net class unavailable, skipping physical carrier check"
            );
            return Ok(());
        }

        if read_carrier(&self.cfg.wan_iface) == Some(true) {
            info!(
                wan_iface = %self.cfg.wan_iface,
                "Physical carrier detected on WAN interface (link UP)"
            );
            return Ok(());
        }

        warn!(
            wan_iface = %self.cfg.wan_iface,
            "No physical carrier detected on WAN interface (cable disconnected or terminal power off), waiting for link UP..."
        );
        self.publish_session_state(
            PppoeSessionState::WaitingForCarrier,
            Some("No physical carrier detected (cable disconnected or power off)".into()),
        );

        let mut bus_rx = self.ctx.bus().subscribe_system();
        let mut check_timer = tokio::time::interval(Duration::from_secs(1));
        let mut wait_ticks = 0u64;

        loop {
            if !self.ctx.is_running() {
                return Err(PppoeError::NegotiationFailed(
                    "Daemon shutdown while waiting for carrier".into(),
                ));
            }

            tokio::select! {
                _ = check_timer.tick() => {
                    wait_ticks += 1;
                    if read_carrier(&self.cfg.wan_iface) == Some(true) {
                        info!(
                            wan_iface = %self.cfg.wan_iface,
                            waited_secs = wait_ticks,
                            "Physical carrier detected on WAN interface (link UP), proceeding to PPPoE discovery"
                        );
                        self.attempt = 0;
                        return Ok(());
                    }

                    if wait_ticks.is_multiple_of(15) {
                        warn!(
                            wan_iface = %self.cfg.wan_iface,
                            waited_secs = wait_ticks,
                            "Still waiting for physical carrier on WAN interface..."
                        );
                    }
                }
                res = bus_rx.recv() => {
                    let Ok(event) = res else { continue; };
                    match event.event {
                        LanforgeEvent::System(SystemEvent::Shutdown) => {
                            info!("PPPoE carrier wait interrupted by daemon shutdown");
                            return Err(PppoeError::NegotiationFailed("Shutdown received".into()));
                        }
                        LanforgeEvent::System(SystemEvent::ServiceControl { ref id, ref action })
                            if id == "pppoe" && matches!(action, ServiceAction::Stop | ServiceAction::Restart) =>
                        {
                            info!(action = ?action, "PPPoE carrier wait interrupted by service control");
                            return Err(PppoeError::NegotiationFailed("Service stopped or restarted".into()));
                        }
                        LanforgeEvent::System(SystemEvent::ConfigPppoeChanged) => {
                            info!("PPPoE carrier wait interrupted by configuration update");
                            return Err(PppoeError::NegotiationFailed("Configuration changed".into()));
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn wait_for_terminal(&mut self) -> Result<Option<ArpProber>, PppoeError> {
        if !self.cfg.terminal_probe.enabled {
            return Ok(None);
        }

        let probe_iface_name = self
            .cfg
            .terminal_probe
            .iface
            .as_deref()
            .unwrap_or_else(|| resolve_parent_iface(&self.cfg.wan_iface));

        let prober = if let Some(p) = self.prober.clone() {
            p
        } else {
            let Some((probe_ifindex, probe_mac)) = Self::find_interface_details(probe_iface_name) else {
                warn!(
                    target_ip = %self.cfg.terminal_probe.target_ip,
                    probe_iface = %probe_iface_name,
                    "Probe interface not found for terminal probe; proceeding to PPPoE discovery without probe"
                );
                return Ok(None);
            };

            match ArpProber::bind(probe_ifindex, probe_mac.0) {
                Ok(p) => p,
                Err(e) => {
                    warn!(
                        error = %e,
                        probe_iface = %probe_iface_name,
                        "Failed to bind raw ARP prober socket; proceeding to PPPoE discovery without probe"
                    );
                    return Ok(None);
                }
            }
        };

        let target_ip = self.cfg.terminal_probe.target_ip;
        let sender_ip = self.cfg.terminal_probe.sender_ip;
        let probe_timeout = Duration::from_millis(self.cfg.terminal_probe.timeout_ms);

        info!(
            target_ip = %target_ip,
            sender_ip = ?sender_ip,
            probe_iface = %probe_iface_name,
            timeout_ms = self.cfg.terminal_probe.timeout_ms,
            "Probing GPON ONT / modem underlay via Layer 2 ARP"
        );

        match prober.probe(target_ip, sender_ip, probe_timeout).await {
            Ok(Some(reply)) => {
                let rtt_us = u32::try_from(reply.rtt.as_micros()).unwrap_or(u32::MAX);
                let terminal_mac = MacAddr(reply.mac);
                info!(
                    target_ip = %target_ip,
                    mac = %terminal_mac,
                    rtt_us,
                    "Terminal (GPON ONT/modem) is reachable via Layer 2 ARP"
                );
                self.terminal_status = Some((true, Some(terminal_mac), Some(rtt_us)));
                return Ok(Some(prober));
            }
            Ok(None) => {
                warn!(
                    target_ip = %target_ip,
                    timeout_ms = self.cfg.terminal_probe.timeout_ms,
                    "Terminal did not answer initial ARP probe"
                );
            }
            Err(e) => {
                warn!(
                    target_ip = %target_ip,
                    error = %e,
                    "ARP probe execution error on initial check"
                );
            }
        }

        if self.cfg.terminal_probe.max_wait_secs == 0 {
            warn!(
                target_ip = %target_ip,
                "Soft-gate max_wait_secs is 0; proceeding with PPPoE discovery immediately"
            );
            self.terminal_status = Some((false, None, None));
            return Ok(Some(prober));
        }

        self.terminal_status = Some((false, None, None));
        self.publish_session_state(
            PppoeSessionState::WaitingForTerminal,
            Some(format!("Waiting for terminal ({target_ip})")),
        );

        warn!(
            target_ip = %target_ip,
            max_wait_secs = self.cfg.terminal_probe.max_wait_secs,
            poll_interval_secs = self.cfg.terminal_probe.poll_interval_secs,
            "Waiting for terminal to respond before dialing PPPoE (soft gate)..."
        );

        let mut bus_rx = self.ctx.bus().subscribe_system();
        let poll_duration = Duration::from_secs(self.cfg.terminal_probe.poll_interval_secs.max(1));
        let mut poll_timer = tokio::time::interval(poll_duration);
        poll_timer.tick().await;
        let start = tokio::time::Instant::now();
        let deadline = Duration::from_secs(self.cfg.terminal_probe.max_wait_secs);

        loop {
            if !self.ctx.is_running() {
                return Err(PppoeError::NegotiationFailed(
                    "Daemon shutdown while waiting for terminal".into(),
                ));
            }

            tokio::select! {
                _ = poll_timer.tick() => {
                    if start.elapsed() >= deadline {
                        warn!(
                            target_ip = %target_ip,
                            waited_secs = start.elapsed().as_secs(),
                            "Soft gate deadline expired without reply from terminal; proceeding with PPPoE discovery anyway"
                        );
                        return Ok(Some(prober));
                    }

                    match prober.probe(target_ip, sender_ip, probe_timeout).await {
                        Ok(Some(reply)) => {
                            let rtt_us = u32::try_from(reply.rtt.as_micros()).unwrap_or(u32::MAX);
                            let terminal_mac = MacAddr(reply.mac);
                            info!(
                                target_ip = %target_ip,
                                mac = %terminal_mac,
                                rtt_us,
                                waited_secs = start.elapsed().as_secs(),
                                "Terminal responded to ARP probe; proceeding to PPPoE discovery"
                            );
                            self.terminal_status = Some((true, Some(terminal_mac), Some(rtt_us)));
                            return Ok(Some(prober));
                        }
                        Ok(None) => {
                            debug!(
                                target_ip = %target_ip,
                                waited_secs = start.elapsed().as_secs(),
                                "Terminal still not responding to ARP probe..."
                            );
                        }
                        Err(e) => {
                            debug!(
                                target_ip = %target_ip,
                                error = %e,
                                "ARP probe poll error"
                            );
                        }
                    }
                }
                res = bus_rx.recv() => {
                    let Ok(event) = res else { continue; };
                    match event.event {
                        LanforgeEvent::System(SystemEvent::Shutdown) => {
                            info!("PPPoE terminal wait interrupted by daemon shutdown");
                            return Err(PppoeError::NegotiationFailed("Shutdown received".into()));
                        }
                        LanforgeEvent::System(SystemEvent::ServiceControl { ref id, ref action })
                            if id == "pppoe" && matches!(action, ServiceAction::Stop | ServiceAction::Restart) =>
                        {
                            info!(action = ?action, "PPPoE terminal wait interrupted by service control");
                            return Err(PppoeError::NegotiationFailed("Service stopped or restarted".into()));
                        }
                        LanforgeEvent::System(SystemEvent::ConfigPppoeChanged) => {
                            info!("PPPoE terminal wait interrupted by configuration update");
                            return Err(PppoeError::NegotiationFailed("Configuration changed".into()));
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    async fn run_session_flow(&mut self) -> Result<(), PppoeError> {
        if self.inert {
            return self.run_inert_session_flow().await;
        }

        self.wait_for_carrier().await?;

        let prober = self.wait_for_terminal().await?;

        let (ifindex, mac) = self.get_interface_details()?;
        info!(
            wan_iface = %self.cfg.wan_iface,
            ifindex,
            mac = %mac,
            "Initiating PPPoE Active Discovery (PADI)"
        );
        self.publish_session_state(PppoeSessionState::Discovering, None);
        let disc_res = self.perform_discovery(ifindex, mac).await?;

        let keepalive_prober = if matches!(self.terminal_status, Some((true, _, _))) {
            prober.as_ref().map(|p| {
                (
                    p,
                    self.cfg.terminal_probe.target_ip,
                    self.cfg.terminal_probe.sender_ip,
                    Duration::from_millis(self.cfg.terminal_probe.timeout_ms),
                )
            })
        } else {
            None
        };

        let flow_res = async {
            info!(
                ac_name = disc_res.ac_name.as_deref().unwrap_or("unknown"),
                ac_mac = %disc_res.ac_mac,
                session_id = disc_res.session_id,
                "PADO/PADS handshake complete, starting LCP/Authentication negotiation"
            );
            self.publish_session_state(PppoeSessionState::Authenticating, None);
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
                keepalive_prober,
            )
            .await
        }
        .await;

        if matches!(flow_res, Err(PppoeError::TerminalUnreachable(..))) {
            self.terminal_status = Some((false, None, None));
        }

        let reason = match &flow_res {
            Ok(()) => "Graceful shutdown".to_string(),
            Err(e) => e.to_string(),
        };

        self.teardown_active_session(reason).await;

        flow_res
    }
}

impl AsyncService for PppoeService {
    fn dependencies(&self) -> &'static [ServiceDependency] {
        &[ServiceDependency::Interfaces]
    }

    fn stats(&self, ctx: &LanforgeContext) -> Vec<(Cow<'static, str>, String)> {
        let (state_str, local_ip, ppp_iface, term_str) = ctx.with_state(|state| {
            state.interfaces.pppoe_status.as_ref().map_or_else(
                || {
                    (
                        "disconnected".to_string(),
                        "none".to_string(),
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
                        p.terminal_reachable.map_or_else(
                            || "unprobed".to_string(),
                            |r| if r { "reachable".to_string() } else { "unreachable".to_string() },
                        ),
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
            (Cow::Borrowed("terminal"), term_str),
            (
                Cow::Borrowed("reconnect_attempts"),
                self.attempt.to_string(),
            ),
        ]
    }

    #[allow(clippy::too_many_lines)]
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

        if !self.inert && self.cfg.dataplane == PppoeDataplane::Kernel && !Path::new("/dev/ppp").exists() {
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
        if !self.inert && self.cfg.dataplane == PppoeDataplane::Ebpf {
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
                    if let Ok(timed) = event_res {
                        match &timed.event {
                            LanforgeEvent::System(SystemEvent::Shutdown) => {
                                info!("PPPoE service received shutdown event, exiting serve loop");
                                self.teardown_active_session("Graceful shutdown".into()).await;
                                break 'main_loop;
                            }
                            LanforgeEvent::System(SystemEvent::ServiceControl { id, action }) if id == "pppoe" => {
                                match action {
                                    ServiceAction::Stop => {
                                        info!("PPPoE service received stop command, transitioning to Inactive");
                                        self.teardown_active_session("Service stopped".into()).await;
                                        ctx.set_service_state("pppoe", ServiceState::Inactive);
                                        break 'main_loop;
                                    }
                                    ServiceAction::Restart => {
                                        info!("PPPoE service received restart command, restarting session");
                                        self.teardown_active_session("Service restarted".into()).await;
                                        self.attempt = 0;
                                    }
                                    ServiceAction::Start => {}
                                }
                            }
                            LanforgeEvent::System(SystemEvent::ConfigPppoeChanged) => {
                                info!("PPPoE service received ConfigPppoeChanged in main loop");
                                self.teardown_active_session("Configuration updated".into()).await;
                                if let Some(dynamic_cfg) = ctx.get_pppoe_config() {
                                    self.cfg = dynamic_cfg;
                                }
                                if !self.cfg.enabled {
                                    info!("PPPoE service disabled via config change");
                                    ctx.set_service_state("pppoe", ServiceState::Inactive);
                                    break 'main_loop;
                                }
                                self.attempt = 0;
                            }
                            _ => {}
                        }
                    }
                }
                flow_res = self.run_session_flow() => {
                    match flow_res {
                        Ok(()) => {
                            if !ctx.is_running() {
                                info!("PPPoE service session finished cleanly (daemon shutting down)");
                                break 'main_loop;
                            }
                            if let Some(dynamic_cfg) = ctx.get_pppoe_config() {
                                self.cfg = dynamic_cfg;
                            }
                            if !self.cfg.enabled {
                                info!("PPPoE service disabled in config, transitioning to Inactive");
                                ctx.set_service_state("pppoe", ServiceState::Inactive);
                                break 'main_loop;
                            }
                            info!("PPPoE session completed, reconnecting with active configuration");
                            self.attempt = 0;
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

                            self.publish_session_state(
                                PppoeSessionState::Reconnecting,
                                Some(e.to_string()),
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
                                    if let Ok(timed) = res {
                                        match &timed.event {
                                            LanforgeEvent::System(SystemEvent::Shutdown) => {
                                                info!("PPPoE service received shutdown during reconnect delay");
                                                break 'main_loop;
                                            }
                                            LanforgeEvent::System(SystemEvent::ServiceControl { id, action }) if id == "pppoe" => {
                                                match action {
                                                    ServiceAction::Stop => {
                                                        info!("PPPoE service received stop during reconnect delay");
                                                        ctx.set_service_state("pppoe", ServiceState::Inactive);
                                                        break 'main_loop;
                                                    }
                                                    ServiceAction::Restart => {
                                                        info!("PPPoE service received restart during reconnect delay, retrying immediately");
                                                        self.attempt = 0;
                                                    }
                                                    ServiceAction::Start => {}
                                                }
                                            }
                                            LanforgeEvent::System(SystemEvent::ConfigPppoeChanged) => {
                                                info!("PPPoE service received config change during reconnect delay, retrying immediately");
                                                if let Some(dynamic_cfg) = ctx.get_pppoe_config() {
                                                    self.cfg = dynamic_cfg;
                                                }
                                                if !self.cfg.enabled {
                                                    ctx.set_service_state("pppoe", ServiceState::Inactive);
                                                    break 'main_loop;
                                                }
                                                self.attempt = 0;
                                            }
                                            _ => {}
                                        }
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

    async fn cleanup(&mut self, _ctx: &LanforgeContext) -> Result<(), CoreError> {
        self.teardown_active_session("Service stopped or shut down".to_string()).await;
        Ok(())
    }
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

