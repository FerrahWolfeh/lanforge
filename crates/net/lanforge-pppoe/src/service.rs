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
use lanforge_core::context::{ConfigSubscription, LanforgeContext};
use lanforge_core::error::CoreError;
use lanforge_core::service::{
    Activation, AsyncService, Condition, Edge, LanforgeService, RestartPolicy, RuntimeClass,
    ServiceCommand, ServiceHandle, ServiceSpec,
};
use lanforge_transport::ArpProber;
use lanforge_types::config::ChangeImpact;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::pppoe::PppoeDataplane;
use lanforge_types::system::{
    DegradedReason, DormantReason, PppoeSessionState, PppoeStatusResponse, ServiceAction,
    ServiceId, ServiceState,
};
use smallvec::smallvec;
use std::borrow::Cow;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{Instant, sleep};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
struct ActiveSessionMeta {
    wan_mac: MacAddr,
    ac_mac: MacAddr,
    session_id: u16,
    peer_ip: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SystemInterrupt {
    Shutdown,
    Stop,
    Restart,
}

pub(crate) fn classify_system_event(event: &LanforgeEvent) -> Option<SystemInterrupt> {
    match event {
        LanforgeEvent::System(SystemEvent::Shutdown) => Some(SystemInterrupt::Shutdown),
        LanforgeEvent::System(SystemEvent::ServiceControl { id, action })
            if *id == ServiceId::Pppoe =>
        {
            match action {
                ServiceAction::Stop => Some(SystemInterrupt::Stop),
                ServiceAction::Restart => Some(SystemInterrupt::Restart),
                ServiceAction::Start => None,
            }
        }
        _ => None,
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

    check(iface).or_else(|| {
        let parent = resolve_parent_iface(iface);
        if parent == iface { None } else { check(parent) }
    })
}

#[cfg(feature = "ebpf")]
type EbpfSessionHandle = Option<crate::ebpf::EbpfSession>;
#[cfg(not(feature = "ebpf"))]
type EbpfSessionHandle = Option<()>;

const PPPOE_DEPS: &[Edge] = &[Edge::requires(
    ServiceId::Interfaces,
    lanforge_core::service::LossPolicy::Continue,
)];

pub struct PppoeService {
    cfg: PppoeConfig,
    ctx: LanforgeContext,
    attempt: u32,
    active_session: Option<ActiveSessionMeta>,
    connected_at: Option<Instant>,
    inert: bool,
    prober: Option<ArpProber>,
    terminal_status: Option<(bool, Option<MacAddr>, Option<u32>)>,
    config_sub: ConfigSubscription<PppoeConfig>,
}

impl PppoeService {
    /// Static identifier for the service.
    pub const SERVICE_ID: ServiceId = ServiceId::Pppoe;
    #[must_use]
    pub fn new(mut cfg: PppoeConfig, ctx: LanforgeContext) -> Self {
        if let Some(dynamic_cfg) = ctx.get_pppoe_config() {
            cfg = dynamic_cfg;
        }
        let mut config_sub = ctx.config_subscription::<PppoeConfig>();
        config_sub.mark_applied(Arc::new(cfg.clone()));
        Self {
            cfg,
            ctx,
            attempt: 0,
            active_session: None,
            connected_at: None,
            inert: false,
            prober: None,
            terminal_status: None,
            config_sub,
        }
    }

    /// Creates an inert instance of `PppoeService` for rootless simulation and testing.
    #[must_use]
    pub fn inert(mut cfg: PppoeConfig, ctx: LanforgeContext) -> Self {
        if let Some(dynamic_cfg) = ctx.get_pppoe_config() {
            cfg = dynamic_cfg;
        }
        let mut config_sub = ctx.config_subscription::<PppoeConfig>();
        config_sub.mark_applied(Arc::new(cfg.clone()));
        Self {
            cfg,
            ctx,
            attempt: 0,
            active_session: None,
            connected_at: None,
            inert: true,
            prober: None,
            terminal_status: None,
            config_sub,
        }
    }

    fn apply_hot_config(&mut self, new_cfg: &PppoeConfig) {
        self.cfg.lcp_echo_interval_secs = new_cfg.lcp_echo_interval_secs;
        self.cfg.lcp_echo_max_failures = new_cfg.lcp_echo_max_failures;
        self.cfg.reconnect_delay_secs = new_cfg.reconnect_delay_secs;
        self.cfg.send_padt_on_shutdown = new_cfg.send_padt_on_shutdown;
        self.cfg.discovery_padi_retries = new_cfg.discovery_padi_retries;
        self.cfg.discovery_padi_timeout_secs = new_cfg.discovery_padi_timeout_secs;
        self.cfg.terminal_probe.clone_from(&new_cfg.terminal_probe);
        self.cfg.nftables.clone_from(&new_cfg.nftables);
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
        let had_session = self.active_session.is_some()
            || self.ctx.pppoe_status().is_some()
            || self.ctx.wan_snapshot().is_up();
        let session_meta = self.active_session.take();
        self.connected_at = None;
        if let Some(ref meta) = session_meta
            && self.cfg.send_padt_on_shutdown
            && !self.inert
        {
            info!(
                wan_iface = %self.cfg.wan_iface,
                session_id = meta.session_id,
                "Sending PPPoE PADT frame during session teardown"
            );
            let _ = send_padt(
                &self.cfg.wan_iface,
                meta.wan_mac,
                meta.ac_mac,
                meta.session_id,
            )
            .await;
        }

        if !self.inert {
            deconfigure_interface(
                &self.cfg.wan_iface,
                self.cfg.dataplane == PppoeDataplane::Ebpf,
                session_meta.as_ref().and_then(|m| m.peer_ip),
            )
            .await;
        }

        self.ctx.set_pppoe_status(None);

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
    async fn run_inert_session_flow(&mut self) -> Result<Option<SystemInterrupt>, PppoeError> {
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
        let local_ip = Ipv4Addr::new(100, 64, 0, 2);
        let peer_ip = Ipv4Addr::new(100, 64, 0, 1);
        self.active_session = Some(ActiveSessionMeta {
            wan_mac,
            ac_mac,
            session_id,
            peer_ip: Some(peer_ip),
        });

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
        let ipcp_res = crate::ipcp::IpcpNegotiated {
            local_ip: Some(local_ip),
            peer_ip: Some(peer_ip),
            dns: smallvec![
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
        self.ctx
            .set_service_state(Self::SERVICE_ID, ServiceState::Online);

        if self.cfg.username == "carrier_drop" {
            sleep(Duration::from_millis(30)).await;
            self.teardown_active_session("LCP Keepalive Echo timeout (carrier loss)".into())
                .await;
            return Err(PppoeError::KeepAliveTimeout);
        }

        let mut bus_rx = self.ctx.bus().subscribe_system();
        loop {
            tokio::select! {
                delta_opt = self.config_sub.next() => {
                    let Some(delta) = delta_opt else { break; };
                    if !delta.new.enabled {
                        self.teardown_active_session("Configuration updated".into()).await;
                        return Ok(Some(SystemInterrupt::Stop));
                    }
                    match delta.impact {
                        ChangeImpact::None => {}
                        ChangeImpact::Hot => {
                            info!("PPPoE inert session hot swap applied in place");
                            self.apply_hot_config(&delta.new);
                        }
                        ChangeImpact::Reconnect | ChangeImpact::Rebind => {
                            info!("PPPoE inert session reconnecting for config changes");
                            self.teardown_active_session("Configuration updated".into()).await;
                            return Ok(Some(SystemInterrupt::Restart));
                        }
                    }
                }
                event_res = bus_rx.recv() => {
                    match event_res {
                        Ok(timed) => match classify_system_event(&timed.event) {
                            Some(SystemInterrupt::Shutdown) => {
                                info!("PPPoE inert keepalive received shutdown");
                                self.teardown_active_session("Graceful shutdown".into()).await;
                                return Ok(Some(SystemInterrupt::Shutdown));
                            }
                            Some(SystemInterrupt::Stop) => {
                                info!("PPPoE inert keepalive received stop");
                                self.teardown_active_session("Service control Stop".into()).await;
                                return Ok(Some(SystemInterrupt::Stop));
                            }
                            Some(SystemInterrupt::Restart) => {
                                info!("PPPoE inert keepalive received restart");
                                self.teardown_active_session("Service control Restart".into()).await;
                                return Ok(Some(SystemInterrupt::Restart));
                            }
                            None => {}
                        },
                        Err(_) => break,
                    }
                }
            }
        }

        self.teardown_active_session("Channel closed".into()).await;
        Ok(None)
    }

    #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
    fn find_interface_details(iface_name: &str) -> Option<(u32, MacAddr)> {
        let mut ifname_buf = [0u8; libc::IF_NAMESIZE];
        let if_bytes = iface_name.as_bytes();
        if if_bytes.len() >= libc::IF_NAMESIZE || if_bytes.contains(&0) {
            return None;
        }
        ifname_buf[..if_bytes.len()].copy_from_slice(if_bytes);
        let ifindex = unsafe { libc::if_nametoindex(ifname_buf.as_ptr().cast::<libc::c_char>()) };
        if ifindex == 0 {
            return None;
        }

        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            return None;
        }

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        for (i, &b) in if_bytes.iter().enumerate() {
            ifr.ifr_name[i] = b as libc::c_char;
        }

        let res = unsafe { libc::ioctl(sock, libc::SIOCGIFHWADDR, &mut ifr) };
        unsafe { libc::close(sock) };

        if res < 0 {
            return None;
        }

        let hw = unsafe { ifr.ifr_ifru.ifru_hwaddr.sa_data };
        let mac = [
            hw[0] as u8,
            hw[1] as u8,
            hw[2] as u8,
            hw[3] as u8,
            hw[4] as u8,
            hw[5] as u8,
        ];
        Some((ifindex, MacAddr(mac)))
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
        info!(wan_iface = %self.cfg.wan_iface, "Starting PPPoE discovery");
        let discovery = PppoeDiscovery::new(
            ifindex,
            mac,
            self.cfg.discovery_padi_retries,
            self.cfg.discovery_padi_timeout_secs,
            self.cfg.service_name.clone(),
            self.cfg.ac_name.clone(),
        );
        let disc_res = discovery.run().await?;
        self.active_session = Some(ActiveSessionMeta {
            wan_mac: mac,
            ac_mac: disc_res.ac_mac,
            session_id: disc_res.session_id,
            peer_ip: None,
        });
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
    ) -> Result<
        (
            PppoeSession,
            crate::lcp::LcpNegotiated,
            crate::ipcp::IpcpNegotiated,
        ),
        PppoeError,
    > {
        let session =
            PppoeSession::connect(&self.cfg.wan_iface, disc_res.ac_mac, disc_res.session_id)?;

        debug!(wan_iface = %self.cfg.wan_iface, "Negotiating LCP");
        let lcp_res = negotiate_lcp(&session, self.cfg.mru, self.cfg.auth).await?;
        debug!(
            wan_iface = %self.cfg.wan_iface,
            mru = lcp_res.mru,
            auth = ?lcp_res.auth_method,
            "LCP negotiation succeeded"
        );

        debug!(wan_iface = %self.cfg.wan_iface, auth = ?lcp_res.auth_method, "Authenticating PPPoE session");
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
        debug!(wan_iface = %self.cfg.wan_iface, "PPPoE authentication succeeded");

        debug!(wan_iface = %self.cfg.wan_iface, "Negotiating IPCP and IPv6CP");
        let ipcp_res = negotiate_ipcp(&session, mac).await?;
        debug!(
            wan_iface = %self.cfg.wan_iface,
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
        self.connected_at = Some(Instant::now());
        let (terminal_reachable, terminal_mac, terminal_rtt_us) = self
            .terminal_status
            .map_or((None, None, None), |(r, m, rtt)| (Some(r), m, rtt));

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
            dns_servers: ipcp_res.dns.to_vec(),
            uptime_secs: Some(0),
            reconnect_attempts: self.attempt,
            last_error: None,
            auth: Some(lcp_res.auth_method),
            terminal_reachable,
            terminal_mac,
            terminal_rtt_us,
        };

        self.ctx.set_pppoe_status(Some(pppoe_status));

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
                    dns: ipcp_res.dns.to_vec(),
                    ipv6_link_local: ipcp_res.local_v6_ll.is_some(),
                },
            ))));

        self.ctx
            .set_service_state(Self::SERVICE_ID, ServiceState::Online);
        self.ctx.set_service_detail(Self::SERVICE_ID, None);
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::ServiceReady {
                id: Self::SERVICE_ID,
            }));
        self.attempt = 0;
    }

    pub fn publish_session_state(&self, state: PppoeSessionState, last_error: Option<String>) {
        let (terminal_reachable, terminal_mac, terminal_rtt_us) = self
            .terminal_status
            .map_or((None, None, None), |(r, m, rtt)| (Some(r), m, rtt));

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

        self.ctx.set_pppoe_status(Some(pppoe_status));
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
                delta_opt = self.config_sub.next() => {
                    let Some(delta) = delta_opt else {
                        return Err(PppoeError::NegotiationFailed("Shutdown received".into()));
                    };
                    if !delta.new.enabled {
                        return Err(PppoeError::NegotiationFailed("Configuration disabled".into()));
                    }
                    match delta.impact {
                        ChangeImpact::None => {}
                        ChangeImpact::Hot => {
                            self.apply_hot_config(&delta.new);
                        }
                        ChangeImpact::Reconnect | ChangeImpact::Rebind => {
                            info!(wan_iface = %self.cfg.wan_iface, "Carrier wait interrupted by configuration update");
                            self.cfg = (*delta.new).clone();
                            return Err(PppoeError::NegotiationFailed("Configuration changed".into()));
                        }
                    }
                }
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
                    match classify_system_event(&event.event) {
                        Some(SystemInterrupt::Shutdown) => {
                            debug!(wan_iface = %self.cfg.wan_iface, "Carrier wait interrupted by daemon shutdown");
                            return Err(PppoeError::NegotiationFailed("Shutdown received".into()));
                        }
                        Some(SystemInterrupt::Stop | SystemInterrupt::Restart) => {
                            info!(wan_iface = %self.cfg.wan_iface, "Carrier wait interrupted by service control");
                            return Err(PppoeError::NegotiationFailed("Service stopped or restarted".into()));
                        }
                        None => {}
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
            let Some((probe_ifindex, probe_mac)) = Self::find_interface_details(probe_iface_name)
            else {
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
                delta_opt = self.config_sub.next() => {
                    let Some(delta) = delta_opt else {
                        return Err(PppoeError::NegotiationFailed("Shutdown received".into()));
                    };
                    if !delta.new.enabled {
                        return Err(PppoeError::NegotiationFailed("Configuration disabled".into()));
                    }
                    match delta.impact {
                        ChangeImpact::None => {}
                        ChangeImpact::Hot => {
                            self.apply_hot_config(&delta.new);
                        }
                        ChangeImpact::Reconnect | ChangeImpact::Rebind => {
                            info!(wan_iface = %self.cfg.wan_iface, "Terminal wait interrupted by configuration update");
                            self.cfg = (*delta.new).clone();
                            return Err(PppoeError::NegotiationFailed("Configuration changed".into()));
                        }
                    }
                }
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
                    match classify_system_event(&event.event) {
                        Some(SystemInterrupt::Shutdown) => {
                            debug!(wan_iface = %self.cfg.wan_iface, "Terminal wait interrupted by daemon shutdown");
                            return Err(PppoeError::NegotiationFailed("Shutdown received".into()));
                        }
                        Some(SystemInterrupt::Stop | SystemInterrupt::Restart) => {
                            info!(wan_iface = %self.cfg.wan_iface, "Terminal wait interrupted by service control");
                            return Err(PppoeError::NegotiationFailed("Service stopped or restarted".into()));
                        }
                        None => {}
                    }
                }
            }
        }
    }

    async fn run_session_flow(&mut self) -> Result<Option<SystemInterrupt>, PppoeError> {
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
            if let Some(ref mut meta) = self.active_session {
                meta.peer_ip = ipcp_res.peer_ip;
            }
            let (interface_name, control_fd, _ebpf_session, _kernel_session) = self
                .setup_dataplane(&session, &disc_res, mac, ifindex, &lcp_res, &ipcp_res)
                .await?;

            self.publish_connected_status(&interface_name, &disc_res, &lcp_res, &ipcp_res);

            info!(
                interface = %interface_name,
                dataplane = ?self.cfg.dataplane,
                ipv4 = ?ipcp_res.local_ip,
                peer = ?ipcp_res.peer_ip,
                dns_count = ipcp_res.dns.len(),
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
            Ok(Some(SystemInterrupt::Shutdown) | None) => "Graceful shutdown".to_string(),
            Ok(Some(SystemInterrupt::Stop)) => "Service control Stop".to_string(),
            Ok(Some(SystemInterrupt::Restart)) => "Service control Restart".to_string(),
            Err(e) => e.to_string(),
        };

        self.teardown_active_session(reason).await;

        flow_res
    }
}

impl LanforgeService for PppoeService {
    fn spec(&self) -> ServiceSpec {
        ServiceSpec {
            id: Self::SERVICE_ID,
            display_name: "PPPoE Client",
            runtime: RuntimeClass::Shared,
            restart: RestartPolicy {
                base_backoff: Duration::from_secs(5),
                max_backoff: Duration::from_secs(10),
                max_retries: 0,
                healthy_uptime: Duration::from_secs(60),
            },
            shutdown_timeout: Duration::from_secs(10),
            deps: PPPOE_DEPS,
            condition: Condition {
                sections: &[lanforge_types::config::ConfigDomain::Pppoe],
                eval: |ctx| {
                    if ctx.get_pppoe_config().is_some_and(|c| c.enabled) {
                        Activation::Active
                    } else {
                        Activation::Dormant(DormantReason::disabled("pppoe.enabled"))
                    }
                },
            },
        }
    }

    fn describe(&self) -> String {
        format!(
            "PPPoE on {} (user: {})",
            self.cfg.wan_iface, self.cfg.username
        )
    }
}

impl AsyncService for PppoeService {
    fn stats(&self, ctx: &LanforgeContext) -> Vec<(Cow<'static, str>, String)> {
        let (state_str, local_ip, ppp_iface, term_str) = ctx.pppoe_status().map_or_else(
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
                        |r| {
                            if r {
                                "reachable".to_string()
                            } else {
                                "unreachable".to_string()
                            }
                        },
                    ),
                )
            },
        );
        vec![
            (Cow::Borrowed("wan_iface"), self.cfg.wan_iface.clone()),
            (Cow::Borrowed("username"), self.cfg.username.clone()),
            (Cow::Borrowed("state"), state_str),
            (Cow::Borrowed("local_ip"), local_ip),
            (Cow::Borrowed("ppp_interface"), ppp_iface),
            (Cow::Borrowed("terminal"), term_str),
            (
                Cow::Borrowed("uptime_secs"),
                self.connected_at
                    .map_or_else(|| "0".to_string(), |t| t.elapsed().as_secs().to_string()),
            ),
            (
                Cow::Borrowed("reconnect_attempts"),
                self.attempt.to_string(),
            ),
        ]
    }

    #[allow(clippy::too_many_lines)]
    async fn serve(&mut self, ctx: &LanforgeContext, h: &ServiceHandle) -> Result<(), CoreError> {
        if let Some(dynamic_cfg) = ctx.get_pppoe_config() {
            self.cfg = dynamic_cfg;
        }

        if !self.cfg.enabled {
            info!("PPPoE service is disabled in configuration.");
            h.dormant(DormantReason::disabled("pppoe.enabled"));
            return Ok(());
        }

        if !self.inert
            && self.cfg.dataplane == PppoeDataplane::Kernel
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
            ctx.set_service_state(Self::SERVICE_ID, ServiceState::Error);
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
            ctx.set_service_state(Self::SERVICE_ID, ServiceState::Error);
            return Ok(());
        }

        'main_loop: loop {
            if !ctx.is_running() {
                break 'main_loop;
            }

            tokio::select! {
                biased;
                cmd = h.next_command() => {
                    match cmd {
                        ServiceCommand::Stop | ServiceCommand::Shutdown => {
                            info!("PPPoE service received stop/shutdown command, exiting serve loop");
                            self.teardown_active_session("Graceful shutdown".into()).await;
                            ctx.set_service_state(Self::SERVICE_ID, ServiceState::Inactive);
                            break 'main_loop;
                        }
                        ServiceCommand::Restart => {
                            info!("PPPoE service received restart command, restarting session");
                            h.request_restart();
                            self.teardown_active_session("Service restarted".into()).await;
                            self.attempt = 0;
                        }
                        _ => {}
                    }
                }
                flow_res = self.run_session_flow() => {
                    match flow_res {
                        Ok(Some(SystemInterrupt::Shutdown)) => {
                            info!("PPPoE service session finished cleanly (daemon shutting down)");
                            ctx.set_service_state(Self::SERVICE_ID, ServiceState::Inactive);
                            break 'main_loop;
                        }
                        Ok(Some(SystemInterrupt::Stop)) => {
                            info!("PPPoE service stopped");
                            ctx.set_service_state(Self::SERVICE_ID, ServiceState::Inactive);
                            break 'main_loop;
                        }
                        Ok(Some(SystemInterrupt::Restart)) => {
                            info!("PPPoE session restart requested, reconnecting");
                            self.attempt = 0;
                        }
                        Ok(None) => {
                            if !ctx.is_running() {
                                info!("PPPoE service session finished cleanly (daemon shutting down)");
                                break 'main_loop;
                            }
                            if let Some(dynamic_cfg) = ctx.get_pppoe_config() {
                                self.cfg = dynamic_cfg;
                            }
                            if !self.cfg.enabled {
                                info!("PPPoE service disabled in config, transitioning to Inactive");
                                h.dormant(DormantReason::disabled("pppoe.enabled"));
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
                                wan_iface = %self.cfg.wan_iface,
                                attempt = self.attempt,
                                error = %e,
                                delay_secs = self.cfg.reconnect_delay_secs,
                                "PPPoE session failed; scheduling reconnection"
                            );

                            if self.attempt >= 3 {
                                h.degraded(DegradedReason::custom("no session"));
                            }

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

                            let mut sys_rx = ctx.bus().subscribe_system();
                            let delay = Duration::from_secs(self.cfg.reconnect_delay_secs);
                            tokio::select! {
                                () = sleep(delay) => {}
                                event_res = sys_rx.recv() => {
                                    if let Ok(timed) = event_res {
                                        match classify_system_event(&timed.event) {
                                            Some(SystemInterrupt::Shutdown) => {
                                                info!("PPPoE service received shutdown during reconnect delay");
                                                ctx.set_service_state(Self::SERVICE_ID, ServiceState::Inactive);
                                                break 'main_loop;
                                            }
                                            Some(SystemInterrupt::Stop) => {
                                                info!("PPPoE service received stop during reconnect delay");
                                                ctx.set_service_state(Self::SERVICE_ID, ServiceState::Inactive);
                                                break 'main_loop;
                                            }
                                            Some(SystemInterrupt::Restart) => {
                                                info!("PPPoE service received restart during reconnect delay, retrying immediately");
                                                self.attempt = 0;
                                            }
                                            None => {}
                                        }
                                    }
                                }
                                delta_opt = self.config_sub.next() => {
                                    if let Some(delta) = delta_opt {
                                        match delta.impact {
                                            ChangeImpact::Hot => {
                                                info!("PPPoE service received hot config update during reconnect delay");
                                                self.apply_hot_config(&delta.new);
                                            }
                                            ChangeImpact::Reconnect | ChangeImpact::Rebind => {
                                                info!("PPPoE service received reconnect config update during reconnect delay, retrying immediately");
                                                self.cfg = (*delta.new).clone();
                                                if !self.cfg.enabled {
                                                    ctx.set_service_state(Self::SERVICE_ID, ServiceState::Inactive);
                                                    break 'main_loop;
                                                }
                                                self.attempt = 0;
                                            }
                                            ChangeImpact::None => {}
                                        }
                                    }
                                }
                                cmd = h.next_command() => {
                                    match cmd {
                                        ServiceCommand::Stop | ServiceCommand::Shutdown => {
                                            info!("PPPoE service received stop/shutdown during reconnect delay");
                                            ctx.set_service_state(Self::SERVICE_ID, ServiceState::Inactive);
                                            break 'main_loop;
                                        }
                                        ServiceCommand::Restart => {
                                            info!("PPPoE service received restart during reconnect delay, retrying immediately");
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

        Ok(())
    }

    async fn cleanup(&mut self, _ctx: &LanforgeContext) -> Result<(), CoreError> {
        self.teardown_active_session("Service stopped or shut down".to_string())
            .await;
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
