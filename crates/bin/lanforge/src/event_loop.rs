use crate::app::sd_notify_ready;
use crate::config::Config;

use anyhow::Result;
use lanforge_core::bus::{LanforgeEvent, NetworkEvent, SystemEvent, TimedEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_db::LanforgeDb;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::system::ServiceState;
use lanforge_wol::wol::send_wol_magic_packet;

use std::collections::HashSet;
use std::hash::BuildHasher;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::broadcast::{Receiver, error::RecvError};
use tokio::time::{Duration, interval};
use tracing::{debug, error, info, warn};

use crate::bootstrap::BootstrapResult;

#[derive(Debug, PartialEq, Eq)]
pub enum LoopResult {
    /// The system should perform a soft-reboot (reload config and restart services).
    Reload,
    /// The system should shut down gracefully.
    Shutdown,
}

macro_rules! handle_bus_recv {
    ($event:expr, $topic:literal, $l_ctx:expr) => {
        match $event {
            Ok(timed_event) => {
                if let Some(res) = handle_bus_event(timed_event.event, $l_ctx) {
                    break res;
                }
            }
            Err(RecvError::Lagged(n)) => {
                warn!("EventBus ({}): consumer lagged, lost {n} events", $topic);
            }
            Err(RecvError::Closed) => {
                error!("EventBus ({}): channel closed unexpectedly", $topic);
                break LoopResult::Shutdown;
            }
        }
    };
}

pub async fn run_event_loop<S>(
    bootstrap: BootstrapResult,
    ctx: LanforgeContext,
    mut sys_rx: Receiver<TimedEvent>,
    mut net_rx: Receiver<TimedEvent>,
    expected_services: HashSet<String, S>,
) -> Result<LoopResult>
where
    S: BuildHasher + Clone + Send + 'static,
{
    let cfg = bootstrap.cfg;
    let target_ifindex = bootstrap.target_ifindex;

    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    let stale_check_interval = Duration::from_secs(30);
    let mut stale_timer = interval(stale_check_interval);
    stale_timer.tick().await;

    let mut expected_sorted: Vec<_> = expected_services.iter().map(String::as_str).collect();
    expected_sorted.sort_unstable();
    info!(
        "Event loop: expecting readiness from {} services: {:?}",
        expected_sorted.len(),
        expected_sorted
    );

    let mut loop_ctx = LoopContext {
        ctx: &ctx,
        cfg: &cfg,
        db: &bootstrap.db,
        target_ifindex,
        ready_services: HashSet::with_hasher(expected_services.hasher().clone()),
        expected_services,
        system_ready_sent: false,
    };

    // Pre-seed any services that already settled in context before subscription
    for s in &loop_ctx.expected_services {
        let st = ctx.get_service_state(s);
        if is_settled_state(st) && loop_ctx.ready_services.insert(s.clone()) {
            debug!(
                "Service '{}' pre-seeded settled ({:?}) ({}/{})",
                s,
                st,
                loop_ctx.ready_services.len(),
                loop_ctx.expected_services.len()
            );
        }
    }

    loop_ctx.try_emit_system_ready();

    let mut status_timer = interval(Duration::from_secs(10));
    status_timer.tick().await; // skip first tick

    let result = loop {
        tokio::select! {
            _ = stale_timer.tick() => {
                #[cfg(feature = "discovery")]
                ctx.expire_stale(Duration::from_secs(cfg.monitor_toml.stale_timeout_secs));
            }
            _ = sigusr1.recv() => {
                info!("SIGUSR1 received");
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received — starting graceful shutdown...");
                break LoopResult::Shutdown;
            }
            _ = sigint.recv() => {
                info!("SIGINT received — starting graceful shutdown...");
                break LoopResult::Shutdown;
            }
            _ = status_timer.tick() => {
                loop_ctx.try_emit_system_ready();
                if !loop_ctx.system_ready_sent {
                    let mut missing: Vec<_> = loop_ctx
                        .expected_services
                        .iter()
                        .filter(|s| !loop_ctx.ready_services.contains(*s))
                        .map(String::as_str)
                        .collect();
                    if !missing.is_empty() {
                        missing.sort_unstable();
                        warn!("⌛ Still waiting for {} services to settle: {:?}", missing.len(), missing);
                    }
                }
            }
            event = sys_rx.recv() => handle_bus_recv!(event, "system", &mut loop_ctx),
            event = net_rx.recv() => handle_bus_recv!(event, "network", &mut loop_ctx),
        }
    };

    Ok(result)
}

const fn is_settled_state(st: ServiceState) -> bool {
    matches!(
        st,
        ServiceState::Online
            | ServiceState::Degraded
            | ServiceState::Inactive
            | ServiceState::Error
    )
}

struct LoopContext<'a, S> {
    ctx: &'a LanforgeContext,
    cfg: &'a Arc<Config>,
    db: &'a Arc<LanforgeDb>,
    target_ifindex: u32,
    expected_services: HashSet<String, S>,
    ready_services: HashSet<String, S>,
    system_ready_sent: bool,
}

impl<S: BuildHasher> LoopContext<'_, S> {
    fn try_emit_system_ready(&mut self) {
        if self.system_ready_sent {
            return;
        }

        // Reconcile any services that settled in state
        for s in &self.expected_services {
            let st = self.ctx.get_service_state(s);
            if is_settled_state(st) {
                self.ready_services.insert(s.clone());
            }
        }

        if self.ready_services.len() < self.expected_services.len() {
            return;
        }

        let mut services: Vec<_> = self.expected_services.iter().map(String::as_str).collect();
        services.sort_unstable();

        let mut non_online = Vec::new();
        for s in &services {
            let st = self.ctx.get_service_state(s);
            if st != ServiceState::Online {
                let detail_str = self
                    .ctx
                    .get_service_detail(s)
                    .map(|d| format!(": {d}"))
                    .unwrap_or_default();
                non_online.push(format!("{s} ({st}{detail_str})"));
            }
        }

        if non_online.is_empty() {
            info!(
                "All {} internal services online ({}). System fully operational.",
                services.len(),
                services.join(", ")
            );
        } else {
            warn!(
                "System ready with {}/{} services online. Non-online: {}",
                services.len() - non_online.len(),
                services.len(),
                non_online.join(", ")
            );
        }

        crate::bootstrap::Bootstrapper::print_startup_banner(self.cfg, self.target_ifindex, self.db);
        let _ = self
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::SystemReady));
        let status = format!(
            "Operational ({} services settled on {})",
            self.expected_services.len(),
            self.cfg.system.iface
        );
        sd_notify_ready(&status);
        self.system_ready_sent = true;
    }
}

fn handle_bus_event<S: BuildHasher>(
    event: LanforgeEvent,
    l_ctx: &mut LoopContext<'_, S>,
) -> Option<LoopResult> {
    match event {
        LanforgeEvent::System(SystemEvent::ServiceReady { name })
            if l_ctx.expected_services.contains(&name)
                && l_ctx.ready_services.insert(name.clone()) =>
        {
            if l_ctx.ctx.get_service_state(&name) == ServiceState::Starting {
                l_ctx.ctx.set_service_state(&name, ServiceState::Online);
            }
            debug!(
                "Service '{}' reported ready ({}/{})",
                name,
                l_ctx.ready_services.len(),
                l_ctx.expected_services.len()
            );

            l_ctx.try_emit_system_ready();
        }
        LanforgeEvent::System(SystemEvent::ReloadConfig) => {
            info!("ReloadConfig: Initiating soft-reboot...");
            return Some(LoopResult::Reload);
        }
        LanforgeEvent::Network(NetworkEvent::WolTriggered { mac, ip_hint }) => {
            handle_wol_event(l_ctx, mac, ip_hint);
        }
        LanforgeEvent::System(SystemEvent::ConfigUpdate { password_hash }) => {
            let hash_path = l_ctx.cfg.get_password_hash_path();
            info!(
                "ConfigUpdate: Saving new API password hash to {:?}...",
                hash_path
            );

            if let Err(e) = std::fs::write(&hash_path, password_hash) {
                error!("❌ Failed to save password hash: {e}");
            } else {
                info!("✅ Configuration updated and saved to {:?}", hash_path);
            }
        }
        LanforgeEvent::System(SystemEvent::Shutdown) => {
            debug!("EventLoop: shutdown received via bus");
            return Some(LoopResult::Shutdown);
        }
        _ => {}
    }
    None
}

fn handle_wol_event<S: BuildHasher>(
    l_ctx: &LoopContext<'_, S>,
    mac: MacAddr,
    ip_hint: Option<Ipv4Addr>,
) {
    info!("WOL: Triggering for {mac} (hint: {ip_hint:?})");
    let directed_broadcast = l_ctx.ctx.with_state(|state| {
        state
            .interfaces
            .interface_ips
            .get(&l_ctx.target_ifindex)
            .and_then(|if_ips| if_ips.v4)
            .map(|(ip, prefix)| {
                let ip_u32 = u32::from(ip);
                let mask = !((1u32.checked_shl(32 - u32::from(prefix))).map_or(0, |v| v - 1));
                let broadcast = ip_u32 | !mask;
                Ipv4Addr::from(broadcast)
            })
    });

    if let Err(e) = send_wol_magic_packet(mac, &l_ctx.cfg.system.iface, directed_broadcast, ip_hint)
    {
        error!("❌ Error sending WOL packet: {e}");
    } else {
        info!(
            "✅ Magic packet sent (targets: 255.255.255.255, {directed_broadcast:?}, {ip_hint:?})"
        );
    }
}
