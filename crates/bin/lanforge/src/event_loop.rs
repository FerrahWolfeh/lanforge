use crate::app::sd_notify_ready;
use crate::config::Config;

use anyhow::Result;
use lanforge_core::bus::{LanforgeEvent, NetworkEvent, StorageEvent, SystemEvent, TimedEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_db::{LanforgeDb, RaConfigStore};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::system::ServiceState;
use lanforge_wol::wol::send_wol_magic_packet;

use std::collections::HashSet;
use std::hash::BuildHasher;
use std::net::{Ipv4Addr, Ipv6Addr};
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

#[allow(clippy::too_many_lines)]
pub async fn run_event_loop<S>(
    bootstrap: BootstrapResult,
    ctx: LanforgeContext,
    mut sys_rx: Receiver<TimedEvent>,
    mut net_rx: Receiver<TimedEvent>,
    mut sto_rx: Receiver<TimedEvent>,
    expected_services: HashSet<String, S>,
) -> Result<LoopResult>
where
    S: BuildHasher + Clone + Send + 'static,
{
    let cfg = bootstrap.cfg;
    let target_ifindex = bootstrap.target_ifindex;

    let if_state = ctx.get_interface_state(target_ifindex);
    let mut state = LoopState::new(if_state.gua, if_state.ula);

    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    let stale_check_interval = Duration::from_secs(30);
    let mut stale_timer = interval(stale_check_interval);
    stale_timer.tick().await;

    let mut expected_sorted: Vec<_> = expected_services.iter().cloned().collect();
    expected_sorted.sort();
    info!(
        "Event loop: expecting readiness from {} services: {:?}",
        expected_sorted.len(),
        expected_sorted
    );

    let mut loop_ctx = LoopContext {
        ctx: &ctx,
        cfg: &cfg,
        db: &bootstrap.db,
        state: &mut state,
        target_ifindex,
        ready_services: HashSet::with_hasher(expected_services.hasher().clone()),
        expected_services,
        system_ready_sent: false,
    };

    // Pre-seed any services that already signaled ready in context before subscription
    for s in &loop_ctx.expected_services {
        if ctx.get_service_state(s) == ServiceState::Online && loop_ctx.ready_services.insert(s.clone()) {
            debug!(
                "Service '{}' pre-seeded online ({}/{})",
                s,
                loop_ctx.ready_services.len(),
                loop_ctx.expected_services.len()
            );
        }
    }

    if !loop_ctx.system_ready_sent
        && loop_ctx.ready_services.len() >= loop_ctx.expected_services.len()
    {
        let mut services: Vec<_> = loop_ctx.expected_services.iter().cloned().collect();
        services.sort();
        info!(
            "All {} internal services online ({}). System fully operational.",
            services.len(),
            services.join(", ")
        );
        crate::bootstrap::Bootstrapper::print_startup_banner(
            loop_ctx.cfg,
            loop_ctx.target_ifindex,
            loop_ctx.db,
        )
        .await;
        let _ = loop_ctx
            .ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::SystemReady));
        let status = format!(
            "Operational ({} services online on {})",
            loop_ctx.expected_services.len(),
            loop_ctx.cfg.system.iface
        );
        sd_notify_ready(&status);
        loop_ctx.system_ready_sent = true;
    }

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
                if !loop_ctx.system_ready_sent {
                    let mut missing = Vec::new();
                    for s in &loop_ctx.expected_services {
                        if !loop_ctx.ready_services.contains(s) {
                            missing.push(s);
                        }
                    }
                    if !missing.is_empty() {
                        missing.sort();
                        warn!("⌛ Still waiting for {} services to be ready: {:?}", missing.len(), missing);
                    }
                }
            }
            event = sys_rx.recv() => {
                match event {
                    Ok(timed_event) => {
                        if let Some(res) = handle_bus_event(timed_event.event, &mut loop_ctx) {
                            break res;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        warn!("EventBus (system): consumer lagged, lost {n} events");
                    }
                    Err(RecvError::Closed) => {
                        error!("EventBus (system): channel closed unexpectedly");
                        break LoopResult::Shutdown;
                    }
                }
            }
            event = net_rx.recv() => {
                match event {
                    Ok(timed_event) => {
                        if let Some(res) = handle_bus_event(timed_event.event, &mut loop_ctx) {
                            break res;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        warn!("EventBus (network): consumer lagged, lost {n} events");
                    }
                    Err(RecvError::Closed) => {
                        error!("EventBus (network): channel closed unexpectedly");
                        break LoopResult::Shutdown;
                    }
                }
            }
            event = sto_rx.recv() => {
                match event {
                    Ok(timed_event) => {
                        if let Some(res) = handle_bus_event(timed_event.event, &mut loop_ctx) {
                            break res;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        warn!("EventBus (storage): consumer lagged, lost {n} events");
                    }
                    Err(RecvError::Closed) => {
                        error!("EventBus (storage): channel closed unexpectedly");
                        break LoopResult::Shutdown;
                    }
                }
            }
        }
    };

    Ok(result)
}

struct LoopContext<'a, S> {
    ctx: &'a LanforgeContext,
    cfg: &'a Arc<Config>,
    db: &'a Arc<LanforgeDb>,
    state: &'a mut LoopState,
    target_ifindex: u32,
    expected_services: HashSet<String, S>,
    ready_services: HashSet<String, S>,
    system_ready_sent: bool,
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
            debug!(
                "Service '{}' reported ready ({}/{})",
                name,
                l_ctx.ready_services.len(),
                l_ctx.expected_services.len()
            );

            if !l_ctx.system_ready_sent
                && l_ctx.ready_services.len() >= l_ctx.expected_services.len()
            {
                let mut services: Vec<_> = l_ctx.expected_services.iter().cloned().collect();
                services.sort();
                info!(
                    "All {} internal services online ({}). System fully operational.",
                    services.len(),
                    services.join(", ")
                );
                let cfg = l_ctx.cfg.clone();
                let db = l_ctx.db.clone();
                let ifindex = l_ctx.target_ifindex;
                tokio::spawn(async move {
                    crate::bootstrap::Bootstrapper::print_startup_banner(&cfg, ifindex, &db).await;
                });
                let _ = l_ctx
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::System(SystemEvent::SystemReady));
                let status = format!(
                    "Operational ({} services online on {})",
                    l_ctx.expected_services.len(),
                    l_ctx.cfg.system.iface
                );
                sd_notify_ready(&status);
                l_ctx.system_ready_sent = true;
            }
        }
        LanforgeEvent::Network(NetworkEvent::PrefixChanged(details))
            if (l_ctx.state.current_gua != details.gua || l_ctx.state.current_ula != details.ula) =>
        {
            info!("IPv6 Prefix update (Event): GUA={:?}, ULA={:?}", details.gua, details.ula);
            l_ctx.state.current_gua = details.gua;
            l_ctx.state.current_ula = details.ula;
            let db = l_ctx.db.clone();
            let new_gua = details.gua;
            tokio::spawn(async move {
                if let Err(e) = db.save_last_gua_prefix(new_gua).await {
                    warn!("Failed to persist last_gua_prefix to DB: {e}");
                }
            });
        }
        LanforgeEvent::System(SystemEvent::ReloadConfig) => {
            info!("ReloadConfig: Initiating soft-reboot...");
            return Some(LoopResult::Reload);
        }
        LanforgeEvent::Network(NetworkEvent::WolTriggered { mac, ip_hint }) => {
            handle_wol_event(l_ctx, mac, ip_hint);
        }
        LanforgeEvent::Storage(StorageEvent::DbResetCompleted) => {
            handle_db_reset(l_ctx);
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
    let mut directed_broadcast = None;

    {
        let ctx_read = l_ctx.ctx.read();
        if let Some(if_ips) = ctx_read.interfaces.interface_ips.get(&l_ctx.target_ifindex)
            && let Some((ip, prefix)) = if_ips.v4
        {
            let ip_u32 = u32::from_be_bytes(ip.octets());
            let mask = !((1u32.checked_shl(32 - u32::from(prefix))).map_or(0, |v| v - 1));
            let broadcast = ip_u32 | !mask;
            directed_broadcast = Some(Ipv4Addr::from(broadcast.to_be_bytes()));
        }
    }

    if let Err(e) = send_wol_magic_packet(mac, &l_ctx.cfg.system.iface, directed_broadcast, ip_hint)
    {
        error!("❌ Error sending WOL packet: {e}");
    } else {
        info!(
            "✅ Magic packet sent (targets: 255.255.255.255, {directed_broadcast:?}, {ip_hint:?})"
        );
    }
}

fn handle_db_reset<S: BuildHasher>(l_ctx: &LoopContext<'_, S>) {
    info!("Database reset confirmed. Performing state refresh...");
    l_ctx.ctx.reset();
}

struct LoopState {
    current_gua: Option<Ipv6Addr>,
    current_ula: Option<Ipv6Addr>,
}

impl LoopState {
    pub const fn new(gua: Option<Ipv6Addr>, ula: Option<Ipv6Addr>) -> Self {
        Self {
            current_gua: gua,
            current_ula: ula,
        }
    }
}
