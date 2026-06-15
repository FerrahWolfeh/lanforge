use crate::app::sd_notify_ready;
use crate::config::Config;

use anyhow::Result;
use lanforge_core::bus::{LanforgeEvent, NetworkEvent, StorageEvent, SystemEvent, TimedEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_types::identifiers::MacAddr;
use lanforge_wol::wol::send_wol_magic_packet;

use std::collections::HashSet;
use std::hash::BuildHasher;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;
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

pub async fn run_event_loop<S>(
    bootstrap: BootstrapResult,
    ctx: LanforgeContext,
    mut bus_rx: Receiver<TimedEvent>,
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

    // Initial scan request to kick off discovery across all services
    let _ = ctx
        .bus()
        .publish(LanforgeEvent::Network(NetworkEvent::NeighborScanRequested));

    info!(
        "Event loop: expecting readiness from {} services: {:?}",
        expected_services.len(),
        expected_services
    );

    let mut loop_ctx = LoopContext {
        ctx: &ctx,
        cfg: &cfg,
        state: &mut state,
        target_ifindex,
        ready_services: HashSet::with_hasher(expected_services.hasher().clone()),
        expected_services,
        system_ready_sent: false,
    };

    let mut status_timer = interval(Duration::from_secs(10));
    status_timer.tick().await; // skip first tick

    let result = loop {
        tokio::select! {
            _ = stale_timer.tick() => {
                #[cfg(feature = "discovery")]
                ctx.expire_stale(Duration::from_secs(cfg.monitor_toml.stale_timeout_secs));
            }
            _ = sigusr1.recv() => {
                info!("SIGUSR1 received, forcing state synchronization...");
                let _ = ctx.bus().publish(LanforgeEvent::Network(NetworkEvent::NeighborScanRequested));
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
                        warn!("⌛ Still waiting for {} services to be ready: {:?}", missing.len(), missing);
                    }
                }
            }
            event = bus_rx.recv() => {
                match event {
                    Ok(timed_event) => {
                        if let Some(res) = handle_bus_event(timed_event.event, &mut loop_ctx) {
                            break res;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        warn!("EventBus: consumer lagged, lost {n} events");
                    }
                    Err(RecvError::Closed) => {
                        error!("EventBus: channel closed unexpectedly");
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
            info!(
                "▸ Service '{}' reported ready ({}/{})",
                name,
                l_ctx.ready_services.len(),
                l_ctx.expected_services.len()
            );

            if !l_ctx.system_ready_sent
                && l_ctx.ready_services.len() >= l_ctx.expected_services.len()
            {
                info!("✅ All internal services ready. System fully operational.");
                let _ = l_ctx
                    .ctx
                    .bus()
                    .publish(LanforgeEvent::System(SystemEvent::SystemReady));
                sd_notify_ready();
                l_ctx.system_ready_sent = true;
            }
        }
        LanforgeEvent::Network(NetworkEvent::PrefixChanged { gua, ula, .. })
            if (l_ctx.state.current_gua != gua || l_ctx.state.current_ula != ula) =>
        {
            info!("IPv6 Prefix update (Event): GUA={:?}, ULA={:?}", gua, ula);
            l_ctx.state.current_gua = gua;
            l_ctx.state.current_ula = ula;
            let _ = l_ctx
                .ctx
                .bus()
                .publish(LanforgeEvent::Network(NetworkEvent::NeighborScanRequested));
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

    info!("State cleared. Triggering new discovery scan...");
    let _ = l_ctx
        .ctx
        .bus()
        .publish(LanforgeEvent::Network(NetworkEvent::NeighborScanRequested));
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
