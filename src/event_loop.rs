use crate::app::sd_notify_ready;
use crate::config::Config;

use anyhow::Result;
use lanforge_core::bus::{LanforgeEvent, TimedEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_network::wol::send_wol_magic_packet;

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::{Duration, interval};
use tracing::{debug, error, info, warn};

use crate::bootstrap::BootstrapResult;

pub async fn run_event_loop(
    bootstrap: BootstrapResult,
    ctx: LanforgeContext,
    mut bus_rx: Receiver<TimedEvent>,
) -> Result<()> {
    let cfg = bootstrap.cfg;
    let target_ifindex = bootstrap.target_ifindex;

    let if_state = ctx.get_interface_state(target_ifindex);
    let mut state = LoopState::new(if_state.gua, if_state.ula);

    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    let stale_interval = Duration::from_secs(120);
    let mut stale_timer = interval(stale_interval);
    stale_timer.tick().await;

    // Initial scan request to kick off discovery across all services
    let _ = ctx.bus().publish(LanforgeEvent::NeighborScanRequested);

    let expected_services = determine_expected_services(&cfg);
    let mut loop_ctx = LoopContext {
        ctx: &ctx,
        cfg: &cfg,
        state: &mut state,
        target_ifindex,
        expected_services: &expected_services,
        ready_services: HashSet::new(),
        system_ready_sent: false,
    };

    loop {
        tokio::select! {
            _ = stale_timer.tick() => {
                ctx.expire_stale(stale_interval);
            }
            _ = sigusr1.recv() => {
                info!("SIGUSR1 received, forcing state synchronization...");
                let _ = ctx.bus().publish(LanforgeEvent::NeighborScanRequested);
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received — starting graceful shutdown...");
                break;
            }
            _ = sigint.recv() => {
                info!("SIGINT received — starting graceful shutdown...");
                break;
            }
            event = bus_rx.recv() => {
                match event {
                    Ok(timed_event) => {
                        if !handle_bus_event(timed_event.event, &mut loop_ctx) {
                            break;
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        warn!("EventBus: consumer lagged, lost {n} events");
                    }
                    Err(RecvError::Closed) => {
                        error!("EventBus: channel closed unexpectedly");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

struct LoopContext<'a> {
    ctx: &'a LanforgeContext,
    cfg: &'a Arc<Config>,
    state: &'a mut LoopState,
    target_ifindex: u32,
    expected_services: &'a HashSet<&'static str>,
    ready_services: HashSet<String>,
    system_ready_sent: bool,
}

fn handle_bus_event(event: LanforgeEvent, l_ctx: &mut LoopContext) -> bool {
    match event {
        LanforgeEvent::ServiceReady { name } if l_ctx.expected_services.contains(name.as_str()) => {
            l_ctx.ready_services.insert(name.clone());
            debug!(
                "ServiceReady: {} ({}/{})",
                name,
                l_ctx.ready_services.len(),
                l_ctx.expected_services.len()
            );

            if !l_ctx.system_ready_sent
                && l_ctx.ready_services.len() >= l_ctx.expected_services.len()
            {
                info!("✅ All internal services ready. System fully operational.");
                let _ = l_ctx.ctx.bus().publish(LanforgeEvent::SystemReady);
                sd_notify_ready();
                l_ctx.system_ready_sent = true;
            }
        }
        LanforgeEvent::PrefixChanged { gua, ula, .. }
            if (l_ctx.state.current_gua != gua || l_ctx.state.current_ula != ula) =>
        {
            info!("IPv6 Prefix update (Event): GUA={:?}, ULA={:?}", gua, ula);
            l_ctx.state.current_gua = gua;
            l_ctx.state.current_ula = ula;
            let _ = l_ctx
                .ctx
                .bus()
                .publish(LanforgeEvent::NeighborScanRequested);
        }
        LanforgeEvent::ReloadConfig => {
            info!("ReloadConfig: Forcing background synchronization...");
            let _ = l_ctx
                .ctx
                .bus()
                .publish(LanforgeEvent::NeighborScanRequested);
        }
        LanforgeEvent::WolTriggered { mac, ip_hint } => {
            handle_wol_event(l_ctx, mac, ip_hint);
        }
        LanforgeEvent::DbResetCompleted => {
            handle_db_reset(l_ctx);
        }
        LanforgeEvent::ConfigUpdate { password_hash } => {
            let hash_path = l_ctx.cfg.get_password_hash_path();
            info!("ConfigUpdate: Saving new API password hash to {:?}...", hash_path);
            
            if let Err(e) = std::fs::write(&hash_path, password_hash) {
                error!("❌ Failed to save password hash: {e}");
            } else {
                info!("✅ Configuration updated and saved to {:?}", hash_path);
            }
        }
        LanforgeEvent::Shutdown => {
            debug!("EventLoop: shutdown received via bus");
            return false;
        }
        _ => {}
    }
    true
}

fn handle_wol_event(
    l_ctx: &LoopContext,
    mac: lanforge_core::identifiers::MacAddr,
    ip_hint: Option<Ipv4Addr>,
) {
    info!("WOL: Triggering for {mac} (hint: {ip_hint:?})");
    let mut directed_broadcast = None;

    {
        let ctx_read = l_ctx.ctx.read();
        if let Some(if_ips) = ctx_read.interface_ips.get(&l_ctx.target_ifindex)
            && let Some((ip, prefix)) = if_ips.v4
        {
            let ip_u32 = u32::from_be_bytes(ip.octets());
            let mask = !((1u32.checked_shl(32 - u32::from(prefix))).map_or(0, |v| v - 1));
            let broadcast = ip_u32 | !mask;
            directed_broadcast = Some(Ipv4Addr::from(broadcast.to_be_bytes()));
        }
    }

    if let Err(e) = send_wol_magic_packet(mac, &l_ctx.cfg.iface_lan, directed_broadcast, ip_hint) {
        error!("❌ Error sending WOL packet: {e}");
    } else {
        info!(
            "✅ Magic packet sent (targets: 255.255.255.255, {directed_broadcast:?}, {ip_hint:?})"
        );
    }
}

fn handle_db_reset(l_ctx: &LoopContext) {
    info!("Database reset confirmed. Performing state refresh...");
    l_ctx.ctx.reset();

    // Reload static devices from config
    let mut state = l_ctx.ctx.write();
    crate::bootstrap::Bootstrapper::reload_static_devices_into_state(&mut state, l_ctx.cfg);
    drop(state);

    info!("State re-seeded with static devices. Triggering new discovery scan...");
    let _ = l_ctx
        .ctx
        .bus()
        .publish(LanforgeEvent::NeighborScanRequested);
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

fn determine_expected_services(cfg: &Config) -> HashSet<&'static str> {
    let mut services =
        HashSet::from(["db", "mdns", "monitor", "ifmon", "control", "slaac_tracker"]);
    if cfg.ra_enabled {
        services.insert("ra");
    }
    if cfg.dhcpv4_enabled {
        services.insert("dhcpv4");
    }
    if cfg.dhcpv6_enabled {
        services.insert("dhcpv6");
    }
    if cfg.dns_enabled {
        services.insert("dns");
    }
    if cfg.http_listen.is_some() {
        services.insert("http");
    }
    services
}
