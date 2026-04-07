use crate::app::{run_scan, sd_notify_ready};
use crate::config::Config;
use anyhow::Result;
use lanforge_core::bus::{LanforgeEvent, TimedEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_network::wol::send_wol_magic_packet;
use rtnetlink::Handle;
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
    let handle = bootstrap.rt_handle;
    let target_ifindex = bootstrap.target_ifindex;

    let mut state = LoopState::new();

    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    let mut fallback = interval(Duration::from_secs(cfg.fallback_mins * 60));
    fallback.tick().await;

    let mut stale_timer = interval(Duration::from_secs(600));
    stale_timer.tick().await;

    // Initial scan
    spawn_scan(
        ctx.clone(),
        cfg.clone(),
        handle.clone(),
        None,
        None,
        target_ifindex,
    );

    let expected_services = determine_expected_services(&cfg);
    let mut ready_services = HashSet::new();
    let mut system_ready_sent = false;

    loop {
        tokio::select! {
            _ = fallback.tick() => {
                debug!("Periodic SLAAC synchronization (Fallback)...");
            }
            _ = stale_timer.tick() => {
                ctx.expire_stale();
            }
            _ = sigusr1.recv() => {
                info!("SIGUSR1 received, forcing state synchronization...");
                spawn_scan(ctx.clone(), cfg.clone(), handle.clone(), state.current_gua, state.current_ula, target_ifindex);
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
                        if !handle_bus_event(
                            timed_event.event,
                            &ctx,
                            &cfg,
                            &handle,
                            &mut state,
                            target_ifindex,
                            &expected_services,
                            &mut ready_services,
                            &mut system_ready_sent
                        ) {
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

#[allow(clippy::too_many_arguments)]
fn handle_bus_event(
    event: LanforgeEvent,
    ctx: &LanforgeContext,
    cfg: &Arc<Config>,
    handle: &Handle,
    state: &mut LoopState,
    target_ifindex: u32,
    expected_services: &HashSet<&'static str>,
    ready_services: &mut HashSet<String>,
    system_ready_sent: &mut bool,
) -> bool {
    match event {
        LanforgeEvent::ServiceReady { name } => {
            if expected_services.contains(name.as_str()) {
                ready_services.insert(name.clone());
                debug!(
                    "ServiceReady: {} ({}/{})",
                    name,
                    ready_services.len(),
                    expected_services.len()
                );

                if !*system_ready_sent && ready_services.len() >= expected_services.len() {
                    info!("✅ All internal services ready. System fully operational.");
                    let _ = ctx.bus().publish(LanforgeEvent::SystemReady);
                    sd_notify_ready();
                    *system_ready_sent = true;
                }
            }
        }
        LanforgeEvent::PrefixChanged { gua, ula, .. } => {
            if state.current_gua != gua || state.current_ula != ula {
                info!("IPv6 Prefix update (Event): GUA={:?}, ULA={:?}", gua, ula);
                state.current_gua = gua;
                state.current_ula = ula;
                spawn_scan(
                    ctx.clone(),
                    cfg.clone(),
                    handle.clone(),
                    gua,
                    ula,
                    target_ifindex,
                );
            }
        }
        LanforgeEvent::ReloadConfig => {
            info!("ReloadConfig: Forcing background synchronization...");
            spawn_scan(
                ctx.clone(),
                cfg.clone(),
                handle.clone(),
                state.current_gua,
                state.current_ula,
                target_ifindex,
            );
        }
        LanforgeEvent::WolTriggered { mac, ip_hint } => {
            info!("WOL: Triggering for {mac} (hint: {ip_hint:?})");
            let mut directed_broadcast = None;

            {
                let ctx_read = ctx.read();
                if let Some(if_ips) = ctx_read.interface_ips.get(&target_ifindex)
                    && let Some((ip, prefix)) = if_ips.v4
                {
                    let ip_u32 = u32::from_be_bytes(ip.octets());
                    // Fix truncation warning by using u32::MAX >> prefix
                    let mask = !((1u32.checked_shl(32 - u32::from(prefix))).map_or(0, |v| v - 1));
                    let broadcast = ip_u32 | !mask;
                    directed_broadcast = Some(Ipv4Addr::from(broadcast.to_be_bytes()));
                }
            }

            if let Err(e) = send_wol_magic_packet(mac, &cfg.iface_lan, directed_broadcast, ip_hint)
            {
                error!("❌ Error sending WOL packet: {e}");
            } else {
                info!(
                    "✅ Magic packet sent (targets: 255.255.255.255, {directed_broadcast:?}, {ip_hint:?})"
                );
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

struct LoopState {
    current_gua: Option<Ipv6Addr>,
    current_ula: Option<Ipv6Addr>,
}

impl LoopState {
    const fn new() -> Self {
        Self {
            current_gua: None,
            current_ula: None,
        }
    }
}

fn determine_expected_services(cfg: &Config) -> HashSet<&'static str> {
    let mut services = HashSet::from(["db", "mdns", "monitor", "ifmon", "control"]);
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

fn spawn_scan(
    ctx: LanforgeContext,
    cfg: Arc<Config>,
    handle: Handle,
    gua: Option<Ipv6Addr>,
    ula: Option<Ipv6Addr>,
    target_ifindex: u32,
) {
    tokio::spawn(async move {
        if let Err(e) = run_scan(&ctx, &cfg, &handle, gua, ula, target_ifindex).await {
            error!("❌ Scan error: {e:#}");
        }
    });
}
