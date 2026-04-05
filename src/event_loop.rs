use crate::app::{run_scan, sd_notify_ready};
use anyhow::Result;
use lanforge_core::bus::LanforgeEvent;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, interval};
use tracing::{debug, error, info, warn};

use crate::bootstrap::BootstrapResult;

pub async fn run_event_loop(
    bootstrap: BootstrapResult,
    mut bus_rx: tokio::sync::broadcast::Receiver<lanforge_core::bus::TimedEvent>,
) -> Result<()> {
    let cfg = bootstrap.cfg;
    let bus = bootstrap.bus;
    let table = bootstrap.table;
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
    spawn_scan(cfg.clone(), handle.clone(), None, None, target_ifindex);

    let expected_services = determine_expected_services(&cfg);
    let mut ready_services = HashSet::new();
    let mut system_ready_sent = false;

    loop {
        tokio::select! {
            _ = fallback.tick() => {
                debug!("Sincronização periódica de SLAAC (Fallback)...");
                spawn_scan(cfg.clone(), handle.clone(), state.current_gua, state.current_ula, target_ifindex);
            }
            _ = stale_timer.tick() => {
                if table.write().expire_stale() {
                    let _ = bus.publish(LanforgeEvent::DeviceTableDirty);
                }
            }
            _ = sigusr1.recv() => {
                info!("SIGUSR1 recebido, forçando sincronização de estado...");
                spawn_scan(cfg.clone(), handle.clone(), state.current_gua, state.current_ula, target_ifindex);
            }
            _ = sigterm.recv() => {
                info!("SIGTERM recebido — iniciando encerramento gracioso...");
                break;
            }
            _ = sigint.recv() => {
                info!("SIGINT recebido — iniciando encerramento gracioso...");
                break;
            }
            event = bus_rx.recv() => {
                match event {
                    Ok(timed_event) => {
                        match timed_event.event {
                            LanforgeEvent::ServiceReady { name } => {
                                if expected_services.contains(name.as_str()) {
                                    ready_services.insert(name.clone());
                                    debug!("ServiceReady: {} ({}/{})", name, ready_services.len(), expected_services.len());

                                    if !system_ready_sent && ready_services.len() >= expected_services.len() {
                                        info!("✅ All internal services ready. System fully operational.");
                                        let _ = bus.publish(LanforgeEvent::SystemReady);
                                        sd_notify_ready();
                                        system_ready_sent = true;
                                    }
                                }
                            }
                            LanforgeEvent::PrefixChanged { gua, ula, .. } => {
                                if state.current_gua != gua || state.current_ula != ula {
                                    info!("IPv6 Prefix update (Event): GUA={:?}, ULA={:?}", gua, ula);
                                    state.current_gua = gua;
                                    state.current_ula = ula;
                                    spawn_scan(cfg.clone(), handle.clone(), gua, ula, target_ifindex);
                                }
                            }
                            LanforgeEvent::ReloadConfig => {
                                info!("ReloadConfig: Forçando sincronização em background...");
                                spawn_scan(cfg.clone(), handle.clone(), state.current_gua, state.current_ula, target_ifindex);
                            }
                            LanforgeEvent::Shutdown => {
                                debug!("EventLoop: shutdown received via bus");
                                break;
                            }
                            _ => {}
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("EventBus: consumer atrasado, perdeu {n} eventos");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        error!("EventBus: canal fechado inesperadamente");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
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

fn determine_expected_services(cfg: &crate::config::Config) -> HashSet<&'static str> {
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
    cfg: Arc<crate::config::Config>,
    handle: rtnetlink::Handle,
    gua: Option<Ipv6Addr>,
    ula: Option<Ipv6Addr>,
    target_ifindex: u32,
) {
    tokio::spawn(async move {
        if let Err(e) = run_scan(&cfg, &handle, gua, ula, target_ifindex).await {
            error!("❌ Erro no scan: {e:#}");
        }
    });
}
