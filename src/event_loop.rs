use anyhow::Result;
use lanforge_core::bus::LanforgeEvent;
use std::collections::HashSet;
use std::net::Ipv6Addr;
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

    let mut current_gua: Option<Ipv6Addr> = None;
    let mut current_ula: Option<Ipv6Addr> = None;

    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    let mut fallback = interval(Duration::from_secs(cfg.fallback_mins * 60));
    fallback.tick().await;

    let mut stale_timer = interval(Duration::from_secs(600));
    stale_timer.tick().await;

    // Initial scan
    let b_cfg = cfg.clone();
    let b_handle = handle.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::run_scan(&b_cfg, &b_handle, None, None, target_ifindex).await {
            error!("❌ Erro no scan inicial: {e:#}");
        }
    });

    let mut expected_services = HashSet::from(["db", "mdns", "monitor", "ifmon", "control"]);
    if cfg.ra_enabled {
        expected_services.insert("ra");
    }
    if cfg.dhcpv4_enabled {
        expected_services.insert("dhcpv4");
    }
    if cfg.dhcpv6_enabled {
        expected_services.insert("dhcpv6");
    }
    if cfg.dns_enabled {
        expected_services.insert("dns");
    }
    if cfg.http_listen.is_some() {
        expected_services.insert("http");
    }

    let mut ready_services = HashSet::new();
    let mut system_ready_sent = false;

    loop {
        tokio::select! {
            _ = fallback.tick() => {
                debug!("Sincronização periódica de SLAAC (Fallback)...");
                let b_cfg = cfg.clone();
                let b_handle = handle.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::run_scan(&b_cfg, &b_handle, current_gua, current_ula, target_ifindex).await {
                        error!("Erro no fallback scan: {e:#}");
                    }
                });
            }
            _ = stale_timer.tick() => {
                let changed = table.write().expire_stale();
                if changed {
                    let _ = bus.publish(LanforgeEvent::DeviceTableDirty);
                }
            }
            _ = sigusr1.recv() => {
                info!("SIGUSR1 recebido, forçando sincronização de estado...");
                let b_cfg = cfg.clone();
                let b_handle = handle.clone();
                tokio::spawn(async move {
                    if let Err(e) = crate::run_scan(&b_cfg, &b_handle, current_gua, current_ula, target_ifindex).await {
                        error!("Erro na sincronização manual: {e:#}");
                    }
                });
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
                                        crate::sd_notify_ready();
                                        system_ready_sent = true;
                                    }
                                }
                            }
                            LanforgeEvent::PrefixChanged { gua, ula, .. } => {
                                if current_gua != gua || current_ula != ula {
                                    info!("IPv6 Prefix update (Event): GUA={:?}, ULA={:?}", gua, ula);
                                    current_gua = gua;
                                    current_ula = ula;

                                    let cfg = cfg.clone();
                                    let handle = handle.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = crate::run_scan(&cfg, &handle, gua, ula, target_ifindex).await {
                                            error!("Erro ao atualizar prefixo (GUA={:?}, ULA={:?}): {e:#}", gua, ula);
                                        }
                                    });
                                }
                            }
                            LanforgeEvent::ReloadConfig => {
                                info!("ReloadConfig: Forçando sincronização em background...");
                                let cfg = cfg.clone();
                                let handle = handle.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = crate::run_scan(&cfg, &handle, current_gua, current_ula, target_ifindex).await {
                                        error!("Erro no reload scan: {e:#}");
                                    }
                                });
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
