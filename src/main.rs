//! `lanforge` — Gerenciador central de identidades de rede (IPv6/IPv4).
mod bootstrap;
mod config;
mod event_loop;
mod registry;
mod supervisor;

use anyhow::Result;
use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use std::net::Ipv6Addr;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use tracing::{debug, info};

use crate::bootstrap::run_bootstrap;
use crate::event_loop::run_event_loop;
use crate::registry::ServiceRegistry;

fn main() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name("lanforge-main")
        .build()?;

    let res = rt.block_on(async_main());

    if let Err(e) = res {
        eprintln!("❌ Erro fatal: {e:#}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

async fn async_main() -> Result<()> {
    // 1. Setup Logging
    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // 2. Run Bootstrap (Config, DB, Netlink, ManagedTable)
    let bootstrap = run_bootstrap().await?;
    let cfg = bootstrap.cfg.clone();
    let bus = bootstrap.bus.clone();
    let target_ifindex = bootstrap.target_ifindex;
    let netlink_handle = bootstrap.rt_handle.clone();
    let messages = bootstrap.messages.clone();

    // 3. Subscribe to bus BEFORE spawning services to capture all ServiceReady events
    let bus_rx = bus.subscribe();

    // 4. Register and Spawn Services
    let mut registry = ServiceRegistry::new();

    // DB Worker (Sync)
    let db_path = std::path::PathBuf::from(&cfg.leases_db);
    let log_db_path = std::path::PathBuf::from(&cfg.log_db);
    registry.spawn_sync(move || {
        lanforge_db::worker::DbWorker::new(db_path.clone(), log_db_path.clone())
    });

    // mDNS Prober (Async)
    registry.spawn_async(lanforge_network::mdns::MdnsProber::new);

    // Interface Monitor (Async)
    let h1 = netlink_handle.clone();
    let m1 = messages.clone();
    registry.spawn_async(move || {
        lanforge_network::ifmon::InterfaceMonitor::new(h1.clone(), m1.clone(), target_ifindex)
    });

    // Ndp Monitor (Async)
    let h2 = netlink_handle.clone();
    let m2 = messages.clone();
    registry.spawn_async(move || {
        lanforge_network::netlink::NdpMonitor::new(h2.clone(), m2.clone(), target_ifindex)
    });

    // RA Service (Async)
    if cfg.ra_enabled {
        let ra_cfg = cfg.to_ra_config();
        registry.spawn_async(move || lanforge_network::ra::RaService::new(ra_cfg.clone()));
    }

    // DHCPv4 Service (Sync)
    if cfg.dhcpv4_enabled {
        let d4_cfg = cfg.to_dhcpv4_config();
        registry.spawn_sync(move || lanforge_network::dhcp::v4::Dhcpv4Service::new(d4_cfg.clone()));
    }

    // DHCPv6 Service (Sync)
    if cfg.dhcpv6_enabled {
        let d6_cfg = cfg.to_dhcpv6_config();
        registry.spawn_sync(move || lanforge_network::dhcp::v6::Dhcpv6Service::new(d6_cfg.clone()));
    }

    // DNS Service (Async)
    if cfg.dns_enabled {
        let dns_cfg = cfg.to_dns_config();
        registry.spawn_async(move || lanforge_dns::server::DnsService::new(dns_cfg.clone()));
    }

    // Control Service (Async)
    let api_cfg = Arc::new(cfg.to_api_config());
    let api_cfg_ctrl = api_cfg.clone();
    registry.spawn_async(move || lanforge_api::server::ControlService::new(api_cfg_ctrl.clone()));

    // HTTP Service (Async)
    if cfg.http_listen.is_some() {
        let api_cfg_http = api_cfg.clone();
        registry.spawn_async(move || lanforge_api::http::HttpService::new(api_cfg_http.clone()));
    }

    // 5. Run Event Loop (with pre-subscribed bus receiver)
    run_event_loop(bootstrap, bus_rx).await?;

    // 5. Shutdown Sequence
    info!("🛑 Iniciando sequência de shutdown...");
    LanforgeContext::terminate();
    let _ = bus.publish(LanforgeEvent::Shutdown);

    // Wait for all services to stop (with timeout)
    tokio::select! {
        _ = registry.wait_all() => {
            info!("All services shut down cleanly.");
        }
        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
            info!("Shutdown timeout reached, exiting.");
        }
    }

    info!("👋 Lanforge encerrado.");
    Ok(())
}

/// Helper public functions needed by modules
pub(crate) async fn run_scan(
    cfg: &config::Config,
    handle: &rtnetlink::Handle,
    gua: Option<Ipv6Addr>,
    ula: Option<Ipv6Addr>,
    target_ifindex: u32,
) -> Result<()> {
    lanforge_network::slaac::bootstrap_table(
        &cfg.target_prefix,
        handle,
        gua,
        ula,
        Some(target_ifindex),
    )
    .await
    .map_err(anyhow::Error::from)
}

pub(crate) fn sd_notify_ready() {
    if let Ok(path) = std::env::var("NOTIFY_SOCKET") {
        debug!("systemd: Notificando READY=1 via {}", path);
        if let Ok(sock) = UnixDatagram::unbound()
            && sock.connect(path).is_ok()
        {
            let _ = sock.send(b"READY=1\n");
        }
    }
}
