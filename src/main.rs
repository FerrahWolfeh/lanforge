//! `lanforge` — Gerenciador central de identidades de rede (IPv6/IPv4).
//!
//! Este daemon coordena o estado dos dispositivos na rede local integrando
//! múltiplos protocolos (`DHCPv4`, `DHCPv6`, RA, SLAAC, DNS).
//!
//! ## Ciclo de Vida e Bootstrap
//!
//! ```text
//!    [ Bootstrap ]             [ Event Loop ]             [ Shutdown ]
//!          │                         │                         │
//!  1. Load Config (TOML)             │                         │
//!          │           ┌─────────────┼─────────────┐           │
//!  2. Init EventBus    │             ▼             │           │
//!          │           │     Eventos Netlink       │      1. SIGTERM
//!  3. Load State (DB)  │             │             │           │
//!          │           │             ▼             │      2. Publish
//!  4. Load Statics     │      Update ManagedTable  │         Shutdown
//!          │           │             │             │           │
//!  5. Spawn Workers ───┼──────────►  │ ────────────┼───►  3. DB Flush
//!     (DHCP, DNS, RA,  │             ▼             │           │
//!      DB, Control)    │      Publish EventBus     │      4. Exit
//!          │           │             │             │
//!          │           │      Consumers React      │
//!          ▼           └─────────────┬─────────────┘
//!    Ready State                     │
//! ```
//!
//! ## Componentes Principais
//!
//! - **`ManagedTable`**: Autoridade central de estado (Thread-safe).
//! - **`EventBus`**: Barramento de eventos reativo asincrono.
//! - **Supervisores**: Garantem que tasks de protocolo continuem rodando após erros.

mod config;
mod supervisor;
mod threads;

use crate::config::load_devices_only;
use crate::threads::{spawn_service_thread, wait_for_service_threads};

use anyhow::Result;
use config::Config;
use lanforge_core::bus::{EventBus, LanforgeEvent, ManagedTable};
use lanforge_core::context::LanforgeContext;
use lanforge_core::device::Ipv6AddrOrSuffix;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::DeviceTable;
use lanforge_core::state::update::DeviceUpdate;
use lanforge_db::engine::LeaseDb;
use lanforge_network::mdns::MdnsProber;
use lanforge_network::slaac::bootstrap_table;
use netlink_sys::AsyncSocket;
use rtnetlink::constants::RTMGRP_NEIGH;
use rtnetlink::new_connection;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, interval};
use tracing::{debug, error, info, warn};

/// Notifies systemd that the service is ready if $NOTIFY_SOCKET is set.
fn sd_notify_ready() {
    if let Ok(path) = std::env::var("NOTIFY_SOCKET") {
        debug!("systemd: Notificando READY=1 via {}", path);
        if let Ok(sock) = UnixDatagram::unbound()
            && sock.connect(path).is_ok()
        {
            let _ = sock.send(b"READY=1\n");
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

// DEPOIS: main síncrona + runtime current_thread + função async separada
fn main() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name("lanforge-main")
        .build()?;

    let res = rt.block_on(async_main());

    // Forçamos a saída imediata para evitar hangs em destrutores globais
    // ou runtimes que se recusam a morrer após o "Lanforge encerrado".
    if let Err(e) = res {
        eprintln!("❌ Erro fatal: {e:#}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

/// Ponto de entrada principal do daemon.
///
/// Configura o logging, carrega a configuração TOML, inicia o banco de dados
/// `SQLite` e dispara os serviços de rede (RA, DHCP, DNS, Control) como tasks do Tokio.
async fn async_main() -> Result<()> {
    #[cfg(feature = "debug-commands")]
    let mut cfg = Config::load();

    #[cfg(not(feature = "debug-commands"))]
    let cfg = Config::load();

    #[cfg(feature = "debug-commands")]
    if let config::Command::Run { only: Some(s) } = &cfg.command {
        let modules: Vec<&str> = s.split(',').collect();
        cfg.ra_enabled = modules.contains(&"ra");
        cfg.dhcpv4_enabled = modules.contains(&"dhcpv4") || modules.contains(&"dhcp");
        cfg.dhcpv6_enabled = modules.contains(&"dhcpv6") || modules.contains(&"dhcp");
        cfg.dns_enabled = modules.contains(&"dns");
        info!("🎯 Running ONLY (Debug Mode): {:?}", modules);
    }

    let cfg = Arc::new(cfg);

    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!(
        "🚀 Starting Lanforge (RA: {}, DHCPv4: {}, DHCPv6: {}, DNS: {})",
        cfg.ra_enabled, cfg.dhcpv4_enabled, cfg.dhcpv6_enabled, cfg.dns_enabled
    );
    debug!("  target_prefix = {}", cfg.target_prefix);
    debug!("  debounce      = {}s", cfg.debounce_secs);
    debug!("  fallback scan = every {}min", cfg.fallback_mins);

    // -----------------------------------------------------------------------
    // EventBus — instanciado antes de tudo para que o ManagedTable possa
    // publicar durante o bootstrap
    // -----------------------------------------------------------------------
    let bus = Arc::new(EventBus::new());

    // -----------------------------------------------------------------------
    // ManagedTable — autoridade central de estado
    //
    // Sequência de bootstrap:
    //   1. Carrega estado persistido do SQLite (apply_update, respeita invariantes)
    //   2. Aplica entradas estáticas do TOML (têm precedência sobre o DB)
    //   3. Cria ManagedTable encapsulando a tabela inicial completa
    // -----------------------------------------------------------------------
    let leases_db_path = std::path::PathBuf::from(&cfg.leases_db);

    // 1. Criamos a tabela inicial direto na stack da thread principal (Lock-free)
    let mut initial_table = match LeaseDb::open(&leases_db_path) {
        Ok(db) => match db.load_table() {
            Ok(persisted) => {
                info!("📦 Database loaded: {}", cfg.leases_db);
                persisted
            }
            Err(e) => {
                warn!("Falha ao carregar DB ({e}), iniciando do zero");
                DeviceTable::new()
            }
        },
        Err(e) => {
            error!("❌ Erro fatal abrindo leases DB: {e}");
            return Err(e.into());
        }
    };

    // 2. Lemos o TOML (StaticDeviceCfg) e populamos a tabela AQUI no main
    let mut all_static_devices = cfg.devices.clone();

    // 2b. Carrega devices extras de arquivo externo (CLI override)
    if let Some(ref extra_path) = cfg.devices_file {
        info!("📂 Carregando devices adicionais de {extra_path}");
        let mut extra = load_devices_only(extra_path);
        all_static_devices.append(&mut extra);
    }

    if !all_static_devices.is_empty() {
        let count = all_static_devices.len();

        for e in &all_static_devices {
            // Parsing das strings sujas
            let Some(mac) = MacAddr::parse(&e.mac) else {
                warn!("Invalid MAC in config: '{}', skipping", e.mac);
                continue;
            };

            let v4_ip = e.v4_ip.as_ref().and_then(|s| {
                s.parse::<std::net::Ipv4Addr>().ok().or_else(|| {
                    warn!("Invalid v4_ip for {}: '{s}'", e.hostname);
                    None
                })
            });

            let v6_suffix = e.v6_suffix.as_ref().and_then(|s| {
                Ipv6AddrOrSuffix::parse(s).or_else(|| {
                    warn!("Invalid v6_suffix for {}: '{s}'", e.hostname);
                    None
                })
            });

            initial_table.add_static_device(mac, e.hostname.clone(), v4_ip, v6_suffix);
        }

        info!("👥 Static reservations: {count} entries");
    }

    // 3. Montamos os índices O(1) do DNS apenas UMA vez após tudo ser carregado
    initial_table.apply_update(DeviceUpdate::RebuildDnsIndices);

    // 4. Transformamos em ManagedTable reativa (Arc<RwLock<DeviceTable>>)
    let table = Arc::new(ManagedTable::from_table(bus.clone(), initial_table));

    // 5. Initialize global context
    lanforge_core::context::LanforgeContext::init(bus.clone(), table.clone());
    let _ = bus.publish(LanforgeEvent::StateReady);

    let mut service_threads: Vec<(&'static str, std::thread::JoinHandle<()>)> = Vec::new();

    // -----------------------------------------------------------------------
    // API Config & Control Tokens
    // -----------------------------------------------------------------------
    let api_cfg = Arc::new(cfg.to_api_config());
    let api_cfg_ctrl = api_cfg.clone();
    let api_cfg_http = api_cfg.clone();

    // -----------------------------------------------------------------------
    // Sync Bridges & Service Channels (for SyncService)
    // -----------------------------------------------------------------------
    let (db_tx, db_rx) = std::sync::mpsc::channel::<LanforgeEvent>();
    let db_rx = Arc::new(std::sync::Mutex::new(db_rx));
    let (d4_tx, d4_rx) = std::sync::mpsc::channel::<LanforgeEvent>();
    let d4_rx = Arc::new(std::sync::Mutex::new(d4_rx));
    let (d6_tx, d6_rx) = std::sync::mpsc::channel::<LanforgeEvent>();
    let d6_rx = Arc::new(std::sync::Mutex::new(d6_rx));

    // Bridge task: forward EventBus to sync mpsc channels
    let mut bridge_sub = bus.subscribe();
    let bridge_db = db_tx.clone();
    let bridge_d4 = d4_tx.clone();
    let bridge_d6 = d6_tx.clone();

    tokio::spawn(async move {
        while let Ok(event) = bridge_sub.recv().await {
            let _ = bridge_db.send(event.clone());
            let _ = bridge_d4.send(event.clone());
            let _ = bridge_d6.send(event);
        }
    });

    {
        let db_path = leases_db_path.clone();
        let log_db_path: std::path::PathBuf = cfg.log_db.clone().into();
        let rx = db_rx.clone();

        service_threads.push((
            "db",
            threads::spawn_sync_service_thread("DB Worker", 512, move || {
                supervisor::supervise_sync(
                    "db",
                    true,
                    0,
                    Duration::from_secs(2),
                    Duration::from_secs(30),
                    move || {
                        lanforge_db::worker::DbWorker::new(
                            db_path.clone(),
                            log_db_path.clone(),
                            rx.clone(),
                        )
                    },
                )
            }),
        ));
    }

    // -----------------------------------------------------------------------
    // mDNS Prober — Supervised service
    // -----------------------------------------------------------------------
    service_threads.push((
        "mdns",
        spawn_service_thread("mDNS Prober", 256, move || async move {
            supervisor::supervise_async(
                "mdns",
                false,
                0,
                Duration::from_secs(5),
                Duration::from_secs(60),
                MdnsProber::new,
            )
            .await
        }),
    ));

    // -----------------------------------------------------------------------
    // Netlink connection
    // -----------------------------------------------------------------------
    let (mut connection, handle, messages) = new_connection()?;
    // Forçamos o join no grupo multicast da vizinhança
    connection
        .socket_mut()
        .socket_mut()
        .add_membership(RTMGRP_NEIGH)?;
    let netlink_task = tokio::spawn(connection);

    let messages = Arc::new(tokio::sync::Mutex::new(messages));

    let monitor_handle = handle.clone();
    let monitor_messages = messages.clone();
    service_threads.push((
        "monitor",
        spawn_service_thread("NdpMonitor", 512, move || {
            let h = monitor_handle.clone();
            let m = monitor_messages.clone();
            async move {
                supervisor::supervise_async(
                    "monitor",
                    true,
                    0,
                    Duration::from_secs(1),
                    Duration::from_secs(10),
                    move || lanforge_network::netlink::NdpMonitor::new(h.clone(), m.clone()),
                )
                .await
            }
        }),
    ));

    // -----------------------------------------------------------------------
    // RA service — Supervised service
    // -----------------------------------------------------------------------
    if cfg.ra_enabled {
        let ra_cfg = cfg.to_ra_config();

        service_threads.push((
            "ra",
            spawn_service_thread("RA Server", 512, move || {
                let rc = ra_cfg.clone();
                async move {
                    supervisor::supervise_async(
                        "ra",
                        true,
                        0,
                        Duration::from_secs(2),
                        Duration::from_secs(30),
                        move || lanforge_network::ra::RaService::new(rc.clone()),
                    )
                    .await
                }
            }),
        ));
    }

    // -----------------------------------------------------------------------
    // DHCPv4 service — Supervised service
    // -----------------------------------------------------------------------
    if cfg.dhcpv4_enabled {
        let dhcp_cfg = cfg.to_dhcpv4_config();
        let rx = d4_rx.clone();

        service_threads.push((
            "dhcpv4",
            threads::spawn_sync_service_thread("DHCPv4 Server", 512, move || {
                let dc = dhcp_cfg.clone();
                let r = rx.clone();
                supervisor::supervise_sync(
                    "dhcpv4",
                    true,
                    0,
                    Duration::from_secs(2),
                    Duration::from_secs(30),
                    move || lanforge_network::dhcp::v4::Dhcpv4Service::new(dc.clone(), r.clone()),
                )
            }),
        ));
    }

    if cfg.dhcpv6_enabled {
        let dhcp_cfg = cfg.to_dhcpv6_config();
        let rx = d6_rx.clone();

        service_threads.push((
            "dhcpv6",
            threads::spawn_sync_service_thread("DHCPv6 Server", 512, move || {
                let dc = dhcp_cfg.clone();
                let r = rx.clone();
                supervisor::supervise_sync(
                    "dhcpv6",
                    true,
                    0,
                    Duration::from_secs(2),
                    Duration::from_secs(30),
                    move || lanforge_network::dhcp::v6::Dhcpv6Service::new(dc.clone(), r.clone()),
                )
            }),
        ));
    }

    // -----------------------------------------------------------------------
    // DNS service
    // -----------------------------------------------------------------------
    if cfg.dns_enabled {
        let dns_cfg = cfg.to_dns_config();

        service_threads.push((
            "dns",
            spawn_service_thread("DNS Server", 384, move || {
                let dc = dns_cfg.clone();
                async move {
                    supervisor::supervise_async(
                        "dns",
                        true,
                        0,
                        Duration::from_secs(5),
                        Duration::from_secs(60),
                        move || lanforge_dns::server::DnsService::new(dc.clone()),
                    )
                    .await
                }
            }),
        ));
    }

    // -----------------------------------------------------------------------
    // Control service (UDS) — Interface de controle via JSON-RPC
    // -----------------------------------------------------------------------
    // -----------------------------------------------------------------------
    // Control service (UDS) — Supervised service
    // -----------------------------------------------------------------------
    service_threads.push((
        "control",
        spawn_service_thread("Control Service", 256, move || async move {
            supervisor::supervise_async(
                "control",
                true,
                0,
                Duration::from_secs(2),
                Duration::from_secs(30),
                move || lanforge_api::server::ControlService::new(api_cfg_ctrl.clone()),
            )
            .await
        }),
    ));

    // -----------------------------------------------------------------------
    // HTTP API responder — Supervised Axum service
    // -----------------------------------------------------------------------
    if cfg.http_listen.is_some() {
        let http_api_cfg = api_cfg_http.clone();

        service_threads.push((
            "http",
            spawn_service_thread("http", 1536, move || async move {
                supervisor::supervise_async(
                    "http",
                    true,
                    0,
                    Duration::from_secs(2),
                    Duration::from_secs(30),
                    move || lanforge_api::http::HttpService::new(http_api_cfg.clone()),
                )
                .await
            }),
        ));
    }

    // -----------------------------------------------------------------------
    // Prefixo GUA — aprendido dinamicamente via PrefixChanged do RA.
    // Começa como None; é atualizado no handler do EventBus abaixo.
    // Passado para o scan SLAAC para distinguir SlaacObserved de NdpSeen.
    // -----------------------------------------------------------------------
    let mut current_gua: Option<Ipv6Addr> = None;

    // -----------------------------------------------------------------------
    // Loop principal — eventos Netlink, timers, sinais
    // -----------------------------------------------------------------------
    let mut bus_rx = bus.subscribe();
    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    let mut fallback = interval(Duration::from_secs(cfg.fallback_mins * 60));
    fallback.tick().await;

    let mut stale_timer = interval(Duration::from_secs(600));
    stale_timer.tick().await;

    // Scan inicial (sem GUA ainda — RA ainda não anunciou)
    if let Err(e) = run_scan(&cfg, &handle, current_gua).await {
        error!("❌ Erro no scan inicial: {e:#}");
    }

    let mut expected_services = HashSet::from(["db", "mdns", "monitor", "control"]);
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
            // ── Fallback — Garantia de Consistência ──────────────────────
            _ = fallback.tick() => {
                debug!("Sincronização periódica de SLAAC (Fallback)...");
                if let Err(e) = run_scan(&cfg, &handle, current_gua).await {
                    error!("Erro no fallback: {e:#}");
                }
            }

            // ── Stale — Expiração de leases e IPs antigos ────────────────
            _ = stale_timer.tick() => {
                let changed = table.write().expire_stale();
                if changed {
                    let _ = bus.publish(LanforgeEvent::DeviceTableDirty);
                }
            }

            // ── SIGUSR1 — Sincronização manual ───────────────────────────
            _ = sigusr1.recv() => {
                info!("SIGUSR1 recebido, forçando sincronização de estado...");
                if let Err(e) = run_scan(&cfg, &handle, current_gua).await {
                    error!("Erro na sincronização manual: {e:#}");
                }
            }

            // ── SIGINT/SIGTERM — Shutdown gracioso ──────────────────────
            _ = sigterm.recv() => {
                info!("SIGTERM recebido — iniciando encerramento gracioso...");
                break;
            }
            _ = sigint.recv() => {
                info!("SIGINT recebido — iniciando encerramento gracioso...");
                break;
            }

            // ── EventBus — Eventos internos ──────────────────────────────
            event = bus_rx.recv() => {
                match event {
                    Ok(LanforgeEvent::ServiceReady { name }) => {
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
                    Ok(LanforgeEvent::PrefixChanged { gua, .. }) => {
                        if current_gua != gua {
                            info!("Prefixo GUA alterado: {:?} → {:?}", current_gua, gua);
                            current_gua = gua;
                        }
                        // Novo prefixo exige repopular o estado do zero
                        if let Err(e) = run_scan(&cfg, &handle, current_gua).await {
                            error!("Erro ao atualizar prefixo: {e:#}");
                        }
                    }
                    Ok(LanforgeEvent::DeviceDiscovered { mac }) => {
                        debug!("Novo device descoberto: {mac}");
                    }
                    Ok(LanforgeEvent::DeviceExpired { mac }) => {
                        debug!("Device expirado: {mac}");
                    }
                    Ok(LanforgeEvent::ReloadConfig) => {
                        info!("ReloadConfig: Forçando sincronização via sinalizador manual!");
                        if let Err(e) = run_scan(&cfg, &handle, current_gua).await {
                            error!("Erro no reload: {e:#}");
                        }
                    }
                    Ok(_) => {}
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

    info!("🛑 Iniciando sequência de shutdown...");
    LanforgeContext::terminate();
    let _ = bus.publish(LanforgeEvent::Shutdown);
    netlink_task.abort();

    // O wait é bloqueante mas estamos fora do hot path — o runtime main
    // pode ficar idle enquanto as threads de serviço terminam.
    wait_for_service_threads(service_threads, Duration::from_secs(5));

    info!("👋 Lanforge encerrado.");
    Ok(())
}

/// Executa um ciclo de scan SLAAC via netlink.
///
/// Este helper centraliza a chamada ao módulo `slaac` para descobrir
/// endereços IPv6 ativos (GUA e link-local) no segmento de rede.
async fn run_scan(cfg: &Config, handle: &rtnetlink::Handle, gua: Option<Ipv6Addr>) -> Result<()> {
    bootstrap_table(&cfg.target_prefix, handle, gua)
        .await
        .map_err(anyhow::Error::from)
}
