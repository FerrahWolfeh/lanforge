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

mod cli;
mod config;
mod supervisor;

use crate::config::load_devices_only;

use anyhow::Result;
use config::Config;
use futures::StreamExt;
use lanforge_core::bus::{EventBus, LanforgeEvent, ManagedTable};
use lanforge_core::device::Ipv6AddrOrSuffix;
use lanforge_core::identifiers::MacAddr;
use lanforge_core::state::DeviceTable;
use lanforge_core::state::update::DeviceUpdate;
use lanforge_db::engine::LeaseDb;
use lanforge_db::worker::db_worker;
use lanforge_dns::dns_service;
use lanforge_network::dhcp::v4::dhcpv4_service;
use lanforge_network::dhcp::v6::dhcpv6_service;
use lanforge_network::mdns::MdnsProber;
use lanforge_network::netlink::extract_neigh_info;
use lanforge_network::ra::ra_service;
use lanforge_network::slaac::bootstrap_table;
use netlink_sys::AsyncSocket;
use rtnetlink::new_connection;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, interval};
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Ponto de entrada principal do daemon.
///
/// Configura o logging, carrega a configuração TOML, inicia o banco de dados
/// `SQLite` e dispara os serviços de rede (RA, DHCP, DNS, Control) como tasks do Tokio.
#[tokio::main]
async fn main() -> Result<()> {
    let mut cfg = Config::load();

    // Se for comando cliente (Devices, Status, Reload), executa e sai sem subir o daemon (nem env filter/logging)
    match &cfg.command {
        config::Command::Devices { .. }
        | config::Command::Status
        | config::Command::Reload
        | config::Command::Watch
        | config::Command::Log { .. }
        | config::Command::Lease { .. }
        | config::Command::Scan
        | config::Command::Host { .. }
        | config::Command::Db { .. }
        | config::Command::Purge { .. }
        | config::Command::Shutdown => {
            return cli::run_client(cfg.command.clone(), &cfg.control_socket).await;
        }
        config::Command::Run { only: Some(s) } => {
            let modules: Vec<&str> = s.split(',').collect();
            cfg.ra_enabled = modules.contains(&"ra");
            cfg.dhcpv4_enabled = modules.contains(&"dhcpv4") || modules.contains(&"dhcp");
            cfg.dhcpv6_enabled = modules.contains(&"dhcpv6") || modules.contains(&"dhcp");
            cfg.dns_enabled = modules.contains(&"dns");
            info!("🎯 Running ONLY: {:?}", modules);
        }
        config::Command::Run { only: None } => {}
    }

    let cfg = Arc::new(cfg);

    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("🚀 Lanforge starting up...");
    debug!("  target_prefix = {}", cfg.target_prefix);
    debug!("  debounce      = {}s", cfg.debounce_secs);
    debug!("  fallback scan = every {}min", cfg.fallback_mins);
    info!(
        "🔧 Configuration loaded (RA={}, DHCPv4={}, DHCPv6={}, DNS={})",
        cfg.ra_enabled, cfg.dhcpv4_enabled, cfg.dhcpv6_enabled, cfg.dns_enabled
    );

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
                info!("📦 Estado persistido carregado de {}", cfg.leases_db);
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

        info!("👥 {count} reservas estáticas carregadas (TOML + Overrides)");
    }

    // 3. Montamos os índices O(1) do DNS apenas UMA vez após tudo ser carregado
    initial_table.apply_update(DeviceUpdate::RebuildDnsIndices);

    // 4. Transformamos em ManagedTable reativa (Arc<RwLock<DeviceTable>>)
    let table = Arc::new(ManagedTable::from_table(bus.clone(), initial_table));

    // -----------------------------------------------------------------------
    // DB worker — persiste reativamente via EventBus
    // -----------------------------------------------------------------------
    tokio::spawn(db_worker(leases_db_path, table.clone(), bus.clone()));

    // -----------------------------------------------------------------------
    // mDNS Prober — descoberta ativa e passiva de hostnames
    // -----------------------------------------------------------------------
    let prober = Arc::new(MdnsProber::new(bus.clone(), table.clone()));

    // -----------------------------------------------------------------------
    // Netlink connection
    // -----------------------------------------------------------------------
    let (mut connection, handle, mut messages) = new_connection()?;
    connection.socket_mut().socket_mut().add_membership(3)?;
    tokio::spawn(connection);

    // -----------------------------------------------------------------------
    // RA service
    // -----------------------------------------------------------------------
    if cfg.ra_enabled {
        let ra_cfg = cfg.to_ra_config();
        let ra_bus = bus.clone();

        info!(
            "⚡ Iniciando: RA (iface={}, M={}, O={})",
            ra_cfg.iface,
            u8::from(ra_cfg.managed),
            u8::from(ra_cfg.other_config)
        );

        tokio::spawn(supervisor::supervise_task(
            "ra",
            true,
            0,
            Duration::from_secs(5),
            Duration::from_secs(60),
            move || {
                let cfg = ra_cfg.clone();
                let bus = ra_bus.clone();
                async move { ra_service(cfg, bus).await.map_err(anyhow::Error::from) }
            },
        ));
    }

    // -----------------------------------------------------------------------
    // DHCPv4 service
    // -----------------------------------------------------------------------
    if cfg.dhcpv4_enabled {
        let dhcp_cfg = cfg.to_dhcpv4_config();
        let dhcp_table = table.clone();

        info!(
            "⚡ Iniciando: DHCPv4 ({}–{}, mask={})",
            dhcp_cfg.range_start, dhcp_cfg.range_end, dhcp_cfg.subnet_mask
        );

        tokio::spawn(supervisor::supervise_task(
            "dhcpv4",
            true,
            0,
            Duration::from_secs(5),
            Duration::from_secs(60),
            move || {
                let cfg = dhcp_cfg.clone();
                let table = dhcp_table.clone();
                async move {
                    dhcpv4_service(cfg, table)
                        .await
                        .map_err(anyhow::Error::from)
                }
            },
        ));
    }

    // -----------------------------------------------------------------------
    // DHCPv6 service
    // -----------------------------------------------------------------------
    if cfg.dhcpv6_enabled {
        let dhcp_cfg = cfg.to_dhcpv6_config();
        let dhcp_table = table.clone();
        let dhcp_handle = handle.clone();

        info!("⚡ Iniciando: DHCPv6 ({})", dhcp_cfg.iface);

        tokio::spawn(supervisor::supervise_task(
            "dhcpv6",
            true,
            0,
            Duration::from_secs(5),
            Duration::from_secs(60),
            move || {
                let handle = dhcp_handle.clone();
                let cfg = dhcp_cfg.clone();
                let table = dhcp_table.clone();
                async move {
                    dhcpv6_service(cfg, table, &handle)
                        .await
                        .map_err(anyhow::Error::from)
                }
            },
        ));
    }

    // -----------------------------------------------------------------------
    // DNS service
    // -----------------------------------------------------------------------
    if cfg.dns_enabled {
        let dns_cfg = cfg.to_dns_config();
        let dns_table = table.clone();

        info!("⚡ Iniciando: DNS");

        tokio::spawn(supervisor::supervise_task(
            "dns",
            true,
            0,
            Duration::from_secs(5),
            Duration::from_secs(60),
            move || {
                let cfg = dns_cfg.clone();
                let table = dns_table.clone();
                async move { dns_service(cfg, table).await.map_err(anyhow::Error::from) }
            },
        ));
    }

    // -----------------------------------------------------------------------
    // Control service (UDS) — Interface de controle via JSON-RPC
    // -----------------------------------------------------------------------
    let ctrl_table = table.clone();
    let ctrl_bus = bus.clone();
    let api_cfg = Arc::new(cfg.to_api_config());

    tokio::spawn(supervisor::supervise_task(
        "control",
        true,
        0,
        Duration::from_secs(2),
        Duration::from_secs(30),
        move || {
            let table = ctrl_table.clone();
            let bus = ctrl_bus.clone();
            let cfg = api_cfg.clone();
            async move {
                lanforge_api::server::control_service(table, bus, cfg)
                    .await
                    .map_err(anyhow::Error::from)
            }
        },
    ));

    // -----------------------------------------------------------------------
    // Prefixo GUA — aprendido dinamicamente via PrefixChanged do RA.
    // Começa como None; é atualizado no handler do EventBus abaixo.
    // Passado para o scan SLAAC para distinguir SlaacObserved de NdpSeen.
    // -----------------------------------------------------------------------
    let mut current_gua: Option<std::net::Ipv6Addr> = None;

    // -----------------------------------------------------------------------
    // Loop principal — eventos Netlink, timers, sinais
    // -----------------------------------------------------------------------
    let mut bus_rx = bus.subscribe();
    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    let mut fallback = interval(Duration::from_secs(cfg.fallback_mins * 60));
    fallback.tick().await;

    let mut stale_timer = interval(Duration::from_secs(600));
    stale_timer.tick().await;

    // Scan inicial (sem GUA ainda — RA ainda não anunciou)
    if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
        error!("❌ Erro no scan inicial: {e:#}");
    }

    info!("✅ Sistema pronto. Escutando eventos de rede.");

    loop {
        tokio::select! {
            // ── Netlink — Eventos Reativos (Delta) ───────────────────────
            Some((msg, _)) = messages.next() => {
                // Alimenta o Manager APENAS com o IP/MAC reportado pelo kernel no momento.
                // Zero overhead de varredura completa. CPU agradece.
                if let Some(event) = extract_neigh_info(&msg) {
                    let update = event.to_device_update(current_gua.as_ref());

                    // Trigger passive mDNS probe for new/named-less devices
                    match update {
                        DeviceUpdate::NdpSeen { mac, ip } => {
                            let table_read = table.read();
                            if let Some(dev) = table_read.get_device(&mac)
                                && dev.hostname.name.is_empty() {
                                    let p = prober.clone();
                                    tokio::spawn(async move { p.probe_ip(ip.into()).await });
                                }
                        }
                        DeviceUpdate::ArpSeen { mac, ip } => {
                            let table_read = table.read();
                            if let Some(dev) = table_read.get_device(&mac)
                                && dev.hostname.name.is_empty() {
                                    let p = prober.clone();
                                    tokio::spawn(async move { p.probe_ip(ip.into()).await });
                                }
                        }
                        _ => {}
                    }

                    table.update(update).await;
                }
            }

            // ── Fallback — Garantia de Consistência ──────────────────────
            _ = fallback.tick() => {
                debug!("Sincronização periódica de SLAAC (Fallback)...");
                if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
                    error!("Erro no fallback: {e:#}");
                }
            }

            // ── Stale — Expiração de leases e IPs antigos ────────────────
            _ = stale_timer.tick() => {
                let changed = table.write().expire_stale();
                if changed {
                    bus.publish(LanforgeEvent::DeviceTableDirty);
                }
            }

            // ── SIGUSR1 — Sincronização manual ───────────────────────────
            _ = sigusr1.recv() => {
                info!("SIGUSR1 recebido, forçando sincronização de estado...");
                if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
                    error!("Erro na sincronização manual: {e:#}");
                }
            }

            // ── SIGTERM — Shutdown gracioso ──────────────────────────────
            _ = sigterm.recv() => {
                info!("SIGTERM recebido — encerrando...");
                bus.publish(LanforgeEvent::Shutdown);
                tokio::time::sleep(Duration::from_secs(2)).await;
                break;
            }

            // ── EventBus — Eventos internos ──────────────────────────────
            event = bus_rx.recv() => {
                match event {
                    Ok(LanforgeEvent::PrefixChanged { gua, .. }) => {
                        if current_gua != gua {
                            info!("Prefixo GUA alterado: {:?} → {:?}", current_gua, gua);
                            current_gua = gua;
                        }
                        // Novo prefixo exige repopular o estado do zero
                        if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
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
                        if let Err(e) = run_scan(&cfg, &handle, &table, current_gua).await {
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

    info!("👋 Lanforge encerrado.");
    Ok(())
}

/// Executa um ciclo de scan SLAAC via netlink.
///
/// Este helper centraliza a chamada ao módulo `slaac` para descobrir
/// endereços IPv6 ativos (GUA e link-local) no segmento de rede.
async fn run_scan(
    cfg: &Config,
    handle: &rtnetlink::Handle,
    table: &Arc<ManagedTable>,
    gua: Option<Ipv6Addr>,
) -> Result<()> {
    bootstrap_table(&cfg.target_prefix, handle, table, gua)
        .await
        .map_err(anyhow::Error::from)
}
