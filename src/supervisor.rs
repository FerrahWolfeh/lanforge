//! Supervisor de tasks — Monitoramento e resiliência com backoff exponencial.
//!
//! Este módulo provê a infraestrutura para garantir que as tasks de protocolo
//! (DHCP, DNS, RA) continuem rodando mesmo após falhas críticas, aplicando
//! uma estratégia de reinício com espera progressiva.
//!
//! ## Fluxo de Supervisão
//!
//! ```text
//!    [ Factory ] ──► [ Future ] ──► [ Execução ]
//!          ▲                            │
//!          │                            ▼
//!          │                    ┌───────────────┐
//!          │                    │  Sucesso?     │──► Ok(())
//!          │                    └──────┬────────┘
//!          │       [ Backoff ]         │ Não
//!          └───────────────────────────┘
//! ```

#[allow(unused_imports)]
use lanforge_core::bus::{LanforgeEvent, StorageEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{AsyncService, ServiceControl, SyncBusReceiver, SyncService};
use std::thread::sleep;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tracing::{error, info, warn};

/// Executa uma task supervisionada que implementa `AsyncService`.
pub async fn supervise_async<S, F>(ctx: &LanforgeContext, factory: F)
where
    S: AsyncService,
    F: Fn() -> S,
{
    let mut consecutive_failures: u32 = 0;

    loop {
        let mut service = factory();
        let meta = service.meta();
        let description = service.describe();
        let name = meta.display_name;

        info!("▸ Starting async service: {}", description);

        let ctrl = ServiceControl::new(meta.id, ctx.clone());

        let mut bus_rx = ctx.bus().subscribe();
        tokio::select! {
            shutdown = async {
                while let Ok(e) = bus_rx.recv().await {
                    if matches!(e.event, LanforgeEvent::System(SystemEvent::Shutdown)) {
                        return true;
                    }
                }
                false
            } => {
                if shutdown {
                    info!("▪ {} shutting down", description);
                    if let Err(e) = service.on_shutdown() {
                        error!("Error during async service '{}' shutdown: {e}", name);
                    }
                    return;
                }
            }
            res = service.run(ctrl) => {
                match res {
                    Ok(()) => {
                        if !ctx.is_running() {
                            info!("▪ {} exited (shutdown)", description);
                            return;
                        }
                        info!("▪ {} exited cleanly, restarting", description);
                        consecutive_failures = 0;
                    }
                    Err(err) => {
                        consecutive_failures += 1;
                        error!("✗ {} failed ({}x): {:#}", description, consecutive_failures, err);

                        if meta.max_retries > 0 && consecutive_failures >= meta.max_retries {
                            if meta.critical {
                                error!("FATAL: Critical service '{}' failed after {} retries. Shutting down.", name, consecutive_failures);
                                ctx.terminate();
                                return;
                            }
                            warn!("Service '{}' exhausted {} retries — giving up", name, meta.max_retries);
                            return;
                        }

                        let exp = meta.base_backoff.saturating_mul(1 << (consecutive_failures - 1).min(16));
                        let backoff = exp.min(meta.max_backoff);

                        warn!(
                            "Restarting async service '{}' in {:.1}s (attempt {}/{})",
                            name,
                            backoff.as_secs_f64(),
                            consecutive_failures + 1,
                            if meta.max_retries == 0 { "∞".into() } else { meta.max_retries.to_string() }
                        );

                        tokio::select! {
                            () = async {
                                while let Ok(e) = bus_rx.recv().await {
                                    if matches!(e.event, LanforgeEvent::System(SystemEvent::Shutdown)) {
                                        return;
                                    }
                                }
                            } => {
                                info!("Supervisor '{}' received shutdown signal during backoff, stopping", name);
                                return;
                            }
                            () = tokio::time::sleep(backoff) => {}
                        }
                    }
                }
            }
        }
    }
}

/// Executa uma task supervisionada que implementa `SyncService`.
///
/// Esta função é SÍNCRONA e deve ser chamada dentro de uma OS thread dedicada
/// (ex: via `spawn_sync_service_thread`). Ela não requer um executor Tokio.
pub fn supervise_sync<S, F>(ctx: &LanforgeContext, rt_handle: &tokio::runtime::Handle, factory: F)
where
    S: SyncService,
    F: Fn() -> S,
{
    let mut consecutive_failures: u32 = 0;

    loop {
        if !ctx.is_running() {
            info!("Supervisor (sync) received shutdown, stopping before start");
            return;
        }

        let mut service = factory();
        let meta = service.meta();
        let description = service.describe();
        let name = meta.display_name;

        info!("▸ Starting sync service: {}", description);

        // Create the event bus bridge for this sync service
        let bus = ctx.bus();
        let (tx, rx) = std::sync::mpsc::channel();
        let bus_rx = SyncBusReceiver::new(rx, ctx.clone());

        // Spawn the bridge task on the Tokio runtime (not this OS thread)
        let mut event_rx = bus.subscribe();
        rt_handle.spawn(async move {
            loop {
                // We use a small timeout to check the termination flag occasionally
                // but mostly we rely on the broadcast events.
                match event_rx.recv().await {
                    Ok(event) => {
                        let is_shutdown =
                            matches!(event.event, LanforgeEvent::System(SystemEvent::Shutdown));
                        if tx.send(event).is_err() {
                            break;
                        }
                        if is_shutdown {
                            break;
                        }
                    }
                    Err(RecvError::Lagged(count)) => {
                        warn!(
                            "Event bridge for '{}' lagged by {} messages",
                            meta.id, count
                        );
                    }
                    Err(RecvError::Closed) => {
                        break;
                    }
                }
            }
        });

        let ctrl = ServiceControl::new(meta.id, ctx.clone());

        let res = service.run(ctrl, &bus_rx);

        match res {
            Ok(()) => {
                if !ctx.is_running() {
                    info!("▪ {} exited (shutdown)", description);
                    return;
                }
                info!("▪ {} exited cleanly, restarting", description);
                consecutive_failures = 0;
            }
            Err(err) => {
                consecutive_failures += 1;
                error!(
                    "✗ {} failed ({}x): {:#}",
                    description, consecutive_failures, err
                );

                if meta.max_retries > 0 && consecutive_failures >= meta.max_retries {
                    if meta.critical {
                        ctx.terminate();
                        let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
                        return;
                    }
                    warn!(
                        "Service '{}' exhausted {} retries — giving up",
                        name, meta.max_retries
                    );
                    return;
                }

                let exp = meta
                    .base_backoff
                    .saturating_mul(1 << (consecutive_failures - 1).min(16));
                let backoff = exp.min(meta.max_backoff);

                warn!(
                    "Restarting sync service '{}' in {:.1}s (attempt {}/{})",
                    name,
                    backoff.as_secs_f64(),
                    consecutive_failures + 1,
                    if meta.max_retries == 0 {
                        "∞".into()
                    } else {
                        meta.max_retries.to_string()
                    }
                );

                // No supervisor síncrono, fazemos sleep da thread.
                // Verificamos o cancelamento antes e depois do sleep.
                let start = std::time::Instant::now();
                while start.elapsed() < backoff {
                    if !ctx.is_running() {
                        info!(
                            "Supervisor (sync) '{}' received shutdown during backoff",
                            name
                        );
                        return;
                    }
                    sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_core::bus::EventBus;
    use lanforge_core::error::CoreError;
    use lanforge_core::service::LanforgeService;
    use lanforge_core::service::ServiceControl;
    use lanforge_core::service::ServiceMeta;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    fn init_test_context() -> LanforgeContext {
        let bus = Arc::new(EventBus::new());
        let table = lanforge_core::state::State::new();
        LanforgeContext::new(bus, table, None)
    }

    #[tokio::test]
    async fn gives_up_after_max_retries_non_critical() {
        let ctx = init_test_context();
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        supervise_async(&ctx, move || {
            let a = attempts_clone.clone();
            TestAsyncService { attempts: a }
        })
        .await;

        assert_eq!(
            attempts.load(Ordering::Relaxed),
            3,
            "Supervisor deveria tentar exatamente max_retries vezes"
        );
    }

    struct TestAsyncService {
        attempts: Arc<AtomicU32>,
    }
    impl LanforgeService for TestAsyncService {
        fn meta(&self) -> ServiceMeta {
            ServiceMeta {
                id: "test",
                display_name: "test",
                critical: false,
                max_retries: 3,
                base_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(10),
                stack_kb: 1,
            }
        }
    }
    impl lanforge_core::service::AsyncService for TestAsyncService {
        async fn run(&mut self, _ctrl: ServiceControl) -> Result<(), CoreError> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            Err(CoreError::Generic("always fails".into()))
        }
    }

    #[tokio::test]
    async fn resets_failure_counter_on_success() {
        let ctx = init_test_context();
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        supervise_async(&ctx, move || {
            let a = attempts_clone.clone();
            TestResetService { attempts: a }
        })
        .await;

        assert_eq!(attempts.load(Ordering::Relaxed), 4);
    }

    struct TestResetService {
        attempts: Arc<AtomicU32>,
    }
    impl LanforgeService for TestResetService {
        fn meta(&self) -> ServiceMeta {
            ServiceMeta {
                id: "test-reset",
                display_name: "test-reset",
                critical: false,
                max_retries: 3,
                base_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(10),
                stack_kb: 1,
            }
        }
    }
    impl lanforge_core::service::AsyncService for TestResetService {
        async fn run(&mut self, _ctrl: ServiceControl) -> Result<(), CoreError> {
            let n = self.attempts.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                Ok(())
            } else if n < 4 {
                Err(CoreError::Generic("fails after success".into()))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn test_supervisor_reference_implementation() {
        let ctx = init_test_context();
        let bus = ctx.bus();
        let mut sub = bus.subscribe();

        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        // Spawn supervisor in background
        let ctx_clone = ctx.clone();
        let handle = tokio::spawn(async move {
            supervise_async(&ctx_clone, move || {
                let a = attempts_clone.clone();
                RefService { attempts: a }
            })
            .await;
        });

        // 1. Check for ServiceReady
        let mut ready = false;
        // We might get multiple events, we want to see at least one ServiceReady
        for _ in 0..20 {
            if let Ok(event) = sub.recv().await
                && let LanforgeEvent::System(SystemEvent::ServiceReady { name }) = event.event
                && name == "ref-service"
            {
                ready = true;
                break;
            }
        }
        assert!(ready, "ServiceReady should be published");

        // 2. Wait for a few attempts (it fails and restarts)
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            attempts.load(Ordering::Relaxed) > 1,
            "Should have restarted at least once"
        );

        // 3. Signal Shutdown
        let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));

        // 4. Verify supervisor terminates
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("Supervisor should terminate on shutdown")
            .expect("Supervisor task panicked");
    }

    #[tokio::test]
    async fn test_sync_service_bridge_resilience() {
        println!("INFO: Starting test_sync_service_bridge_resilience v5");
        let ctx = init_test_context();
        let bus = ctx.bus();
        let mut ready_sub = bus.subscribe();
        let rt_handle = tokio::runtime::Handle::current();
        let received_count = Arc::new(AtomicU32::new(0));
        let count_clone = received_count.clone();

        // Spawn sync service that exits on Shutdown
        let ctx_spawn = ctx.clone();
        let handle = std::thread::spawn(move || {
            let ctx_2 = ctx_spawn.clone();
            supervise_sync(&ctx_spawn, &rt_handle, move || {
                let r = count_clone.clone();
                TestSyncService {
                    received: r,
                    ctx: ctx_2.clone(),
                }
            });
        });

        // 1. Wait for ServiceReady
        let mut ready = false;
        for _ in 0..100 {
            if let Ok(event) =
                tokio::time::timeout(Duration::from_millis(50), ready_sub.recv()).await
                && let Ok(e) = event
                && let LanforgeEvent::System(SystemEvent::ServiceReady { name }) = e.event
                && name == "test-sync"
            {
                ready = true;
                break;
            }
        }
        assert!(ready, "test-sync never became ready");
        println!("INFO: Service ready, publishing probes");

        // 2. Publish two loggable events and a shutdown
        let _ = bus.publish(LanforgeEvent::Storage(StorageEvent::DbVacuum));
        let _ = bus.publish(LanforgeEvent::Storage(StorageEvent::DbVacuum));
        let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));

        // Dá um tempo para a task assíncrona do bridge rotear os eventos pro MPSC
        tokio::time::sleep(Duration::from_millis(100)).await;

        ctx.terminate();

        // 3. Join thread - NÃO BLOQUEIE O RUNTIME, use spawn_blocking!
        let _ = tokio::task::spawn_blocking(move || {
            let _ = handle.join();
        })
        .await;

        // 4. Verify we received the 2 events
        let count = received_count.load(Ordering::Relaxed);
        println!("INFO: Received count: {count}");
        assert!(
            count >= 2,
            "Bridge failed to deliver events even without overload"
        );
    }

    struct TestSyncService {
        received: Arc<AtomicU32>,
        ctx: LanforgeContext,
    }
    impl LanforgeService for TestSyncService {
        fn meta(&self) -> ServiceMeta {
            ServiceMeta {
                id: "test-sync",
                display_name: "test-sync",
                critical: false,
                max_retries: 3,
                base_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(10),
                stack_kb: 1,
            }
        }
    }

    impl lanforge_core::service::SyncService for TestSyncService {
        fn run(
            &mut self,
            ctrl: ServiceControl,
            bus_rx: &lanforge_core::service::SyncBusReceiver,
        ) -> Result<(), CoreError> {
            ctrl.signal_ready();
            loop {
                if let Some(e) = bus_rx.recv_timeout(Duration::from_millis(500)) {
                    println!("LOG: TestSyncService received: {:?}", e.event);
                    if matches!(e.event, LanforgeEvent::System(SystemEvent::Shutdown)) {
                        break;
                    }
                    if matches!(e.event, LanforgeEvent::Storage(StorageEvent::DbVacuum)) {
                        self.received.fetch_add(1, Ordering::SeqCst);
                    }
                } else if !self.ctx.is_running() {
                    // Sai apenas se o contexto geral foi finalizado
                    break;
                }
            }
            Ok(())
        }
    }

    struct RefService {
        attempts: Arc<AtomicU32>,
    }
    impl LanforgeService for RefService {
        fn meta(&self) -> ServiceMeta {
            ServiceMeta {
                id: "ref-service",
                display_name: "Reference Service",
                critical: false,
                max_retries: 0, // infinite
                base_backoff: Duration::from_millis(5),
                max_backoff: Duration::from_millis(20),
                stack_kb: 1,
            }
        }
        fn describe(&self) -> String {
            "RefService".into()
        }
    }
    impl lanforge_core::service::AsyncService for RefService {
        async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            // Simulate work then failure
            tokio::time::sleep(Duration::from_millis(2)).await;
            ctrl.signal_ready();
            Err(CoreError::Generic("simulated error".into()))
        }
    }
}
