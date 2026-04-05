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

use lanforge_core::bus::LanforgeEvent;
use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{AsyncService, ServiceMeta, SyncBusReceiver, SyncService};
use std::time::Duration;
use tracing::{error, info, warn};

/// Publishes a `ServiceReady` event and logs the readiness signal.
fn signal_ready(meta: &ServiceMeta, description: &str) {
    info!("▸ {} ready ({})", description, meta.id);
    let _ = LanforgeContext::bus().publish(LanforgeEvent::ServiceReady {
        name: meta.id.to_string(),
    });
}

/// Executa uma task supervisionada que implementa `AsyncService`.
pub async fn supervise_async<S, F>(factory: F)
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

        signal_ready(&meta, &description);

        let mut bus_rx = LanforgeContext::bus().subscribe();
        tokio::select! {
            _event = async {
                while let Ok(e) = bus_rx.recv().await {
                    if matches!(e, LanforgeEvent::Shutdown) {
                        return;
                    }
                }
            } => {
                info!("▪ {} shutting down", description);
                if let Err(e) = service.on_shutdown() {
                    error!("Error during async service '{}' shutdown: {e}", name);
                }
                return;
            }
            res = service.run() => {
                match res {
                    Ok(()) => {
                        if !LanforgeContext::is_running() {
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
                                LanforgeContext::terminate();
                                return;
                            } else {
                                warn!("Service '{}' exhausted {} retries — giving up", name, meta.max_retries);
                                return;
                            }
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
                            _ = async {
                                while let Ok(e) = bus_rx.recv().await {
                                    if matches!(e, LanforgeEvent::Shutdown) {
                                        return;
                                    }
                                }
                            } => {
                                info!("Supervisor '{}' received shutdown signal during backoff, stopping", name);
                                return;
                            }
                            _ = tokio::time::sleep(backoff) => {}
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
pub fn supervise_sync<S, F>(rt_handle: tokio::runtime::Handle, factory: F)
where
    S: SyncService,
    F: Fn() -> S,
{
    let mut consecutive_failures: u32 = 0;

    loop {
        if !LanforgeContext::is_running() {
            info!("Supervisor (sync) received shutdown, stopping before start");
            return;
        }

        let mut service = factory();
        let meta = service.meta();
        let description = service.describe();
        let name = meta.display_name;

        info!("▸ Starting sync service: {}", description);

        // Create the event bus bridge for this sync service
        let bus = LanforgeContext::bus();
        let (tx, rx) = std::sync::mpsc::channel();
        let bus_rx = SyncBusReceiver::new(rx);

        // Spawn the bridge task on the Tokio runtime (not this OS thread)
        let mut event_rx = bus.subscribe();
        rt_handle.spawn(async move {
            while let Ok(event) = event_rx.recv().await {
                let is_shutdown = matches!(event, LanforgeEvent::Shutdown);
                if tx.send(event).is_err() || is_shutdown {
                    break;
                }
            }
        });

        signal_ready(&meta, &description);

        let res = service.run(&bus_rx);

        match res {
            Ok(()) => {
                if !LanforgeContext::is_running() {
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
                        error!(
                            "FATAL: Critical service '{}' failed after {} retries. Shutting down.",
                            name, consecutive_failures
                        );
                        LanforgeContext::terminate();
                        return;
                    } else {
                        warn!(
                            "Service '{}' exhausted {} retries — giving up",
                            name, meta.max_retries
                        );
                        return;
                    }
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
                    if !LanforgeContext::is_running() {
                        info!(
                            "Supervisor (sync) '{}' received shutdown during backoff",
                            name
                        );
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_core::bus::EventBus;
    use lanforge_core::bus::ManagedTable;
    use std::sync::Arc;
    use std::sync::Once;
    use std::sync::atomic::AtomicU32;
    use std::sync::atomic::Ordering;

    static INIT: Once = Once::new();

    fn init_context() {
        INIT.call_once(|| {
            let bus = Arc::new(EventBus::new());
            let table = Arc::new(ManagedTable::new(bus.clone(), None));
            LanforgeContext::init(bus, table);
        });
    }

    #[tokio::test]
    async fn gives_up_after_max_retries_non_critical() {
        init_context();
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        supervise_async(move || {
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
    impl lanforge_core::service::LanforgeService for TestAsyncService {
        fn meta(&self) -> lanforge_core::service::ServiceMeta {
            lanforge_core::service::ServiceMeta {
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
        async fn run(&mut self) -> lanforge_core::error::Result<()> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            Err(lanforge_core::error::CoreError::Generic(
                "always fails".into(),
            ))
        }
    }

    #[tokio::test]
    async fn resets_failure_counter_on_success() {
        init_context();
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        supervise_async(move || {
            let a = attempts_clone.clone();
            TestResetService { attempts: a }
        })
        .await;

        assert_eq!(attempts.load(Ordering::Relaxed), 4);
    }

    struct TestResetService {
        attempts: Arc<AtomicU32>,
    }
    impl lanforge_core::service::LanforgeService for TestResetService {
        fn meta(&self) -> lanforge_core::service::ServiceMeta {
            lanforge_core::service::ServiceMeta {
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
        async fn run(&mut self) -> lanforge_core::error::Result<()> {
            let n = self.attempts.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                Ok(())
            } else if n < 4 {
                Err(lanforge_core::error::CoreError::Generic(
                    "fails after success".into(),
                ))
            } else {
                Ok(())
            }
        }
    }
}
