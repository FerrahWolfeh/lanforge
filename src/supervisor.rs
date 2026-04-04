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
use std::time::Duration;
use tracing::{error, info, warn};

/// Executa uma task supervisionada que implementa `AsyncService`.
pub async fn supervise_async<S, F>(
    name: &'static str,
    critical: bool,
    max_retries: u32,
    base_backoff: Duration,
    max_backoff: Duration,
    factory: F,
) where
    S: lanforge_core::service::AsyncService,
    F: Fn() -> S,
{
    let mut consecutive_failures: u32 = 0;

    loop {
        info!("Starting async service '{name}'");
        let mut service = factory();

        let mut bus_rx = LanforgeContext::bus().subscribe();
        tokio::select! {
            _event = async {
                while let Ok(e) = bus_rx.recv().await {
                    if matches!(e, LanforgeEvent::Shutdown) {
                        return;
                    }
                }
            } => {
                info!("Supervisor '{name}' received shutdown signal via bus, stopping");
                if let Err(e) = service.on_shutdown() {
                    error!("Error during async service '{name}' shutdown: {e}");
                }
                return;
            }
            res = service.run() => {
                match res {
                    Ok(()) => {
                        if !LanforgeContext::is_running() {
                            info!("Supervisor '{name}' shutting down after clean service exit");
                            return;
                        }
                        info!("Async service '{name}' exited cleanly, restarting");
                        consecutive_failures = 0;
                    }
                    Err(e) => {
                        consecutive_failures += 1;
                        error!("Async service '{name}' failed ({consecutive_failures}x): {e:#}");

                        if max_retries > 0 && consecutive_failures >= max_retries {
                            if critical {
                                error!(
                                    "Critical async service '{name}' exhausted {max_retries} retries — aborting process"
                                );
                                std::process::exit(1);
                            } else {
                                warn!(
                                    "Non-critical async service '{name}' exhausted {max_retries} retries — giving up"
                                );
                                return;
                            }
                        }

                        let exp = base_backoff.saturating_mul(1 << (consecutive_failures - 1).min(16));
                        let backoff = exp.min(max_backoff);

                        warn!(
                            "Restarting async service '{name}' in {:.1}s (attempt {}/{})",
                            backoff.as_secs_f64(),
                            consecutive_failures + 1,
                            if max_retries == 0 { "∞".into() } else { max_retries.to_string() }
                        );

                        tokio::select! {
                            _ = async {
                                while let Ok(e) = bus_rx.recv().await {
                                    if matches!(e, LanforgeEvent::Shutdown) {
                                        return;
                                    }
                                }
                            } => {
                                info!("Supervisor '{name}' received shutdown signal during backoff, stopping");
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
pub fn supervise_sync<S, F>(
    name: &'static str,
    critical: bool,
    max_retries: u32,
    base_backoff: Duration,
    max_backoff: Duration,
    factory: F,
) where
    S: lanforge_core::service::SyncService,
    F: Fn() -> S,
{
    let mut consecutive_failures: u32 = 0;

    loop {
        if !LanforgeContext::is_running() {
            info!("Supervisor (sync) '{name}' received shutdown, stopping before start");
            return;
        }

        info!("Starting sync service '{name}'");
        let mut service = factory();

        let res = service.run();

        match res {
            Ok(()) => {
                if !LanforgeContext::is_running() {
                    info!("Supervisor (sync) '{name}' shutting down after clean service exit");
                    return;
                }
                info!("Sync service '{name}' exited cleanly, restarting");
                consecutive_failures = 0;
            }
            Err(e) => {
                consecutive_failures += 1;
                error!("Sync service '{name}' failed ({consecutive_failures}x): {e:#}");

                if max_retries > 0 && consecutive_failures >= max_retries {
                    if critical {
                        error!(
                            "Critical sync service '{name}' exhausted {max_retries} retries — aborting"
                        );
                        std::process::exit(1);
                    } else {
                        warn!(
                            "Non-critical sync service '{name}' exhausted {max_retries} retries — giving up"
                        );
                        return;
                    }
                }

                let exp = base_backoff.saturating_mul(1 << (consecutive_failures - 1).min(16));
                let backoff = exp.min(max_backoff);

                warn!(
                    "Restarting sync service '{name}' in {:.1}s (attempt {}/{})",
                    backoff.as_secs_f64(),
                    consecutive_failures + 1,
                    if max_retries == 0 {
                        "∞".into()
                    } else {
                        max_retries.to_string()
                    }
                );

                // No supervisor síncrono, fazemos sleep da thread.
                // Verificamos o cancelamento antes e depois do sleep.
                let start = std::time::Instant::now();
                while start.elapsed() < backoff {
                    if !LanforgeContext::is_running() {
                        info!("Supervisor (sync) '{name}' received shutdown during backoff");
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

        supervise_async(
            "test-service",
            false, // non-critical
            3,     // max 3 retries
            Duration::from_millis(1),
            Duration::from_millis(10),
            move || {
                let a = attempts_clone.clone();
                TestAsyncService { attempts: a }
            },
        )
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
        fn name(&self) -> &str {
            "test"
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

        supervise_async(
            "test-reset",
            false,
            3,
            Duration::from_millis(1),
            Duration::from_millis(10),
            move || {
                let a = attempts_clone.clone();
                TestResetService { attempts: a }
            },
        )
        .await;

        assert_eq!(attempts.load(Ordering::Relaxed), 4);
    }

    struct TestResetService {
        attempts: Arc<AtomicU32>,
    }
    impl lanforge_core::service::LanforgeService for TestResetService {
        fn name(&self) -> &str {
            "test-reset"
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
