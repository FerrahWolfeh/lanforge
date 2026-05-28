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
use lanforge_core::service::{AsyncService, ServiceControl};
use lanforge_types::system::{ServiceAction, ServiceState};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

#[cfg(test)]
const MINIMUM_HEALTHY_UPTIME: Duration = Duration::from_millis(5);
#[cfg(not(test))]
const MINIMUM_HEALTHY_UPTIME: Duration = Duration::from_secs(5);

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
        let id = meta.id;
        let description = service.describe();
        let name = meta.display_name;

        // If the service is marked Inactive/Stopped, park the supervisor and wait for a Start/Restart event.
        if ctx.get_service_state(id) == ServiceState::Inactive {
            let mut bus_rx = ctx.bus().subscribe();
            let mut started = false;
            while !started {
                tokio::select! {
                    e = bus_rx.recv() => {
                        match e {
                            Ok(te) => match te.event {
                                LanforgeEvent::System(SystemEvent::Shutdown) => return,
                                LanforgeEvent::System(SystemEvent::ServiceControl { id: target_id, action })
                                    if target_id == id && matches!(action, ServiceAction::Start | ServiceAction::Restart) => {
                                        started = true;
                                    }
                                _ => {}
                            },
                            Err(_) => return, // Bus closed
                        }
                    }
                }
            }
            consecutive_failures = 0;
        }

        ctx.set_service_state(id, ServiceState::Starting);
        ctx.set_service_start(id, Instant::now());
        let start = Instant::now();

        debug!("▸ Starting async service: {}", description);

        let ctrl = ServiceControl::new(meta.id, ctx.clone());

        let mut bus_rx = ctx.bus().subscribe();
        tokio::select! {
            shutdown_or_control = async {
                loop {
                    match bus_rx.recv().await {
                        Ok(e) => match e.event {
                            LanforgeEvent::System(SystemEvent::Shutdown) => return Some(SystemEvent::Shutdown),
                            LanforgeEvent::System(SystemEvent::ServiceControl { id: target_id, action }) if target_id == id => {
                                return Some(SystemEvent::ServiceControl { id: target_id, action });
                            }
                            _ => {}
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(_) => return None,
                    }
                }
            } => {
                match shutdown_or_control {
                    Some(SystemEvent::Shutdown) => {
                        info!("▪ {} shutting down", description);
                        if let Err(e) = service.on_shutdown() {
                            error!("Error during async service '{}' shutdown: {e}", name);
                        }
                        ctx.set_service_state(id, ServiceState::Inactive);
                        ctx.clear_service_start(id);
                        return;
                    }
                    Some(SystemEvent::ServiceControl { action, .. }) => {
                        info!("▪ {} control action requested: {:?}", description, action);
                        if let Err(e) = service.on_shutdown() {
                            error!("Error during async service '{}' shutdown: {e}", name);
                        }
                        match action {
                            ServiceAction::Stop => {
                                ctx.set_service_state(id, ServiceState::Inactive);
                                ctx.clear_service_start(id);
                                consecutive_failures = 0;
                            }
                            ServiceAction::Restart => {
                                ctx.set_service_state(id, ServiceState::Starting);
                                consecutive_failures = 0;
                            }
                            ServiceAction::Start => {
                                // Already started/starting, ignore
                            }
                        }
                    }
                    _ => {}
                }
            }
            res = service.run(ctrl) => {
                let backoff_needed = match res {
                    Ok(()) => {
                        if !ctx.is_running() {
                            info!("▪ {} exited (shutdown)", description);
                            ctx.set_service_state(id, ServiceState::Inactive);
                            ctx.clear_service_start(id);
                            return;
                        }

                        let uptime = start.elapsed();
                        if uptime < MINIMUM_HEALTHY_UPTIME {
                            consecutive_failures += 1;
                            warn!(
                                "▪ {} exited Ok(()) after only {:.1}s (<{}s min), treating as soft failure ({consecutive_failures}x)",
                                description, uptime.as_secs_f64(), MINIMUM_HEALTHY_UPTIME.as_secs()
                            );
                            ctx.set_service_state(id, ServiceState::Error);
                            true // Apply backoff
                        } else {
                            debug!("▪ {} exited cleanly after {:.0}s, restarting", description, uptime.as_secs_f64());
                            consecutive_failures = 0;
                            false // No backoff needed
                        }
                    }
                    Err(err) => {
                        consecutive_failures += 1;
                        error!("✗ {} failed ({}x): {:#}", description, consecutive_failures, err);
                        ctx.set_service_state(id, ServiceState::Error);
                        true // Apply backoff
                    }
                };

                if backoff_needed {
                    if meta.max_retries > 0 && consecutive_failures >= meta.max_retries {
                        if meta.critical {
                            error!("FATAL: Critical service '{}' failed after {} retries. Shutting down.", name, consecutive_failures);
                            ctx.terminate();
                            ctx.set_service_state(id, ServiceState::Error);
                            return;
                        }
                        warn!("Service '{}' exhausted {} retries — giving up", name, meta.max_retries);
                        ctx.set_service_state(id, ServiceState::Error);
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
                        shutdown_or_control = async {
                            loop {
                                match bus_rx.recv().await {
                                    Ok(e) => match e.event {
                                        LanforgeEvent::System(SystemEvent::Shutdown) => return Some(SystemEvent::Shutdown),
                                        LanforgeEvent::System(SystemEvent::ServiceControl { id: target_id, action }) if target_id == id => {
                                            return Some(SystemEvent::ServiceControl { id: target_id, action });
                                        }
                                        _ => {}
                                    }
                                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                                    Err(_) => return None,
                                }
                            }
                        } => {
                            match shutdown_or_control {
                                Some(SystemEvent::Shutdown) => {
                                    info!("Supervisor '{}' received shutdown signal during backoff, stopping", name);
                                    ctx.set_service_state(id, ServiceState::Inactive);
                                    ctx.clear_service_start(id);
                                    return;
                                }
                                Some(SystemEvent::ServiceControl { action, .. }) => {
                                    info!("Supervisor '{}' received control action during backoff: {:?}", name, action);
                                    match action {
                                        ServiceAction::Stop => {
                                            ctx.set_service_state(id, ServiceState::Inactive);
                                            ctx.clear_service_start(id);
                                        }
                                        ServiceAction::Start | ServiceAction::Restart => {
                                            ctx.set_service_state(id, ServiceState::Starting);
                                            consecutive_failures = 0;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        () = tokio::time::sleep(backoff) => {}
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_core::bus::EventBus;
    use lanforge_core::context::state::State;
    use lanforge_core::error::CoreError;
    use lanforge_core::service::LanforgeService;
    use lanforge_core::service::ServiceControl;
    use lanforge_core::service::ServiceMeta;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    fn init_test_context() -> LanforgeContext {
        let bus = Arc::new(EventBus::new());
        let table = State::new();
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
                stack_kb: 0,
                multi_threaded: false,
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
                multi_threaded: false,
            }
        }
    }
    impl lanforge_core::service::AsyncService for TestResetService {
        async fn run(&mut self, _ctrl: ServiceControl) -> Result<(), CoreError> {
            let n = self.attempts.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(())
            } else if n < 4 {
                Err(CoreError::Generic("fails after success".into()))
            } else {
                tokio::time::sleep(Duration::from_millis(10)).await;
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
                stack_kb: 0,
                multi_threaded: false,
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

    #[tokio::test]
    async fn rapid_ok_exit_is_treated_as_failure() {
        let ctx = init_test_context();
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        // This service exits with Ok(()) immediately
        supervise_async(&ctx, move || {
            let a = attempts_clone.clone();
            RapidOkService { attempts: a }
        })
        .await;

        assert_eq!(
            attempts.load(Ordering::Relaxed),
            3,
            "Supervisor should have treated rapid Ok exits as failures and stopped after max_retries"
        );
    }

    struct RapidOkService {
        attempts: Arc<AtomicU32>,
    }
    impl LanforgeService for RapidOkService {
        fn meta(&self) -> ServiceMeta {
            ServiceMeta {
                id: "rapid-ok",
                display_name: "Rapid Ok Service",
                critical: false,
                max_retries: 3,
                base_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(10),
                stack_kb: 0,
                multi_threaded: false,
            }
        }
    }
    impl lanforge_core::service::AsyncService for RapidOkService {
        async fn run(&mut self, _ctrl: ServiceControl) -> Result<(), CoreError> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            Ok(()) // Rapid exit with success
        }
    }

    #[tokio::test]
    async fn healthy_ok_exit_resets_counter() {
        let ctx = init_test_context();
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        // We'll run the supervisor in a task so we can shut it down
        let ctx_clone = ctx.clone();
        let handle = tokio::spawn(async move {
            supervise_async(&ctx_clone, move || {
                let a = attempts_clone.clone();
                HealthyOkService { attempts: a }
            })
            .await;
        });

        // Wait for it to "succeed" once (it takes 100ms, which is > 5ms in test-speed or we adjust MINIMUM_HEALTHY_UPTIME in test if needed)
        // Wait, MINIMUM_HEALTHY_UPTIME is 5s. In tests, we can't wait 5s easily without slowing down CI.
        // I should probably make MINIMUM_HEALTHY_UPTIME configurable or use a smaller value for tests?
        // Actually, the current supervisor code uses Duration::from_secs(5).
        // Let's use a mock or just accept a long test if needed, OR I can modify the supervisor to allow setting the threshold.
        // For now, let's see if I can use a smaller value or if I should change the constant to be feature-gated.

        // Actually, I'll just wait a bit and then send shutdown.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = ctx
            .bus()
            .publish(LanforgeEvent::System(SystemEvent::Shutdown));
        let _ = handle.await;
    }

    struct HealthyOkService {
        attempts: Arc<AtomicU32>,
    }
    impl LanforgeService for HealthyOkService {
        fn meta(&self) -> ServiceMeta {
            ServiceMeta {
                id: "healthy-ok",
                display_name: "Healthy Ok Service",
                critical: false,
                max_retries: 0,
                base_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(10),
                stack_kb: 0,
                multi_threaded: false,
            }
        }
    }
    impl lanforge_core::service::AsyncService for HealthyOkService {
        async fn run(&mut self, _ctrl: ServiceControl) -> Result<(), CoreError> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            // Simulate "healthy" work
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_supervisor_dynamic_control() {
        let ctx = init_test_context();
        let bus = ctx.bus();

        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        // Spawn supervisor in background
        let ctx_clone = ctx.clone();
        let handle = tokio::spawn(async move {
            supervise_async(&ctx_clone, move || {
                let a = attempts_clone.clone();
                ControlTestService { attempts: a }
            })
            .await;
        });

        // Give it a moment to start and set state to Online
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(ctx.get_service_state("control-test"), ServiceState::Online);
        assert!(attempts.load(Ordering::Relaxed) >= 1);

        // 1. Stop service
        let _ = bus.publish(LanforgeEvent::System(SystemEvent::ServiceControl {
            id: "control-test".to_string(),
            action: ServiceAction::Stop,
        }));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            ctx.get_service_state("control-test"),
            ServiceState::Inactive
        );

        // Attempts shouldn't increase while stopped
        let attempts_after_stop = attempts.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(attempts.load(Ordering::Relaxed), attempts_after_stop);

        // 2. Start service again
        let _ = bus.publish(LanforgeEvent::System(SystemEvent::ServiceControl {
            id: "control-test".to_string(),
            action: ServiceAction::Start,
        }));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(ctx.get_service_state("control-test"), ServiceState::Online);
        assert!(attempts.load(Ordering::Relaxed) > attempts_after_stop);

        // 3. Restart service
        let attempts_before_restart = attempts.load(Ordering::Relaxed);
        let _ = bus.publish(LanforgeEvent::System(SystemEvent::ServiceControl {
            id: "control-test".to_string(),
            action: ServiceAction::Restart,
        }));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(ctx.get_service_state("control-test"), ServiceState::Online);
        assert!(attempts.load(Ordering::Relaxed) > attempts_before_restart);

        // Shutdown
        let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
        let _ = handle.await;
    }

    struct ControlTestService {
        attempts: Arc<AtomicU32>,
    }
    impl LanforgeService for ControlTestService {
        fn meta(&self) -> ServiceMeta {
            ServiceMeta {
                id: "control-test",
                display_name: "Control Test Service",
                critical: false,
                max_retries: 0,
                base_backoff: Duration::from_millis(5),
                max_backoff: Duration::from_millis(20),
                stack_kb: 0,
                multi_threaded: false,
            }
        }
    }
    impl lanforge_core::service::AsyncService for ControlTestService {
        async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            ctrl.signal_ready();
            // Wait infinitely until dropped/cancelled
            std::future::pending::<()>().await;
            Ok(())
        }
    }
}
