use crate::app::sd_notify_ready;
use crate::bootstrap::BootstrapResult;
use crate::supervisor::GraphSupervisor;

use anyhow::Result;
use lanforge_core::bus::{LanforgeEvent, SystemEvent, TimedEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_types::system::{ServiceId, ServiceState};

use std::collections::HashSet;
use std::hash::BuildHasher;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::broadcast::{error::RecvError, Receiver};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// Tracks service settled states and emits `SystemReady` when all expected services are settled.
pub struct ReadinessTracker<'a, S> {
    ctx: &'a LanforgeContext,
    expected_services: HashSet<ServiceId, S>,
    ready_services: HashSet<ServiceId, S>,
    system_ready_sent: bool,
}

impl<'a, S: BuildHasher + Clone> ReadinessTracker<'a, S> {
    pub fn new(ctx: &'a LanforgeContext, expected_services: HashSet<ServiceId, S>) -> Self {
        let mut tracker = Self {
            ctx,
            ready_services: HashSet::with_hasher(expected_services.hasher().clone()),
            expected_services,
            system_ready_sent: false,
        };

        // Pre-seed any services that already settled before subscription
        for s in &tracker.expected_services {
            let st = ctx.get_service_state(*s);
            if is_settled_state(st) && tracker.ready_services.insert(*s) {
                debug!(
                    "Service '{}' pre-seeded settled ({:?}) ({}/{})",
                    s,
                    st,
                    tracker.ready_services.len(),
                    tracker.expected_services.len()
                );
            }
        }

        tracker.try_emit_system_ready();
        tracker
    }

    pub fn on_service_ready(&mut self, id: ServiceId) {
        if self.expected_services.contains(&id) && self.ready_services.insert(id) {
            if self.ctx.get_service_state(id) == ServiceState::Starting {
                self.ctx.set_service_state(id, ServiceState::Online);
            }
            debug!(
                "Service '{}' reported ready ({}/{})",
                id,
                self.ready_services.len(),
                self.expected_services.len()
            );
            self.try_emit_system_ready();
        }
    }

    pub fn try_emit_system_ready(&mut self) {
        if self.system_ready_sent {
            return;
        }

        let all_ready = self
            .expected_services
            .iter()
            .all(|s| self.ready_services.contains(s));

        if all_ready && !self.expected_services.is_empty() {
            self.system_ready_sent = true;
            info!(
                "All {} expected services settled. Emitting SystemReady.",
                self.expected_services.len()
            );
            let _ = self
                .ctx
                .bus()
                .publish(LanforgeEvent::System(SystemEvent::SystemReady));
            sd_notify_ready("READY=1\nSTATUS=Lanforge daemon is ready");
        }
    }

    pub fn check_pending(&mut self) {
        self.try_emit_system_ready();
        if !self.system_ready_sent {
            let mut missing: Vec<_> = self
                .expected_services
                .iter()
                .filter(|s| !self.ready_services.contains(s))
                .map(ServiceId::as_str)
                .collect();
            if !missing.is_empty() {
                missing.sort_unstable();
                warn!(
                    "Still waiting for {} services to settle: {:?}",
                    missing.len(),
                    missing
                );
            }
        }
    }
}

#[must_use]
pub const fn is_settled_state(st: ServiceState) -> bool {
    matches!(
        st,
        ServiceState::Online
            | ServiceState::Degraded
            | ServiceState::Inactive
            | ServiceState::Error
    )
}

pub async fn run_event_loop<S>(
    bootstrap: BootstrapResult,
    ctx: LanforgeContext,
    mut sys_rx: Receiver<TimedEvent>,
    mut net_rx: Receiver<TimedEvent>,
    expected_services: HashSet<ServiceId, S>,
    supervisor: &GraphSupervisor,
) -> Result<()>
where
    S: BuildHasher + Clone + Send + 'static,
{
    let cfg = bootstrap.cfg;

    let mut sigusr1 = signal(SignalKind::user_defined1())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;

    let stale_check_interval = Duration::from_secs(30);
    let mut stale_timer = interval(stale_check_interval);
    stale_timer.tick().await;

    let mut expected_sorted: Vec<_> = expected_services.iter().map(ServiceId::as_str).collect();
    expected_sorted.sort_unstable();
    info!(
        "Event loop: expecting readiness from {} services: {:?}",
        expected_sorted.len(),
        expected_sorted
    );

    let mut tracker = ReadinessTracker::new(&ctx, expected_services);

    let mut status_timer = interval(Duration::from_secs(10));
    status_timer.tick().await;

    loop {
        tokio::select! {
            _ = stale_timer.tick() => {
                #[cfg(feature = "discovery")]
                ctx.expire_stale(Duration::from_secs(cfg.monitor_toml.stale_timeout_secs));
            }
            _ = sigusr1.recv() => {
                info!("SIGUSR1 received; re-evaluating conditions");
                supervisor.reevaluate_conditions();
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received — starting graceful shutdown...");
                break;
            }
            _ = sigint.recv() => {
                info!("SIGINT received — starting graceful shutdown...");
                break;
            }
            _ = status_timer.tick() => {
                tracker.check_pending();
            }
            event = sys_rx.recv() => {
                match event {
                    Ok(timed_event) => {
                        match timed_event.event {
                            LanforgeEvent::System(SystemEvent::ServiceReady { id }) => {
                                tracker.on_service_ready(id);
                            }
                            LanforgeEvent::System(SystemEvent::ReloadConfig) => {
                                info!("ReloadConfig: in-place configuration reload");
                                supervisor.reevaluate_conditions();
                            }
                            LanforgeEvent::System(SystemEvent::ConfigUpdate { password_hash }) => {
                                let hash_path = cfg.get_password_hash_path();
                                info!("ConfigUpdate: Saving new API password hash to {:?}...", hash_path);
                                if let Err(e) = std::fs::write(&hash_path, password_hash) {
                                    error!("Failed to save password hash: {e}");
                                } else {
                                    info!("Configuration updated and saved to {:?}", hash_path);
                                }
                            }
                            LanforgeEvent::System(SystemEvent::Shutdown) => {
                                debug!("EventLoop: shutdown received via bus");
                                break;
                            }
                            _ => {}
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        warn!("EventBus (system): consumer lagged, lost {n} events");
                    }
                    Err(RecvError::Closed) => {
                        error!("EventBus (system): channel closed unexpectedly");
                        break;
                    }
                }
            }
            event = net_rx.recv() => {
                match event {
                    Ok(_) => {}
                    Err(RecvError::Lagged(n)) => {
                        warn!("EventBus (network): consumer lagged, lost {n} events");
                    }
                    Err(RecvError::Closed) => {
                        error!("EventBus (network): channel closed unexpectedly");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
