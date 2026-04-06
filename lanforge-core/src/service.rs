use crate::bus::TimedEvent;
use crate::error::Result;
use std::time::Duration;

/// Supervision metadata for a service.
/// Services declare this via `LanforgeService::meta()` instead of
/// the caller passing 6 loose parameters to `supervise_async/supervise_sync`.
pub struct ServiceMeta {
    /// Stable identifier used for readiness tracking, logging, and
    /// `ServiceReady` events. Examples: "ra", "dhcpv4", "db", "monitor".
    pub id: &'static str,

    /// Human-readable name used for the OS thread. Shows in htop/ps.
    /// Examples: "RA Server", "`DHCPv4` Server", "DB Worker".
    pub display_name: &'static str,

    /// If true, the process exits when retries are exhausted.
    pub critical: bool,

    /// Maximum retries before giving up (0 = unlimited restarts).
    pub max_retries: u32,

    /// Base backoff duration on failure (doubles per failure).
    pub base_backoff: Duration,

    /// Maximum backoff cap.
    pub max_backoff: Duration,

    /// Stack size for the service's dedicated OS thread, in KiB.
    pub stack_kb: usize,
}

/// Core trait defining a service within the Lanforge system.
///
/// A service is a component that provides identity and responds to
/// external signals from the global event bus.
pub trait LanforgeService: Send + Sync {
    /// Returns the service's supervision metadata.
    fn meta(&self) -> ServiceMeta;

    /// Returns a one-line description of this service instance for logging.
    /// Override to include service-specific configuration details.
    fn describe(&self) -> String {
        self.meta().display_name.to_string()
    }

    /// Called when the system is shutting down or the service should deinitialize.
    ///
    /// This is where the service should perform final logging, cleanup resources,
    /// or commit any pending state before being dropped.
    ///
    /// # Errors
    /// Returns `CoreError` if the shutdown procedure fails.
    fn on_shutdown(&mut self) -> Result<()> {
        Ok(())
    }
}

/// A service that executes within a Tokio asynchronous task.
///
/// This trait desugars the `run` method to ensure the resulting Future is `Send`,
/// which is required for spawning the service in a multi-threaded Tokio runtime.
///
/// Services implementing this trait should:
/// 1. Use the `LanforgeContext` to access the `EventBus` and global state.
/// 2. Listen for the `LanforgeEvent::Shutdown` signal on the bus to exit `run`.
/// 3. Prefer native async I/O (`tokio::net`) over synchronous blocking calls.
pub trait AsyncService: LanforgeService {
    /// Runs the service's main loop asynchronously.
    ///
    /// # Errors
    /// Returns `CoreError` if the service execution fails and cannot be recovered.
    fn run(&mut self) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// A thread-safe receiver for `EventBus` events in synchronous contexts.
///
/// Wraps the `std::sync::mpsc` channel that the `ServiceRegistry` bridges
/// from the async `EventBus`. Provides convenience methods for common
/// patterns like shutdown detection and dependency waiting.
pub struct SyncBusReceiver {
    rx: std::sync::mpsc::Receiver<TimedEvent>,
    ctx: crate::context::LanforgeContext,
}

impl SyncBusReceiver {
    #[must_use]
    pub const fn new(
        rx: std::sync::mpsc::Receiver<TimedEvent>,
        ctx: crate::context::LanforgeContext,
    ) -> Self {
        Self { rx, ctx }
    }

    /// Blocking receive with timeout.
    #[must_use]
    pub fn recv_timeout(&self, timeout: Duration) -> Option<TimedEvent> {
        self.rx.recv_timeout(timeout).ok()
    }

    /// Non-blocking drain of all pending events.
    #[must_use]
    pub fn try_recv_all(&self) -> Vec<TimedEvent> {
        let mut events = Vec::new();
        while let Ok(e) = self.rx.try_recv() {
            events.push(e);
        }
        events
    }

    /// Provides access to the injected `LanforgeContext`.
    #[must_use]
    pub const fn ctx(&self) -> &crate::context::LanforgeContext {
        &self.ctx
    }

    /// Blocks until `InterfaceReady` is received (or shutdown).
    pub fn wait_for_interfaces(&self) {
        self.ctx.wait_for_interfaces_sync(&self.rx);
    }

    /// Blocks until `DbReady` is received (or shutdown).
    pub fn wait_for_db(&self) {
        self.ctx.wait_for_db_sync(&self.rx);
    }
}

/// A service that executes within a dedicated synchronous OS thread.
///
/// This trait is for services that must remain purely synchronous (like the DB worker)
/// or that interact with blocking APIs without a Tokio runtime.
///
/// Services implementing this trait should:
/// 1. Use the `LanforgeContext` and `std::sync::mpsc` for communication.
/// 2. Check for shutdown signals periodically.
pub trait SyncService: LanforgeService {
    /// Runs the service's main loop synchronously.
    ///
    /// The `bus_rx` receiver is provided by the supervisor/registry — the service
    /// does not need to create or manage its own bridge channel.
    ///
    /// # Errors
    /// Returns `CoreError` if the service execution fails.
    fn run(&mut self, bus_rx: &SyncBusReceiver) -> Result<()>;
}
