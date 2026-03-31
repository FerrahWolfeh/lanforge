use crate::bus::LanforgeEvent;
use crate::error::Result;

/// Core trait defining a service within the Lanforge system.
///
/// A service is a component that provides identity and responds to
/// external signals from the global event bus.
pub trait LanforgeService: Send + Sync {
    /// Returns the human-readable name of the service.
    fn name(&self) -> &str;

    /// Called when an event is received from the system bus.
    ///
    /// This allows services to react to `ReloadConfig`, `DbVacuum`, etc.
    ///
    /// # Errors
    /// Returns `CoreError` if the signal handling fails.
    fn on_event(&mut self, _event: &LanforgeEvent) -> Result<()> {
        Ok(())
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
/// 1. Use the `LanforgeContext` to access the `EventBus` and `ManagedTable`.
/// 2. Listen for the `LanforgeEvent::Shutdown` signal on the bus to exit `run`.
/// 3. Prefer native async I/O (`tokio::net`) over synchronous blocking calls.
pub trait AsyncService: LanforgeService {
    /// Runs the service's main loop asynchronously.
    ///
    /// # Errors
    /// Returns `CoreError` if the service execution fails and cannot be recovered.
    fn run(&mut self) -> impl std::future::Future<Output = Result<()>> + Send;
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
    /// # Errors
    /// Returns `CoreError` if the service execution fails.
    fn run(&mut self) -> Result<()>;
}
