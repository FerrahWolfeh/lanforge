//! Service supervision and lifecycle management.
//!
//! This module defines the traits and types for managing long-running services
//! within the Lanforge system. Services are components that provide identity
//! and respond to external signals from the global event bus.
//!
//! # Service Types
//!
//! | Trait              | Execution Model | Use Case                        |
//! |--------------------|-----------------|---------------------------------|
//! | [`AsyncService`]   | Tokio async task | Network protocols, HTTP APIs    |
//! | [`SyncService`]    | Dedicated OS thread | Database workers, blocking I/O |
//!
//! # Service Lifecycle
//!
//! 1. **Initialization**: Service declares its [`ServiceMeta`]
//! 2. **Execution**: `run()` method is called by the service registry
//! 3. **Supervision**: Failures trigger exponential backoff restarts
//! 4. **Shutdown**: `on_shutdown()` is called for cleanup
//!
//! # Example
//!
//! ```rust
//! use lanforge_core::service::{AsyncService, LanforgeService, ServiceMeta, ServiceControl};
//! use lanforge_core::error::CoreError;
//! use std::time::Duration;
//!
//! struct MyService;
//!
//! impl LanforgeService for MyService {
//!     fn meta(&self) -> ServiceMeta {
//!         ServiceMeta {
//!             id: "my-service",
//!             display_name: "My Service",
//!             critical: true,
//!             max_retries: 3,
//!             base_backoff: Duration::from_secs(1),
//!             max_backoff: Duration::from_secs(30),
//!             stack_kb: 256,
//!         }
//!     }
//! }
//!
//! impl AsyncService for MyService {
//!     async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
//!         ctrl.signal_ready();
//!         // Service main loop
//!         Ok(())
//!     }
//! }
//! ```

use crate::bus::TimedEvent;
use crate::context::LanforgeContext;
use crate::error::CoreError;
use std::future::Future;
use std::sync::mpsc::Receiver;
use std::time::Duration;

/// Supervision metadata for a service.
///
/// Services declare this via `LanforgeService::meta()` instead of
/// the caller passing 6 loose parameters to `supervise_async/supervise_sync`.
///
/// # Fields
///
/// | Field           | Description                                      | Example             |
/// |-----------------|--------------------------------------------------|---------------------|
/// | `id`            | Stable identifier for readiness tracking         | "ra", "dhcpv4", "db"|
/// | `display_name`  | Human-readable name for OS thread (shows in htop)| "RA Server"         |
/// | `critical`      | If true, system exits when retries exhausted     | `true` for DB       |
/// | `max_retries`   | Max restarts before giving up (0 = unlimited)    | 3                   |
/// | `base_backoff`  | Initial backoff on failure (doubles per retry)   | 1 second            |
/// | `max_backoff`   | Maximum backoff cap                              | 30 seconds          |
/// | `stack_kb`      | Stack size for sync service's OS thread (KiB)    | 256                 |
///
/// # Backoff Strategy
///
/// On each failure, the service waits: `min(base_backoff * 2^attempt, max_backoff)`
/// For example, with `base_backoff=1s` and `max_backoff=30s`:
/// - Attempt 0: 1s
/// - Attempt 1: 2s
/// - Attempt 2: 4s
/// - Attempt 3: 8s
/// - Attempt 4+: 16s → capped at 30s
///
/// # Example
///
/// ```rust
/// use lanforge_core::service::ServiceMeta;
/// use std::time::Duration;
///
/// let meta = ServiceMeta {
///     id: "dhcpv6",
///     display_name: "DHCPv6 Server",
///     critical: false, // Non-critical, can retry indefinitely
///     max_retries: 0,  // Unlimited
///     base_backoff: Duration::from_secs(2),
///     max_backoff: Duration::from_secs(60),
///     stack_kb: 512,
/// };
/// ```
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
///
/// # Implementing
///
/// All services must:
/// 1. Implement [`meta()`](LanforgeService::meta) to declare supervision config
/// 2. Optionally override [`describe()`](LanforgeService::describe) for logging
/// 3. Optionally override [`on_shutdown()`](LanforgeService::on_shutdown) for cleanup
/// 4. Implement either [`AsyncService`] or [`SyncService`] for execution
///
/// # Thread Safety
///
/// Services must be `Send + Sync` as they may be accessed from multiple threads.
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
    fn on_shutdown(&mut self) -> Result<(), CoreError> {
        Ok(())
    }
}

/// A service that executes within a Tokio asynchronous task.
///
/// This trait desugars the `run` method to ensure the resulting Future is `Send`,
/// which is required for spawning the service in a multi-threaded Tokio runtime.
///
/// # Guidelines
///
/// Services implementing this trait should:
/// 1. Use the [`LanforgeContext`] to access the [`EventBus`](crate::bus::EventBus) and global state
/// 2. Listen for the `LanforgeEvent::Shutdown` signal on the bus to exit `run`
/// 3. Prefer native async I/O (`tokio::net`) over synchronous blocking calls
/// 4. Handle errors gracefully — unrecoverable errors should return `Err(CoreError)`
///
/// # Example
///
/// ```rust
/// use lanforge_core::service::{AsyncService, LanforgeService, ServiceMeta, ServiceControl};
/// use lanforge_core::context::LanforgeContext;
/// use lanforge_core::error::CoreError;
/// use lanforge_core::bus::LanforgeEvent;
/// use std::time::Duration;
///
/// struct MyAsyncService {
///     ctx: LanforgeContext,
/// }
///
/// impl LanforgeService for MyAsyncService {
///     fn meta(&self) -> ServiceMeta {
///         ServiceMeta {
///             id: "my-async",
///             display_name: "My Async Service",
///             critical: false,
///             max_retries: 5,
///             base_backoff: Duration::from_secs(1),
///             max_backoff: Duration::from_secs(10),
///             stack_kb: 256,
///         }
///     }
/// }
///
/// impl AsyncService for MyAsyncService {
///     async fn run(&mut self, ctrl: ServiceControl) -> Result<(), CoreError> {
///         ctrl.signal_ready();
///         let mut rx = self.ctx.bus().subscribe();
///         loop {
///             match rx.recv().await {
///                 Ok(timed) => {
///                     if matches!(timed.event, LanforgeEvent::Shutdown) {
///                         break;
///                     }
///                     // Handle events...
///                 }
///                 Err(_) => break, // Bus closed
///             }
///         }
///         Ok(())
///     }
/// }
/// ```
pub trait AsyncService: LanforgeService {
    /// Runs the service's main loop asynchronously.
    ///
    /// # Errors
    /// Returns `CoreError` if the service execution fails and cannot be recovered.
    fn run(&mut self, ctrl: ServiceControl) -> impl Future<Output = Result<(), CoreError>> + Send;
}

/// A thread-safe receiver for `EventBus` events in synchronous contexts.
///
/// Wraps the `std::sync::mpsc` channel that the `ServiceRegistry` bridges
/// from the async `EventBus`. Provides convenience methods for common
/// patterns like shutdown detection and dependency waiting.
///
/// # Usage
///
/// This is provided to [`SyncService::run`] by the supervisor — services
/// should not create their own instances.
///
/// # Example
///
/// ```rust
/// use lanforge_core::service::SyncBusReceiver;
/// use std::time::Duration;
///
/// fn process_events(rx: &SyncBusReceiver) {
///     // Non-blocking drain
///     let events = rx.try_recv_all();
///     for event in events {
///         // Handle event...
///     }
///
///     // Or block with timeout
///     if let Some(timed) = rx.recv_timeout(Duration::from_secs(1)) {
///         // Handle event...
///     }
/// }
/// ```
pub struct SyncBusReceiver {
    rx: Receiver<TimedEvent>,
    ctx: LanforgeContext,
}

impl SyncBusReceiver {
    #[must_use]
    pub const fn new(rx: Receiver<TimedEvent>, ctx: LanforgeContext) -> Self {
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
    pub const fn ctx(&self) -> &LanforgeContext {
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
/// # Guidelines
///
/// Services implementing this trait should:
/// 1. Use the provided [`SyncBusReceiver`] for communication (do not create your own channel)
/// 2. Check for shutdown signals periodically via [`SyncBusReceiver::recv_timeout`]
/// 3. Use [`SyncBusReceiver::wait_for_interfaces`] and [`SyncBusReceiver::wait_for_db`]
///    to wait for dependencies before starting work
/// 4. Avoid long-running blocking operations that would delay shutdown detection
///
/// # Example
///
/// ```rust
/// use lanforge_core::service::{SyncService, LanforgeService, ServiceMeta, SyncBusReceiver, ServiceControl};
/// use lanforge_core::error::CoreError;
/// use std::time::Duration;
///
/// struct MySyncService;
///
/// impl LanforgeService for MySyncService {
///     fn meta(&self) -> ServiceMeta {
///         ServiceMeta {
///             id: "my-sync",
///             display_name: "My Sync Service",
///             critical: true,
///             max_retries: 0,
///             base_backoff: Duration::from_secs(1),
///             max_backoff: Duration::from_secs(30),
///             stack_kb: 512,
///         }
///     }
/// }
///
/// impl SyncService for MySyncService {
///     fn run(&mut self, ctrl: ServiceControl, bus_rx: &SyncBusReceiver) -> Result<(), CoreError> {
///         ctrl.signal_ready();
///
///         // Wait for dependencies
///         bus_rx.wait_for_interfaces();
///         bus_rx.wait_for_db();
///
///         // Main loop
///         loop {
///             if let Some(timed) = bus_rx.recv_timeout(Duration::from_secs(1)) {
///                 // Handle event or check shutdown
///             }
///             // Do work...
///         }
///     }
/// }
/// ```
pub trait SyncService: LanforgeService {
    /// Runs the service's main loop synchronously.
    ///
    /// The `bus_rx` receiver is provided by the supervisor/registry — the service
    /// does not need to create or manage its own bridge channel.
    ///
    /// # Errors
    /// Returns `CoreError` if the service execution fails.
    fn run(&mut self, ctrl: ServiceControl, bus_rx: &SyncBusReceiver) -> Result<(), CoreError>;
}

/// A handle provided to services to control their lifecycle and signal readiness.
pub struct ServiceControl {
    id: &'static str,
    ctx: LanforgeContext,
    signaled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ServiceControl {
    /// Creates a new service control handle.
    #[must_use]
    pub fn new(id: &'static str, ctx: LanforgeContext) -> Self {
        Self {
            id,
            ctx,
            signaled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Signals that the service is now fully initialized and ready to handle traffic.
    /// This is idempotent; multiple calls will only result in one signal.
    pub fn signal_ready(&self) {
        if !self
            .signaled
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            let _ = self
                .ctx
                .bus()
                .publish(crate::bus::LanforgeEvent::ServiceReady {
                    name: self.id.to_string(),
                });
        }
    }

    /// Returns the ID of the service this handle belongs to.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        self.id
    }
}
