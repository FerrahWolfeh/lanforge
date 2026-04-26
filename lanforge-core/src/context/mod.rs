//! `LanforgeContext` — Thread-safe central state and event coordination.
//!
//! This module provides the main entry point for all system state mutations
//! and event publishing. It wraps the device [`State`](state::State) in a
//! `parking_lot::RwLock` and provides a unified API for reading and writing.
//!
//! # Architecture
//!
//! ```mermaid
//! graph TD
//!     A[LanforgeContext] --> B[Arc&lt;LanforgeContextInner&gt;]
//!     B --> C[EventBus]
//!     B --> D[RwLock&lt;State&gt;]
//!     B --> E[Atomic Flags]
//!     B --> F[target_ifindex]
//! ```
//!
//! # Key Components
//!
//! | Submodule | Purpose |
//! |-----------|---------|
//! | [`read`]  | Read-only queries (get device by MAC, IP, hostname) |
//! | [`write`] | State mutations (apply updates, allocate leases) |
//! | [`state`] | Raw device state and interface storage |
//! | [`utils`] | Helper functions for update-to-event conversion |
//!
//! # Usage Pattern
//!
//! ```rust
//! use lanforge_core::context::LanforgeContext;
//! use lanforge_core::state::State;
//! use lanforge_core::bus::EventBus;
//! use std::sync::Arc;
//!
//! let bus = Arc::new(EventBus::new());
//! let state = State::new();
//! let ctx = LanforgeContext::new(bus, state, None);
//!
//! // Read
//! let devices = ctx.all_devices();
//!
//! // Write
//! // ctx.apply(&DeviceUpdate::...);
//! ```
//!
//! # Thread Safety
//!
//! All operations are thread-safe. Multiple readers can access state
//! concurrently, while writes acquire an exclusive lock.
//!
//! # Lifecycle Management
//!
//! The context tracks readiness states:
//! - **DB Ready**: Database worker is active
//! - **Interface Ready**: Network interfaces are configured
//! - **Running**: System is operational (false = shutdown)

use crate::bus::{EventBus, LanforgeEvent, TimedEvent};
use crate::error::CoreError;
use crate::state::State;
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::SystemTime;

pub mod read;
pub mod state;
pub mod utils;
pub mod write;

use std::sync::atomic::AtomicU64;

/// Internal counters for tracking transient network events.
///
/// These are exported via Prometheus to monitor discovery rates.
#[derive(Debug, Default)]
pub struct EventCounters {
    pub arp_seen: AtomicU64,
    pub ndp_seen: AtomicU64,
    pub slaac_observed: AtomicU64,
    pub dhcp_v4_leases: AtomicU64,
    pub dhcp_v6_leases: AtomicU64,
    pub dns_auth_hits: AtomicU64,
    #[cfg(feature = "adblock")]
    pub dns_blocked: AtomicU64,
}

#[derive(Clone)]
pub struct LanforgeContext {
    inner: Arc<LanforgeContextInner>,
}

/// Internal state shared behind an `Arc`.
///
/// This is intentionally private to enforce access patterns — all interaction
/// goes through the typed methods on [`LanforgeContext`].
struct LanforgeContextInner {
    /// The event bus for broadcasting state changes.
    bus: Arc<EventBus>,
    /// The device and interface state, protected by an `RwLock`.
    state: RwLock<state::State>,
    /// The network interface index to monitor for RA/DHCP.
    target_ifindex: Option<u32>,
    /// System running flag — set to false on shutdown.
    running: AtomicBool,
    /// Database readiness flag.
    db_ready: AtomicBool,
    /// Network interface readiness flag.
    if_ready: AtomicBool,
    /// Shared DNS statistics, updated by the DNS module.
    dns_stats: RwLock<Option<Arc<dyn std::any::Any + Send + Sync>>>,
    /// Timestamp of the last successful database flush.
    last_db_flush: RwLock<Option<SystemTime>>,
    /// Internal counters for event rates.
    event_counters: Arc<EventCounters>,
}

#[allow(clippy::missing_panics_doc)] // Temporary
impl LanforgeContext {
    /// Creates a new isolated context instance.
    ///
    /// # Parameters
    ///
    /// - `bus`: The shared event bus for publishing state changes
    /// - `state`: The initial device state (can be empty via [`State::new()`])
    /// - `target_ifindex`: Optional interface index to monitor for RA/DHCP events.
    ///   If `None`, the system will auto-detect the primary interface.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lanforge_core::context::LanforgeContext;
    /// use lanforge_core::state::State;
    /// use lanforge_core::bus::EventBus;
    /// use std::sync::Arc;
    ///
    /// let bus = Arc::new(EventBus::new());
    /// let state = State::new();
    /// let ctx = LanforgeContext::new(bus, state, None);
    ///
    /// assert!(ctx.is_running());
    /// assert!(ctx.target_ifindex().is_none());
    /// ```
    #[must_use]
    pub fn new(bus: Arc<EventBus>, state: State, target_ifindex: Option<u32>) -> Self {
        Self {
            inner: Arc::new(LanforgeContextInner {
                bus,
                state: RwLock::new(state),
                target_ifindex,
                running: AtomicBool::new(true),
                db_ready: AtomicBool::new(false),
                if_ready: AtomicBool::new(false),
                dns_stats: RwLock::new(None),
                last_db_flush: RwLock::new(None),
                event_counters: Arc::new(EventCounters::default()),
            }),
        }
    }

    /// Returns the target interface index for this context.
    ///
    /// This is the interface monitored for router advertisements and DHCP events.
    /// Returns `None` if no specific interface is configured.
    #[must_use]
    pub fn target_ifindex(&self) -> Option<u32> {
        self.inner.target_ifindex
    }

    /// Returns the shared event bus for this instance.
    ///
    /// The bus can be used to subscribe to or publish events.
    #[must_use]
    pub fn bus(&self) -> Arc<EventBus> {
        self.inner.bus.clone()
    }

    /// Records a new database flush timestamp.
    ///
    /// Call this after a successful database write to track staleness.
    pub fn record_db_flush(&self) {
        *self.inner.last_db_flush.write() = Some(SystemTime::now());
    }

    /// Returns the last database flush time, if any.
    ///
    /// Used to determine if the in-memory state is synced to disk.
    #[must_use]
    pub fn last_db_flush(&self) -> Option<SystemTime> {
        *self.inner.last_db_flush.read()
    }

    /// Returns a reference to the internal event counters.
    #[must_use]
    pub fn counters(&self) -> Arc<EventCounters> {
        self.inner.event_counters.clone()
    }

    /// Increments the DNS blocked queries counter.
    #[cfg(feature = "adblock")]
    pub fn inc_dns_blocked(&self) {
        self.inner
            .event_counters
            .dns_blocked
            .fetch_add(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Lifecycle & Coordination
// ---------------------------------------------------------------------------

impl LanforgeContext {
    /// Blocks the current THREAD (sync) until the database is ready.
    ///
    /// This is used by sync services to wait for DB initialization before
    /// performing database-dependent operations.
    ///
    /// Exits early if:
    /// - DB is already ready
    /// - Shutdown is requested
    /// - `self.is_running()` returns false
    pub fn wait_for_db_sync(&self, rx: &Receiver<TimedEvent>) {
        if self.is_db_ready() {
            return;
        }
        while let Ok(timed_event) = rx.recv() {
            if matches!(timed_event.event, LanforgeEvent::DbReady) {
                break;
            }
            if matches!(timed_event.event, LanforgeEvent::Shutdown) || !self.is_running() {
                break;
            }
        }
    }

    /// Blocks the current THREAD (sync) until network interfaces are ready.
    ///
    /// This is used by sync services to wait for interface discovery before
    /// starting network-dependent operations.
    ///
    /// Exits early if:
    /// - Interfaces are already ready
    /// - Shutdown is requested
    /// - `self.is_running()` returns false
    pub fn wait_for_interfaces_sync(&self, rx: &Receiver<TimedEvent>) {
        if self.is_if_ready() {
            return;
        }
        while let Ok(timed_event) = rx.recv() {
            if matches!(timed_event.event, LanforgeEvent::InterfaceReady) {
                break;
            }
            if matches!(timed_event.event, LanforgeEvent::Shutdown) || !self.is_running() {
                break;
            }
        }
    }

    /// Blocks the current task until network interfaces are ready (async version).
    ///
    /// This is the async counterpart to [`wait_for_interfaces_sync`], usable
    /// from Tokio tasks.
    ///
    /// # Errors
    ///
    /// Currently, this method always returns `Ok(())`. Future versions may return
    /// `CoreError` if the internal bus becomes unreachable or if a timeout occurs.
    pub async fn wait_for_interfaces(&self) -> Result<(), CoreError> {
        let mut rx = self.inner.bus.subscribe();
        if self.is_if_ready() {
            return Ok(());
        }
        while let Ok(timed_event) = rx.recv().await {
            if !self.is_running() || matches!(timed_event.event, LanforgeEvent::Shutdown) {
                return Ok(());
            }
            if matches!(timed_event.event, LanforgeEvent::InterfaceReady) {
                break;
            }
        }
        Ok(())
    }

    /// Blocks the current task until the database is ready (async version).
    ///
    /// This is the async counterpart to [`wait_for_db_sync`], usable
    /// from Tokio tasks.
    ///
    /// # Errors
    ///
    /// Currently, this method always returns `Ok(())`. Future versions may return
    /// `CoreError` if the internal bus becomes unreachable or if a timeout occurs.
    pub async fn wait_for_db(&self) -> Result<(), CoreError> {
        let mut rx = self.inner.bus.subscribe();
        if self.is_db_ready() {
            return Ok(());
        }
        while let Ok(timed_event) = rx.recv().await {
            if !self.is_running() || matches!(timed_event.event, LanforgeEvent::Shutdown) {
                return Ok(());
            }
            if matches!(timed_event.event, LanforgeEvent::DbReady) {
                break;
            }
        }
        Ok(())
    }

    /// Returns true if this instance is currently running.
    ///
    /// When false, the system is in shutdown mode and services should exit.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::Relaxed)
    }

    /// Returns true if the database is ready.
    ///
    /// This flag is set by the database worker after successful initialization.
    #[must_use]
    pub fn is_db_ready(&self) -> bool {
        self.inner.db_ready.load(Ordering::SeqCst)
    }

    /// Returns true if the network interfaces are ready.
    ///
    /// This flag is set after interface discovery completes successfully.
    #[must_use]
    pub fn is_if_ready(&self) -> bool {
        self.inner.if_ready.load(Ordering::SeqCst)
    }
}
