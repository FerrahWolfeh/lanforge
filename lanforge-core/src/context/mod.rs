//! `GlobalContext` — Thread-safe singleton for system-wide state.
//!
//! This module provides a global access point for the [`ManagedTable`] and
//! [`EventBus`]. It is intended to reduce "constructor drilling" while
//! maintaining thread safety.

use crate::bus::{EventBus, LanforgeEvent, TimedEvent};
use crate::error::CoreError;
use crate::state::State;
use parking_lot::RwLock;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

pub mod read;
pub mod state;
pub mod utils;
pub mod write;

#[derive(Clone)]
pub struct LanforgeContext {
    inner: Arc<LanforgeContextInner>,
}

struct LanforgeContextInner {
    bus: Arc<EventBus>,
    state: RwLock<state::State>,
    target_ifindex: Option<u32>,
    running: AtomicBool,
    db_ready: AtomicBool,
    if_ready: AtomicBool,
    dns_stats: RwLock<Option<Arc<dyn std::any::Any + Send + Sync>>>,
    last_db_flush: RwLock<Option<SystemTime>>,
}

#[allow(clippy::missing_panics_doc)] // Temporary
impl LanforgeContext {
    /// Creates a new isolated context instance.
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
            }),
        }
    }

    /// Returns the target interface index for this context.
    #[must_use]
    pub fn target_ifindex(&self) -> Option<u32> {
        self.inner.target_ifindex
    }

    /// Returns the shared event bus for this instance.
    #[must_use]
    pub fn bus(&self) -> Arc<EventBus> {
        self.inner.bus.clone()
    }

    /// Records a new database flush timestamp.
    pub fn record_db_flush(&self) {
        *self.inner.last_db_flush.write() = Some(SystemTime::now());
    }

    /// Returns the last database flush time, if any.
    #[must_use]
    pub fn last_db_flush(&self) -> Option<SystemTime> {
        *self.inner.last_db_flush.read()
    }
}

// ---------------------------------------------------------------------------
// Lifecycle & Coordination
// ---------------------------------------------------------------------------

impl LanforgeContext {
    /// Blocks the current THREAD (sync) until the database is ready.
    pub fn wait_for_db_sync(&self, rx: &std::sync::mpsc::Receiver<TimedEvent>) {
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
    pub fn wait_for_interfaces_sync(&self, rx: &std::sync::mpsc::Receiver<TimedEvent>) {
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

    /// Blocks the current task until network interfaces are ready.
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

    /// Blocks the current task until the database is ready.
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
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::Relaxed)
    }

    /// Returns true if the database is ready.
    #[must_use]
    pub fn is_db_ready(&self) -> bool {
        self.inner.db_ready.load(Ordering::SeqCst)
    }

    /// Returns true if the network interfaces are ready.
    #[must_use]
    pub fn is_if_ready(&self) -> bool {
        self.inner.if_ready.load(Ordering::SeqCst)
    }
}
