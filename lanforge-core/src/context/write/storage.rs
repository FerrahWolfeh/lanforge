//! Storage and lifecycle state management.

use crate::{context::LanforgeContext, state::DeviceUpdate};
use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::Ordering;

impl LanforgeContext {
    /// Sets the system lifecycle to shutdown mode for this instance.
    pub fn terminate(&self) {
        self.inner.running.store(false, Ordering::SeqCst);
    }

    /// Sets the database readiness state.
    pub fn set_db_ready(&self, ready: bool) {
        self.inner.db_ready.store(ready, Ordering::SeqCst);
    }

    /// Sets the interface readiness state.
    pub fn set_if_ready(&self, ready: bool) {
        self.inner.if_ready.store(ready, Ordering::SeqCst);
    }

    /// Sets the shared DNS statistics.
    pub fn set_dns_stats<T: Any + Send + Sync + 'static>(&self, stats: Arc<T>) {
        *self.inner.dns_stats.write() = Some(stats as Arc<dyn Any + Send + Sync>);
    }

    /// Sets the shared DNS context.
    pub fn set_dns_context<T: Any + Send + Sync + 'static>(&self, ctx: Arc<T>) {
        *self.inner.dns_context.write() = Some(ctx as Arc<dyn Any + Send + Sync>);
    }

    /// Completely resets the in-memory state.
    pub fn reset(&self) {
        let _ = self.apply(DeviceUpdate::Reset);
        *self.inner.last_db_flush.write() = None;
    }
}
