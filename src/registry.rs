use std::thread::JoinHandle;

use crate::supervisor::{supervise_async, supervise_sync};
use lanforge_core::{
    context::LanforgeContext,
    service::{AsyncService, SyncService},
};
use tokio::runtime::{Builder, Handle};
use tracing::info;

/// Centralized registry for Lanforge services.
///
/// Handles the lifecycle of both asynchronous (Tokio) and synchronous (OS thread)
/// services, providing a unified interface for spawning and supervision.
pub struct ServiceRegistry {
    handles: Vec<JoinHandle<()>>,
}

impl ServiceRegistry {
    /// Creates a new, empty service registry.
    pub const fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    /// Spawns an asynchronous service as a supervised task in a dedicated OS thread.
    ///
    /// Each async service gets its own `current_thread` Tokio runtime and a named OS thread,
    /// making it visible in system monitoring tools like `htop`.
    pub fn spawn_async<S, F>(&mut self, ctx: &LanforgeContext, factory: F)
    where
        S: AsyncService + 'static,
        F: Fn() -> S + Send + Sync + 'static,
    {
        let meta = factory().meta();
        let name = meta.display_name.to_string();
        let stack_size = meta.stack_kb * 1024;

        info!(
            "Spawning async service thread: {} (stack: {}KB)",
            name, meta.stack_kb
        );

        let ctx_spawn = ctx.clone();
        let handle = std::thread::Builder::new()
            .name(name.clone())
            .stack_size(stack_size)
            .spawn(move || {
                let rt = Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to build per-service runtime");
                rt.block_on(supervise_async(&ctx_spawn, factory));
            })
            .unwrap_or_else(|e| panic!("Failed to spawn async thread for {name}: {e}"));

        self.handles.push(handle);
    }

    /// Spawns a synchronous service in a dedicated, named OS thread.
    pub fn spawn_sync<S, F>(&mut self, ctx: &LanforgeContext, factory: F)
    where
        S: SyncService + 'static,
        F: Fn() -> S + Send + Sync + 'static,
    {
        let meta = factory().meta();
        let name = meta.display_name.to_string();
        let stack_size = meta.stack_kb * 1024;
        let rt_handle = Handle::current();

        info!(
            "Spawning sync service thread: {} (stack: {}KB)",
            name, meta.stack_kb
        );

        let ctx_spawn = ctx.clone();
        let handle = std::thread::Builder::new()
            .name(name.clone())
            .stack_size(stack_size)
            .spawn(move || {
                supervise_sync(&ctx_spawn, &rt_handle, factory);
            })
            .unwrap_or_else(|e| panic!("Failed to spawn sync thread for {name}: {e}"));

        self.handles.push(handle);
    }

    /// Waits for all registered services to complete.
    pub fn wait_all(self) {
        for handle in self.handles {
            let _ = handle.join();
        }
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}
