use std::collections::HashSet;
use std::sync::Arc;
use std::thread::JoinHandle;

use crate::supervisor::supervise_async;
use lanforge_core::{context::LanforgeContext, service::AsyncService};
use tokio::runtime::Builder;
use tracing::debug;

/// Centralized registry for Lanforge services.
///
/// Handles the lifecycle of both asynchronous (Tokio) and synchronous (OS thread)
/// services, providing a unified interface for spawning and supervision.
pub struct ServiceRegistry {
    handles: Vec<JoinHandle<()>>,
    ids: HashSet<String>,
}

impl ServiceRegistry {
    /// Creates a new, empty service registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
            ids: HashSet::new(),
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
        let service = factory();
        let meta = service.meta();
        let id = meta.id.to_string();
        let name = meta.display_name.to_string();
        self.ids.insert(id);

        ctx.register_status_provider(Arc::new(service));

        debug!("Spawning async service thread: {}", name);

        let ctx_spawn = ctx.clone();
        let mut builder = std::thread::Builder::new().name(name.clone());
        if meta.stack_kb > 0 {
            builder = builder.stack_size(meta.stack_kb * 1024);
        }

        let name_thread = name.clone();
        let handle = builder
            .spawn(move || {
                let mut rt_builder = if meta.multi_threaded {
                    Builder::new_multi_thread()
                } else {
                    Builder::new_current_thread()
                };
                let rt = rt_builder
                    .enable_all()
                    .thread_name(format!("{name_thread} worker"))
                    .build()
                    .expect("Failed to build per-service runtime");
                rt.block_on(supervise_async(&ctx_spawn, factory));
            })
            .unwrap_or_else(|e| panic!("Failed to spawn async thread for {name}: {e}"));

        self.handles.push(handle);
    }

    /// Waits for all registered services to complete.
    pub fn wait_all(self) {
        for handle in self.handles {
            let _ = handle.join();
        }
    }

    /// Returns the IDs of all services registered in this registry.
    #[must_use]
    pub fn registered_ids(&self) -> HashSet<String> {
        self.ids.clone()
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}
