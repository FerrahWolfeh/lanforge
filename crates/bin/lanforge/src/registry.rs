use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::supervisor::{
    graph::GraphError, GraphSupervisor, SpawnableRunner, TypedRunner,
};
use lanforge_core::{
    context::LanforgeContext,
    service::{AsyncService, LanforgeService, ServiceSpec},
};

/// Centralized registry for Lanforge services.
///
/// Collects service specifications and factories, validates the DAG,
/// and delegates execution to `GraphSupervisor`.
pub struct ServiceRegistry {
    specs: Vec<ServiceSpec>,
    runners: HashMap<&'static str, Box<dyn SpawnableRunner>>,
    ids: HashSet<String>,
}

impl ServiceRegistry {
    /// Creates a new, empty service registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            specs: Vec::new(),
            runners: HashMap::new(),
            ids: HashSet::new(),
        }
    }

    /// Registers an asynchronous service with the registry.
    pub fn register<S, F>(&mut self, ctx: &LanforgeContext, factory: F)
    where
        S: AsyncService + LanforgeService + 'static,
        F: Fn() -> S + Send + Sync + 'static,
    {
        let sample = factory();
        let spec = sample.spec();
        let id = spec.id;
        self.ids.insert(id.to_string());

        ctx.register_status_provider(Arc::new(sample));

        self.specs.push(spec.clone());
        self.runners.insert(
            id,
            Box::new(TypedRunner::new(spec, factory)) as Box<dyn SpawnableRunner>,
        );
    }

    /// Backwards compatibility alias for `register`.
    pub fn spawn_async<S, F>(&mut self, ctx: &LanforgeContext, factory: F)
    where
        S: AsyncService + LanforgeService + 'static,
        F: Fn() -> S + Send + Sync + 'static,
    {
        self.register(ctx, factory);
    }

    /// Builds the DAG and starts all registered services via `GraphSupervisor`.
    ///
    /// # Errors
    ///
    /// Returns `GraphError` if DAG validation fails.
    pub fn start(self, ctx: &LanforgeContext) -> Result<GraphSupervisor, GraphError> {
        GraphSupervisor::start(ctx, self.specs, self.runners)
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

/// DSL macro to simplify service registration and spawning.
#[macro_export]
macro_rules! spawn_services {
    ($registry:expr, $ctx_ref:expr, {
        $( $(#[$attr:meta])* $kind:ident $( [ $($clone:ident),* ] )? $( if $cond:expr )? => $ctor:expr ),* $(,)?
    }) => {
        $(
            $(#[$attr])*
            {
                #[allow(unused_mut)]
                let mut run = true;
                $( run = $cond; )?
                if run {
                    $( $( let $clone = $clone.clone(); )* )?
                    $crate::spawn_one!($registry, $ctx_ref, $kind, $ctor, $($($clone),*)?);
                }
            }
        )*
    };
}

/// Internal helper for `spawn_services!`. Do not use directly.
#[macro_export]
macro_rules! spawn_one {
    ($registry:expr, $ctx_ref:expr, async, $ctor:expr, $($clone:ident),*) => {
        $registry.register($ctx_ref, move || {
            $( let $clone = $clone.clone(); )*
            $ctor
        })
    };
}
