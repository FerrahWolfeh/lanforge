//! Graph-based supervisor and DAG orchestration engine.

pub mod backoff;
pub mod graph;
pub mod node;
pub mod runner;

use graph::DependencyGraph;
use node::NodeHandle;
use runner::ServiceRunner;

use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{
    AsyncService, LanforgeService, NodeStatus, RuntimeClass, ServiceSpec,
};
use lanforge_types::system::ServiceState;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Builder;
use tokio::sync::{watch, Notify};
use tracing::{debug, info, warn};

/// Result of spawning a supervised service.
pub enum SpawnedService {
    Shared(tokio::task::JoinHandle<()>),
    Dedicated(std::thread::JoinHandle<()>),
}

/// Abstract runner factory decoupled from concrete service types.
pub trait SpawnableRunner: Send {
    fn id(&self) -> &'static str;
    fn spec(&self) -> ServiceSpec;
    fn spawn(
        self: Box<Self>,
        ctx: LanforgeContext,
        node: Arc<NodeHandle>,
        dep_rxs: HashMap<&'static str, watch::Receiver<NodeStatus>>,
        notify_condition: Arc<Notify>,
    ) -> SpawnedService;
}

/// Typed runner implementation for a concrete `(S, F)` pair.
pub struct TypedRunner<S, F>
where
    S: AsyncService + LanforgeService + 'static,
    F: Fn() -> S + Send + Sync + 'static,
{
    pub spec: ServiceSpec,
    pub factory: F,
    _marker: std::marker::PhantomData<S>,
}

impl<S, F> TypedRunner<S, F>
where
    S: AsyncService + LanforgeService + 'static,
    F: Fn() -> S + Send + Sync + 'static,
{
    #[must_use]
    pub const fn new(spec: ServiceSpec, factory: F) -> Self {
        Self {
            spec,
            factory,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<S, F> SpawnableRunner for TypedRunner<S, F>
where
    S: AsyncService + LanforgeService + 'static,
    F: Fn() -> S + Send + Sync + 'static,
{
    fn id(&self) -> &'static str {
        self.spec.id
    }

    fn spec(&self) -> ServiceSpec {
        self.spec.clone()
    }

    fn spawn(
        self: Box<Self>,
        ctx: LanforgeContext,
        node: Arc<NodeHandle>,
        dep_rxs: HashMap<&'static str, watch::Receiver<NodeStatus>>,
        notify_condition: Arc<Notify>,
    ) -> SpawnedService {
        let spec = self.spec.clone();
        let shutdown_rx = node.shutdown_rx.clone();
        let runner = ServiceRunner {
            spec: self.spec,
            factory: self.factory,
            ctx,
            node,
            dep_rxs,
            notify_condition,
            shutdown_rx,
        };

        match spec.runtime {
            RuntimeClass::Shared => {
                debug!(service = spec.id, "Spawning shared service task");
                SpawnedService::Shared(tokio::spawn(runner.run()))
            }
            RuntimeClass::Dedicated {
                multi_thread,
                worker_threads,
            } => {
                let display_name = spec.display_name.to_string();
                let thread_name = format!("{display_name} worker");
                debug!(service = spec.id, thread = %thread_name, "Spawning dedicated service runtime");

                let handle = std::thread::Builder::new()
                    .name(thread_name.clone())
                    .spawn(move || {
                        let mut builder = if multi_thread {
                            let mut b = Builder::new_multi_thread();
                            if let Some(workers) = worker_threads {
                                b.worker_threads(usize::from(workers));
                            }
                            b
                        } else {
                            Builder::new_current_thread()
                        };

                        let rt = builder
                            .enable_all()
                            .thread_name(thread_name)
                            .build()
                            .expect("Failed to build dedicated service runtime");

                        rt.block_on(runner.run());
                    })
                    .unwrap_or_else(|e| {
                        panic!("Failed to spawn dedicated thread for {display_name}: {e}")
                    });

                SpawnedService::Dedicated(handle)
            }
        }
    }
}

/// Central orchestrator supervising all Lanforge services in a DAG.
pub struct GraphSupervisor {
    graph: Arc<DependencyGraph>,
    nodes: HashMap<&'static str, Arc<NodeHandle>>,
    notify_condition: Arc<Notify>,
    shared_tasks: Vec<tokio::task::JoinHandle<()>>,
    dedicated_threads: Vec<std::thread::JoinHandle<()>>,
}

impl GraphSupervisor {
    /// Builds the dependency graph and launches all services.
    ///
    /// # Errors
    ///
    /// Returns `graph::GraphError` if DAG validation fails.
    pub fn start(
        ctx: &LanforgeContext,
        specs: Vec<ServiceSpec>,
        mut runners: HashMap<&'static str, Box<dyn SpawnableRunner>>,
    ) -> Result<Self, graph::GraphError> {
        let graph = Arc::new(DependencyGraph::build(specs)?);
        let mut nodes = HashMap::new();
        let notify_condition = Arc::new(Notify::new());

        for spec in graph.nodes() {
            let handle = Arc::new(NodeHandle::new(spec.id));
            nodes.insert(spec.id, handle);
        }

        // Background task listening for system config updates to re-evaluate conditions
        let mut sys_bus = ctx.bus().subscribe_system();
        let notify_clone = Arc::clone(&notify_condition);
        tokio::spawn(async move {
            while let Ok(event) = sys_bus.recv().await {
                if matches!(
                    event.event,
                    LanforgeEvent::System(SystemEvent::ConfigUpdate { .. })
                ) {
                    debug!("Config updated; notifying condition re-evaluation");
                    notify_clone.notify_waiters();
                }
            }
        });

        let mut shared_tasks = Vec::new();
        let mut dedicated_threads = Vec::new();

        for &id in graph.topological_order() {
            let runner = runners
                .remove(id)
                .expect("Runner missing for registered service");
            let spec = runner.spec();
            let node = Arc::clone(nodes.get(id).unwrap());

            // Build receiver map for all dependencies
            let mut dep_rxs = HashMap::new();
            for &edge in spec.deps {
                let target = edge.target;
                if let Some(target_node) = nodes.get(target) {
                    dep_rxs.insert(target, target_node.rx.clone());
                }
            }

            match runner.spawn(
                ctx.clone(),
                node,
                dep_rxs,
                Arc::clone(&notify_condition),
            ) {
                SpawnedService::Shared(task) => shared_tasks.push(task),
                SpawnedService::Dedicated(thread) => dedicated_threads.push(thread),
            }
        }

        Ok(Self {
            graph,
            nodes,
            notify_condition,
            shared_tasks,
            dedicated_threads,
        })
    }

    /// Returns the underlying dependency graph.
    #[must_use]
    pub const fn graph(&self) -> &Arc<DependencyGraph> {
        &self.graph
    }

    /// Triggers re-evaluation of all service conditions (e.g. after config change).
    pub fn reevaluate_conditions(&self) {
        self.notify_condition.notify_waiters();
    }

    /// Queries the live status of a service.
    #[must_use]
    pub fn status_of(&self, id: &str) -> Option<NodeStatus> {
        self.nodes.get(id).map(|node| node.current())
    }

    /// Returns true if all registered services have reached a settled state.
    #[must_use]
    pub fn all_settled(&self) -> bool {
        self.nodes
            .values()
            .all(|n| node::is_settled(n.current().state))
    }

    /// Performs graceful reverse-topological shutdown of all services.
    pub async fn shutdown(self, ctx: &LanforgeContext, timeout: Duration) {
        info!("GraphSupervisor: Initiating graceful reverse-topological shutdown");

        // 1. Calling ctx.terminate() BEFORE broadcasting shutdown (Supervisor Rule)
        ctx.terminate();

        let num_nodes = self.graph.reverse_topological_order().len().max(1);
        let per_node_timeout = timeout / u32::try_from(num_nodes).unwrap_or(1);

        // 2. Shut down nodes in reverse topological order (dependents first)
        for &id in &self.graph.reverse_topological_order() {
            if let Some(node) = self.nodes.get(id) {
                debug!(service = id, "Signaling shutdown to service node");
                let _ = node.shutdown_tx.send(true);

                // Wait for node to reach Inactive state or timeout
                let mut status_rx = node.rx.clone();
                let wait_fut = async {
                    while status_rx.borrow().state != ServiceState::Inactive {
                        if status_rx.changed().await.is_err() {
                            break;
                        }
                    }
                };

                let _ = tokio::time::timeout(per_node_timeout, wait_fut).await;
            }
        }

        // 3. Await all tasks and threads
        let join_fut = async {
            for task in self.shared_tasks {
                let _ = task.await;
            }
            for thread in self.dedicated_threads {
                let _ = thread.join();
            }
        };

        if tokio::time::timeout(timeout, join_fut).await.is_err() {
            warn!(
                "GraphSupervisor: Shutdown timed out after {}s; forcing exit",
                timeout.as_secs()
            );
        } else {
            info!("GraphSupervisor: All services terminated cleanly");
        }
    }
}
