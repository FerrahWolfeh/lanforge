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
use lanforge_types::system::{ServiceAction, ServiceId, ServiceState};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Builder;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

/// Channels wiring one runner to the rest of the graph.
pub struct RunnerLinks {
    pub node: Arc<NodeHandle>,
    pub dep_rxs: HashMap<ServiceId, watch::Receiver<NodeStatus>>,
    /// Condition epoch: bumped on every config change so dormant nodes re-evaluate.
    /// A `watch` (not `Notify`) so a bump between evaluation and waiting is never lost.
    pub condition_rx: watch::Receiver<u64>,
    /// Admin `start|stop|restart` requests routed from `SystemEvent::ServiceControl`.
    pub control_rx: mpsc::Receiver<ServiceAction>,
}

/// Result of spawning a supervised service.
pub enum SpawnedService {
    Shared(tokio::task::JoinHandle<()>),
    Dedicated(std::thread::JoinHandle<()>),
}

/// Abstract runner factory decoupled from concrete service types.
pub trait SpawnableRunner: Send {
    fn id(&self) -> ServiceId;
    fn spec(&self) -> ServiceSpec;
    fn spawn(self: Box<Self>, ctx: LanforgeContext, links: RunnerLinks) -> SpawnedService;
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
    fn id(&self) -> ServiceId {
        self.spec.id
    }

    fn spec(&self) -> ServiceSpec {
        self.spec.clone()
    }

    fn spawn(self: Box<Self>, ctx: LanforgeContext, links: RunnerLinks) -> SpawnedService {
        let spec = self.spec.clone();
        let runner = ServiceRunner::new(self.spec, self.factory, ctx, links);

        match spec.runtime {
            RuntimeClass::Shared => {
                debug!(service = %spec.id, "Spawning shared service task");
                SpawnedService::Shared(tokio::spawn(runner.run()))
            }
            RuntimeClass::Dedicated {
                multi_thread,
                worker_threads,
            } => {
                let display_name = spec.display_name.to_string();
                let thread_name = format!("{display_name} worker");
                debug!(service = %spec.id, thread = %thread_name, "Spawning dedicated service runtime");

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
    nodes: HashMap<ServiceId, Arc<NodeHandle>>,
    condition_tx: Arc<watch::Sender<u64>>,
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
        mut runners: HashMap<ServiceId, Box<dyn SpawnableRunner>>,
    ) -> Result<Self, graph::GraphError> {
        let graph = Arc::new(DependencyGraph::build(specs)?);
        let mut nodes = HashMap::new();
        let mut control_txs = HashMap::new();
        let mut pending_controls = HashMap::new();
        let (condition_tx, _) = watch::channel(0_u64);
        let condition_tx = Arc::new(condition_tx);

        for spec in graph.nodes() {
            let handle = Arc::new(NodeHandle::new(spec.id));
            nodes.insert(spec.id, handle);
            let (tx, rx) = mpsc::channel(8);
            control_txs.insert(spec.id, tx);
            pending_controls.insert(spec.id, rx);
        }

        // Routes config changes (D-3) and admin service control (D-20) into the graph.
        let mut sys_bus = ctx.bus().subscribe_system();
        let condition_clone = Arc::clone(&condition_tx);
        tokio::spawn(async move {
            loop {
                let event = match sys_bus.recv().await {
                    Ok(event) => event,
                    Err(RecvError::Lagged(n)) => {
                        // A missed ConfigChanged must not leave a node dormant: re-evaluate all.
                        warn!("Supervisor: system bus lagged by {n}; re-evaluating conditions");
                        condition_clone.send_modify(|epoch| *epoch += 1);
                        continue;
                    }
                    Err(RecvError::Closed) => break,
                };
                match event.event {
                    LanforgeEvent::System(SystemEvent::ConfigChanged { sections }) => {
                        debug!(?sections, "Config changed; re-evaluating conditions");
                        condition_clone.send_modify(|epoch| *epoch += 1);
                    }
                    LanforgeEvent::System(SystemEvent::ServiceControl { id, action }) => {
                        match control_txs.get(&id) {
                            Some(tx) => {
                                if tx.try_send(action).is_err() {
                                    warn!(service = %id, ?action, "Service control queue full; request dropped");
                                }
                            }
                            None => {
                                warn!(service = %id, ?action, "Service control for unknown node ignored");
                            }
                        }
                    }
                    LanforgeEvent::System(SystemEvent::Shutdown) => break,
                    _ => {}
                }
            }
        });

        let mut shared_tasks = Vec::new();
        let mut dedicated_threads = Vec::new();

        for &id in graph.topological_order() {
            let runner = runners
                .remove(&id)
                .expect("Runner missing for registered service");
            let spec = runner.spec();
            let node = Arc::clone(nodes.get(&id).unwrap());

            // Build receiver map for all dependencies
            let mut dep_rxs = HashMap::new();
            for &edge in spec.deps {
                let target = edge.target;
                if let Some(target_node) = nodes.get(&target) {
                    dep_rxs.insert(target, target_node.rx.clone());
                }
            }

            let links = RunnerLinks {
                node,
                dep_rxs,
                condition_rx: condition_tx.subscribe(),
                control_rx: pending_controls
                    .remove(&id)
                    .expect("control channel created for every graph node"),
            };
            match runner.spawn(ctx.clone(), links) {
                SpawnedService::Shared(task) => shared_tasks.push(task),
                SpawnedService::Dedicated(thread) => dedicated_threads.push(thread),
            }
        }

        Ok(Self {
            graph,
            nodes,
            condition_tx,
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
        self.condition_tx.send_modify(|epoch| *epoch += 1);
    }

    /// Queries the live status of a service.
    #[must_use]
    pub fn status_of(&self, id: ServiceId) -> Option<NodeStatus> {
        self.nodes.get(&id).map(|node| node.current())
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
        for id in self.graph.reverse_topological_order() {
            if let Some(node) = self.nodes.get(&id) {
                debug!(service = %id, "Signaling shutdown to service node");
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
