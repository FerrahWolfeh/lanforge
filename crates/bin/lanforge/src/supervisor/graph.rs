//! Directed Acyclic Graph (DAG) for service dependencies.

use lanforge_core::service::{Edge, ServiceSpec};
use lanforge_types::system::ServiceId;
use std::collections::{HashMap, VecDeque};
use std::fmt;

/// Graph validation errors.
#[derive(Debug, PartialEq, Eq)]
pub enum GraphError {
    DuplicateService(ServiceId),
    UnknownDependency { from: ServiceId, to: ServiceId },
    CycleDetected(Vec<ServiceId>),
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateService(id) => write!(f, "Duplicate service id: {id}"),
            Self::UnknownDependency { from, to } => write!(
                f,
                "Unknown dependency target: service '{from}' depends on '{to}', which does not exist"
            ),
            Self::CycleDetected(cycle) => {
                write!(f, "Dependency cycle detected involving: {cycle:?}")
            }
        }
    }
}

impl std::error::Error for GraphError {}

/// Service dependency graph representing the system architecture.
#[derive(Debug)]
pub struct DependencyGraph {
    nodes: HashMap<ServiceId, ServiceSpec>,
    deps: HashMap<ServiceId, Vec<Edge>>,
    dependents: HashMap<ServiceId, Vec<(ServiceId, Edge)>>,
    topo_order: Vec<ServiceId>,
}

impl DependencyGraph {
    /// Builds and validates a `DependencyGraph` from a collection of `ServiceSpec`s.
    ///
    /// # Errors
    ///
    /// Returns `GraphError` if there are duplicate IDs, unknown dependencies, or cycles.
    pub fn build(specs: Vec<ServiceSpec>) -> Result<Self, GraphError> {
        let mut nodes = HashMap::new();
        let mut deps = HashMap::new();
        let mut dependents = HashMap::new();

        // 1. Check duplicate IDs and populate nodes
        for spec in specs {
            let id = spec.id;
            if nodes.insert(id, spec).is_some() {
                return Err(GraphError::DuplicateService(id));
            }
            deps.insert(id, Vec::new());
            dependents.insert(id, Vec::new());
        }

        // 2. Validate all dependency targets exist
        for (&id, spec) in &nodes {
            for &edge in spec.deps {
                let target = edge.target();
                if !nodes.contains_key(&target) {
                    return Err(GraphError::UnknownDependency {
                        from: id,
                        to: target,
                    });
                }
                deps.get_mut(&id).unwrap().push(edge);
                dependents.get_mut(&target).unwrap().push((id, edge));
            }
        }

        // 3. Compute topological order using Kahn's algorithm
        let mut in_degrees: HashMap<ServiceId, usize> = HashMap::new();
        for &id in nodes.keys() {
            in_degrees.insert(id, 0);
        }

        for (&dep_id, edges) in &deps {
            in_degrees.insert(dep_id, edges.len());
        }

        let mut queue = VecDeque::new();
        for (&id, &deg) in &in_degrees {
            if deg == 0 {
                queue.push_back(id);
            }
        }

        let mut topo_order = Vec::with_capacity(nodes.len());
        while let Some(node) = queue.pop_front() {
            topo_order.push(node);

            // For every dependent that depended on this node, decrement its in-degree
            if let Some(deps_list) = dependents.get(&node) {
                for &(dependent, _) in deps_list {
                    if let Some(deg) = in_degrees.get_mut(&dependent) {
                        *deg = deg.saturating_sub(1);
                        if *deg == 0 {
                            queue.push_back(dependent);
                        }
                    }
                }
            }
        }

        if topo_order.len() != nodes.len() {
            // Find nodes with remaining in-degree (cycle participants)
            let cycle_nodes: Vec<ServiceId> = in_degrees
                .into_iter()
                .filter(|(_, deg)| *deg > 0)
                .map(|(id, _)| id)
                .collect();
            return Err(GraphError::CycleDetected(cycle_nodes));
        }

        Ok(Self {
            nodes,
            deps,
            dependents,
            topo_order,
        })
    }

    /// Returns the services in topological startup order (dependencies first).
    #[must_use]
    pub fn topological_order(&self) -> &[ServiceId] {
        &self.topo_order
    }

    /// Returns the services in reverse topological order (dependents first, for shutdown).
    #[must_use]
    pub fn reverse_topological_order(&self) -> Vec<ServiceId> {
        let mut rev = self.topo_order.clone();
        rev.reverse();
        rev
    }

    /// Returns the dependencies declared by `id`.
    #[must_use]
    pub fn dependencies_of(&self, id: ServiceId) -> &[Edge] {
        self.deps.get(&id).map_or(&[], Vec::as_slice)
    }

    /// Returns the dependents that depend on `id`.
    #[must_use]
    pub fn dependents_of(&self, id: ServiceId) -> &[(ServiceId, Edge)] {
        self.dependents.get(&id).map_or(&[], Vec::as_slice)
    }

    /// Returns the `ServiceSpec` for `id`, if found.
    #[must_use]
    pub fn spec_of(&self, id: ServiceId) -> Option<&ServiceSpec> {
        self.nodes.get(&id)
    }

    /// Returns all registered nodes.
    pub fn nodes(&self) -> impl Iterator<Item = &ServiceSpec> {
        self.nodes.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_core::service::{Condition, LossPolicy, RestartPolicy, RuntimeClass};
    use std::time::Duration;

    fn make_spec(id: ServiceId, deps: &'static [Edge]) -> ServiceSpec {
        ServiceSpec {
            id,
            display_name: id.as_str(),
            runtime: RuntimeClass::Shared,
            restart: RestartPolicy::default(),
            shutdown_timeout: Duration::from_secs(5),
            deps,
            condition: Condition::ALWAYS,
        }
    }

    #[test]
    fn test_valid_dag_topological_sort() {
        static DB_DEPS: &[Edge] = &[];
        static HTTP_DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Restart)];
        static DNS_DEPS: &[Edge] = &[Edge::after(ServiceId::Db)];

        let specs = vec![
            make_spec(ServiceId::Http, HTTP_DEPS),
            make_spec(ServiceId::Db, DB_DEPS),
            make_spec(ServiceId::Dns, DNS_DEPS),
        ];

        let graph = DependencyGraph::build(specs).expect("Graph should be valid");
        let order = graph.topological_order();

        // db must come before http and dns
        let pos_db = order.iter().position(|&x| x == ServiceId::Db).unwrap();
        let pos_http = order.iter().position(|&x| x == ServiceId::Http).unwrap();
        let pos_dns = order.iter().position(|&x| x == ServiceId::Dns).unwrap();

        assert!(pos_db < pos_http);
        assert!(pos_db < pos_dns);

        let rev_order = graph.reverse_topological_order();
        let rev_pos_db = rev_order.iter().position(|&x| x == ServiceId::Db).unwrap();
        let rev_pos_http = rev_order
            .iter()
            .position(|&x| x == ServiceId::Http)
            .unwrap();
        assert!(rev_pos_db > rev_pos_http);
    }

    #[test]
    fn test_rejects_unknown_dependency() {
        static HTTP_DEPS: &[Edge] = &[Edge::requires(ServiceId::Db, LossPolicy::Restart)];

        // Only register HTTP, not Db
        let specs = vec![make_spec(ServiceId::Http, HTTP_DEPS)];
        let err = DependencyGraph::build(specs).unwrap_err();

        assert_eq!(
            err,
            GraphError::UnknownDependency {
                from: ServiceId::Http,
                to: ServiceId::Db,
            }
        );
    }

    #[test]
    fn test_rejects_direct_cycle() {
        static A_DEPS: &[Edge] = &[Edge::after(ServiceId::Http)];
        static B_DEPS: &[Edge] = &[Edge::after(ServiceId::Db)];

        let specs = vec![
            make_spec(ServiceId::Db, A_DEPS),
            make_spec(ServiceId::Http, B_DEPS),
        ];
        let err = DependencyGraph::build(specs).unwrap_err();

        match err {
            GraphError::CycleDetected(nodes) => {
                assert!(nodes.contains(&ServiceId::Db));
                assert!(nodes.contains(&ServiceId::Http));
            }
            other => panic!("Expected CycleDetected, got {other:?}"),
        }
    }
}
