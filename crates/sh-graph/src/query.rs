//! Graph query engine

use crate::{
    AttackGraph, EdgeType, EntityId, GraphEdge, GraphError, GraphNode, NodeType, Properties, Result,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use tracing::{debug, trace, warn};

/// Graph query engine
#[derive(Debug)]
pub struct GraphQuery<'a> {
    graph: &'a AttackGraph,
}

impl<'a> GraphQuery<'a> {
    /// Create a new query engine
    pub fn new(graph: &'a AttackGraph) -> Self {
        Self { graph }
    }

    /// Execute a query
    pub fn execute(&self, query: &QueryBuilder) -> Result<QueryResult> {
        let start_time = Utc::now();

        // Start with all nodes or specific starting points
        let mut candidates: Vec<GraphNode> = if query.starting_nodes.is_empty() {
            self.graph.get_nodes()
        } else {
            query
                .starting_nodes
                .iter()
                .filter_map(|id| self.graph.get_node(*id))
                .collect()
        };

        // Apply node filters
        for filter in &query.node_filters {
            candidates = self.apply_node_filter(candidates, filter)?;
        }

        // Apply relationship filters if specified
        let mut edges: Vec<GraphEdge> = Vec::new();
        if !query.relationship_filters.is_empty() {
            edges = self.graph.get_edges();
            for filter in &query.relationship_filters {
                edges = self.apply_edge_filter(edges, filter)?;
            }
        }

        // Apply path constraints if specified
        if let Some(ref path_constraint) = query.path_constraint {
            candidates = self.apply_path_constraint(candidates, path_constraint)?;
        }

        // Apply sorting
        if let Some(ref sort) = query.sort {
            candidates = self.apply_sort(candidates, sort);
        }

        // Apply limit
        if let Some(limit) = query.limit {
            candidates.truncate(limit);
        }

        let end_time = Utc::now();
        let execution_time_ms = (end_time - start_time).num_milliseconds() as f64;

        Ok(QueryResult {
            nodes: candidates,
            edges,
            total_count: candidates.len(),
            execution_time_ms,
            timestamp: Utc::now(),
        })
    }

    /// Apply a node filter
    fn apply_node_filter(
        &self,
        nodes: Vec<GraphNode>,
        filter: &NodeFilter,
    ) -> Result<Vec<GraphNode>> {
        Ok(nodes
            .into_iter()
            .filter(|node| match filter {
                NodeFilter::ByType(node_type) => node.node_type == *node_type,
                NodeFilter::ByLabel(label) => node.labels.contains(label),
                NodeFilter::ByProperty { key, value } => node
                    .properties
                    .get(key)
                    .map(|v| v == value)
                    .unwrap_or(false),
                NodeFilter::ByRiskRange { min, max } => {
                    node.risk_score >= *min && node.risk_score <= *max
                }
                NodeFilter::ByNamePattern(pattern) => {
                    node.name.to_lowercase().contains(&pattern.to_lowercase())
                }
                NodeFilter::ById(ids) => ids.contains(&node.id),
                NodeFilter::Custom(predicate) => predicate(node),
            })
            .collect())
    }

    /// Apply an edge filter
    fn apply_edge_filter(
        &self,
        edges: Vec<GraphEdge>,
        filter: &EdgeFilter,
    ) -> Result<Vec<GraphEdge>> {
        Ok(edges
            .into_iter()
            .filter(|edge| match filter {
                EdgeFilter::ByType(edge_type) => edge.edge_type == *edge_type,
                EdgeFilter::ByProperty { key, value } => edge
                    .properties
                    .get(key)
                    .map(|v| v == value)
                    .unwrap_or(false),
                EdgeFilter::ByWeightRange { min, max } => {
                    edge.weight >= *min && edge.weight <= *max
                }
                EdgeFilter::FromNode(node_id) => edge.from == *node_id,
                EdgeFilter::ToNode(node_id) => edge.to == *node_id,
                EdgeFilter::Between { from, to } => edge.from == *from && edge.to == *to,
                EdgeFilter::Custom(predicate) => predicate(edge),
            })
            .collect())
    }

    /// Apply path constraint
    fn apply_path_constraint(
        &self,
        nodes: Vec<GraphNode>,
        constraint: &PathConstraint,
    ) -> Result<Vec<GraphNode>> {
        match constraint {
            PathConstraint::ReachableFrom { source, max_depth } => {
                let reachable = self.find_reachable_nodes(*source, *max_depth)?;
                Ok(nodes.into_iter().filter(|n| reachable.contains(&n.id)).collect())
            }
            PathConstraint::CanReach { target, max_depth } => {
                let can_reach = self.find_nodes_that_can_reach(*target, *max_depth)?;
                Ok(nodes.into_iter().filter(|n| can_reach.contains(&n.id)).collect())
            }
            PathConstraint::OnPathBetween { from, to, max_depth } => {
                let path_nodes = self.find_nodes_on_path(*from, *to, *max_depth)?;
                Ok(nodes.into_iter().filter(|n| path_nodes.contains(&n.id)).collect())
            }
            PathConstraint::DistanceFrom { source, distance } => {
                let at_distance = self.find_nodes_at_distance(*source, *distance)?;
                Ok(nodes.into_iter().filter(|n| at_distance.contains(&n.id)).collect())
            }
        }
    }

    /// Find all nodes reachable from a source within max_depth
    fn find_reachable_nodes(&self, source: EntityId, max_depth: usize) -> Result<HashSet<EntityId>> {
        if !self.graph.has_node(source) {
            return Err(GraphError::NodeNotFound(source));
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        visited.insert(source);
        queue.push_back((source, 0));

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            if let Ok(neighbors) = self.graph.get_neighbors(current) {
                for neighbor in neighbors {
                    if !visited.contains(&neighbor.id) {
                        visited.insert(neighbor.id);
                        queue.push_back((neighbor.id, depth + 1));
                    }
                }
            }
        }

        Ok(visited)
    }

    /// Find all nodes that can reach a target within max_depth
    fn find_nodes_that_can_reach(
        &self,
        target: EntityId,
        max_depth: usize,
    ) -> Result<HashSet<EntityId>> {
        if !self.graph.has_node(target) {
            return Err(GraphError::NodeNotFound(target));
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        visited.insert(target);
        queue.push_back((target, 0));

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            if let Ok(predecessors) = self.graph.get_predecessors(current) {
                for pred in predecessors {
                    if !visited.contains(&pred.id) {
                        visited.insert(pred.id);
                        queue.push_back((pred.id, depth + 1));
                    }
                }
            }
        }

        Ok(visited)
    }

    /// Find all nodes on any path between from and to
    fn find_nodes_on_path(
        &self,
        from: EntityId,
        to: EntityId,
        max_depth: usize,
    ) -> Result<HashSet<EntityId>> {
        if !self.graph.has_node(from) {
            return Err(GraphError::NodeNotFound(from));
        }
        if !self.graph.has_node(to) {
            return Err(GraphError::NodeNotFound(to));
        }

        let mut all_path_nodes = HashSet::new();
        let mut visited = HashSet::new();
        let mut current_path = VecDeque::new();

        self.dfs_collect_path_nodes(
            from,
            to,
            max_depth,
            &mut visited,
            &mut current_path,
            &mut all_path_nodes,
        );

        Ok(all_path_nodes)
    }

    fn dfs_collect_path_nodes(
        &self,
        current: EntityId,
        target: EntityId,
        max_depth: usize,
        visited: &mut HashSet<EntityId>,
        current_path: &mut VecDeque<EntityId>,
        all_path_nodes: &mut HashSet<EntityId>,
    ) {
        if current_path.len() >= max_depth {
            return;
        }

        visited.insert(current);
        current_path.push_back(current);

        if current == target {
            // Add all nodes in current path
            for node_id in current_path.iter() {
                all_path_nodes.insert(*node_id);
            }
        } else {
            if let Ok(neighbors) = self.graph.get_neighbors(current) {
                for neighbor in neighbors {
                    if !visited.contains(&neighbor.id) {
                        self.dfs_collect_path_nodes(
                            neighbor.id,
                            target,
                            max_depth,
                            visited,
                            current_path,
                            all_path_nodes,
                        );
                    }
                }
            }
        }

        current_path.pop_back();
        visited.remove(&current);
    }

    /// Find nodes at a specific distance from source
    fn find_nodes_at_distance(
        &self,
        source: EntityId,
        distance: usize,
    ) -> Result<HashSet<EntityId>> {
        if !self.graph.has_node(source) {
            return Err(GraphError::NodeNotFound(source));
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut at_distance = HashSet::new();

        visited.insert(source);
        queue.push_back((source, 0));

        while let Some((current, dist)) = queue.pop_front() {
            if dist == distance {
                at_distance.insert(current);
                continue;
            }

            if dist > distance {
                continue;
            }

            if let Ok(neighbors) = self.graph.get_neighbors(current) {
                for neighbor in neighbors {
                    if !visited.contains(&neighbor.id) {
                        visited.insert(neighbor.id);
                        queue.push_back((neighbor.id, dist + 1));
                    }
                }
            }
        }

        Ok(at_distance)
    }

    /// Apply sorting
    fn apply_sort(&self, mut nodes: Vec<GraphNode>, sort: &SortSpec) -> Vec<GraphNode> {
        nodes.sort_by(|a, b| {
            let cmp = match sort.field {
                SortField::Name => a.name.cmp(&b.name),
                SortField::RiskScore => a
                    .risk_score
                    .partial_cmp(&b.risk_score)
                    .unwrap_or(std::cmp::Ordering::Equal),
                SortField::CreatedAt => a.created_at.cmp(&b.created_at),
                SortField::UpdatedAt => a.updated_at.cmp(&b.updated_at),
                SortField::NodeType => a.node_type.to_string().cmp(&b.node_type.to_string()),
            };

            if sort.descending {
                cmp.reverse()
            } else {
                cmp
            }
        });

        nodes
    }

    /// Find nodes by type
    pub fn find_by_type(&self, node_type: NodeType) -> Vec<GraphNode> {
        self.graph.get_nodes_by_type(node_type)
    }

    /// Find nodes by label
    pub fn find_by_label(&self, label: &str) -> Vec<GraphNode> {
        self.graph.find_nodes_by_label(label)
    }

    /// Find nodes by property
    pub fn find_by_property<T: Serialize>(
        &self,
        key: &str,
        value: T,
    ) -> Result<Vec<GraphNode>> {
        let json_value = serde_json::to_value(value)
            .map_err(|e| GraphError::Serialization(e.to_string()))?;
        self.graph.find_nodes_by_property(key, &json_value)
    }

    /// Find nodes by risk level
    pub fn find_by_risk_level(&self, level: RiskLevel) -> Vec<GraphNode> {
        let (min, max) = level.score_range();
        self.graph
            .get_nodes()
            .into_iter()
            .filter(|n| n.risk_score >= min && n.risk_score <= max)
            .collect()
    }

    /// Find neighbors of a node
    pub fn find_neighbors(&self, node_id: EntityId) -> Result<Vec<GraphNode>> {
        self.graph.get_neighbors(node_id)
    }

    /// Find predecessors of a node
    pub fn find_predecessors(&self, node_id: EntityId) -> Result<Vec<GraphNode>> {
        self.graph.get_predecessors(node_id)
    }

    /// Find edges by type
    pub fn find_edges_by_type(&self, edge_type: EdgeType) -> Vec<GraphEdge> {
        self.graph.get_edges_by_type(edge_type)
    }

    /// Find paths between two nodes
    pub fn find_paths(
        &self,
        from: EntityId,
        to: EntityId,
        max_depth: usize,
    ) -> Result<Vec<Vec<EntityId>>> {
        use crate::PathAnalyzer;

        let analyzer = PathAnalyzer::new(self.graph);
        let paths = analyzer.find_paths(from, to, max_depth)?;
        Ok(paths.into_iter().map(|p| p.nodes).collect())
    }
}

use crate::RiskLevel;
use serde::Serialize;

/// Query builder for constructing graph queries
#[derive(Debug, Clone, Default)]
pub struct QueryBuilder {
    starting_nodes: Vec<EntityId>,
    node_filters: Vec<NodeFilter>,
    relationship_filters: Vec<EdgeFilter>,
    path_constraint: Option<PathConstraint>,
    sort: Option<SortSpec>,
    limit: Option<usize>,
}

impl QueryBuilder {
    /// Create a new query builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Start from specific nodes
    pub fn from_nodes(mut self, node_ids: Vec<EntityId>) -> Self {
        self.starting_nodes = node_ids;
        self
    }

    /// Filter by node type
    pub fn with_node_type(mut self, node_type: NodeType) -> Self {
        self.node_filters.push(NodeFilter::ByType(node_type));
        self
    }

    /// Filter by node label
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.node_filters.push(NodeFilter::ByLabel(label.into()));
        self
    }

    /// Filter by node property
    pub fn with_property<T: Serialize>(mut self, key: impl Into<String>, value: T) -> Self {
        if let Ok(json_value) = serde_json::to_value(value) {
            self.node_filters.push(NodeFilter::ByProperty {
                key: key.into(),
                value: json_value,
            });
        }
        self
    }

    /// Filter by risk range
    pub fn with_risk_range(mut self, min: f64, max: f64) -> Self {
        self.node_filters.push(NodeFilter::ByRiskRange { min, max });
        self
    }

    /// Filter by name pattern
    pub fn with_name_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.node_filters.push(NodeFilter::ByNamePattern(pattern.into()));
        self
    }

    /// Filter by node IDs
    pub fn with_ids(mut self, ids: Vec<EntityId>) -> Self {
        self.node_filters.push(NodeFilter::ById(ids));
        self
    }

    /// Add custom node filter
    pub fn with_custom_filter<F>(mut self, predicate: F) -> Self
    where
        F: Fn(&GraphNode) -> bool + Send + Sync + 'static,
    {
        self.node_filters.push(NodeFilter::Custom(Box::new(predicate)));
        self
    }

    /// Filter by edge type
    pub fn with_edge_type(mut self, edge_type: EdgeType) -> Self {
        self.relationship_filters.push(EdgeFilter::ByType(edge_type));
        self
    }

    /// Filter by edge property
    pub fn with_edge_property<T: Serialize>(mut self, key: impl Into<String>, value: T) -> Self {
        if let Ok(json_value) = serde_json::to_value(value) {
            self.relationship_filters.push(EdgeFilter::ByProperty {
                key: key.into(),
                value: json_value,
            });
        }
        self
    }

    /// Filter by edge weight range
    pub fn with_edge_weight_range(mut self, min: f64, max: f64) -> Self {
        self.relationship_filters.push(EdgeFilter::ByWeightRange { min, max });
        self
    }

    /// Filter edges from a specific node
    pub fn with_edge_from(mut self, node_id: EntityId) -> Self {
        self.relationship_filters.push(EdgeFilter::FromNode(node_id));
        self
    }

    /// Filter edges to a specific node
    pub fn with_edge_to(mut self, node_id: EntityId) -> Self {
        self.relationship_filters.push(EdgeFilter::ToNode(node_id));
        self
    }

    /// Add path constraint: nodes reachable from source
    pub fn reachable_from(mut self, source: EntityId, max_depth: usize) -> Self {
        self.path_constraint = Some(PathConstraint::ReachableFrom { source, max_depth });
        self
    }

    /// Add path constraint: nodes that can reach target
    pub fn can_reach(mut self, target: EntityId, max_depth: usize) -> Self {
        self.path_constraint = Some(PathConstraint::CanReach { target, max_depth });
        self
    }

    /// Add path constraint: nodes on path between two nodes
    pub fn on_path_between(mut self, from: EntityId, to: EntityId, max_depth: usize) -> Self {
        self.path_constraint = Some(PathConstraint::OnPathBetween { from, to, max_depth });
        self
    }

    /// Add path constraint: nodes at specific distance
    pub fn at_distance_from(mut self, source: EntityId, distance: usize) -> Self {
        self.path_constraint = Some(PathConstraint::DistanceFrom { source, distance });
        self
    }

    /// Sort results
    pub fn order_by(mut self, field: SortField, descending: bool) -> Self {
        self.sort = Some(SortSpec { field, descending });
        self
    }

    /// Limit number of results
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Execute the query
    pub fn execute(&self, graph: &AttackGraph) -> Result<QueryResult> {
        let query = GraphQuery::new(graph);
        query.execute(self)
    }
}

/// Node filter types
#[derive(Clone)]
pub enum NodeFilter {
    ByType(NodeType),
    ByLabel(String),
    ByProperty { key: String, value: serde_json::Value },
    ByRiskRange { min: f64, max: f64 },
    ByNamePattern(String),
    ById(Vec<EntityId>),
    Custom(Box<dyn Fn(&GraphNode) -> bool + Send + Sync>),
}

impl std::fmt::Debug for NodeFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeFilter::ByType(t) => write!(f, "ByType({:?})", t),
            NodeFilter::ByLabel(l) => write!(f, "ByLabel({})", l),
            NodeFilter::ByProperty { key, value } => write!(f, "ByProperty({}, {:?})", key, value),
            NodeFilter::ByRiskRange { min, max } => write!(f, "ByRiskRange({}, {})", min, max),
            NodeFilter::ByNamePattern(p) => write!(f, "ByNamePattern({})", p),
            NodeFilter::ById(ids) => write!(f, "ById({} ids)", ids.len()),
            NodeFilter::Custom(_) => write!(f, "Custom(predicate)"),
        }
    }
}

/// Edge filter types
#[derive(Clone)]
pub enum EdgeFilter {
    ByType(EdgeType),
    ByProperty { key: String, value: serde_json::Value },
    ByWeightRange { min: f64, max: f64 },
    FromNode(EntityId),
    ToNode(EntityId),
    Between { from: EntityId, to: EntityId },
    Custom(Box<dyn Fn(&GraphEdge) -> bool + Send + Sync>),
}

impl std::fmt::Debug for EdgeFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeFilter::ByType(t) => write!(f, "ByType({:?})", t),
            EdgeFilter::ByProperty { key, value } => write!(f, "ByProperty({}, {:?})", key, value),
            EdgeFilter::ByWeightRange { min, max } => write!(f, "ByWeightRange({}, {})", min, max),
            EdgeFilter::FromNode(id) => write!(f, "FromNode({})", id),
            EdgeFilter::ToNode(id) => write!(f, "ToNode({})", id),
            EdgeFilter::Between { from, to } => write!(f, "Between({}, {})", from, to),
            EdgeFilter::Custom(_) => write!(f, "Custom(predicate)"),
        }
    }
}

/// Path constraint types
#[derive(Debug, Clone)]
pub enum PathConstraint {
    ReachableFrom { source: EntityId, max_depth: usize },
    CanReach { target: EntityId, max_depth: usize },
    OnPathBetween { from: EntityId, to: EntityId, max_depth: usize },
    DistanceFrom { source: EntityId, distance: usize },
}

/// Sort field
#[derive(Debug, Clone, Copy)]
pub enum SortField {
    Name,
    RiskScore,
    CreatedAt,
    UpdatedAt,
    NodeType,
}

/// Sort specification
#[derive(Debug, Clone)]
pub struct SortSpec {
    pub field: SortField,
    pub descending: bool,
}

/// Query result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// Matching nodes
    pub nodes: Vec<GraphNode>,
    /// Matching edges (if relationship filters applied)
    pub edges: Vec<GraphEdge>,
    /// Total count of nodes
    pub total_count: usize,
    /// Execution time in milliseconds
    pub execution_time_ms: f64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl QueryResult {
    /// Get node IDs
    pub fn node_ids(&self) -> Vec<EntityId> {
        self.nodes.iter().map(|n| n.id).collect()
    }

    /// Get edge IDs
    pub fn edge_ids(&self) -> Vec<EntityId> {
        self.edges.iter().map(|e| e.id).collect()
    }

    /// Check if result is empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Get the first node
    pub fn first(&self) -> Option<&GraphNode> {
        self.nodes.first()
    }

    /// Get average risk score of nodes
    pub fn avg_risk(&self) -> f64 {
        if self.nodes.is_empty() {
            return 0.0;
        }
        self.nodes.iter().map(|n| n.risk_score).sum::<f64>() / self.nodes.len() as f64
    }

    /// Get highest risk node
    pub fn highest_risk_node(&self) -> Option<&GraphNode> {
        self.nodes.iter().max_by(|a, b| {
            a.risk_score.partial_cmp(&b.risk_score).unwrap_or(std::cmp::Ordering::Equal)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttackGraph, GraphEdge, GraphNode, NodeType};

    fn create_test_graph() -> AttackGraph {
        let graph = AttackGraph::new();

        // Create nodes
        let web = GraphNode::new(NodeType::EntryPoint, "Web Server")
            .with_label("external")
            .with_risk_score(5.0);
        let web_id = graph.add_node(web).unwrap();

        let api = GraphNode::new(NodeType::Application, "API Gateway")
            .with_label("internal")
            .with_risk_score(6.0);
        let api_id = graph.add_node(api).unwrap();

        let db = GraphNode::new(NodeType::Data, "Database")
            .with_label("sensitive")
            .with_property("encrypted", false)
            .with_risk_score(9.0);
        let db_id = graph.add_node(db).unwrap();

        // Create edges
        graph
            .add_edge(GraphEdge::new(web_id, api_id, EdgeType::ConnectsTo).with_weight(1.0))
            .unwrap();
        graph
            .add_edge(GraphEdge::new(api_id, db_id, EdgeType::Accesses).with_weight(2.0))
            .unwrap();

        graph
    }

    #[test]
    fn test_query_by_type() {
        let graph = create_test_graph();
        let query = GraphQuery::new(&graph);

        let nodes = query.find_by_type(NodeType::Data);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Database");
    }

    #[test]
    fn test_query_by_label() {
        let graph = create_test_graph();
        let query = GraphQuery::new(&graph);

        let nodes = query.find_by_label("sensitive");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Database");
    }

    #[test]
    fn test_query_by_risk_level() {
        let graph = create_test_graph();
        let query = GraphQuery::new(&graph);

        let nodes = query.find_by_risk_level(RiskLevel::Critical);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "Database");
    }

    #[test]
    fn test_query_builder() {
        let graph = create_test_graph();

        let result = QueryBuilder::new()
            .with_node_type(NodeType::Data)
            .with_label("sensitive")
            .execute(&graph)
            .unwrap();

        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.nodes[0].name, "Database");
    }

    #[test]
    fn test_query_builder_chain() {
        let graph = create_test_graph();

        let result = QueryBuilder::new()
            .with_risk_range(5.0, 7.0)
            .order_by(SortField::RiskScore, true)
            .limit(2)
            .execute(&graph)
            .unwrap();

        assert_eq!(result.nodes.len(), 2);
        // Should be sorted by risk descending
        assert!(result.nodes[0].risk_score >= result.nodes[1].risk_score);
    }

    #[test]
    fn test_reachable_from() {
        let graph = create_test_graph();
        let entry_id = graph.get_entry_points()[0].id;

        let result = QueryBuilder::new()
            .reachable_from(entry_id, 3)
            .execute(&graph)
            .unwrap();

        // Should find all reachable nodes including the source
        assert!(!result.nodes.is_empty());
    }

    #[test]
    fn test_query_result_methods() {
        let graph = create_test_graph();

        let result = QueryBuilder::new().execute(&graph).unwrap();

        assert_eq!(result.total_count, 3);
        assert!(!result.is_empty());
        assert!(result.first().is_some());
        assert!(result.avg_risk() > 0.0);
        assert!(result.highest_risk_node().is_some());
    }

    #[test]
    fn test_find_neighbors() {
        let graph = create_test_graph();
        let query = GraphQuery::new(&graph);
        let entry_id = graph.get_entry_points()[0].id;

        let neighbors = query.find_neighbors(entry_id).unwrap();
        assert_eq!(neighbors.len(), 1);
    }

    #[test]
    fn test_find_predecessors() {
        let graph = create_test_graph();
        let query = GraphQuery::new(&graph);
        let targets: Vec<_> = graph.get_targets();

        let predecessors = query.find_predecessors(targets[0].id).unwrap();
        assert_eq!(predecessors.len(), 1);
    }

    #[test]
    fn test_find_edges_by_type() {
        let graph = create_test_graph();
        let query = GraphQuery::new(&graph);

        let edges = query.find_edges_by_type(EdgeType::Accesses);
        assert_eq!(edges.len(), 1);
    }

    #[test]
    fn test_error_handling() {
        let graph = create_test_graph();
        let query = GraphQuery::new(&graph);
        let fake_id = EntityId::new_v4();

        assert!(query.find_neighbors(fake_id).is_err());
    }
}
