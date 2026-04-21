//! Attack path analysis for the graph database

use crate::{
    AttackGraph, EdgeType, EntityId, GraphEdge, GraphError, GraphNode, NodeType, Result, RiskLevel,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use tracing::{debug, trace, warn};

/// Attack path analyzer
///
/// Provides algorithms for finding and analyzing attack paths in the graph.
#[derive(Debug)]
pub struct PathAnalyzer<'a> {
    graph: &'a AttackGraph,
}

impl<'a> PathAnalyzer<'a> {
    /// Create a new path analyzer for the given graph
    pub fn new(graph: &'a AttackGraph) -> Self {
        Self { graph }
    }

    /// Find all simple paths from start to target using BFS
    ///
    /// # Arguments
    /// * `start` - Starting node ID
    /// * `target` - Target node ID
    /// * `max_depth` - Maximum path length
    ///
    /// # Returns
    /// * `Ok(Vec<AttackPath>)` - List of attack paths
    pub fn find_paths(&self, start: EntityId, target: EntityId, max_depth: usize) -> Result<Vec<AttackPath>> {
        if !self.graph.has_node(start) {
            return Err(GraphError::NodeNotFound(start));
        }
        if !self.graph.has_node(target) {
            return Err(GraphError::NodeNotFound(target));
        }

        if start == target {
            return Ok(vec![AttackPath::singleton(start)]);
        }

        let mut paths = Vec::new();
        let mut visited = HashSet::new();
        let mut current_path = VecDeque::new();

        self.dfs_paths(start, target, max_depth, &mut visited, &mut current_path, &mut paths);

        trace!("Found {} paths from {} to {}", paths.len(), start, target);
        Ok(paths)
    }

    fn dfs_paths(
        &self,
        current: EntityId,
        target: EntityId,
        max_depth: usize,
        visited: &mut HashSet<EntityId>,
        current_path: &mut VecDeque<EntityId>,
        paths: &mut Vec<AttackPath>,
    ) {
        if current_path.len() >= max_depth {
            return;
        }

        visited.insert(current);
        current_path.push_back(current);

        if current == target {
            // Found a path
            let path_nodes: Vec<EntityId> = current_path.iter().copied().collect();
            let path = self.build_path(&path_nodes);
            paths.push(path);
        } else {
            // Continue DFS
            if let Ok(neighbors) = self.graph.get_neighbors(current) {
                for neighbor in neighbors {
                    if !visited.contains(&neighbor.id) {
                        self.dfs_paths(
                            neighbor.id,
                            target,
                            max_depth,
                            visited,
                            current_path,
                            paths,
                        );
                    }
                }
            }
        }

        current_path.pop_back();
        visited.remove(&current);
    }

    /// Find the shortest path using BFS
    pub fn find_shortest_path(&self, start: EntityId, target: EntityId) -> Result<Option<AttackPath>> {
        if !self.graph.has_node(start) {
            return Err(GraphError::NodeNotFound(start));
        }
        if !self.graph.has_node(target) {
            return Err(GraphError::NodeNotFound(target));
        }

        if start == target {
            return Ok(Some(AttackPath::singleton(start)));
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut parent: HashMap<EntityId, (EntityId, EntityId)> = HashMap::new(); // node -> (parent_node, edge_id)

        queue.push_back(start);
        visited.insert(start);

        while let Some(current) = queue.pop_front() {
            if current == target {
                // Reconstruct path
                let mut path_nodes = vec![target];
                let mut edges = Vec::new();
                let mut node = target;

                while let Some((parent_node, edge_id)) = parent.get(&node) {
                    path_nodes.push(*parent_node);
                    if let Some(edge) = self.graph.get_edge(*edge_id) {
                        edges.push(edge);
                    }
                    node = *parent_node;
                }

                path_nodes.reverse();
                edges.reverse();

                let path = AttackPath {
                    nodes: path_nodes,
                    edges,
                    total_risk: self.calculate_path_risk(&path_nodes),
                    total_weight: self.calculate_path_weight(&path_nodes),
                    path_length: path_nodes.len(),
                    created_at: Utc::now(),
                };

                return Ok(Some(path));
            }

            if let Ok(neighbors) = self.graph.get_neighbors(current) {
                for neighbor in neighbors {
                    if !visited.contains(&neighbor.id) {
                        // Find the edge connecting current to neighbor
                        if let Ok(outgoing) = self.graph.get_outgoing_edges(current) {
                            for edge in outgoing {
                                if edge.to == neighbor.id {
                                    visited.insert(neighbor.id);
                                    parent.insert(neighbor.id, (current, edge.id));
                                    queue.push_back(neighbor.id);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Find paths using Dijkstra's algorithm (weighted shortest paths)
    pub fn find_weighted_paths(
        &self,
        start: EntityId,
        target: EntityId,
        max_paths: usize,
    ) -> Result<Vec<AttackPath>> {
        if !self.graph.has_node(start) {
            return Err(GraphError::NodeNotFound(start));
        }
        if !self.graph.has_node(target) {
            return Err(GraphError::NodeNotFound(target));
        }

        if start == target {
            return Ok(vec![AttackPath::singleton(start)]);
        }

        // Dijkstra's algorithm
        let mut distances: HashMap<EntityId, f64> = HashMap::new();
        let mut previous: HashMap<EntityId, (Option<EntityId>, Option<EntityId>)> = HashMap::new(); // node -> (prev_node, edge_id)
        let mut visited = HashSet::new();

        // Priority queue: (distance, node_id)
        let mut heap: BinaryHeap<std::cmp::Reverse<(OrderedF64, EntityId)>> = BinaryHeap::new();

        distances.insert(start, 0.0);
        heap.push(std::cmp::Reverse((OrderedF64(0.0), start)));

        while let Some(std::cmp::Reverse((dist, current))) = heap.pop() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current);

            if current == target {
                break;
            }

            if let Ok(outgoing) = self.graph.get_outgoing_edges(current) {
                for edge in outgoing {
                    let neighbor = edge.to;
                    let weight = edge.weight;
                    let new_dist = dist.0 + weight;

                    if new_dist < *distances.get(&neighbor).unwrap_or(&f64::INFINITY) {
                        distances.insert(neighbor, new_dist);
                        previous.insert(neighbor, (Some(current), Some(edge.id)));
                        heap.push(std::cmp::Reverse((OrderedF64(new_dist), neighbor)));
                    }
                }
            }
        }

        // Reconstruct path
        if !distances.contains_key(&target) {
            return Ok(Vec::new());
        }

        let mut path_nodes = vec![target];
        let mut edges = Vec::new();
        let mut node = target;

        while let Some((Some(prev_node), Some(edge_id))) = previous.get(&node) {
            path_nodes.push(*prev_node);
            if let Some(edge) = self.graph.get_edge(*edge_id) {
                edges.push(edge);
            }
            node = *prev_node;
        }

        path_nodes.reverse();
        edges.reverse();

        let path = AttackPath {
            nodes: path_nodes.clone(),
            edges,
            total_risk: self.calculate_path_risk(&path_nodes),
            total_weight: distances[&target],
            path_length: path_nodes.len(),
            created_at: Utc::now(),
        };

        Ok(vec![path])
    }

    /// Find critical paths (high-risk paths from entry points to sensitive data)
    pub fn find_critical_paths(&self, min_risk: f64) -> Result<Vec<AttackPath>> {
        let entry_points = self.graph.get_entry_points();
        let sensitive_nodes: Vec<GraphNode> = self
            .graph
            .get_nodes()
            .into_iter()
            .filter(|n| {
                n.node_type == NodeType::Data
                    || n.labels.contains(&"sensitive".to_string())
                    || n.risk_score >= min_risk
            })
            .collect();

        let mut critical_paths = Vec::new();

        for entry in &entry_points {
            for target in &sensitive_nodes {
                if entry.id != target.id {
                    match self.find_paths(entry.id, target.id, 10) {
                        Ok(paths) => {
                            for path in paths {
                                if path.total_risk >= min_risk {
                                    critical_paths.push(path);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Error finding paths: {}", e);
                        }
                    }
                }
            }
        }

        // Sort by risk score (highest first)
        critical_paths.sort_by(|a, b| {
            b.total_risk
                .partial_cmp(&a.total_risk)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        debug!("Found {} critical paths", critical_paths.len());
        Ok(critical_paths)
    }

    /// Find all paths from any entry point to any target
    pub fn find_all_attack_paths(&self, max_depth: usize) -> Result<Vec<AttackPath>> {
        let entry_points: Vec<EntityId> = self
            .graph
            .get_entry_points()
            .into_iter()
            .map(|n| n.id)
            .collect();
        let targets: Vec<EntityId> = self
            .graph
            .get_targets()
            .into_iter()
            .map(|n| n.id)
            .collect();

        let mut all_paths = Vec::new();

        for entry in &entry_points {
            for target in &targets {
                if entry != target {
                    match self.find_paths(*entry, *target, max_depth) {
                        Ok(paths) => all_paths.extend(paths),
                        Err(e) => warn!("Error finding paths: {}", e),
                    }
                }
            }
        }

        // Remove duplicates and sort by risk
        all_paths.sort_by(|a, b| {
            b.total_risk
                .partial_cmp(&a.total_risk)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        all_paths.dedup_by(|a, b| a.nodes == b.nodes);

        Ok(all_paths)
    }

    /// Find choke points (nodes that appear in many attack paths)
    pub fn find_choke_points(&self, min_path_count: usize) -> Result<Vec<(GraphNode, usize)>> {
        let paths = self.find_all_attack_paths(10)?;
        let mut node_frequency: HashMap<EntityId, usize> = HashMap::new();

        for path in &paths {
            for node_id in &path.nodes {
                *node_frequency.entry(*node_id).or_insert(0) += 1;
            }
        }

        let mut choke_points: Vec<(GraphNode, usize)> = node_frequency
            .into_iter()
            .filter(|(_, count)| *count >= min_path_count)
            .filter_map(|(id, count)| self.graph.get_node(id).map(|n| (n, count)))
            .collect();

        choke_points.sort_by(|a, b| b.1.cmp(&a.1));

        Ok(choke_points)
    }

    /// Calculate the risk score for a path
    fn calculate_path_risk(&self, node_ids: &[EntityId]) -> f64 {
        let mut total_risk = 0.0;
        let mut count = 0;

        for node_id in node_ids {
            if let Some(node) = self.graph.get_node(*node_id) {
                total_risk += node.risk_score;
                count += 1;
            }
        }

        if count == 0 {
            0.0
        } else {
            total_risk / count as f64
        }
    }

    /// Calculate the total weight for a path
    fn calculate_path_weight(&self, node_ids: &[EntityId]) -> f64 {
        let mut total_weight = 0.0;

        for window in node_ids.windows(2) {
            if let [from, to] = window {
                if let Ok(edges) = self.graph.get_outgoing_edges(*from) {
                    for edge in edges {
                        if edge.to == *to {
                            total_weight += edge.weight;
                            break;
                        }
                    }
                }
            }
        }

        total_weight
    }

    /// Build an AttackPath from a list of node IDs
    fn build_path(&self, node_ids: &[EntityId]) -> AttackPath {
        let mut edges = Vec::new();

        for window in node_ids.windows(2) {
            if let [from, to] = window {
                if let Ok(outgoing) = self.graph.get_outgoing_edges(*from) {
                    for edge in outgoing {
                        if edge.to == *to {
                            edges.push(edge);
                            break;
                        }
                    }
                }
            }
        }

        AttackPath {
            nodes: node_ids.to_vec(),
            edges,
            total_risk: self.calculate_path_risk(node_ids),
            total_weight: self.calculate_path_weight(node_ids),
            path_length: node_ids.len(),
            created_at: Utc::now(),
        }
    }

    /// Calculate path metrics
    pub fn calculate_path_metrics(&self, path: &AttackPath) -> PathMetrics {
        let node_count = path.nodes.len();
        let edge_count = path.edges.len();

        // Calculate average node risk
        let avg_node_risk: f64 = path
            .nodes
            .iter()
            .filter_map(|id| self.graph.get_node(*id).map(|n| n.risk_score))
            .sum::<f64>()
            / node_count as f64;

        // Calculate average edge weight
        let avg_edge_weight: f64 = if edge_count > 0 {
            path.edges.iter().map(|e| e.weight).sum::<f64>() / edge_count as f64
        } else {
            0.0
        };

        // Count node types
        let mut node_type_counts: HashMap<NodeType, usize> = HashMap::new();
        for node_id in &path.nodes {
            if let Some(node) = self.graph.get_node(*node_id) {
                *node_type_counts.entry(node.node_type).or_insert(0) += 1;
            }
        }

        // Count edge types
        let mut edge_type_counts: HashMap<EdgeType, usize> = HashMap::new();
        for edge in &path.edges {
            *edge_type_counts.entry(edge.edge_type).or_insert(0) += 1;
        }

        PathMetrics {
            node_count,
            edge_count,
            avg_node_risk,
            avg_edge_weight,
            total_risk: path.total_risk,
            total_weight: path.total_weight,
            node_type_counts,
            edge_type_counts,
        }
    }
}

/// Represents an attack path through the graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    /// Node IDs in the path (in order)
    pub nodes: Vec<EntityId>,
    /// Edges in the path (in order)
    pub edges: Vec<GraphEdge>,
    /// Average risk score of the path
    pub total_risk: f64,
    /// Total weight of the path
    pub total_weight: f64,
    /// Number of nodes in the path
    pub path_length: usize,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

impl AttackPath {
    /// Create a singleton path (single node)
    pub fn singleton(node_id: EntityId) -> Self {
        Self {
            nodes: vec![node_id],
            edges: Vec::new(),
            total_risk: 0.0,
            total_weight: 0.0,
            path_length: 1,
            created_at: Utc::now(),
        }
    }

    /// Get the start node ID
    pub fn start(&self) -> Option<EntityId> {
        self.nodes.first().copied()
    }

    /// Get the end node ID
    pub fn end(&self) -> Option<EntityId> {
        self.nodes.last().copied()
    }

    /// Check if the path contains a specific node
    pub fn contains_node(&self, node_id: EntityId) -> bool {
        self.nodes.contains(&node_id)
    }

    /// Get the risk level of this path
    pub fn risk_level(&self) -> RiskLevel {
        RiskLevel::from_score(self.total_risk)
    }

    /// Check if this is a high-risk path
    pub fn is_high_risk(&self) -> bool {
        self.total_risk >= 7.0
    }

    /// Get the number of hops in the path
    pub fn hop_count(&self) -> usize {
        self.nodes.len().saturating_sub(1)
    }
}

/// Metrics for an attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathMetrics {
    /// Number of nodes in the path
    pub node_count: usize,
    /// Number of edges in the path
    pub edge_count: usize,
    /// Average risk score of nodes
    pub avg_node_risk: f64,
    /// Average weight of edges
    pub avg_edge_weight: f64,
    /// Total risk score
    pub total_risk: f64,
    /// Total weight
    pub total_weight: f64,
    /// Count of nodes by type
    pub node_type_counts: HashMap<NodeType, usize>,
    /// Count of edges by type
    pub edge_type_counts: HashMap<EdgeType, usize>,
}

impl PathMetrics {
    /// Get the density of the path (edges / possible edges)
    pub fn density(&self) -> f64 {
        if self.node_count <= 1 {
            return 0.0;
        }
        let possible_edges = self.node_count - 1;
        self.edge_count as f64 / possible_edges as f64
    }

    /// Get the most common node type
    pub fn dominant_node_type(&self) -> Option<NodeType> {
        self.node_type_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(t, _)| t.clone())
    }

    /// Get the most common edge type
    pub fn dominant_edge_type(&self) -> Option<EdgeType> {
        self.edge_type_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(t, _)| t.clone())
    }
}

/// Wrapper for f64 to implement Ord for use in BinaryHeap
#[derive(Debug, Clone, Copy, PartialEq)]
struct OrderedF64(f64);

impl Eq for OrderedF64 {}

impl PartialOrd for OrderedF64 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl Ord for OrderedF64 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.partial_cmp(other).unwrap_or(std::cmp::Ordering::Equal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttackGraph, GraphEdge, GraphNode, NodeType};

    fn create_test_graph() -> AttackGraph {
        let graph = AttackGraph::new();

        // Create nodes: Entry -> Vuln -> Asset -> Data
        let entry = GraphNode::new(NodeType::EntryPoint, "Web Server").with_risk_score(5.0);
        let entry_id = graph.add_node(entry).unwrap();

        let vuln = GraphNode::new(NodeType::Vulnerability, "SQL Injection").with_risk_score(8.0);
        let vuln_id = graph.add_node(vuln).unwrap();

        let asset = GraphNode::new(NodeType::Asset, "Database Server").with_risk_score(7.0);
        let asset_id = graph.add_node(asset).unwrap();

        let data = GraphNode::new(NodeType::Data, "User Data")
            .with_label("sensitive")
            .with_risk_score(9.0);
        let data_id = graph.add_node(data).unwrap();

        // Create edges
        graph
            .add_edge(GraphEdge::new(entry_id, vuln_id, EdgeType::Exploits).with_weight(1.0))
            .unwrap();
        graph
            .add_edge(GraphEdge::new(vuln_id, asset_id, EdgeType::LeadsTo).with_weight(2.0))
            .unwrap();
        graph
            .add_edge(GraphEdge::new(asset_id, data_id, EdgeType::Accesses).with_weight(1.0))
            .unwrap();

        graph
    }

    #[test]
    fn test_find_paths() {
        let graph = create_test_graph();
        let analyzer = PathAnalyzer::new(&graph);

        let entry_id = graph.get_entry_points()[0].id;
        let data_id = graph
            .get_nodes_by_type(NodeType::Data)[0]
            .id;

        let paths = analyzer.find_paths(entry_id, data_id, 10).unwrap();
        assert!(!paths.is_empty());

        let path = &paths[0];
        assert_eq!(path.nodes.len(), 4);
        assert_eq!(path.start(), Some(entry_id));
        assert_eq!(path.end(), Some(data_id));
    }

    #[test]
    fn test_find_shortest_path() {
        let graph = create_test_graph();
        let analyzer = PathAnalyzer::new(&graph);

        let entry_id = graph.get_entry_points()[0].id;
        let data_id = graph
            .get_nodes_by_type(NodeType::Data)[0]
            .id;

        let path = analyzer.find_shortest_path(entry_id, data_id).unwrap();
        assert!(path.is_some());

        let path = path.unwrap();
        assert_eq!(path.nodes.len(), 4);
        assert_eq!(path.hop_count(), 3);
    }

    #[test]
    fn test_find_critical_paths() {
        let graph = create_test_graph();
        let analyzer = PathAnalyzer::new(&graph);

        let paths = analyzer.find_critical_paths(7.0).unwrap();
        assert!(!paths.is_empty());

        // All paths should have risk >= 7.0
        for path in &paths {
            assert!(path.total_risk >= 7.0 || path.is_high_risk());
        }
    }

    #[test]
    fn test_path_metrics() {
        let graph = create_test_graph();
        let analyzer = PathAnalyzer::new(&graph);

        let entry_id = graph.get_entry_points()[0].id;
        let data_id = graph
            .get_nodes_by_type(NodeType::Data)[0]
            .id;

        let paths = analyzer.find_paths(entry_id, data_id, 10).unwrap();
        assert!(!paths.is_empty());

        let metrics = analyzer.calculate_path_metrics(&paths[0]);
        assert_eq!(metrics.node_count, 4);
        assert_eq!(metrics.edge_count, 3);
        assert!(metrics.avg_node_risk > 0.0);
        assert!(metrics.density() > 0.0);
    }

    #[test]
    fn test_attack_path_methods() {
        let path = AttackPath::singleton(EntityId::new_v4());
        assert_eq!(path.nodes.len(), 1);
        assert_eq!(path.hop_count(), 0);
        assert!(!path.is_high_risk());
    }

    #[test]
    fn test_find_choke_points() {
        let graph = create_test_graph();
        let analyzer = PathAnalyzer::new(&graph);

        let choke_points = analyzer.find_choke_points(1).unwrap();
        // Should find nodes that appear in paths
        assert!(!choke_points.is_empty());
    }

    #[test]
    fn test_error_handling() {
        let graph = AttackGraph::new();
        let analyzer = PathAnalyzer::new(&graph);

        let fake_id = EntityId::new_v4();
        assert!(matches!(
            analyzer.find_paths(fake_id, fake_id, 10),
            Err(GraphError::NodeNotFound(_))
        ));
    }
}
