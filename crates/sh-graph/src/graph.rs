//! Graph database implementation for attack graphs

use crate::{
    EdgeType, EntityId, GraphError, GraphStats, NodeType, Properties, Result, RiskLevel,
};
use chrono::{DateTime, Utc};
use dashmap::{DashMap, DashSet};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use tracing::{debug, trace, warn};
use uuid::Uuid;

/// Attack graph database
///
/// Stores nodes and edges in concurrent hash maps for thread-safe access.
/// Uses adjacency lists for efficient traversal operations.
#[derive(Debug)]
pub struct AttackGraph {
    /// All nodes in the graph
    nodes: DashMap<EntityId, GraphNode>,
    /// All edges in the graph
    edges: DashMap<EntityId, GraphEdge>,
    /// Outgoing adjacency list: node_id -> set of edge_ids
    adjacency_out: DashMap<EntityId, DashSet<EntityId>>,
    /// Incoming adjacency list: node_id -> set of edge_ids
    adjacency_in: DashMap<EntityId, DashSet<EntityId>>,
    /// Graph statistics
    stats: std::sync::RwLock<GraphStats>,
}

impl AttackGraph {
    /// Create a new empty attack graph
    pub fn new() -> Self {
        Self {
            nodes: DashMap::new(),
            edges: DashMap::new(),
            adjacency_out: DashMap::new(),
            adjacency_in: DashMap::new(),
            stats: std::sync::RwLock::new(GraphStats::new()),
        }
    }

    /// Add a node to the graph
    ///
    /// # Arguments
    /// * `node` - The node to add
    ///
    /// # Returns
    /// * `Ok(EntityId)` - The ID of the added node
    /// * `Err(GraphError::NodeExists)` - If a node with the same ID already exists
    pub fn add_node(&self, node: GraphNode) -> Result<EntityId> {
        let id = node.id;

        if self.nodes.contains_key(&id) {
            return Err(GraphError::NodeExists(id));
        }

        // Update adjacency lists
        self.adjacency_out.entry(id).or_insert_with(DashSet::new);
        self.adjacency_in.entry(id).or_insert_with(DashSet::new);

        // Update stats
        {
            let mut stats = self.stats.write().map_err(|_| {
                GraphError::LockAcquisition("Failed to acquire stats lock".to_string())
            })?;
            stats.node_count += 1;
            *stats.node_types.entry(node.node_type).or_insert(0) += 1;
            stats.touch();
        }

        self.nodes.insert(id, node);
        trace!("Added node {} to graph", id);

        Ok(id)
    }

    /// Remove a node from the graph
    ///
    /// Also removes all connected edges.
    pub fn remove_node(&self, id: EntityId) -> Result<GraphNode> {
        // Remove connected edges first
        let outgoing: Vec<EntityId> = self
            .adjacency_out
            .get(&id)
            .map(|set| set.iter().map(|e| *e.key()).collect())
            .unwrap_or_default();
        let incoming: Vec<EntityId> = self
            .adjacency_in
            .get(&id)
            .map(|set| set.iter().map(|e| *e.key()).collect())
            .unwrap_or_default();

        for edge_id in outgoing.iter().chain(incoming.iter()) {
            let _ = self.remove_edge(*edge_id);
        }

        // Remove from adjacency lists
        self.adjacency_out.remove(&id);
        self.adjacency_in.remove(&id);

        // Remove node
        let node = self
            .nodes
            .remove(&id)
            .map(|(_, n)| n)
            .ok_or(GraphError::NodeNotFound(id))?;

        // Update stats
        {
            let mut stats = self.stats.write().map_err(|_| {
                GraphError::LockAcquisition("Failed to acquire stats lock".to_string())
            })?;
            stats.node_count -= 1;
            if let Some(count) = stats.node_types.get_mut(&node.node_type) {
                *count -= 1;
            }
            stats.touch();
        }

        trace!("Removed node {} from graph", id);
        Ok(node)
    }

    /// Get a node by ID
    pub fn get_node(&self, id: EntityId) -> Option<GraphNode> {
        self.nodes.get(&id).map(|n| n.clone())
    }

    /// Check if a node exists
    pub fn has_node(&self, id: EntityId) -> bool {
        self.nodes.contains_key(&id)
    }

    /// Update a node
    pub fn update_node(&self, node: GraphNode) -> Result<()> {
        let id = node.id;

        if !self.nodes.contains_key(&id) {
            return Err(GraphError::NodeNotFound(id));
        }

        self.nodes.insert(id, node);

        // Update stats
        {
            let mut stats = self.stats.write().map_err(|_| {
                GraphError::LockAcquisition("Failed to acquire stats lock".to_string())
            })?;
            stats.touch();
        }

        trace!("Updated node {} in graph", id);
        Ok(())
    }

    /// Add an edge to the graph
    ///
    /// # Arguments
    /// * `edge` - The edge to add
    ///
    /// # Returns
    /// * `Ok(EntityId)` - The ID of the added edge
    /// * `Err(GraphError::NodeNotFound)` - If source or target node doesn't exist
    /// * `Err(GraphError::EdgeExists)` - If an edge with the same ID already exists
    pub fn add_edge(&self, edge: GraphEdge) -> Result<EntityId> {
        let id = edge.id;
        let from = edge.from;
        let to = edge.to;

        // Validate nodes exist
        if !self.nodes.contains_key(&from) {
            return Err(GraphError::NodeNotFound(from));
        }
        if !self.nodes.contains_key(&to) {
            return Err(GraphError::NodeNotFound(to));
        }

        if self.edges.contains_key(&id) {
            return Err(GraphError::EdgeExists(id));
        }

        // Update adjacency lists
        self.adjacency_out
            .entry(from)
            .or_insert_with(DashSet::new)
            .insert(id);
        self.adjacency_in
            .entry(to)
            .or_insert_with(DashSet::new)
            .insert(id);

        // Update stats
        {
            let mut stats = self.stats.write().map_err(|_| {
                GraphError::LockAcquisition("Failed to acquire stats lock".to_string())
            })?;
            stats.edge_count += 1;
            *stats.edge_types.entry(edge.edge_type).or_insert(0) += 1;
            stats.touch();
        }

        self.edges.insert(id, edge);
        trace!("Added edge {} from {} to {}", id, from, to);

        Ok(id)
    }

    /// Remove an edge from the graph
    pub fn remove_edge(&self, id: EntityId) -> Result<GraphEdge> {
        let edge = self
            .edges
            .remove(&id)
            .map(|(_, e)| e)
            .ok_or(GraphError::EdgeNotFound(id))?;

        // Update adjacency lists
        if let Some(mut set) = self.adjacency_out.get_mut(&edge.from) {
            set.remove(&id);
        }
        if let Some(mut set) = self.adjacency_in.get_mut(&edge.to) {
            set.remove(&id);
        }

        // Update stats
        {
            let mut stats = self.stats.write().map_err(|_| {
                GraphError::LockAcquisition("Failed to acquire stats lock".to_string())
            })?;
            stats.edge_count -= 1;
            if let Some(count) = stats.edge_types.get_mut(&edge.edge_type) {
                *count -= 1;
            }
            stats.touch();
        }

        trace!("Removed edge {} from graph", id);
        Ok(edge)
    }

    /// Get an edge by ID
    pub fn get_edge(&self, id: EntityId) -> Option<GraphEdge> {
        self.edges.get(&id).map(|e| e.clone())
    }

    /// Check if an edge exists
    pub fn has_edge(&self, id: EntityId) -> bool {
        self.edges.contains_key(&id)
    }

    /// Get all nodes
    pub fn get_nodes(&self) -> Vec<GraphNode> {
        self.nodes.iter().map(|n| n.clone()).collect()
    }

    /// Get all edges
    pub fn get_edges(&self) -> Vec<GraphEdge> {
        self.edges.iter().map(|e| e.clone()).collect()
    }

    /// Get nodes by type
    pub fn get_nodes_by_type(&self, node_type: NodeType) -> Vec<GraphNode> {
        self.nodes
            .iter()
            .filter(|n| n.node_type == node_type)
            .map(|n| n.clone())
            .collect()
    }

    /// Get edges by type
    pub fn get_edges_by_type(&self, edge_type: EdgeType) -> Vec<GraphEdge> {
        self.edges
            .iter()
            .filter(|e| e.edge_type == edge_type)
            .map(|e| e.clone())
            .collect()
    }

    /// Get outgoing edges from a node
    pub fn get_outgoing_edges(&self, node_id: EntityId) -> Result<Vec<GraphEdge>> {
        if !self.nodes.contains_key(&node_id) {
            return Err(GraphError::NodeNotFound(node_id));
        }

        let edge_ids: Vec<EntityId> = self
            .adjacency_out
            .get(&node_id)
            .map(|set| set.iter().map(|e| *e.key()).collect())
            .unwrap_or_default();

        Ok(edge_ids
            .iter()
            .filter_map(|id| self.edges.get(id).map(|e| e.clone()))
            .collect())
    }

    /// Get incoming edges to a node
    pub fn get_incoming_edges(&self, node_id: EntityId) -> Result<Vec<GraphEdge>> {
        if !self.nodes.contains_key(&node_id) {
            return Err(GraphError::NodeNotFound(node_id));
        }

        let edge_ids: Vec<EntityId> = self
            .adjacency_in
            .get(&node_id)
            .map(|set| set.iter().map(|e| *e.key()).collect())
            .unwrap_or_default();

        Ok(edge_ids
            .iter()
            .filter_map(|id| self.edges.get(id).map(|e| e.clone()))
            .collect())
    }

    /// Get neighbors of a node (nodes connected by outgoing edges)
    pub fn get_neighbors(&self, node_id: EntityId) -> Result<Vec<GraphNode>> {
        let edges = self.get_outgoing_edges(node_id)?;
        Ok(edges
            .iter()
            .filter_map(|e| self.nodes.get(&e.to).map(|n| n.clone()))
            .collect())
    }

    /// Get predecessors of a node (nodes connected by incoming edges)
    pub fn get_predecessors(&self, node_id: EntityId) -> Result<Vec<GraphNode>> {
        let edges = self.get_incoming_edges(node_id)?;
        Ok(edges
            .iter()
            .filter_map(|e| self.nodes.get(&e.from).map(|n| n.clone()))
            .collect())
    }

    /// Get the number of nodes
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get the number of edges
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Check if the graph is empty
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Clear the graph
    pub fn clear(&self) {
        self.nodes.clear();
        self.edges.clear();
        self.adjacency_out.clear();
        self.adjacency_in.clear();

        if let Ok(mut stats) = self.stats.write() {
            *stats = GraphStats::new();
        }

        debug!("Cleared graph");
    }

    /// Get graph statistics
    pub fn stats(&self) -> Result<GraphStats> {
        self.stats
            .read()
            .map(|s| s.clone())
            .map_err(|_| GraphError::LockAcquisition("Failed to acquire stats lock".to_string()))
    }

    /// Calculate graph density
    /// Density = 2 * |E| / (|V| * (|V| - 1)) for directed graphs
    pub fn density(&self) -> f64 {
        let n = self.node_count() as f64;
        let m = self.edge_count() as f64;

        if n <= 1.0 {
            return 0.0;
        }

        m / (n * (n - 1.0))
    }

    /// Calculate average degree
    pub fn average_degree(&self) -> f64 {
        let n = self.node_count() as f64;
        if n == 0.0 {
            return 0.0;
        }

        let total_degree: usize = self
            .nodes
            .iter()
            .map(|n| {
                let out = self
                    .adjacency_out
                    .get(&n.id)
                    .map(|s| s.len())
                    .unwrap_or(0);
                let in_deg = self
                    .adjacency_in
                    .get(&n.id)
                    .map(|s| s.len())
                    .unwrap_or(0);
                out + in_deg
            })
            .sum();

        total_degree as f64 / n
    }

    /// Find nodes by property value
    pub fn find_nodes_by_property<T: Serialize>(
        &self,
        key: &str,
        value: T,
    ) -> Result<Vec<GraphNode>> {
        let target_value = serde_json::to_value(value)
            .map_err(|e| GraphError::Serialization(e.to_string()))?;

        Ok(self
            .nodes
            .iter()
            .filter(|n| {
                n.properties
                    .get(key)
                    .map(|v| v == &target_value)
                    .unwrap_or(false)
            })
            .map(|n| n.clone())
            .collect())
    }

    /// Find nodes by label
    pub fn find_nodes_by_label(&self, label: &str) -> Vec<GraphNode> {
        self.nodes
            .iter()
            .filter(|n| n.labels.contains(&label.to_string()))
            .map(|n| n.clone())
            .collect()
    }

    /// Get entry points (nodes with no incoming edges)
    pub fn get_entry_points(&self) -> Vec<GraphNode> {
        self.nodes
            .iter()
            .filter(|n| {
                self.adjacency_in
                    .get(&n.id)
                    .map(|s| s.is_empty())
                    .unwrap_or(true)
            })
            .map(|n| n.clone())
            .collect()
    }

    /// Get targets (nodes with no outgoing edges)
    pub fn get_targets(&self) -> Vec<GraphNode> {
        self.nodes
            .iter()
            .filter(|n| {
                self.adjacency_out
                    .get(&n.id)
                    .map(|s| s.is_empty())
                    .unwrap_or(true)
            })
            .map(|n| n.clone())
            .collect()
    }

    /// Check if the graph has cycles
    pub fn has_cycles(&self) -> bool {
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();

        for node in self.nodes.iter() {
            if !visited.contains(&node.id) {
                if self.has_cycles_dfs(node.id, &mut visited, &mut rec_stack) {
                    return true;
                }
            }
        }

        false
    }

    fn has_cycles_dfs(
        &self,
        node_id: EntityId,
        visited: &mut HashSet<EntityId>,
        rec_stack: &mut HashSet<EntityId>,
    ) -> bool {
        visited.insert(node_id);
        rec_stack.insert(node_id);

        if let Some(edges) = self.adjacency_out.get(&node_id) {
            for edge_id in edges.iter() {
                if let Some(edge) = self.edges.get(edge_id.key()) {
                    let neighbor = edge.to;
                    if !visited.contains(&neighbor) {
                        if self.has_cycles_dfs(neighbor, visited, rec_stack) {
                            return true;
                        }
                    } else if rec_stack.contains(&neighbor) {
                        return true;
                    }
                }
            }
        }

        rec_stack.remove(&node_id);
        false
    }
}

impl Default for AttackGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Graph node representing an entity in the attack graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    /// Unique identifier
    pub id: EntityId,
    /// Node type
    pub node_type: NodeType,
    /// Human-readable name
    pub name: String,
    /// Labels for categorization
    pub labels: Vec<String>,
    /// Node properties
    pub properties: Properties,
    /// Risk score (0-10)
    pub risk_score: f64,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl GraphNode {
    /// Create a new graph node
    pub fn new(node_type: NodeType, name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            node_type,
            name: name.into(),
            labels: Vec::new(),
            properties: Properties::new(),
            risk_score: 0.0,
            created_at: now,
            updated_at: now,
        }
    }

    /// Set the node ID
    pub fn with_id(mut self, id: EntityId) -> Self {
        self.id = id;
        self
    }

    /// Add a label
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.labels.push(label.into());
        self
    }

    /// Add multiple labels
    pub fn with_labels(mut self, labels: Vec<impl Into<String>>) -> Self {
        self.labels.extend(labels.into_iter().map(|l| l.into()));
        self
    }

    /// Add a property
    pub fn with_property<T: Serialize>(mut self, key: impl Into<String>, value: T) -> Self {
        self.properties = self.properties.with(key, value);
        self
    }

    /// Set the risk score
    pub fn with_risk_score(mut self, score: f64) -> Self {
        self.risk_score = score.clamp(0.0, 10.0);
        self
    }

    /// Get the risk level
    pub fn risk_level(&self) -> RiskLevel {
        RiskLevel::from_score(self.risk_score)
    }

    /// Update the timestamp
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    /// Check if the node has a specific label
    pub fn has_label(&self, label: &str) -> bool {
        self.labels.contains(&label.to_string())
    }

    /// Check if the node has a specific type
    pub fn is_type(&self, node_type: NodeType) -> bool {
        self.node_type == node_type
    }
}

/// Graph edge representing a relationship between nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    /// Unique identifier
    pub id: EntityId,
    /// Source node ID
    pub from: EntityId,
    /// Target node ID
    pub to: EntityId,
    /// Edge type
    pub edge_type: EdgeType,
    /// Edge properties
    pub properties: Properties,
    /// Weight for path calculations
    pub weight: f64,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

impl GraphEdge {
    /// Create a new graph edge
    pub fn new(from: EntityId, to: EntityId, edge_type: impl Into<EdgeType>) -> Self {
        let now = Utc::now();
        let edge_type = edge_type.into();
        Self {
            id: Uuid::new_v4(),
            from,
            to,
            edge_type,
            properties: Properties::new(),
            weight: 1.0,
            created_at: now,
        }
    }

    /// Set the edge ID
    pub fn with_id(mut self, id: EntityId) -> Self {
        self.id = id;
        self
    }

    /// Add a property
    pub fn with_property<T: Serialize>(mut self, key: impl Into<String>, value: T) -> Self {
        self.properties = self.properties.with(key, value);
        self
    }

    /// Set the weight
    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = weight.max(0.0);
        self
    }

    /// Get the edge direction as a tuple
    pub fn endpoints(&self) -> (EntityId, EntityId) {
        (self.from, self.to)
    }
}

impl From<&str> for EdgeType {
    fn from(s: &str) -> Self {
        match s {
            "exploits" => EdgeType::Exploits,
            "leads_to" => EdgeType::LeadsTo,
            "depends_on" => EdgeType::DependsOn,
            "connects_to" => EdgeType::ConnectsTo,
            "contains" => EdgeType::Contains,
            "accesses" => EdgeType::Accesses,
            _ => EdgeType::Custom(s.to_string()),
        }
    }
}

impl From<String> for EdgeType {
    fn from(s: String) -> Self {
        EdgeType::from(s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_basic_operations() {
        let graph = AttackGraph::new();

        // Add nodes
        let node1 = GraphNode::new(NodeType::EntryPoint, "Web Server").with_risk_score(7.5);
        let id1 = graph.add_node(node1.clone()).unwrap();

        let node2 = GraphNode::new(NodeType::Asset, "Database").with_risk_score(9.0);
        let id2 = graph.add_node(node2.clone()).unwrap();

        assert_eq!(graph.node_count(), 2);

        // Add edge
        let edge = GraphEdge::new(id1, id2, EdgeType::Exploits);
        let edge_id = graph.add_edge(edge).unwrap();

        assert_eq!(graph.edge_count(), 1);

        // Get nodes
        let retrieved1 = graph.get_node(id1).unwrap();
        assert_eq!(retrieved1.name, "Web Server");
        assert_eq!(retrieved1.risk_score, 7.5);

        // Get edge
        let retrieved_edge = graph.get_edge(edge_id).unwrap();
        assert_eq!(retrieved_edge.from, id1);
        assert_eq!(retrieved_edge.to, id2);

        // Get neighbors
        let neighbors = graph.get_neighbors(id1).unwrap();
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].id, id2);
    }

    #[test]
    fn test_graph_error_handling() {
        let graph = AttackGraph::new();

        // Try to get non-existent node
        let fake_id = Uuid::new_v4();
        assert!(graph.get_node(fake_id).is_none());

        // Try to add edge with non-existent nodes
        let edge = GraphEdge::new(fake_id, fake_id, EdgeType::Exploits);
        assert!(matches!(
            graph.add_edge(edge),
            Err(GraphError::NodeNotFound(_))
        ));

        // Try to remove non-existent node
        assert!(matches!(
            graph.remove_node(fake_id),
            Err(GraphError::NodeNotFound(_))
        ));
    }

    #[test]
    fn test_node_builder() {
        let node = GraphNode::new(NodeType::Vulnerability, "SQL Injection")
            .with_label("cve")
            .with_label("injection")
            .with_property("cve_id", "CVE-2023-1234")
            .with_property("severity", "high")
            .with_risk_score(8.5);

        assert_eq!(node.name, "SQL Injection");
        assert_eq!(node.labels.len(), 2);
        assert!(node.has_label("cve"));
        assert_eq!(node.risk_score, 8.5);
        assert_eq!(node.risk_level(), RiskLevel::High);
        assert!(node.properties.contains("cve_id"));
    }

    #[test]
    fn test_edge_builder() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        let edge = GraphEdge::new(id1, id2, "custom_relation")
            .with_property("confidence", 0.95)
            .with_weight(2.5);

        assert_eq!(edge.from, id1);
        assert_eq!(edge.to, id2);
        assert!(matches!(edge.edge_type, EdgeType::Custom(s) if s == "custom_relation"));
        assert_eq!(edge.weight, 2.5);
        assert!(edge.properties.contains("confidence"));
    }

    #[test]
    fn test_graph_cycles() {
        let graph = AttackGraph::new();

        let n1 = GraphNode::new(NodeType::Asset, "A");
        let id1 = graph.add_node(n1).unwrap();

        let n2 = GraphNode::new(NodeType::Asset, "B");
        let id2 = graph.add_node(n2).unwrap();

        let n3 = GraphNode::new(NodeType::Asset, "C");
        let id3 = graph.add_node(n3).unwrap();

        // A -> B -> C (no cycle)
        graph
            .add_edge(GraphEdge::new(id1, id2, EdgeType::LeadsTo))
            .unwrap();
        graph
            .add_edge(GraphEdge::new(id2, id3, EdgeType::LeadsTo))
            .unwrap();

        assert!(!graph.has_cycles());

        // C -> A (creates cycle)
        graph
            .add_edge(GraphEdge::new(id3, id1, EdgeType::LeadsTo))
            .unwrap();

        assert!(graph.has_cycles());
    }

    #[test]
    fn test_entry_points_and_targets() {
        let graph = AttackGraph::new();

        let n1 = GraphNode::new(NodeType::EntryPoint, "Entry");
        let id1 = graph.add_node(n1).unwrap();

        let n2 = GraphNode::new(NodeType::Asset, "Middle");
        let id2 = graph.add_node(n2).unwrap();

        let n3 = GraphNode::new(NodeType::Data, "Target");
        let id3 = graph.add_node(n3).unwrap();

        // Entry -> Middle -> Target
        graph
            .add_edge(GraphEdge::new(id1, id2, EdgeType::LeadsTo))
            .unwrap();
        graph
            .add_edge(GraphEdge::new(id2, id3, EdgeType::LeadsTo))
            .unwrap();

        let entry_points = graph.get_entry_points();
        assert_eq!(entry_points.len(), 1);
        assert_eq!(entry_points[0].id, id1);

        let targets = graph.get_targets();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].id, id3);
    }

    #[test]
    fn test_graph_stats() {
        let graph = AttackGraph::new();

        // Add nodes of different types
        let n1 = GraphNode::new(NodeType::EntryPoint, "E1");
        graph.add_node(n1).unwrap();

        let n2 = GraphNode::new(NodeType::EntryPoint, "E2");
        graph.add_node(n2).unwrap();

        let n3 = GraphNode::new(NodeType::Asset, "A1");
        let id3 = graph.add_node(n3).unwrap();

        let n4 = GraphNode::new(NodeType::Asset, "A2");
        let id4 = graph.add_node(n4).unwrap();

        // Add edges
        graph
            .add_edge(GraphEdge::new(id3, id4, EdgeType::ConnectsTo))
            .unwrap();

        let stats = graph.stats().unwrap();
        assert_eq!(stats.node_count, 4);
        assert_eq!(stats.edge_count, 1);
        assert_eq!(stats.node_types.get(&NodeType::EntryPoint), Some(&2));
        assert_eq!(stats.node_types.get(&NodeType::Asset), Some(&2));
    }
}
