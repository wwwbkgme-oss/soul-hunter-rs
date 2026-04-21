//! Attack Surface Graph runtime implementation
//!
//! This module provides a specialized graph structure for modeling attack surfaces
//! in security analysis. It uses petgraph for efficient graph operations and provides
//! thread-safe access through Arc<RwLock<>> wrappers.

use crate::{EntityId, GraphError, Properties, Result, RiskLevel};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

/// Node types in the attack surface graph
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackSurfaceNodeType {
    /// Software component (e.g., service, library, module)
    Component,
    /// Network endpoint (e.g., API, port, URL)
    Endpoint,
    /// Permission or privilege level
    Permission,
    /// Data flow between components
    DataFlow,
}

impl std::fmt::Display for AttackSurfaceNodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackSurfaceNodeType::Component => write!(f, "Component"),
            AttackSurfaceNodeType::Endpoint => write!(f, "Endpoint"),
            AttackSurfaceNodeType::Permission => write!(f, "Permission"),
            AttackSurfaceNodeType::DataFlow => write!(f, "DataFlow"),
        }
    }
}

/// Relationship types between attack surface nodes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelationshipType {
    /// One component accesses another
    Accesses,
    /// One component depends on another
    DependsOn,
    /// One component exposes functionality to another
    Exposes,
    /// Data flows from one component to another
    FlowsTo,
    /// One component trusts another
    Trusts,
}

impl std::fmt::Display for RelationshipType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelationshipType::Accesses => write!(f, "ACCESSES"),
            RelationshipType::DependsOn => write!(f, "DEPENDS_ON"),
            RelationshipType::Exposes => write!(f, "EXPOSES"),
            RelationshipType::FlowsTo => write!(f, "FLOWS_TO"),
            RelationshipType::Trusts => write!(f, "TRUSTS"),
        }
    }
}

/// A node in the attack surface graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceNode {
    /// Unique identifier
    pub id: EntityId,
    /// Node type
    pub node_type: AttackSurfaceNodeType,
    /// Human-readable name
    pub name: String,
    /// Risk score (0-10)
    pub risk_score: f64,
    /// Entry points (e.g., exposed ports, URLs)
    pub entry_points: Vec<String>,
    /// Required permissions
    pub permissions: Vec<String>,
    /// Data types handled
    pub data_types: Vec<String>,
    /// Whether this component is exposed to external access
    pub exposed: bool,
    /// Additional properties
    pub properties: Properties,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl AttackSurfaceNode {
    /// Create a new attack surface node
    pub fn new(node_type: AttackSurfaceNodeType, name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            node_type,
            name: name.into(),
            risk_score: 0.0,
            entry_points: Vec::new(),
            permissions: Vec::new(),
            data_types: Vec::new(),
            exposed: false,
            properties: Properties::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Set the node ID
    pub fn with_id(mut self, id: EntityId) -> Self {
        self.id = id;
        self
    }

    /// Set the risk score
    pub fn with_risk_score(mut self, score: f64) -> Self {
        self.risk_score = score.clamp(0.0, 10.0);
        self
    }

    /// Add an entry point
    pub fn with_entry_point(mut self, entry_point: impl Into<String>) -> Self {
        self.entry_points.push(entry_point.into());
        self
    }

    /// Add multiple entry points
    pub fn with_entry_points(mut self, entry_points: Vec<impl Into<String>>) -> Self {
        self.entry_points
            .extend(entry_points.into_iter().map(|e| e.into()));
        self
    }

    /// Add a permission
    pub fn with_permission(mut self, permission: impl Into<String>) -> Self {
        self.permissions.push(permission.into());
        self
    }

    /// Add multiple permissions
    pub fn with_permissions(mut self, permissions: Vec<impl Into<String>>) -> Self {
        self.permissions
            .extend(permissions.into_iter().map(|p| p.into()));
        self
    }

    /// Add a data type
    pub fn with_data_type(mut self, data_type: impl Into<String>) -> Self {
        self.data_types.push(data_type.into());
        self
    }

    /// Add multiple data types
    pub fn with_data_types(mut self, data_types: Vec<impl Into<String>>) -> Self {
        self.data_types
            .extend(data_types.into_iter().map(|d| d.into()));
        self
    }

    /// Set whether the component is exposed
    pub fn with_exposed(mut self, exposed: bool) -> Self {
        self.exposed = exposed;
        self
    }

    /// Add a property
    pub fn with_property<T: Serialize>(mut self, key: impl Into<String>, value: T) -> Self {
        self.properties = self.properties.with(key, value);
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

    /// Check if this is a high-risk node
    pub fn is_high_risk(&self) -> bool {
        self.risk_score >= 7.0
    }

    /// Check if the node has a specific entry point
    pub fn has_entry_point(&self, entry_point: &str) -> bool {
        self.entry_points.contains(&entry_point.to_string())
    }

    /// Check if the node requires a specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }

    /// Check if the node handles a specific data type
    pub fn handles_data_type(&self, data_type: &str) -> bool {
        self.data_types.contains(&data_type.to_string())
    }
}

/// A relationship (edge) in the attack surface graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceRelationship {
    /// Unique identifier
    pub id: EntityId,
    /// Source node ID
    pub from: EntityId,
    /// Target node ID
    pub to: EntityId,
    /// Relationship type
    pub relationship_type: RelationshipType,
    /// Weight for path calculations
    pub weight: f64,
    /// Additional properties
    pub properties: Properties,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

impl AttackSurfaceRelationship {
    /// Create a new relationship
    pub fn new(
        from: EntityId,
        to: EntityId,
        relationship_type: RelationshipType,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            from,
            to,
            relationship_type,
            weight: 1.0,
            properties: Properties::new(),
            created_at: Utc::now(),
        }
    }

    /// Set the relationship ID
    pub fn with_id(mut self, id: EntityId) -> Self {
        self.id = id;
        self
    }

    /// Set the weight
    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = weight.max(0.0);
        self
    }

    /// Add a property
    pub fn with_property<T: Serialize>(mut self, key: impl Into<String>, value: T) -> Self {
        self.properties = self.properties.with(key, value);
        self
    }
}

/// Internal node data stored in petgraph
#[derive(Debug, Clone)]
struct InternalNode {
    node_id: EntityId,
    node_data: AttackSurfaceNode,
}

/// Internal edge data stored in petgraph
#[derive(Debug, Clone)]
struct InternalEdge {
    edge_id: EntityId,
    relationship_type: RelationshipType,
    weight: f64,
    properties: Properties,
    created_at: DateTime<Utc>,
}

/// Attack Surface Graph
///
/// A specialized graph structure for modeling attack surfaces using petgraph
/// for efficient graph operations. Provides thread-safe access and supports
/// persistence to disk.
#[derive(Debug)]
pub struct AttackSurfaceGraph {
    /// The underlying petgraph graph
    graph: Arc<RwLock<DiGraph<InternalNode, InternalEdge>>>,
    /// Mapping from EntityId to NodeIndex for O(1) lookups
    node_indices: DashMap<EntityId, NodeIndex>,
    /// Mapping from EntityId to edge information
    edge_map: DashMap<EntityId, (EntityId, EntityId, NodeIndex, NodeIndex)>,
    /// Graph metadata
    metadata: Arc<RwLock<GraphMetadata>>,
}

/// Graph metadata for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GraphMetadata {
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: String,
}

impl GraphMetadata {
    fn new() -> Self {
        let now = Utc::now();
        Self {
            created_at: now,
            updated_at: now,
            version: "1.0.0".to_string(),
        }
    }

    fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
}

/// Graph metrics for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfaceMetrics {
    pub node_count: usize,
    pub relationship_count: usize,
    pub avg_risk_score: f64,
    pub max_risk_score: f64,
    pub density: f64,
    pub component_count: usize,
    pub endpoint_count: usize,
    pub permission_count: usize,
    pub dataflow_count: usize,
    pub exposed_component_count: usize,
    pub high_risk_node_count: usize,
}

/// A path through the attack surface graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurfacePath {
    /// Node IDs in the path
    pub nodes: Vec<EntityId>,
    /// Relationship IDs in the path
    pub relationships: Vec<EntityId>,
    /// Cumulative risk score
    pub cumulative_risk: f64,
    /// Path length (number of hops)
    pub path_length: usize,
    /// Whether this is a critical path
    pub is_critical: bool,
}

impl AttackSurfacePath {
    /// Create an empty path
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            relationships: Vec::new(),
            cumulative_risk: 0.0,
            path_length: 0,
            is_critical: false,
        }
    }

    /// Create a singleton path (single node)
    pub fn singleton(node_id: EntityId) -> Self {
        Self {
            nodes: vec![node_id],
            relationships: Vec::new(),
            cumulative_risk: 0.0,
            path_length: 0,
            is_critical: false,
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
}

impl Default for AttackSurfacePath {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable graph data for export/import
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializableGraph {
    metadata: GraphMetadata,
    nodes: Vec<AttackSurfaceNode>,
    relationships: Vec<AttackSurfaceRelationship>,
}

impl AttackSurfaceGraph {
    /// Create a new empty attack surface graph
    pub fn new() -> Self {
        info!("Creating new AttackSurfaceGraph");
        Self {
            graph: Arc::new(RwLock::new(DiGraph::new())),
            node_indices: DashMap::new(),
            edge_map: DashMap::new(),
            metadata: Arc::new(RwLock::new(GraphMetadata::new())),
        }
    }

    /// Add a node to the graph
    pub fn add_node(&self, node: AttackSurfaceNode) -> Result<EntityId> {
        let id = node.id;

        // Check if node already exists
        if self.node_indices.contains_key(&id) {
            return Err(GraphError::NodeExists(id));
        }

        // Add to petgraph
        let internal_node = InternalNode {
            node_id: id,
            node_data: node,
        };

        let mut graph = self.graph.write().map_err(|_| {
            GraphError::LockAcquisition("Failed to acquire graph lock".to_string())
        })?;

        let node_index = graph.add_node(internal_node);
        drop(graph);

        // Update index
        self.node_indices.insert(id, node_index);

        // Update metadata
        if let Ok(mut metadata) = self.metadata.write() {
            metadata.touch();
        }

        trace!("Added node {} to attack surface graph", id);
        Ok(id)
    }

    /// Remove a node from the graph
    pub fn remove_node(&self, id: EntityId) -> Result<AttackSurfaceNode> {
        // Get node index
        let node_index = self
            .node_indices
            .get(&id)
            .map(|entry| *entry.value())
            .ok_or(GraphError::NodeNotFound(id))?;

        // Remove from petgraph
        let mut graph = self.graph.write().map_err(|_| {
            GraphError::LockAcquisition("Failed to acquire graph lock".to_string())
        })?;

        // Get node data before removal
        let node_data = graph
            .node_weight(node_index)
            .map(|n| n.node_data.clone())
            .ok_or(GraphError::NodeNotFound(id))?;

        // Remove the node (this also removes connected edges)
        graph.remove_node(node_index);
        drop(graph);

        // Update indices
        self.node_indices.remove(&id);

        // Remove edges connected to this node from edge_map
        let edges_to_remove: Vec<EntityId> = self
            .edge_map
            .iter()
            .filter(|entry| entry.value().0 == id || entry.value().1 == id)
            .map(|entry| *entry.key())
            .collect();

        for edge_id in edges_to_remove {
            self.edge_map.remove(&edge_id);
        }

        // Update metadata
        if let Ok(mut metadata) = self.metadata.write() {
            metadata.touch();
        }

        trace!("Removed node {} from attack surface graph", id);
        Ok(node_data)
    }

    /// Get a node by ID
    pub fn get_node(&self, id: EntityId) -> Option<AttackSurfaceNode> {
        let node_index = self.node_indices.get(&id).map(|entry| *entry.value())?;

        let graph = self.graph.read().ok()?;
        graph
            .node_weight(node_index)
            .map(|n| n.node_data.clone())
    }

    /// Check if a node exists
    pub fn has_node(&self, id: EntityId) -> bool {
        self.node_indices.contains_key(&id)
    }

    /// Update a node
    pub fn update_node(&self, node: AttackSurfaceNode) -> Result<()> {
        let id = node.id;

        let node_index = self
            .node_indices
            .get(&id)
            .map(|entry| *entry.value())
            .ok_or(GraphError::NodeNotFound(id))?;

        let mut graph = self.graph.write().map_err(|_| {
            GraphError::LockAcquisition("Failed to acquire graph lock".to_string())
        })?;

        if let Some(internal_node) = graph.node_weight_mut(node_index) {
            internal_node.node_data = node;
        } else {
            return Err(GraphError::NodeNotFound(id));
        }

        drop(graph);

        // Update metadata
        if let Ok(mut metadata) = self.metadata.write() {
            metadata.touch();
        }

        trace!("Updated node {} in attack surface graph", id);
        Ok(())
    }

    /// Add a relationship (edge) between nodes
    pub fn add_relationship(&self, relationship: AttackSurfaceRelationship) -> Result<EntityId> {
        let id = relationship.id;
        let from = relationship.from;
        let to = relationship.to;

        // Validate nodes exist
        let from_index = self
            .node_indices
            .get(&from)
            .map(|entry| *entry.value())
            .ok_or(GraphError::NodeNotFound(from))?;

        let to_index = self
            .node_indices
            .get(&to)
            .map(|entry| *entry.value())
            .ok_or(GraphError::NodeNotFound(to))?;

        // Check if relationship already exists
        if self.edge_map.contains_key(&id) {
            return Err(GraphError::EdgeExists(id));
        }

        // Create internal edge
        let internal_edge = InternalEdge {
            edge_id: id,
            relationship_type: relationship.relationship_type,
            weight: relationship.weight,
            properties: relationship.properties,
            created_at: relationship.created_at,
        };

        let mut graph = self.graph.write().map_err(|_| {
            GraphError::LockAcquisition("Failed to acquire graph lock".to_string())
        })?;

        let edge_index = graph.add_edge(from_index, to_index, internal_edge);
        drop(graph);

        // Update edge map
        self.edge_map.insert(id, (from, to, from_index, to_index));

        // Update metadata
        if let Ok(mut metadata) = self.metadata.write() {
            metadata.touch();
        }

        trace!(
            "Added relationship {} from {} to {} ({:?})",
            id,
            from,
            to,
            relationship.relationship_type
        );
        Ok(id)
    }

    /// Remove a relationship
    pub fn remove_relationship(&self, id: EntityId) -> Result<AttackSurfaceRelationship> {
        let (from, to, from_index, to_index) = self
            .edge_map
            .get(&id)
            .map(|entry| *entry.value())
            .ok_or(GraphError::EdgeNotFound(id))?;

        let mut graph = self.graph.write().map_err(|_| {
            GraphError::LockAcquisition("Failed to acquire graph lock".to_string())
        })?;

        // Find and remove the edge
        let edge_index = graph
            .find_edge(from_index, to_index)
            .ok_or(GraphError::EdgeNotFound(id))?;

        let internal_edge = graph
            .remove_edge(edge_index)
            .ok_or(GraphError::EdgeNotFound(id))?;

        drop(graph);

        // Update edge map
        self.edge_map.remove(&id);

        // Update metadata
        if let Ok(mut metadata) = self.metadata.write() {
            metadata.touch();
        }

        let relationship = AttackSurfaceRelationship {
            id,
            from,
            to,
            relationship_type: internal_edge.relationship_type,
            weight: internal_edge.weight,
            properties: internal_edge.properties,
            created_at: internal_edge.created_at,
        };

        trace!("Removed relationship {} from attack surface graph", id);
        Ok(relationship)
    }

    /// Get a relationship by ID
    pub fn get_relationship(&self, id: EntityId) -> Option<AttackSurfaceRelationship> {
        let (from, to, from_index, to_index) = self.edge_map.get(&id).map(|entry| *entry.value())?;

        let graph = self.graph.read().ok()?;
        let edge_index = graph.find_edge(from_index, to_index)?;
        let internal_edge = graph.edge_weight(edge_index)?;

        Some(AttackSurfaceRelationship {
            id,
            from,
            to,
            relationship_type: internal_edge.relationship_type,
            weight: internal_edge.weight,
            properties: internal_edge.properties.clone(),
            created_at: internal_edge.created_at,
        })
    }

    /// Check if a relationship exists
    pub fn has_relationship(&self, id: EntityId) -> bool {
        self.edge_map.contains_key(&id)
    }

    /// Get all nodes
    pub fn get_nodes(&self) -> Vec<AttackSurfaceNode> {
        let graph = match self.graph.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };

        graph
            .node_weights()
            .map(|n| n.node_data.clone())
            .collect()
    }

    /// Get all relationships
    pub fn get_relationships(&self) -> Vec<AttackSurfaceRelationship> {
        let graph = match self.graph.read() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };

        graph
            .edge_references()
            .filter_map(|edge_ref| {
                let internal_edge = edge_ref.weight();
                let source = edge_ref.source();
                let target = edge_ref.target();

                // Get node IDs
                let from_id = graph.node_weight(source)?.node_id;
                let to_id = graph.node_weight(target)?.node_id;

                Some(AttackSurfaceRelationship {
                    id: internal_edge.edge_id,
                    from: from_id,
                    to: to_id,
                    relationship_type: internal_edge.relationship_type,
                    weight: internal_edge.weight,
                    properties: internal_edge.properties.clone(),
                    created_at: internal_edge.created_at,
                })
            })
            .collect()
    }

    /// Get nodes by type
    pub fn get_nodes_by_type(&self, node_type: AttackSurfaceNodeType) -> Vec<AttackSurfaceNode> {
        self.get_nodes()
            .into_iter()
            .filter(|n| n.node_type == node_type)
            .collect()
    }

    /// Get relationships by type
    pub fn get_relationships_by_type(
        &self,
        relationship_type: RelationshipType,
    ) -> Vec<AttackSurfaceRelationship> {
        self.get_relationships()
            .into_iter()
            .filter(|r| r.relationship_type == relationship_type)
            .collect()
    }

    /// Get outgoing relationships from a node
    pub fn get_outgoing_relationships(&self, node_id: EntityId) -> Result<Vec<AttackSurfaceRelationship>> {
        let node_index = self
            .node_indices
            .get(&node_id)
            .map(|entry| *entry.value())
            .ok_or(GraphError::NodeNotFound(node_id))?;

        let graph = self.graph.read().map_err(|_| {
            GraphError::LockAcquisition("Failed to acquire graph lock".to_string())
        })?;

        let relationships: Vec<AttackSurfaceRelationship> = graph
            .edges(node_index)
            .filter_map(|edge_ref| {
                let internal_edge = edge_ref.weight();
                let target = edge_ref.target();
                let to_id = graph.node_weight(target)?.node_id;

                Some(AttackSurfaceRelationship {
                    id: internal_edge.edge_id,
                    from: node_id,
                    to: to_id,
                    relationship_type: internal_edge.relationship_type,
                    weight: internal_edge.weight,
                    properties: internal_edge.properties.clone(),
                    created_at: internal_edge.created_at,
                })
            })
            .collect();

        Ok(relationships)
    }

    /// Get incoming relationships to a node
    pub fn get_incoming_relationships(&self, node_id: EntityId) -> Result<Vec<AttackSurfaceRelationship>> {
        let node_index = self
            .node_indices
            .get(&node_id)
            .map(|entry| *entry.value())
            .ok_or(GraphError::NodeNotFound(node_id))?;

        let graph = self.graph.read().map_err(|_| {
            GraphError::LockAcquisition("Failed to acquire graph lock".to_string())
        })?;

        // petgraph doesn't have direct incoming edges method, we need to scan all edges
        let relationships: Vec<AttackSurfaceRelationship> = graph
            .edge_references()
            .filter(|edge_ref| edge_ref.target() == node_index)
            .filter_map(|edge_ref| {
                let internal_edge = edge_ref.weight();
                let source = edge_ref.source();
                let from_id = graph.node_weight(source)?.node_id;

                Some(AttackSurfaceRelationship {
                    id: internal_edge.edge_id,
                    from: from_id,
                    to: node_id,
                    relationship_type: internal_edge.relationship_type,
                    weight: internal_edge.weight,
                    properties: internal_edge.properties.clone(),
                    created_at: internal_edge.created_at,
                })
            })
            .collect();

        Ok(relationships)
    }

    /// Get neighbors (nodes connected by outgoing relationships)
    pub fn get_neighbors(&self, node_id: EntityId) -> Result<Vec<AttackSurfaceNode>> {
        let relationships = self.get_outgoing_relationships(node_id)?;
        let neighbors: Vec<AttackSurfaceNode> = relationships
            .iter()
            .filter_map(|r| self.get_node(r.to))
            .collect();
        Ok(neighbors)
    }

    /// Get predecessors (nodes connected by incoming relationships)
    pub fn get_predecessors(&self, node_id: EntityId) -> Result<Vec<AttackSurfaceNode>> {
        let relationships = self.get_incoming_relationships(node_id)?;
        let predecessors: Vec<AttackSurfaceNode> = relationships
            .iter()
            .filter_map(|r| self.get_node(r.from))
            .collect();
        Ok(predecessors)
    }

    /// Get the number of nodes
    pub fn node_count(&self) -> usize {
        self.node_indices.len()
    }

    /// Get the number of relationships
    pub fn relationship_count(&self) -> usize {
        self.edge_map.len()
    }

    /// Check if the graph is empty
    pub fn is_empty(&self) -> bool {
        self.node_indices.is_empty()
    }

    /// Clear the graph
    pub fn clear(&self) {
        if let Ok(mut graph) = self.graph.write() {
            graph.clear();
        }
        self.node_indices.clear();
        self.edge_map.clear();

        if let Ok(mut metadata) = self.metadata.write() {
            *metadata = GraphMetadata::new();
        }

        debug!("Cleared attack surface graph");
    }

    /// Find paths between two nodes using DFS with depth limit
    pub fn find_paths(
        &self,
        start: EntityId,
        target: EntityId,
        max_depth: usize,
    ) -> Result<Vec<AttackSurfacePath>> {
        if !self.has_node(start) {
            return Err(GraphError::NodeNotFound(start));
        }
        if !self.has_node(target) {
            return Err(GraphError::NodeNotFound(target));
        }

        if start == target {
            return Ok(vec![AttackSurfacePath::singleton(start)]);
        }

        let mut paths = Vec::new();
        let mut visited = HashSet::new();
        let mut current_path = VecDeque::new();
        let mut current_relationships = VecDeque::new();

        self.dfs_paths(
            start,
            target,
            max_depth,
            &mut visited,
            &mut current_path,
            &mut current_relationships,
            &mut paths,
        );

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
        current_relationships: &mut VecDeque<EntityId>,
        paths: &mut Vec<AttackSurfacePath>,
    ) {
        if current_path.len() >= max_depth {
            return;
        }

        visited.insert(current);
        current_path.push_back(current);

        if current == target {
            // Found a path
            let path_nodes: Vec<EntityId> = current_path.iter().copied().collect();
            let path_relationships: Vec<EntityId> = current_relationships.iter().copied().collect();
            let cumulative_risk = self.calculate_path_risk(&path_nodes);

            paths.push(AttackSurfacePath {
                nodes: path_nodes,
                relationships: path_relationships,
                cumulative_risk,
                path_length: current_path.len() - 1,
                is_critical: cumulative_risk >= 7.0,
            });
        } else {
            // Continue DFS
            if let Ok(relationships) = self.get_outgoing_relationships(current) {
                for relationship in relationships {
                    let neighbor = relationship.to;
                    if !visited.contains(&neighbor) {
                        current_relationships.push_back(relationship.id);
                        self.dfs_paths(
                            neighbor,
                            target,
                            max_depth,
                            visited,
                            current_path,
                            current_relationships,
                            paths,
                        );
                        current_relationships.pop_back();
                    }
                }
            }
        }

        current_path.pop_back();
        visited.remove(&current);
    }

    /// Calculate the cumulative risk score for a path
    fn calculate_path_risk(&self, node_ids: &[EntityId]) -> f64 {
        let mut total_risk = 0.0;
        let mut count = 0;

        for node_id in node_ids {
            if let Some(node) = self.get_node(*node_id) {
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

    /// Find critical paths (highest cumulative risk)
    pub fn find_critical_paths(&self, min_risk: f64) -> Result<Vec<AttackSurfacePath>> {
        // Get entry points (exposed components with no incoming edges)
        let entry_points: Vec<EntityId> = self
            .get_nodes()
            .into_iter()
            .filter(|n| n.exposed)
            .map(|n| n.id)
            .collect();

        // Get high-value targets (high risk or data nodes)
        let targets: Vec<EntityId> = self
            .get_nodes()
            .into_iter()
            .filter(|n| {
                n.risk_score >= min_risk
                    || n.node_type == AttackSurfaceNodeType::DataFlow
                    || !n.data_types.is_empty()
            })
            .map(|n| n.id)
            .collect();

        let mut critical_paths = Vec::new();

        for entry in &entry_points {
            for target in &targets {
                if entry != target {
                    match self.find_paths(*entry, *target, 10) {
                        Ok(paths) => {
                            for path in paths {
                                if path.cumulative_risk >= min_risk {
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

        // Sort by cumulative risk (highest first)
        critical_paths.sort_by(|a, b| {
            b.cumulative_risk
                .partial_cmp(&a.cumulative_risk)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        debug!("Found {} critical paths", critical_paths.len());
        Ok(critical_paths)
    }

    /// Calculate graph metrics
    pub fn calculate_metrics(&self) -> Result<AttackSurfaceMetrics> {
        let nodes = self.get_nodes();
        let relationships = self.get_relationships();

        let node_count = nodes.len();
        let relationship_count = relationships.len();

        // Calculate risk statistics
        let risk_scores: Vec<f64> = nodes.iter().map(|n| n.risk_score).collect();
        let avg_risk_score = if !risk_scores.is_empty() {
            risk_scores.iter().sum::<f64>() / risk_scores.len() as f64
        } else {
            0.0
        };
        let max_risk_score = risk_scores.iter().copied().fold(0.0, f64::max);

        // Calculate density
        let density = if node_count > 1 {
            relationship_count as f64 / (node_count * (node_count - 1)) as f64
        } else {
            0.0
        };

        // Count by type
        let component_count = nodes
            .iter()
            .filter(|n| n.node_type == AttackSurfaceNodeType::Component)
            .count();
        let endpoint_count = nodes
            .iter()
            .filter(|n| n.node_type == AttackSurfaceNodeType::Endpoint)
            .count();
        let permission_count = nodes
            .iter()
            .filter(|n| n.node_type == AttackSurfaceNodeType::Permission)
            .count();
        let dataflow_count = nodes
            .iter()
            .filter(|n| n.node_type == AttackSurfaceNodeType::DataFlow)
            .count();

        // Count exposed and high-risk nodes
        let exposed_component_count = nodes.iter().filter(|n| n.exposed).count();
        let high_risk_node_count = nodes.iter().filter(|n| n.is_high_risk()).count();

        Ok(AttackSurfaceMetrics {
            node_count,
            relationship_count,
            avg_risk_score,
            max_risk_score,
            density,
            component_count,
            endpoint_count,
            permission_count,
            dataflow_count,
            exposed_component_count,
            high_risk_node_count,
        })
    }

    /// Get bi-directional adjacency list representation
    pub fn get_adjacency_list(&self) -> Result<HashMap<EntityId, Vec<EntityId>>> {
        let mut adjacency: HashMap<EntityId, Vec<EntityId>> = HashMap::new();

        // Initialize with all nodes
        for node in self.get_nodes() {
            adjacency.insert(node.id, Vec::new());
        }

        // Add edges (bidirectional)
        for relationship in self.get_relationships() {
            adjacency
                .entry(relationship.from)
                .or_insert_with(Vec::new)
                .push(relationship.to);
            adjacency
                .entry(relationship.to)
                .or_insert_with(Vec::new)
                .push(relationship.from);
        }

        // Remove duplicates
        for neighbors in adjacency.values_mut() {
            neighbors.sort_unstable();
            neighbors.dedup();
        }

        Ok(adjacency)
    }

    /// Export the graph to JSON
    pub fn export_to_json(&self) -> Result<String> {
        let serializable = SerializableGraph {
            metadata: self
                .metadata
                .read()
                .map_err(|_| {
                    GraphError::LockAcquisition("Failed to acquire metadata lock".to_string())
                })?
                .clone(),
            nodes: self.get_nodes(),
            relationships: self.get_relationships(),
        };

        serde_json::to_string_pretty(&serializable)
            .map_err(|e| GraphError::Serialization(e.to_string()))
    }

    /// Import the graph from JSON
    pub fn import_from_json(&self, json: &str) -> Result<()> {
        let serializable: SerializableGraph = serde_json::from_str(json)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?;

        // Clear existing graph
        self.clear();

        // Add nodes
        for node in serializable.nodes {
            self.add_node(node)?;
        }

        // Add relationships
        for relationship in serializable.relationships {
            self.add_relationship(relationship)?;
        }

        // Update metadata
        if let Ok(mut metadata) = self.metadata.write() {
            *metadata = serializable.metadata;
        }

        info!("Imported attack surface graph from JSON");
        Ok(())
    }

    /// Save the graph to disk
    pub fn save_to_disk(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = self.export_to_json()?;
        fs::write(&path, json).map_err(|e| GraphError::External(e.to_string()))?;
        info!("Saved attack surface graph to {:?}", path.as_ref());
        Ok(())
    }

    /// Load the graph from disk
    pub fn load_from_disk(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = fs::read_to_string(&path)
            .map_err(|e| GraphError::External(e.to_string()))?;
        self.import_from_json(&json)?;
        info!("Loaded attack surface graph from {:?}", path.as_ref());
        Ok(())
    }

    /// Get entry points (exposed nodes with no incoming edges)
    pub fn get_entry_points(&self) -> Vec<AttackSurfaceNode> {
        self.get_nodes()
            .into_iter()
            .filter(|n| {
                n.exposed
                    && self
                        .get_incoming_relationships(n.id)
                        .map(|rels| rels.is_empty())
                        .unwrap_or(true)
            })
            .collect()
    }

    /// Get high-risk nodes
    pub fn get_high_risk_nodes(&self) -> Vec<AttackSurfaceNode> {
        self.get_nodes()
            .into_iter()
            .filter(|n| n.is_high_risk())
            .collect()
    }

    /// Get exposed components
    pub fn get_exposed_components(&self) -> Vec<AttackSurfaceNode> {
        self.get_nodes()
            .into_iter()
            .filter(|n| n.exposed && n.node_type == AttackSurfaceNodeType::Component)
            .collect()
    }

    /// Find nodes by name (partial match)
    pub fn find_nodes_by_name(&self, name_pattern: &str) -> Vec<AttackSurfaceNode> {
        let pattern = name_pattern.to_lowercase();
        self.get_nodes()
            .into_iter()
            .filter(|n| n.name.to_lowercase().contains(&pattern))
            .collect()
    }

    /// Find nodes by property value
    pub fn find_nodes_by_property<T: Serialize>(
        &self,
        key: &str,
        value: T,
    ) -> Result<Vec<AttackSurfaceNode>> {
        let target_value = serde_json::to_value(value)
            .map_err(|e| GraphError::Serialization(e.to_string()))?;

        Ok(self
            .get_nodes()
            .into_iter()
            .filter(|n| {
                n.properties
                    .get(key)
                    .map(|v| v == &target_value)
                    .unwrap_or(false)
            })
            .collect())
    }
}

impl Default for AttackSurfaceGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_graph() -> AttackSurfaceGraph {
        let graph = AttackSurfaceGraph::new();

        // Create nodes
        let web_server = AttackSurfaceNode::new(AttackSurfaceNodeType::Component, "Web Server")
            .with_risk_score(7.5)
            .with_exposed(true)
            .with_entry_point("0.0.0.0:80")
            .with_entry_point("0.0.0.0:443")
            .with_permission("network");
        let web_id = graph.add_node(web_server).unwrap();

        let api = AttackSurfaceNode::new(AttackSurfaceNodeType::Endpoint, "API Endpoint")
            .with_risk_score(6.0)
            .with_data_type("JSON")
            .with_permission("read");
        let api_id = graph.add_node(api).unwrap();

        let db = AttackSurfaceNode::new(AttackSurfaceNodeType::Component, "Database")
            .with_risk_score(9.0)
            .with_data_type("PII")
            .with_data_type("Credentials")
            .with_permission("storage");
        let db_id = graph.add_node(db).unwrap();

        let auth = AttackSurfaceNode::new(AttackSurfaceNodeType::Permission, "Admin Role")
            .with_risk_score(8.0);
        let auth_id = graph.add_node(auth).unwrap();

        // Create relationships
        let rel1 = AttackSurfaceRelationship::new(web_id, api_id, RelationshipType::Exposes)
            .with_weight(1.0);
        graph.add_relationship(rel1).unwrap();

        let rel2 = AttackSurfaceRelationship::new(api_id, db_id, RelationshipType::Accesses)
            .with_weight(2.0);
        graph.add_relationship(rel2).unwrap();

        let rel3 = AttackSurfaceRelationship::new(auth_id, db_id, RelationshipType::Accesses)
            .with_weight(1.5);
        graph.add_relationship(rel3).unwrap();

        let rel4 = AttackSurfaceRelationship::new(web_id, auth_id, RelationshipType::Trusts)
            .with_weight(0.5);
        graph.add_relationship(rel4).unwrap();

        graph
    }

    #[test]
    fn test_graph_basic_operations() {
        let graph = AttackSurfaceGraph::new();

        // Add node
        let node = AttackSurfaceNode::new(AttackSurfaceNodeType::Component, "Test Component")
            .with_risk_score(5.0)
            .with_exposed(true);
        let id = graph.add_node(node.clone()).unwrap();

        assert_eq!(graph.node_count(), 1);
        assert!(graph.has_node(id));

        // Get node
        let retrieved = graph.get_node(id).unwrap();
        assert_eq!(retrieved.name, "Test Component");
        assert_eq!(retrieved.risk_score, 5.0);
        assert!(retrieved.exposed);

        // Update node
        let updated = AttackSurfaceNode::new(AttackSurfaceNodeType::Component, "Updated Component")
            .with_id(id)
            .with_risk_score(7.0);
        graph.update_node(updated).unwrap();

        let retrieved = graph.get_node(id).unwrap();
        assert_eq!(retrieved.name, "Updated Component");
        assert_eq!(retrieved.risk_score, 7.0);

        // Remove node
        let removed = graph.remove_node(id).unwrap();
        assert_eq!(removed.name, "Updated Component");
        assert_eq!(graph.node_count(), 0);
        assert!(!graph.has_node(id));
    }

    #[test]
    fn test_relationship_operations() {
        let graph = AttackSurfaceGraph::new();

        // Create nodes
        let node1 = AttackSurfaceNode::new(AttackSurfaceNodeType::Component, "Node 1");
        let id1 = graph.add_node(node1).unwrap();

        let node2 = AttackSurfaceNode::new(AttackSurfaceNodeType::Component, "Node 2");
        let id2 = graph.add_node(node2).unwrap();

        // Add relationship
        let rel = AttackSurfaceRelationship::new(id1, id2, RelationshipType::DependsOn)
            .with_weight(2.0);
        let rel_id = graph.add_relationship(rel).unwrap();

        assert_eq!(graph.relationship_count(), 1);
        assert!(graph.has_relationship(rel_id));

        // Get relationship
        let retrieved = graph.get_relationship(rel_id).unwrap();
        assert_eq!(retrieved.from, id1);
        assert_eq!(retrieved.to, id2);
        assert_eq!(retrieved.relationship_type, RelationshipType::DependsOn);
        assert_eq!(retrieved.weight, 2.0);

        // Get outgoing relationships
        let outgoing = graph.get_outgoing_relationships(id1).unwrap();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].to, id2);

        // Get incoming relationships
        let incoming = graph.get_incoming_relationships(id2).unwrap();
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0].from, id1);

        // Remove relationship
        let removed = graph.remove_relationship(rel_id).unwrap();
        assert_eq!(removed.from, id1);
        assert_eq!(graph.relationship_count(), 0);
    }

    #[test]
    fn test_path_finding() {
        let graph = create_test_graph();

        // Get node IDs
        let web_server = graph.find_nodes_by_name("Web Server").pop().unwrap();
        let database = graph.find_nodes_by_name("Database").pop().unwrap();

        // Find paths
        let paths = graph.find_paths(web_server.id, database.id, 10).unwrap();
        assert!(!paths.is_empty());

        // Check path structure
        let path = &paths[0];
        assert_eq!(path.start(), Some(web_server.id));
        assert_eq!(path.end(), Some(database.id));
        assert!(path.path_length > 0);
    }

    #[test]
    fn test_critical_paths() {
        let graph = create_test_graph();

        let critical_paths = graph.find_critical_paths(7.0).unwrap();
        // Should find paths from exposed components to high-risk targets
        assert!(!critical_paths.is_empty());

        // Verify paths are sorted by risk
        for i in 1..critical_paths.len() {
            assert!(
                critical_paths[i - 1].cumulative_risk >= critical_paths[i].cumulative_risk
            );
        }
    }

    #[test]
    fn test_graph_metrics() {
        let graph = create_test_graph();

        let metrics = graph.calculate_metrics().unwrap();
        assert_eq!(metrics.node_count, 4);
        assert_eq!(metrics.relationship_count, 4);
        assert!(metrics.avg_risk_score > 0.0);
        assert!(metrics.max_risk_score > 0.0);
        assert!(metrics.component_count > 0);
        assert!(metrics.exposed_component_count > 0);
    }

    #[test]
    fn test_adjacency_list() {
        let graph = create_test_graph();

        let adjacency = graph.get_adjacency_list().unwrap();
        assert_eq!(adjacency.len(), 4);

        // Each node should have at least one connection (bidirectional)
        for (node_id, neighbors) in &adjacency {
            assert!(!neighbors.is_empty(), "Node {} has no neighbors", node_id);
        }
    }

    #[test]
    fn test_export_import() {
        let graph = create_test_graph();

        // Export to JSON
        let json = graph.export_to_json().unwrap();
        assert!(!json.is_empty());

        // Create new graph and import
        let new_graph = AttackSurfaceGraph::new();
        new_graph.import_from_json(&json).unwrap();

        // Verify data was imported
        assert_eq!(new_graph.node_count(), 4);
        assert_eq!(new_graph.relationship_count(), 4);

        // Verify node data
        let nodes = new_graph.get_nodes();
        let web_server = nodes.iter().find(|n| n.name == "Web Server").unwrap();
        assert_eq!(web_server.risk_score, 7.5);
        assert!(web_server.exposed);
        assert_eq!(web_server.entry_points.len(), 2);
    }

    #[test]
    fn test_node_queries() {
        let graph = create_test_graph();

        // Test get_nodes_by_type
        let components = graph.get_nodes_by_type(AttackSurfaceNodeType::Component);
        assert_eq!(components.len(), 2);

        let endpoints = graph.get_nodes_by_type(AttackSurfaceNodeType::Endpoint);
        assert_eq!(endpoints.len(), 1);

        // Test get_exposed_components
        let exposed = graph.get_exposed_components();
        assert_eq!(exposed.len(), 1);
        assert_eq!(exposed[0].name, "Web Server");

        // Test get_high_risk_nodes
        let high_risk = graph.get_high_risk_nodes();
        assert!(!high_risk.is_empty());
        for node in &high_risk {
            assert!(node.risk_score >= 7.0);
        }

        // Test find_nodes_by_name
        let found = graph.find_nodes_by_name("API");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "API Endpoint");
    }

    #[test]
    fn test_relationship_queries() {
        let graph = create_test_graph();

        // Test get_relationships_by_type
        let accesses = graph.get_relationships_by_type(RelationshipType::Accesses);
        assert_eq!(accesses.len(), 2);

        let exposes = graph.get_relationships_by_type(RelationshipType::Exposes);
        assert_eq!(exposes.len(), 1);
    }

    #[test]
    fn test_error_handling() {
        let graph = AttackSurfaceGraph::new();

        // Try to get non-existent node
        let fake_id = Uuid::new_v4();
        assert!(graph.get_node(fake_id).is_none());

        // Try to remove non-existent node
        assert!(matches!(
            graph.remove_node(fake_id),
            Err(GraphError::NodeNotFound(_))
        ));

        // Try to add relationship with non-existent nodes
        let rel = AttackSurfaceRelationship::new(fake_id, fake_id, RelationshipType::Accesses);
        assert!(matches!(
            graph.add_relationship(rel),
            Err(GraphError::NodeNotFound(_))
        ));
    }

    #[test]
    fn test_node_builder() {
        let node = AttackSurfaceNode::new(AttackSurfaceNodeType::Component, "Test Service")
            .with_risk_score(8.5)
            .with_exposed(true)
            .with_entry_point("0.0.0.0:8080")
            .with_permission("read")
            .with_permission("write")
            .with_data_type("JSON")
            .with_property("version", "1.0.0")
            .with_property("enabled", true);

        assert_eq!(node.name, "Test Service");
        assert_eq!(node.risk_score, 8.5);
        assert!(node.exposed);
        assert_eq!(node.entry_points.len(), 1);
        assert_eq!(node.permissions.len(), 2);
        assert_eq!(node.data_types.len(), 1);
        assert!(node.properties.contains("version"));
        assert!(node.properties.contains("enabled"));
        assert_eq!(node.risk_level(), RiskLevel::High);
        assert!(node.is_high_risk());
    }

    #[test]
    fn test_clear() {
        let graph = create_test_graph();
        assert!(!graph.is_empty());

        graph.clear();
        assert!(graph.is_empty());
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.relationship_count(), 0);
    }

    #[test]
    fn test_neighbors_and_predecessors() {
        let graph = create_test_graph();

        let web_server = graph.find_nodes_by_name("Web Server").pop().unwrap();
        let api = graph.find_nodes_by_name("API").pop().unwrap();
        let database = graph.find_nodes_by_name("Database").pop().unwrap();

        // Test neighbors (outgoing)
        let neighbors = graph.get_neighbors(web_server.id).unwrap();
        assert_eq!(neighbors.len(), 2); // API and Admin Role

        // Test predecessors (incoming)
        let predecessors = graph.get_predecessors(database.id).unwrap();
        assert_eq!(predecessors.len(), 2); // API and Admin Role
    }

    #[tokio::test]
    async fn test_thread_safety() {
        use std::sync::Arc;
        use tokio::task;

        let graph = Arc::new(AttackSurfaceGraph::new());

        // Spawn multiple tasks to add nodes concurrently
        let mut handles = vec![];
        for i in 0..10 {
            let graph_clone = Arc::clone(&graph);
            let handle = task::spawn(async move {
                let node = AttackSurfaceNode::new(
                    AttackSurfaceNodeType::Component,
                    format!("Component {}", i),
                )
                .with_risk_score(i as f64);
                graph_clone.add_node(node).unwrap();
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        assert_eq!(graph.node_count(), 10);
    }
}
