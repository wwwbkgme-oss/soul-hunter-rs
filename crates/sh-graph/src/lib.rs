//! # Soul Hunter Graph
//!
//! Production-ready attack graph database for security analysis.
//!
//! ## Features
//!
//! - **Graph Storage**: Store attack nodes and edges with properties
//! - **Path Analysis**: Calculate attack paths using BFS/DFS algorithms
//! - **Critical Path Finding**: Identify high-risk attack paths
//! - **Risk Scoring**: Calculate risk scores for nodes and paths
//! - **Graph Queries**: Query the graph for specific patterns
//! - **Metrics**: Calculate graph metrics and analytics
//!
//! ## Example
//!
//! ```rust
//! use sh_graph::{AttackGraph, GraphNode, GraphEdge, NodeType};
//! use uuid::Uuid;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let mut graph = AttackGraph::new();
//!
//! // Add nodes
//! let entry_node = GraphNode::new(NodeType::EntryPoint, "Web Server")
//!     .with_property("port", 80)
//!     .with_risk_score(7.5);
//! let entry_id = graph.add_node(entry_node)?;
//!
//! let target_node = GraphNode::new(NodeType::Asset, "Database")
//!     .with_property("sensitive", true)
//!     .with_risk_score(9.0);
//! let target_id = graph.add_node(target_node)?;
//!
//! // Add edge
//! let edge = GraphEdge::new(entry_id, target_id, "exploits")
//!     .with_property("cve", "CVE-2023-1234");
//! graph.add_edge(edge)?;
//!
//! // Find paths
//! let paths = graph.find_paths(entry_id, target_id, 5)?;
//! # Ok(())
//! # }
//! ```

pub mod attack_surface;
pub mod error;
pub mod graph;
pub mod metrics;
pub mod path_analysis;
pub mod query;

pub use attack_surface::{
    AttackSurfaceGraph, AttackSurfaceMetrics, AttackSurfaceNode, AttackSurfaceNodeType,
    AttackSurfacePath, AttackSurfaceRelationship, RelationshipType,
};
pub use error::{GraphError, Result};
pub use graph::{AttackGraph, GraphEdge, GraphNode};
pub use metrics::{GraphMetrics, MetricsCalculator};
pub use path_analysis::{AttackPath, PathAnalyzer, PathMetrics};
pub use query::{GraphQuery, QueryBuilder, QueryResult};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Unique identifier for graph entities
pub type EntityId = Uuid;

/// Node type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    /// Entry point for attacks (e.g., exposed service)
    EntryPoint,
    /// Vulnerable component
    Vulnerability,
    /// Asset that can be compromised
    Asset,
    /// Attack technique or procedure
    Technique,
    /// Data store or sensitive information
    Data,
    /// User or identity
    Identity,
    /// Network component
    Network,
    /// Application component
    Application,
    /// Custom node type
    Custom(String),
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeType::EntryPoint => write!(f, "entry_point"),
            NodeType::Vulnerability => write!(f, "vulnerability"),
            NodeType::Asset => write!(f, "asset"),
            NodeType::Technique => write!(f, "technique"),
            NodeType::Data => write!(f, "data"),
            NodeType::Identity => write!(f, "identity"),
            NodeType::Network => write!(f, "network"),
            NodeType::Application => write!(f, "application"),
            NodeType::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Edge type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeType {
    /// Exploits relationship
    Exploits,
    /// Leads to relationship
    LeadsTo,
    /// Depends on relationship
    DependsOn,
    /// Connects to relationship
    ConnectsTo,
    /// Contains relationship
    Contains,
    /// Accesses relationship
    Accesses,
    /// Custom edge type
    Custom(String),
}

impl std::fmt::Display for EdgeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeType::Exploits => write!(f, "exploits"),
            EdgeType::LeadsTo => write!(f, "leads_to"),
            EdgeType::DependsOn => write!(f, "depends_on"),
            EdgeType::ConnectsTo => write!(f, "connects_to"),
            EdgeType::Contains => write!(f, "contains"),
            EdgeType::Accesses => write!(f, "accesses"),
            EdgeType::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Risk level for nodes and paths
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Minimal,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    /// Convert a numeric risk score to a risk level
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s >= 9.0 => RiskLevel::Critical,
            s if s >= 7.0 => RiskLevel::High,
            s if s >= 4.0 => RiskLevel::Medium,
            s if s >= 1.0 => RiskLevel::Low,
            _ => RiskLevel::Minimal,
        }
    }

    /// Get the numeric range for this risk level
    pub fn score_range(&self) -> (f64, f64) {
        match self {
            RiskLevel::Minimal => (0.0, 1.0),
            RiskLevel::Low => (1.0, 4.0),
            RiskLevel::Medium => (4.0, 7.0),
            RiskLevel::High => (7.0, 9.0),
            RiskLevel::Critical => (9.0, 10.0),
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Minimal => write!(f, "minimal"),
            RiskLevel::Low => write!(f, "low"),
            RiskLevel::Medium => write!(f, "medium"),
            RiskLevel::High => write!(f, "high"),
            RiskLevel::Critical => write!(f, "critical"),
        }
    }
}

/// Common properties for graph entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Properties {
    #[serde(flatten)]
    inner: HashMap<String, serde_json::Value>,
}

impl Properties {
    /// Create empty properties
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Add a property
    pub fn with<T: Serialize>(mut self, key: impl Into<String>, value: T) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.inner.insert(key.into(), v);
        }
        self
    }

    /// Get a property
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.inner.get(key)
    }

    /// Check if property exists
    pub fn contains(&self, key: &str) -> bool {
        self.inner.contains_key(key)
    }

    /// Get property as specific type
    pub fn get_as<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Option<T> {
        self.inner.get(key).and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Get the number of properties
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if properties are empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get all property keys
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.inner.keys()
    }
}

impl Default for Properties {
    fn default() -> Self {
        Self::new()
    }
}

impl From<HashMap<String, serde_json::Value>> for Properties {
    fn from(map: HashMap<String, serde_json::Value>) -> Self {
        Self { inner: map }
    }
}

impl From<Properties> for HashMap<String, serde_json::Value> {
    fn from(props: Properties) -> Self {
        props.inner
    }
}

/// Graph statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    pub node_count: usize,
    pub edge_count: usize,
    pub node_types: HashMap<NodeType, usize>,
    pub edge_types: HashMap<EdgeType, usize>,
    pub avg_degree: f64,
    pub density: f64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl GraphStats {
    /// Create new stats
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            node_count: 0,
            edge_count: 0,
            node_types: HashMap::new(),
            edge_types: HashMap::new(),
            avg_degree: 0.0,
            density: 0.0,
            created_at: now,
            updated_at: now,
        }
    }

    /// Update timestamp
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
}

impl Default for GraphStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_type_display() {
        assert_eq!(NodeType::EntryPoint.to_string(), "entry_point");
        assert_eq!(NodeType::Vulnerability.to_string(), "vulnerability");
        assert_eq!(NodeType::Custom("custom_type".to_string()).to_string(), "custom_type");
    }

    #[test]
    fn test_edge_type_display() {
        assert_eq!(EdgeType::Exploits.to_string(), "exploits");
        assert_eq!(EdgeType::LeadsTo.to_string(), "leads_to");
        assert_eq!(EdgeType::Custom("custom_rel".to_string()).to_string(), "custom_rel");
    }

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(0.0), RiskLevel::Minimal);
        assert_eq!(RiskLevel::from_score(2.5), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(5.0), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(8.0), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(9.5), RiskLevel::Critical);
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Minimal < RiskLevel::Low);
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_properties() {
        let props = Properties::new()
            .with("port", 80)
            .with("name", "test")
            .with("enabled", true);

        assert_eq!(props.len(), 3);
        assert!(props.contains("port"));
        assert_eq!(props.get_as::<i64>("port"), Some(80));
        assert_eq!(props.get_as::<String>("name"), Some("test".to_string()));
        assert_eq!(props.get_as::<bool>("enabled"), Some(true));
    }

    #[test]
    fn test_graph_stats() {
        let stats = GraphStats::new();
        assert_eq!(stats.node_count, 0);
        assert_eq!(stats.edge_count, 0);
        assert!(stats.node_types.is_empty());
        assert!(stats.edge_types.is_empty());
    }
}
