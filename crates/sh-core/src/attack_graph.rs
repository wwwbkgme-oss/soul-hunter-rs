//! Attack Graph Engine - Production Ready
//! 
//! Builds attack surface graphs and calculates exploit paths
//! Based on tracker-brain-rs implementation

use std::collections::{HashMap, HashSet};

use tracing::{debug, info, warn};
use uuid::Uuid;

use sh_types::prelude::*;
use sh_types::{Finding, FindingId, Severity};

/// Attack graph engine
#[derive(Debug, Clone)]
pub struct AttackGraphEngine {
    enable_explainability: bool,
}

impl AttackGraphEngine {
    pub fn new() -> Self {
        Self {
            enable_explainability: true,
        }
    }

    pub fn with_explainability(mut self, enable: bool) -> Self {
        self.enable_explainability = enable;
        self
    }

    /// Build attack graph from findings
    pub fn build(&self, findings: &[Finding]) -> AttackGraph {
        if findings.is_empty() {
            return AttackGraph::new();
        }

        info!("Building attack graph from {} findings", findings.len());

        let mut graph = AttackGraph::new();

        // Create nodes for each finding
        for finding in findings {
            let node = AttackNode::from_finding(finding);
            graph.add_node(node);
        }

        // Create edges based on relationships
        self.create_edges(&mut graph);

        // Calculate paths
        self.calculate_critical_paths(&mut graph);

        debug!("Attack graph: {} nodes, {} edges", graph.nodes.len(), graph.edges.len());

        graph
    }

    /// Create edges between related nodes
    fn create_edges(&self, graph: &mut AttackGraph) {
        let node_ids: Vec<Uuid> = graph.nodes.keys().cloned().collect();

        for i in 0..node_ids.len() {
            for j in (i + 1)..node_ids.len() {
                let id_a = node_ids[i];
                let id_b = node_ids[j];

                if let Some(edge) = self.analyze_relationship(graph, id_a, id_b) {
                    graph.add_edge(edge);
                }
            }
        }
    }

    /// Analyze relationship between two nodes
    fn analyze_relationship(&self, graph: &AttackGraph, from: Uuid, to: Uuid) -> Option<AttackEdge> {
        let node_a = graph.nodes.get(&from)?;
        let node_b = graph.nodes.get(&to)?;

        // Check for prerequisite relationships
        if self.is_prerequisite(node_a, node_b) {
            return Some(AttackEdge {
                id: Uuid::new_v4(),
                from,
                to,
                edge_type: EdgeType::Prerequisite,
                weight: 0.8,
            });
        }

        // Check for chaining relationships
        if self.can_chain(node_a, node_b) {
            return Some(AttackEdge {
                id: Uuid::new_v4(),
                from,
                to,
                edge_type: EdgeType::Chain,
                weight: 0.6,
            });
        }

        // Check for similar findings
        if self.are_similar(node_a, node_b) {
            return Some(AttackEdge {
                id: Uuid::new_v4(),
                from,
                to,
                edge_type: EdgeType::Similar,
                weight: 0.3,
            });
        }

        None
    }

    /// Check if node_a is a prerequisite for node_b
    fn is_prerequisite(&self, node_a: &AttackNode, node_b: &AttackNode) -> bool {
        // Common prerequisite patterns
        let prereq_patterns: Vec<(&str, &str)> = vec![
            ("debug_enabled", "information_disclosure"),
            ("weak_crypto", "data_exfiltration"),
            ("hardcoded_secret", "unauthorized_access"),
            ("exported_component", "intent_hijacking"),
        ];

        for (prereq, target) in &prereq_patterns {
            if node_a.finding_type.contains(prereq) && node_b.finding_type.contains(target) {
                return true;
            }
        }

        false
    }

    /// Check if findings can be chained
    fn can_chain(&self, node_a: &AttackNode, node_b: &AttackNode) -> bool {
        // Check for sequential attack patterns
        if node_a.severity >= Severity::Medium && node_b.severity >= Severity::Medium {
            // Check if they're in related components
            if let (Some(comp_a), Some(comp_b)) = (&node_a.component, &node_b.component) {
                if comp_a == comp_b {
                    return true;
                }
            }
        }

        false
    }

    /// Check if findings are similar
    fn are_similar(&self, node_a: &AttackNode, node_b: &AttackNode) -> bool {
        node_a.finding_type == node_b.finding_type
    }

    /// Calculate critical paths in the graph
    fn calculate_critical_paths(&self, graph: &mut AttackGraph) {
        let entry_points: Vec<Uuid> = graph.nodes.values()
            .filter(|n| n.is_entry_point())
            .map(|n| n.id)
            .collect();

        let critical_nodes: Vec<Uuid> = graph.nodes.values()
            .filter(|n| n.is_critical())
            .map(|n| n.id)
            .collect();

        for entry in &entry_points {
            for critical in &critical_nodes {
                if let Some(path) = self.find_path(graph, *entry, *critical) {
                    if path.risk_score > 7.0 {
                        graph.critical_paths.push(path);
                    }
                }
            }
        }

        // Sort by risk score
        graph.critical_paths.sort_by(|a, b| {
            b.risk_score.partial_cmp(&a.risk_score).unwrap()
        });
    }

    /// Find path between two nodes
    fn find_path(&self, graph: &AttackGraph, start: Uuid, end: Uuid) -> Option<AttackPath> {
        // Simple BFS for path finding
        let mut visited = HashSet::new();
        let mut queue = vec![(start, vec![start])];

        while let Some((current, path)) = queue.pop() {
            if current == end {
                return Some(self.build_path(graph, path));
            }

            if visited.insert(current) {
                // Find neighbors
                for edge in &graph.edges {
                    if edge.from == current && !visited.contains(&edge.to) {
                        let mut new_path = path.clone();
                        new_path.push(edge.to);
                        queue.push((edge.to, new_path));
                    }
                }
            }
        }

        None
    }

    /// Build attack path from node list
    fn build_path(&self, graph: &AttackGraph, node_ids: Vec<Uuid>) -> AttackPath {
        let nodes: Vec<AttackNode> = node_ids.iter()
            .filter_map(|id| graph.nodes.get(id).cloned())
            .collect();

        let risk_score = nodes.iter()
            .map(|n| n.risk_score)
            .sum::<f64>() / nodes.len().max(1) as f64;

        let complexity = self.calculate_complexity(&nodes);

        AttackPath {
            id: Uuid::new_v4(),
            nodes,
            risk_score,
            complexity,
            description: self.generate_path_description(&node_ids),
        }
    }

    /// Calculate path complexity
    fn calculate_complexity(&self, nodes: &[AttackNode]) -> PathComplexity {
        match nodes.len() {
            0..=2 => PathComplexity::Low,
            3..=5 => PathComplexity::Medium,
            _ => PathComplexity::High,
        }
    }

    /// Generate human-readable path description
    fn generate_path_description(&self, node_ids: &[Uuid]) -> String {
        format!("Attack path with {} steps", node_ids.len())
    }

    /// Calculate overall risk score for graph
    pub fn calculate_risk_score(&self, graph: &AttackGraph) -> f64 {
        if graph.nodes.is_empty() {
            return 0.0;
        }

        let node_risk: f64 = graph.nodes.values()
            .map(|n| n.risk_score)
            .sum();

        let avg_risk = node_risk / graph.nodes.len() as f64;

        // Boost for critical paths
        let critical_boost = graph.critical_paths.len() as f64 * 0.5;

        (avg_risk + critical_boost).min(10.0)
    }
}

impl Default for AttackGraphEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Attack graph structure
#[derive(Debug, Clone)]
pub struct AttackGraph {
    pub nodes: HashMap<Uuid, AttackNode>,
    pub edges: Vec<AttackEdge>,
    pub critical_paths: Vec<AttackPath>,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            critical_paths: Vec::new(),
        }
    }

    pub fn add_node(&mut self, node: AttackNode) {
        self.nodes.insert(node.id, node);
    }

    pub fn add_edge(&mut self, edge: AttackEdge) {
        self.edges.push(edge);
    }

    pub fn get_node(&self, id: &Uuid) -> Option<&AttackNode> {
        self.nodes.get(id)
    }

    pub fn get_neighbors(&self, id: &Uuid) -> Vec<&AttackNode> {
        self.edges.iter()
            .filter(|e| e.from == *id)
            .filter_map(|e| self.nodes.get(&e.to))
            .collect()
    }
}

impl Default for AttackGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Attack node representing a finding
#[derive(Debug, Clone)]
pub struct AttackNode {
    pub id: Uuid,
    pub finding_id: FindingId,
    pub title: String,
    pub finding_type: String,
    pub severity: Severity,
    pub risk_score: f64,
    pub component: Option<String>,
    pub is_entry_point: bool,
    pub is_critical: bool,
}

impl AttackNode {
    pub fn from_finding(finding: &Finding) -> Self {
        let risk_score = finding.cvss_score.unwrap_or(5.0);
        
        Self {
            id: Uuid::new_v4(),
            finding_id: finding.id,
            title: finding.title.clone(),
            finding_type: finding.finding_type.clone(),
            severity: finding.severity,
            risk_score,
            component: finding.location.class_name.clone(),
            is_entry_point: Self::is_entry_point_type(&finding.finding_type),
            is_critical: finding.severity >= Severity::High,
        }
    }

    fn is_entry_point_type(finding_type: &str) -> bool {
        let entry_types = [
            "exported_activity",
            "exported_service",
            "exported_receiver",
            "debug_enabled",
            "backup_enabled",
        ];
        entry_types.iter().any(|t| finding_type.contains(t))
    }

    pub fn is_entry_point(&self) -> bool {
        self.is_entry_point
    }

    pub fn is_critical(&self) -> bool {
        self.is_critical
    }
}

/// Edge between attack nodes
#[derive(Debug, Clone)]
pub struct AttackEdge {
    pub id: Uuid,
    pub from: Uuid,
    pub to: Uuid,
    pub edge_type: EdgeType,
    pub weight: f64,
}

/// Edge type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeType {
    Prerequisite,
    Chain,
    Similar,
}

/// Attack path through the graph
#[derive(Debug, Clone)]
pub struct AttackPath {
    pub id: Uuid,
    pub nodes: Vec<AttackNode>,
    pub risk_score: f64,
    pub complexity: PathComplexity,
    pub description: String,
}

/// Path complexity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathComplexity {
    Low,
    Medium,
    High,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_finding(title: &str, severity: Severity, finding_type: &str) -> Finding {
        Finding::new(title, "Test description")
            .with_severity(severity)
            .with_type(finding_type)
    }

    #[test]
    fn test_attack_graph_build() {
        let engine = AttackGraphEngine::new();
        
        let findings = vec![
            create_test_finding("Debug Enabled", Severity::Medium, "debug_enabled"),
            create_test_finding("Info Disclosure", Severity::High, "information_disclosure"),
            create_test_finding("Hardcoded Key", Severity::Critical, "hardcoded_secret"),
        ];

        let graph = engine.build(&findings);
        
        assert_eq!(graph.nodes.len(), 3);
        assert!(!graph.edges.is_empty());
    }

    #[test]
    fn test_node_from_finding() {
        let finding = create_test_finding("Test", Severity::High, "test_type");
        let node = AttackNode::from_finding(&finding);
        
        assert_eq!(node.title, "Test");
        assert_eq!(node.severity, Severity::High);
        assert!(node.is_critical);
    }

    #[test]
    fn test_risk_score_calculation() {
        let engine = AttackGraphEngine::new();
        let mut graph = AttackGraph::new();
        
        // Add nodes
        let node1 = AttackNode {
            id: Uuid::new_v4(),
            finding_id: Uuid::new_v4(),
            title: "Test".to_string(),
            finding_type: "test".to_string(),
            severity: Severity::High,
            risk_score: 7.5,
            component: None,
            is_entry_point: false,
            is_critical: true,
        };
        
        graph.add_node(node1);
        
        let score = engine.calculate_risk_score(&graph);
        assert!(score > 0.0);
    }
}
