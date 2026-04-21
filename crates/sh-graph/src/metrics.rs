//! Graph metrics and analytics

use crate::{
    AttackGraph, AttackPath, EdgeType, EntityId, GraphError, GraphNode, NodeType, Result, RiskLevel,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use tracing::{debug, trace, warn};

/// Graph metrics calculator
#[derive(Debug)]
pub struct MetricsCalculator<'a> {
    graph: &'a AttackGraph,
}

impl<'a> MetricsCalculator<'a> {
    /// Create a new metrics calculator
    pub fn new(graph: &'a AttackGraph) -> Self {
        Self { graph }
    }

    /// Calculate comprehensive graph metrics
    pub fn calculate_metrics(&self) -> Result<GraphMetrics> {
        let node_count = self.graph.node_count();
        let edge_count = self.graph.edge_count();

        if node_count == 0 {
            return Err(GraphError::EmptyGraph);
        }

        // Calculate density
        let density = self.graph.density();

        // Calculate average degree
        let avg_degree = self.graph.average_degree();

        // Calculate degree distribution
        let degree_distribution = self.calculate_degree_distribution()?;

        // Calculate centrality metrics
        let centrality = self.calculate_centrality()?;

        // Calculate clustering coefficient
        let clustering_coefficient = self.calculate_clustering_coefficient()?;

        // Calculate connected components
        let connected_components = self.calculate_connected_components()?;

        // Calculate node type distribution
        let node_type_distribution = self.calculate_node_type_distribution();

        // Calculate edge type distribution
        let edge_type_distribution = self.calculate_edge_type_distribution();

        // Calculate risk distribution
        let risk_distribution = self.calculate_risk_distribution();

        // Calculate diameter (longest shortest path)
        let diameter = self.calculate_diameter()?;

        // Calculate average path length
        let avg_path_length = self.calculate_average_path_length()?;

        // Calculate reciprocity (for directed graphs)
        let reciprocity = self.calculate_reciprocity();

        GraphMetrics {
            node_count,
            edge_count,
            density,
            avg_degree,
            degree_distribution,
            centrality,
            clustering_coefficient,
            connected_components,
            node_type_distribution,
            edge_type_distribution,
            risk_distribution,
            diameter,
            avg_path_length,
            reciprocity,
            calculated_at: Utc::now(),
        }
    }

    /// Calculate degree distribution
    fn calculate_degree_distribution(&self) -> Result<DegreeDistribution> {
        let mut in_degrees: Vec<usize> = Vec::new();
        let mut out_degrees: Vec<usize> = Vec::new();
        let mut total_degrees: Vec<usize> = Vec::new();

        for node in self.graph.get_nodes() {
            let in_deg = self
                .graph
                .get_incoming_edges(node.id)
                .map(|e| e.len())
                .unwrap_or(0);
            let out_deg = self
                .graph
                .get_outgoing_edges(node.id)
                .map(|e| e.len())
                .unwrap_or(0);

            in_degrees.push(in_deg);
            out_degrees.push(out_deg);
            total_degrees.push(in_deg + out_deg);
        }

        Ok(DegreeDistribution {
            in_degree: DistributionStats::from_values(&in_degrees),
            out_degree: DistributionStats::from_values(&out_degrees),
            total_degree: DistributionStats::from_values(&total_degrees),
        })
    }

    /// Calculate centrality metrics for all nodes
    fn calculate_centrality(&self) -> Result<HashMap<EntityId, CentralityMetrics>> {
        let mut centrality = HashMap::new();

        // Calculate degree centrality
        let degree_centrality = self.calculate_degree_centrality();

        // Calculate betweenness centrality
        let betweenness_centrality = self.calculate_betweenness_centrality()?;

        // Calculate closeness centrality
        let closeness_centrality = self.calculate_closeness_centrality()?;

        // Calculate eigenvector centrality (simplified)
        let eigenvector_centrality = self.calculate_eigenvector_centrality()?;

        for node in self.graph.get_nodes() {
            let metrics = CentralityMetrics {
                degree: *degree_centrality.get(&node.id).unwrap_or(&0.0),
                betweenness: *betweenness_centrality.get(&node.id).unwrap_or(&0.0),
                closeness: *closeness_centrality.get(&node.id).unwrap_or(&0.0),
                eigenvector: *eigenvector_centrality.get(&node.id).unwrap_or(&0.0),
            };
            centrality.insert(node.id, metrics);
        }

        Ok(centrality)
    }

    /// Calculate degree centrality
    fn calculate_degree_centrality(&self) -> HashMap<EntityId, f64> {
        let n = self.graph.node_count() as f64;
        let mut centrality = HashMap::new();

        for node in self.graph.get_nodes() {
            let degree = self
                .graph
                .get_outgoing_edges(node.id)
                .map(|e| e.len())
                .unwrap_or(0) as f64;
            // Normalize by maximum possible degree
            centrality.insert(node.id, degree / (n - 1.0).max(1.0));
        }

        centrality
    }

    /// Calculate betweenness centrality using Brandes' algorithm
    fn calculate_betweenness_centrality(&self) -> Result<HashMap<EntityId, f64>> {
        let mut centrality: HashMap<EntityId, f64> = self
            .graph
            .get_nodes()
            .iter()
            .map(|n| (n.id, 0.0))
            .collect();

        for source in self.graph.get_nodes() {
            let mut stack: Vec<EntityId> = Vec::new();
            let mut predecessors: HashMap<EntityId, Vec<EntityId>> = HashMap::new();
            let mut sigma: HashMap<EntityId, f64> =
                self.graph.get_nodes().iter().map(|n| (n.id, 0.0)).collect();
            let mut distance: HashMap<EntityId, i32> =
                self.graph.get_nodes().iter().map(|n| (n.id, -1)).collect();
            let mut queue: VecDeque<EntityId> = VecDeque::new();

            sigma.insert(source.id, 1.0);
            distance.insert(source.id, 0);
            queue.push_back(source.id);

            while let Some(v) = queue.pop_front() {
                stack.push(v);
                let dist_v = *distance.get(&v).unwrap_or(&-1);

                if let Ok(neighbors) = self.graph.get_neighbors(v) {
                    for neighbor in neighbors {
                        let w = neighbor.id;
                        if *distance.get(&w).unwrap_or(&-1) < 0 {
                            queue.push_back(w);
                            distance.insert(w, dist_v + 1);
                        }

                        if *distance.get(&w).unwrap_or(&-1) == dist_v + 1 {
                            let sigma_v = *sigma.get(&v).unwrap_or(&0.0);
                            *sigma.entry(w).or_insert(0.0) += sigma_v;
                            predecessors.entry(w).or_insert_with(Vec::new).push(v);
                        }
                    }
                }
            }

            let mut delta: HashMap<EntityId, f64> =
                self.graph.get_nodes().iter().map(|n| (n.id, 0.0)).collect();

            while let Some(w) = stack.pop() {
                if let Some(preds) = predecessors.get(&w) {
                    for v in preds {
                        let coeff = (*sigma.get(v).unwrap_or(&0.0) / *sigma.get(&w).unwrap_or(&1.0))
                            * (1.0 + *delta.get(&w).unwrap_or(&0.0));
                        *delta.entry(*v).or_insert(0.0) += coeff;
                    }
                }

                if w != source.id {
                    *centrality.entry(w).or_insert(0.0) += *delta.get(&w).unwrap_or(&0.0);
                }
            }
        }

        // Normalize
        let n = self.graph.node_count() as f64;
        let normalizer = if n > 2.0 {
            1.0 / ((n - 1.0) * (n - 2.0))
        } else {
            1.0
        };

        for value in centrality.values_mut() {
            *value *= normalizer;
        }

        Ok(centrality)
    }

    /// Calculate closeness centrality
    fn calculate_closeness_centrality(&self) -> Result<HashMap<EntityId, f64>> {
        let mut centrality = HashMap::new();

        for node in self.graph.get_nodes() {
            let distances = self.bfs_distances(node.id);
            let total_distance: i32 = distances.values().sum();
            let reachable = distances.len() as f64;
            let n = self.graph.node_count() as f64;

            let closeness = if total_distance > 0 && reachable > 1.0 {
                (reachable - 1.0) / (n - 1.0) * (reachable - 1.0) / total_distance as f64
            } else {
                0.0
            };

            centrality.insert(node.id, closeness);
        }

        Ok(centrality)
    }

    /// Calculate eigenvector centrality (simplified power iteration)
    fn calculate_eigenvector_centrality(&self) -> Result<HashMap<EntityId, f64>> {
        let nodes: Vec<EntityId> = self.graph.get_nodes().iter().map(|n| n.id).collect();
        let n = nodes.len();

        if n == 0 {
            return Ok(HashMap::new());
        }

        let mut scores: HashMap<EntityId, f64> =
            nodes.iter().map(|id| (*id, 1.0 / n as f64)).collect();

        for _ in 0..100 {
            // Max iterations
            let mut new_scores: HashMap<EntityId, f64> = HashMap::new();
            let mut max_score = 0.0_f64;

            for node_id in &nodes {
                let mut score = 0.0;
                if let Ok(neighbors) = self.graph.get_neighbors(*node_id) {
                    for neighbor in neighbors {
                        score += scores.get(&neighbor.id).unwrap_or(&0.0);
                    }
                }
                new_scores.insert(*node_id, score);
                max_score = max_score.max(score);
            }

            // Normalize
            if max_score > 0.0 {
                for score in new_scores.values_mut() {
                    *score /= max_score;
                }
            }

            scores = new_scores;
        }

        Ok(scores)
    }

    /// BFS to calculate distances from a source node
    fn bfs_distances(&self, source: EntityId) -> HashMap<EntityId, i32> {
        let mut distances = HashMap::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        distances.insert(source, 0);
        visited.insert(source);
        queue.push_back((source, 0));

        while let Some((current, dist)) = queue.pop_front() {
            if let Ok(neighbors) = self.graph.get_neighbors(current) {
                for neighbor in neighbors {
                    if !visited.contains(&neighbor.id) {
                        visited.insert(neighbor.id);
                        distances.insert(neighbor.id, dist + 1);
                        queue.push_back((neighbor.id, dist + 1));
                    }
                }
            }
        }

        distances
    }

    /// Calculate clustering coefficient
    fn calculate_clustering_coefficient(&self) -> Result<f64> {
        let mut total_coefficient = 0.0;
        let mut count = 0;

        for node in self.graph.get_nodes() {
            if let Ok(neighbors) = self.graph.get_neighbors(node.id) {
                let neighbor_ids: HashSet<EntityId> =
                    neighbors.iter().map(|n| n.id).collect();
                let k = neighbor_ids.len();

                if k >= 2 {
                    let mut edges_between_neighbors = 0;

                    for neighbor in &neighbors {
                        if let Ok(neighbor_neighbors) = self.graph.get_neighbors(neighbor.id) {
                            for nn in neighbor_neighbors {
                                if neighbor_ids.contains(&nn.id) {
                                    edges_between_neighbors += 1;
                                }
                            }
                        }
                    }

                    // Divide by 2 because we count each edge twice
                    let possible_edges = k * (k - 1);
                    let coefficient = edges_between_neighbors as f64 / possible_edges as f64;
                    total_coefficient += coefficient;
                    count += 1;
                }
            }
        }

        if count == 0 {
            Ok(0.0)
        } else {
            Ok(total_coefficient / count as f64)
        }
    }

    /// Calculate connected components
    fn calculate_connected_components(&self) -> Result<Vec<ConnectedComponent>> {
        let mut visited = HashSet::new();
        let mut components = Vec::new();

        for node in self.graph.get_nodes() {
            if !visited.contains(&node.id) {
                let component_nodes = self.bfs_component(node.id, &mut visited);
                let component = ConnectedComponent {
                    nodes: component_nodes.clone(),
                    size: component_nodes.len(),
                };
                components.push(component);
            }
        }

        Ok(components)
    }

    /// BFS to find all nodes in a component
    fn bfs_component(&self, start: EntityId, visited: &mut HashSet<EntityId>) -> Vec<EntityId> {
        let mut component = Vec::new();
        let mut queue = VecDeque::new();

        queue.push_back(start);
        visited.insert(start);

        while let Some(current) = queue.pop_front() {
            component.push(current);

            // Check outgoing edges
            if let Ok(neighbors) = self.graph.get_neighbors(current) {
                for neighbor in neighbors {
                    if !visited.contains(&neighbor.id) {
                        visited.insert(neighbor.id);
                        queue.push_back(neighbor.id);
                    }
                }
            }

            // Check incoming edges (for undirected component)
            if let Ok(predecessors) = self.graph.get_predecessors(current) {
                for pred in predecessors {
                    if !visited.contains(&pred.id) {
                        visited.insert(pred.id);
                        queue.push_back(pred.id);
                    }
                }
            }
        }

        component
    }

    /// Calculate node type distribution
    fn calculate_node_type_distribution(&self) -> HashMap<NodeType, usize> {
        let mut distribution = HashMap::new();
        for node in self.graph.get_nodes() {
            *distribution.entry(node.node_type).or_insert(0) += 1;
        }
        distribution
    }

    /// Calculate edge type distribution
    fn calculate_edge_type_distribution(&self) -> HashMap<EdgeType, usize> {
        let mut distribution = HashMap::new();
        for edge in self.graph.get_edges() {
            *distribution.entry(edge.edge_type).or_insert(0) += 1;
        }
        distribution
    }

    /// Calculate risk distribution
    fn calculate_risk_distribution(&self) -> RiskDistribution {
        let mut minimal = 0;
        let mut low = 0;
        let mut medium = 0;
        let mut high = 0;
        let mut critical = 0;

        for node in self.graph.get_nodes() {
            match node.risk_level() {
                RiskLevel::Minimal => minimal += 1,
                RiskLevel::Low => low += 1,
                RiskLevel::Medium => medium += 1,
                RiskLevel::High => high += 1,
                RiskLevel::Critical => critical += 1,
            }
        }

        RiskDistribution {
            minimal,
            low,
            medium,
            high,
            critical,
        }
    }

    /// Calculate graph diameter (longest shortest path)
    fn calculate_diameter(&self) -> Result<usize> {
        let mut diameter = 0;

        for node in self.graph.get_nodes() {
            let distances = self.bfs_distances(node.id);
            if let Some(&max_dist) = distances.values().max() {
                diameter = diameter.max(max_dist as usize);
            }
        }

        Ok(diameter)
    }

    /// Calculate average path length
    fn calculate_average_path_length(&self) -> Result<f64> {
        let mut total_length = 0.0;
        let mut path_count = 0;

        for node in self.graph.get_nodes() {
            let distances = self.bfs_distances(node.id);
            for (&target, &dist) in &distances {
                if target != node.id {
                    total_length += dist as f64;
                    path_count += 1;
                }
            }
        }

        if path_count == 0 {
            Ok(0.0)
        } else {
            Ok(total_length / path_count as f64)
        }
    }

    /// Calculate reciprocity (fraction of bidirectional edges)
    fn calculate_reciprocity(&self) -> f64 {
        let mut bidirectional = 0;
        let total_edges = self.graph.edge_count();

        if total_edges == 0 {
            return 0.0;
        }

        for edge in self.graph.get_edges() {
            // Check if reverse edge exists
            let reverse_exists = self
                .graph
                .get_edges()
                .iter()
                .any(|e| e.from == edge.to && e.to == edge.from);
            if reverse_exists {
                bidirectional += 1;
            }
        }

        bidirectional as f64 / total_edges as f64
    }

    /// Calculate risk metrics
    pub fn calculate_risk_metrics(&self) -> RiskMetrics {
        let nodes = self.graph.get_nodes();
        let n = nodes.len() as f64;

        if n == 0.0 {
            return RiskMetrics::default();
        }

        let total_risk: f64 = nodes.iter().map(|n| n.risk_score).sum();
        let avg_risk = total_risk / n;

        let risks: Vec<f64> = nodes.iter().map(|n| n.risk_score).collect();
        let max_risk = risks.iter().cloned().fold(0.0, f64::max);
        let min_risk = risks.iter().cloned().fold(10.0, f64::min);

        // Calculate variance
        let variance: f64 = risks.iter().map(|r| (r - avg_risk).powi(2)).sum::<f64>() / n;
        let std_dev = variance.sqrt();

        // Count high-risk nodes
        let high_risk_count = nodes.iter().filter(|n| n.risk_score >= 7.0).count();
        let critical_count = nodes.iter().filter(|n| n.risk_score >= 9.0).count();

        RiskMetrics {
            avg_risk,
            max_risk,
            min_risk,
            std_dev,
            high_risk_count,
            critical_count,
            high_risk_percentage: (high_risk_count as f64 / n) * 100.0,
        }
    }

    /// Find the most critical nodes (highest betweenness + risk)
    pub fn find_critical_nodes(&self, top_n: usize) -> Result<Vec<(GraphNode, f64)>> {
        let centrality = self.calculate_centrality()?;

        let mut scores: Vec<(GraphNode, f64)> = self
            .graph
            .get_nodes()
            .into_iter()
            .map(|node| {
                let metrics = centrality.get(&node.id).cloned().unwrap_or_default();
                // Combined score: betweenness * risk
                let score = metrics.betweenness * (node.risk_score / 10.0);
                (node, score)
            })
            .collect();

        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores.truncate(top_n);

        Ok(scores)
    }
}

/// Comprehensive graph metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphMetrics {
    /// Number of nodes
    pub node_count: usize,
    /// Number of edges
    pub edge_count: usize,
    /// Graph density
    pub density: f64,
    /// Average degree
    pub avg_degree: f64,
    /// Degree distribution statistics
    pub degree_distribution: DegreeDistribution,
    /// Centrality metrics for each node
    pub centrality: HashMap<EntityId, CentralityMetrics>,
    /// Global clustering coefficient
    pub clustering_coefficient: f64,
    /// Connected components
    pub connected_components: Vec<ConnectedComponent>,
    /// Node type distribution
    pub node_type_distribution: HashMap<NodeType, usize>,
    /// Edge type distribution
    pub edge_type_distribution: HashMap<EdgeType, usize>,
    /// Risk distribution
    pub risk_distribution: RiskDistribution,
    /// Graph diameter
    pub diameter: usize,
    /// Average path length
    pub avg_path_length: f64,
    /// Reciprocity (fraction of bidirectional edges)
    pub reciprocity: f64,
    /// Calculation timestamp
    pub calculated_at: DateTime<Utc>,
}

impl GraphMetrics {
    /// Get the number of connected components
    pub fn component_count(&self) -> usize {
        self.connected_components.len()
    }

    /// Get the size of the largest component
    pub fn largest_component_size(&self) -> usize {
        self.connected_components
            .iter()
            .map(|c| c.size)
            .max()
            .unwrap_or(0)
    }

    /// Check if the graph is connected
    pub fn is_connected(&self) -> bool {
        self.component_count() <= 1
    }

    /// Get average centrality
    pub fn avg_centrality(&self) -> CentralityMetrics {
        let n = self.centrality.len() as f64;
        if n == 0.0 {
            return CentralityMetrics::default();
        }

        let sum: CentralityMetrics = self.centrality.values().fold(CentralityMetrics::default(), |acc, m| {
            CentralityMetrics {
                degree: acc.degree + m.degree,
                betweenness: acc.betweenness + m.betweenness,
                closeness: acc.closeness + m.closeness,
                eigenvector: acc.eigenvector + m.eigenvector,
            }
        });

        CentralityMetrics {
            degree: sum.degree / n,
            betweenness: sum.betweenness / n,
            closeness: sum.closeness / n,
            eigenvector: sum.eigenvector / n,
        }
    }
}

/// Degree distribution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegreeDistribution {
    pub in_degree: DistributionStats,
    pub out_degree: DistributionStats,
    pub total_degree: DistributionStats,
}

/// Distribution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionStats {
    pub min: usize,
    pub max: usize,
    pub mean: f64,
    pub median: f64,
    pub std_dev: f64,
}

impl DistributionStats {
    /// Calculate statistics from a list of values
    pub fn from_values(values: &[usize]) -> Self {
        if values.is_empty() {
            return Self {
                min: 0,
                max: 0,
                mean: 0.0,
                median: 0.0,
                std_dev: 0.0,
            };
        }

        let min = *values.iter().min().unwrap_or(&0);
        let max = *values.iter().max().unwrap_or(&0);
        let mean = values.iter().sum::<usize>() as f64 / values.len() as f64;

        let mut sorted = values.to_vec();
        sorted.sort_unstable();
        let median = if sorted.len() % 2 == 0 {
            let mid = sorted.len() / 2;
            (sorted[mid - 1] + sorted[mid]) as f64 / 2.0
        } else {
            sorted[sorted.len() / 2] as f64
        };

        let variance: f64 = values
            .iter()
            .map(|&v| (v as f64 - mean).powi(2))
            .sum::<f64>()
            / values.len() as f64;
        let std_dev = variance.sqrt();

        Self {
            min,
            max,
            mean,
            median,
            std_dev,
        }
    }
}

/// Centrality metrics for a node
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct CentralityMetrics {
    /// Degree centrality
    pub degree: f64,
    /// Betweenness centrality
    pub betweenness: f64,
    /// Closeness centrality
    pub closeness: f64,
    /// Eigenvector centrality
    pub eigenvector: f64,
}

impl CentralityMetrics {
    /// Get the average centrality score
    pub fn average(&self) -> f64 {
        (self.degree + self.betweenness + self.closeness + self.eigenvector) / 4.0
    }
}

/// Connected component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedComponent {
    /// Node IDs in the component
    pub nodes: Vec<EntityId>,
    /// Number of nodes
    pub size: usize,
}

/// Risk distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskDistribution {
    pub minimal: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

impl RiskDistribution {
    /// Get total count
    pub fn total(&self) -> usize {
        self.minimal + self.low + self.medium + self.high + self.critical
    }

    /// Get percentage for each risk level
    pub fn percentages(&self) -> HashMap<RiskLevel, f64> {
        let total = self.total() as f64;
        if total == 0.0 {
            return HashMap::new();
        }

        let mut map = HashMap::new();
        map.insert(RiskLevel::Minimal, (self.minimal as f64 / total) * 100.0);
        map.insert(RiskLevel::Low, (self.low as f64 / total) * 100.0);
        map.insert(RiskLevel::Medium, (self.medium as f64 / total) * 100.0);
        map.insert(RiskLevel::High, (self.high as f64 / total) * 100.0);
        map.insert(RiskLevel::Critical, (self.critical as f64 / total) * 100.0);
        map
    }
}

/// Risk metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiskMetrics {
    /// Average risk score
    pub avg_risk: f64,
    /// Maximum risk score
    pub max_risk: f64,
    /// Minimum risk score
    pub min_risk: f64,
    /// Standard deviation of risk scores
    pub std_dev: f64,
    /// Number of high-risk nodes
    pub high_risk_count: usize,
    /// Number of critical nodes
    pub critical_count: usize,
    /// Percentage of high-risk nodes
    pub high_risk_percentage: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttackGraph, GraphEdge, GraphNode, NodeType};

    fn create_test_graph() -> AttackGraph {
        let graph = AttackGraph::new();

        // Create a simple graph: A -> B -> C, A -> C
        let a = GraphNode::new(NodeType::EntryPoint, "A").with_risk_score(5.0);
        let id_a = graph.add_node(a).unwrap();

        let b = GraphNode::new(NodeType::Asset, "B").with_risk_score(7.0);
        let id_b = graph.add_node(b).unwrap();

        let c = GraphNode::new(NodeType::Data, "C").with_risk_score(9.0);
        let id_c = graph.add_node(c).unwrap();

        graph
            .add_edge(GraphEdge::new(id_a, id_b, EdgeType::LeadsTo))
            .unwrap();
        graph
            .add_edge(GraphEdge::new(id_b, id_c, EdgeType::LeadsTo))
            .unwrap();
        graph
            .add_edge(GraphEdge::new(id_a, id_c, EdgeType::LeadsTo))
            .unwrap();

        graph
    }

    #[test]
    fn test_calculate_metrics() {
        let graph = create_test_graph();
        let calculator = MetricsCalculator::new(&graph);

        let metrics = calculator.calculate_metrics().unwrap();

        assert_eq!(metrics.node_count, 3);
        assert_eq!(metrics.edge_count, 3);
        assert!(metrics.density > 0.0);
        assert!(metrics.avg_degree > 0.0);
    }

    #[test]
    fn test_degree_distribution() {
        let graph = create_test_graph();
        let calculator = MetricsCalculator::new(&graph);

        let metrics = calculator.calculate_metrics().unwrap();

        assert!(metrics.degree_distribution.out_degree.max > 0);
        assert!(metrics.degree_distribution.in_degree.max > 0);
    }

    #[test]
    fn test_centrality() {
        let graph = create_test_graph();
        let calculator = MetricsCalculator::new(&graph);

        let metrics = calculator.calculate_metrics().unwrap();

        assert!(!metrics.centrality.is_empty());

        // Node B should have higher betweenness as it's on the only path A->B->C
        let centrality_a = metrics.centrality.values().next().unwrap();
        assert!(centrality_a.degree >= 0.0);
    }

    #[test]
    fn test_connected_components() {
        let graph = create_test_graph();
        let calculator = MetricsCalculator::new(&graph);

        let metrics = calculator.calculate_metrics().unwrap();

        assert_eq!(metrics.component_count(), 1);
        assert!(metrics.is_connected());
    }

    #[test]
    fn test_risk_distribution() {
        let graph = create_test_graph();
        let calculator = MetricsCalculator::new(&graph);

        let metrics = calculator.calculate_metrics().unwrap();

        assert_eq!(metrics.risk_distribution.total(), 3);
        assert!(metrics.risk_distribution.high > 0 || metrics.risk_distribution.critical > 0);
    }

    #[test]
    fn test_risk_metrics() {
        let graph = create_test_graph();
        let calculator = MetricsCalculator::new(&graph);

        let risk_metrics = calculator.calculate_risk_metrics();

        assert!(risk_metrics.avg_risk > 0.0);
        assert!(risk_metrics.max_risk > 0.0);
        assert!(risk_metrics.high_risk_count > 0);
    }

    #[test]
    fn test_find_critical_nodes() {
        let graph = create_test_graph();
        let calculator = MetricsCalculator::new(&graph);

        let critical = calculator.find_critical_nodes(2).unwrap();
        assert!(!critical.is_empty());
    }

    #[test]
    fn test_empty_graph() {
        let graph = AttackGraph::new();
        let calculator = MetricsCalculator::new(&graph);

        assert!(matches!(
            calculator.calculate_metrics(),
            Err(GraphError::EmptyGraph)
        ));
    }

    #[test]
    fn test_distribution_stats() {
        let values = vec![1, 2, 3, 4, 5];
        let stats = DistributionStats::from_values(&values);

        assert_eq!(stats.min, 1);
        assert_eq!(stats.max, 5);
        assert_eq!(stats.mean, 3.0);
        assert_eq!(stats.median, 3.0);
    }

    #[test]
    fn test_centrality_metrics() {
        let metrics = CentralityMetrics {
            degree: 0.5,
            betweenness: 0.3,
            closeness: 0.7,
            eigenvector: 0.4,
        };

        assert!((metrics.average() - 0.475).abs() < 0.001);
    }
}
