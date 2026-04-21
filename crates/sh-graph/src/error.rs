//! Error types for the graph module

use thiserror::Error;

/// Result type alias for graph operations
pub type Result<T> = std::result::Result<T, GraphError>;

/// Error types for graph operations
#[derive(Error, Debug, Clone)]
pub enum GraphError {
    /// Node not found in the graph
    #[error("Node not found: {0}")]
    NodeNotFound(crate::EntityId),

    /// Edge not found in the graph
    #[error("Edge not found: {0}")]
    EdgeNotFound(crate::EntityId),

    /// Node already exists
    #[error("Node already exists: {0}")]
    NodeExists(crate::EntityId),

    /// Edge already exists
    #[error("Edge already exists: {0}")]
    EdgeExists(crate::EntityId),

    /// Invalid node type for operation
    #[error("Invalid node type: expected {expected}, got {actual}")]
    InvalidNodeType {
        expected: String,
        actual: String,
    },

    /// Invalid edge type for operation
    #[error("Invalid edge type: {0}")]
    InvalidEdgeType(String),

    /// Cycle detected in graph
    #[error("Cycle detected in graph")]
    CycleDetected,

    /// Path not found between nodes
    #[error("No path found from {from} to {to}")]
    PathNotFound {
        from: crate::EntityId,
        to: crate::EntityId,
    },

    /// Maximum depth exceeded during traversal
    #[error("Maximum depth exceeded: {depth}")]
    MaxDepthExceeded { depth: usize },

    /// Invalid query syntax
    #[error("Invalid query: {0}")]
    InvalidQuery(String),

    /// Query execution error
    #[error("Query execution failed: {0}")]
    QueryExecution(String),

    /// Invalid operation on graph
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),

    /// Property not found
    #[error("Property not found: {0}")]
    PropertyNotFound(String),

    /// Invalid property value
    #[error("Invalid property value for {key}: {message}")]
    InvalidPropertyValue {
        key: String,
        message: String,
    },

    /// Graph is empty
    #[error("Graph is empty")]
    EmptyGraph,

    /// Concurrent modification error
    #[error("Concurrent modification detected")]
    ConcurrentModification,

    /// Lock acquisition failed
    #[error("Failed to acquire lock: {0}")]
    LockAcquisition(String),

    /// External error (e.g., from storage backend)
    #[error("External error: {0}")]
    External(String),

    /// Unknown error
    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl GraphError {
    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            GraphError::ConcurrentModification
                | GraphError::LockAcquisition(_)
                | GraphError::External(_)
        )
    }

    /// Check if this error indicates a missing resource
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            GraphError::NodeNotFound(_) | GraphError::EdgeNotFound(_) | GraphError::PathNotFound { .. }
        )
    }

    /// Check if this error indicates a duplicate resource
    pub fn is_duplicate(&self) -> bool {
        matches!(self, GraphError::NodeExists(_) | GraphError::EdgeExists(_))
    }

    /// Get the error category
    pub fn category(&self) -> ErrorCategory {
        match self {
            GraphError::NodeNotFound(_) | GraphError::EdgeNotFound(_) | GraphError::PathNotFound { .. } => {
                ErrorCategory::NotFound
            }
            GraphError::NodeExists(_) | GraphError::EdgeExists(_) => ErrorCategory::Duplicate,
            GraphError::InvalidNodeType { .. }
            | GraphError::InvalidEdgeType(_)
            | GraphError::InvalidQuery(_)
            | GraphError::InvalidOperation(_)
            | GraphError::InvalidPropertyValue { .. } => ErrorCategory::InvalidInput,
            GraphError::CycleDetected | GraphError::MaxDepthExceeded { .. } => ErrorCategory::GraphConstraint,
            GraphError::QueryExecution(_) | GraphError::Serialization(_) | GraphError::Deserialization(_) => {
                ErrorCategory::Execution
            }
            GraphError::PropertyNotFound(_) => ErrorCategory::NotFound,
            GraphError::EmptyGraph => ErrorCategory::GraphConstraint,
            GraphError::ConcurrentModification | GraphError::LockAcquisition(_) => ErrorCategory::Concurrency,
            GraphError::External(_) | GraphError::Unknown(_) => ErrorCategory::External,
        }
    }
}

/// Error categories for classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Resource not found
    NotFound,
    /// Duplicate resource
    Duplicate,
    /// Invalid input
    InvalidInput,
    /// Graph constraint violation
    GraphConstraint,
    /// Execution error
    Execution,
    /// Concurrency error
    Concurrency,
    /// External error
    External,
}

impl std::fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorCategory::NotFound => write!(f, "not_found"),
            ErrorCategory::Duplicate => write!(f, "duplicate"),
            ErrorCategory::InvalidInput => write!(f, "invalid_input"),
            ErrorCategory::GraphConstraint => write!(f, "graph_constraint"),
            ErrorCategory::Execution => write!(f, "execution"),
            ErrorCategory::Concurrency => write!(f, "concurrency"),
            ErrorCategory::External => write!(f, "external"),
        }
    }
}

impl From<serde_json::Error> for GraphError {
    fn from(err: serde_json::Error) -> Self {
        if err.is_data() {
            GraphError::Deserialization(err.to_string())
        } else {
            GraphError::Serialization(err.to_string())
        }
    }
}

impl From<std::io::Error> for GraphError {
    fn from(err: std::io::Error) -> Self {
        GraphError::External(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_error_categories() {
        let id = Uuid::new_v4();

        let not_found = GraphError::NodeNotFound(id);
        assert_eq!(not_found.category(), ErrorCategory::NotFound);
        assert!(not_found.is_not_found());
        assert!(!not_found.is_retryable());

        let duplicate = GraphError::NodeExists(id);
        assert_eq!(duplicate.category(), ErrorCategory::Duplicate);
        assert!(duplicate.is_duplicate());

        let invalid = GraphError::InvalidQuery("syntax error".to_string());
        assert_eq!(invalid.category(), ErrorCategory::InvalidInput);

        let retryable = GraphError::ConcurrentModification;
        assert!(retryable.is_retryable());
    }

    #[test]
    fn test_error_display() {
        let id = Uuid::new_v4();
        let err = GraphError::NodeNotFound(id);
        assert!(err.to_string().contains("Node not found"));
    }

    #[test]
    fn test_serde_error_conversion() {
        let json_err = serde_json::from_str::<i32>("not a number").unwrap_err();
        let graph_err: GraphError = json_err.into();
        assert!(matches!(graph_err, GraphError::Deserialization(_)));
    }
}
