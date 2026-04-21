//! Core Orchestrator - Production Ready
//! 
//! Merged implementation from:
//! - zero-hero-rs: Assessment lifecycle, event coordination, session tracking
//! - tracker-brain-rs: Task scheduling, finding normalization, attack graph
//! - newbie-rs: Agent orchestration, policy enforcement

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

pub mod orchestrator;
pub mod finding_normalizer;
pub mod attack_graph;
pub mod risk_calculator;
pub mod session_manager;
pub mod agent_manager;
pub mod workflow;

pub use orchestrator::{Orchestrator, Config};
pub use finding_normalizer::FindingNormalizer;
pub use attack_graph::{AttackGraphEngine, AttackPath, AttackNode};
pub use risk_calculator::{RiskCalculator, BusinessContext};
pub use session_manager::{SessionManager, AssessmentSession};
pub use agent_manager::AgentManager;
pub use workflow::{
    ExecutionMode, PhaseResult, TaskPriority, WorkflowConfig, WorkflowContext, WorkflowEngine,
    WorkflowEngineBuilder, WorkflowError, WorkflowPhase, WorkflowResult, WorkflowStats, WorkflowStatus,
};

use sh_types::prelude::*;
use sh_types::{Assessment, AssessmentConfig, AssessmentId, AssessmentStatus, Finding, FindingCollection, Platform};

/// Re-export commonly used types
pub mod prelude {
    pub use super::{Orchestrator, Config, AssessmentSession, SessionManager};
    pub use super::{FindingNormalizer, AttackGraphEngine, RiskCalculator};
    pub use super::AgentManager;
}

/// Core error types
#[derive(thiserror::Error, Debug)]
pub enum CoreError {
    #[error("Session not found: {0}")]
    SessionNotFound(String),
    
    #[error("Assessment failed: {0}")]
    AssessmentFailed(String),
    
    #[error("Agent not found: {0}")]
    AgentNotFound(String),
    
    #[error("Tool not available: {0}")]
    ToolNotAvailable(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_core_module() {
        // Test that the module compiles and basic types work
        let config = Config::default();
        assert_eq!(config.max_workers, 8);
    }
}
