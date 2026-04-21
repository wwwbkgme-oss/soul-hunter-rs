//! Error types for security skills

use thiserror::Error;

/// Errors that can occur during skill execution
#[derive(Error, Debug, Clone)]
pub enum SkillError {
    #[error("Skill not initialized: {0}")]
    NotInitialized(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Analysis failed: {0}")]
    Analysis(String),

    #[error("Target not found: {0}")]
    TargetNotFound(String),

    #[error("Target not supported: {0}")]
    TargetNotSupported(String),

    #[error("Execution timeout: {0}")]
    Timeout(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Tool error: {0}")]
    Tool(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl From<std::io::Error> for SkillError {
    fn from(err: std::io::Error) -> Self {
        SkillError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for SkillError {
    fn from(err: serde_json::Error) -> Self {
        SkillError::Serialization(err.to_string())
    }
}

/// Result type alias for skill operations
pub type Result<T> = std::result::Result<T, SkillError>;
