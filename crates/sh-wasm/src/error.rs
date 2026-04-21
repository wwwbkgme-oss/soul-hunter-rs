//! # WASM Error Types
//!
//! Error types for the WASM sandbox and runtime.

use thiserror::Error;

/// Result type alias for WASM operations
pub type Result<T> = std::result::Result<T, WasmError>;

/// Errors that can occur in the WASM sandbox and runtime
#[derive(Error, Debug)]
pub enum WasmError {
    /// Module compilation failed
    #[error("WASM module compilation failed: {0}")]
    Compilation(String),

    /// Module instantiation failed
    #[error("WASM module instantiation failed: {0}")]
    Instantiation(String),

    /// Module execution failed
    #[error("WASM module execution failed: {0}")]
    Execution(String),

    /// Resource limit exceeded
    #[error("Resource limit exceeded: {limit} (current: {current}, max: {max})")]
    ResourceLimitExceeded {
        limit: String,
        current: u64,
        max: u64,
    },

    /// Memory limit exceeded
    #[error("Memory limit exceeded: requested {requested} bytes, max allowed {max} bytes")]
    MemoryLimitExceeded { requested: u64, max: u64 },

    /// Time limit exceeded
    #[error("Execution time limit exceeded: limit was {limit_ms}ms")]
    TimeLimitExceeded { limit_ms: u64 },

    /// WASI operation failed
    #[error("WASI operation failed: {0}")]
    Wasi(String),

    /// Invalid module
    #[error("Invalid WASM module: {0}")]
    InvalidModule(String),

    /// Invalid function
    #[error("Invalid function: {0}")]
    InvalidFunction(String),

    /// Invalid argument
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Security violation
    #[error("Security violation: {0}")]
    SecurityViolation(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Runtime error from wasmtime
    #[error("WASM runtime error: {0}")]
    Runtime(String),

    /// Trap occurred during execution
    #[error("WASM trap: {0}")]
    Trap(String),

    /// Skill execution error
    #[error("Skill execution error: {0}")]
    SkillExecution(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Unknown error
    #[error("Unknown error: {0}")]
    Unknown(String),
}

impl WasmError {
    /// Create a compilation error
    pub fn compilation(msg: impl Into<String>) -> Self {
        Self::Compilation(msg.into())
    }

    /// Create an instantiation error
    pub fn instantiation(msg: impl Into<String>) -> Self {
        Self::Instantiation(msg.into())
    }

    /// Create an execution error
    pub fn execution(msg: impl Into<String>) -> Self {
        Self::Execution(msg.into())
    }

    /// Create a WASI error
    pub fn wasi(msg: impl Into<String>) -> Self {
        Self::Wasi(msg.into())
    }

    /// Create an invalid module error
    pub fn invalid_module(msg: impl Into<String>) -> Self {
        Self::InvalidModule(msg.into())
    }

    /// Create a security violation error
    pub fn security(msg: impl Into<String>) -> Self {
        Self::SecurityViolation(msg.into())
    }

    /// Create a skill execution error
    pub fn skill_execution(msg: impl Into<String>) -> Self {
        Self::SkillExecution(msg.into())
    }

    /// Create a configuration error
    pub fn configuration(msg: impl Into<String>) -> Self {
        Self::Configuration(msg.into())
    }

    /// Check if this error is a resource limit error
    pub fn is_resource_limit(&self) -> bool {
        matches!(
            self,
            Self::ResourceLimitExceeded { .. }
                | Self::MemoryLimitExceeded { .. }
                | Self::TimeLimitExceeded { .. }
        )
    }

    /// Check if this error is a security error
    pub fn is_security(&self) -> bool {
        matches!(self, Self::SecurityViolation(_))
    }
}

/// Convert from wasmtime::Error
impl From<wasmtime::Error> for WasmError {
    fn from(err: wasmtime::Error) -> Self {
        // Check if it's a trap
        if let Some(trap) = err.downcast_ref::<wasmtime::Trap>() {
            return Self::Trap(trap.to_string());
        }
        Self::Runtime(err.to_string())
    }
}

/// Convert from anyhow::Error
impl From<anyhow::Error> for WasmError {
    fn from(err: anyhow::Error) -> Self {
        Self::Unknown(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = WasmError::compilation("test error");
        assert!(matches!(err, WasmError::Compilation(_)));
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_is_resource_limit() {
        let err = WasmError::ResourceLimitExceeded {
            limit: "memory".to_string(),
            current: 100,
            max: 50,
        };
        assert!(err.is_resource_limit());

        let err = WasmError::SecurityViolation("test".to_string());
        assert!(!err.is_resource_limit());
    }

    #[test]
    fn test_is_security() {
        let err = WasmError::SecurityViolation("test".to_string());
        assert!(err.is_security());

        let err = WasmError::Compilation("test".to_string());
        assert!(!err.is_security());
    }
}
