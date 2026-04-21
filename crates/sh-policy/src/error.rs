//! Error types for policy enforcement

use thiserror::Error;

/// Policy engine errors
#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Policy not found: {0}")]
    PolicyNotFound(String),

    #[error("Invalid policy type: {0}")]
    InvalidPolicyType(String),

    #[error("Policy compilation failed: {0}")]
    CompilationFailed(String),

    #[error("Policy evaluation failed: {0}")]
    EvaluationFailed(String),

    #[error("WASM error: {0}")]
    WasmError(#[from] WasmError),

    #[error("Rego error: {0}")]
    RegoError(#[from] RegoError),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Policy store error: {0}")]
    StoreError(String),

    #[error("Timeout error: {0}")]
    TimeoutError(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// WASM-specific errors
#[derive(Error, Debug)]
pub enum WasmError {
    #[error("WASM module compilation failed: {0}")]
    CompilationFailed(String),

    #[error("WASM instantiation failed: {0}")]
    InstantiationFailed(String),

    #[error("WASM execution failed: {0}")]
    ExecutionFailed(String),

    #[error("WASM memory error: {0}")]
    MemoryError(String),

    #[error("WABI error: {0}")]
    AbiError(String),

    #[error("Invalid WASM module: {0}")]
    InvalidModule(String),
}

/// Rego/OPA-specific errors
#[derive(Error, Debug)]
pub enum RegoError {
    #[error("Rego compilation failed: {0}")]
    CompilationFailed(String),

    #[error("Rego query failed: {0}")]
    QueryFailed(String),

    #[error("Rego evaluation failed: {0}")]
    EvaluationFailed(String),

    #[error("Invalid Rego policy: {0}")]
    InvalidPolicy(String),

    #[error("OPA server error: {0}")]
    OpaServerError(String),

    #[error("Bundle error: {0}")]
    BundleError(String),
}

/// Result type alias
pub type Result<T> = std::result::Result<T, PolicyError>;
