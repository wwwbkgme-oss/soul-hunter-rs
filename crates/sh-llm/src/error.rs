//! Error types for the LLM integration

use std::fmt;

/// Result type alias for LLM operations
pub type Result<T> = std::result::Result<T, LlmError>;

/// Error types for LLM operations
#[derive(Debug, Clone)]
pub enum LlmError {
    /// Configuration error
    Configuration(String),
    
    /// Provider not found
    ProviderNotFound(String),
    
    /// Provider not available
    ProviderNotAvailable(String),
    
    /// Model not found
    ModelNotFound(String),
    
    /// Model not available
    ModelNotAvailable(String),
    
    /// API key missing
    ApiKeyMissing(String),
    
    /// Invalid request
    InvalidRequest(String),
    
    /// Rate limit exceeded
    RateLimitExceeded {
        provider: String,
        retry_after: Option<u64>,
    },
    
    /// Request timeout
    Timeout {
        provider: String,
        duration_secs: u64,
    },
    
    /// Network error
    Network(String),
    
    /// HTTP error with status code
    Http {
        status: u16,
        message: String,
        provider: String,
    },
    
    /// Serialization error
    Serialization(String),
    
    /// Deserialization error
    Deserialization(String),
    
    /// Streaming error
    Streaming(String),
    
    /// Provider-specific error
    Provider {
        provider: String,
        code: String,
        message: String,
    },
    
    /// Context length exceeded
    ContextLengthExceeded {
        model: String,
        max_tokens: u32,
        requested_tokens: u32,
    },
    
    /// Content filtered
    ContentFiltered {
        reason: String,
        provider: String,
    },
    
    /// Unknown error
    Unknown(String),
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LlmError::Configuration(msg) => {
                write!(f, "Configuration error: {}", msg)
            }
            LlmError::ProviderNotFound(provider) => {
                write!(f, "Provider not found: {}", provider)
            }
            LlmError::ProviderNotAvailable(provider) => {
                write!(f, "Provider not available: {}", provider)
            }
            LlmError::ModelNotFound(model) => {
                write!(f, "Model not found: {}", model)
            }
            LlmError::ModelNotAvailable(model) => {
                write!(f, "Model not available: {}", model)
            }
            LlmError::ApiKeyMissing(provider) => {
                write!(f, "API key missing for provider: {}", provider)
            }
            LlmError::InvalidRequest(msg) => {
                write!(f, "Invalid request: {}", msg)
            }
            LlmError::RateLimitExceeded { provider, retry_after } => {
                if let Some(retry) = retry_after {
                    write!(f, "Rate limit exceeded for {}. Retry after {} seconds", provider, retry)
                } else {
                    write!(f, "Rate limit exceeded for {}", provider)
                }
            }
            LlmError::Timeout { provider, duration_secs } => {
                write!(f, "Request to {} timed out after {} seconds", provider, duration_secs)
            }
            LlmError::Network(msg) => {
                write!(f, "Network error: {}", msg)
            }
            LlmError::Http { status, message, provider } => {
                write!(f, "HTTP error from {}: {} - {}", provider, status, message)
            }
            LlmError::Serialization(msg) => {
                write!(f, "Serialization error: {}", msg)
            }
            LlmError::Deserialization(msg) => {
                write!(f, "Deserialization error: {}", msg)
            }
            LlmError::Streaming(msg) => {
                write!(f, "Streaming error: {}", msg)
            }
            LlmError::Provider { provider, code, message } => {
                write!(f, "Provider error from {} ({}): {}", provider, code, message)
            }
            LlmError::ContextLengthExceeded { model, max_tokens, requested_tokens } => {
                write!(f, "Context length exceeded for {}. Max: {}, Requested: {}", 
                    model, max_tokens, requested_tokens)
            }
            LlmError::ContentFiltered { reason, provider } => {
                write!(f, "Content filtered by {}: {}", provider, reason)
            }
            LlmError::Unknown(msg) => {
                write!(f, "Unknown error: {}", msg)
            }
        }
    }
}

impl std::error::Error for LlmError {}

impl From<reqwest::Error> for LlmError {
    fn from(error: reqwest::Error) -> Self {
        if error.is_timeout() {
            LlmError::Timeout {
                provider: "unknown".to_string(),
                duration_secs: 60,
            }
        } else if error.is_connect() {
            LlmError::Network(format!("Connection failed: {}", error))
        } else if error.is_request() {
            LlmError::InvalidRequest(format!("Request error: {}", error))
        } else if error.is_body() {
            LlmError::Streaming(format!("Body error: {}", error))
        } else {
            LlmError::Network(error.to_string())
        }
    }
}

impl From<serde_json::Error> for LlmError {
    fn from(error: serde_json::Error) -> Self {
        if error.is_syntax() {
            LlmError::Deserialization(format!("JSON syntax error: {}", error))
        } else if error.is_eof() {
            LlmError::Deserialization(format!("Unexpected end of JSON: {}", error))
        } else {
            LlmError::Serialization(format!("JSON error: {}", error))
        }
    }
}

impl From<std::io::Error> for LlmError {
    fn from(error: std::io::Error) -> Self {
        LlmError::Network(format!("IO error: {}", error))
    }
}

impl From<anyhow::Error> for LlmError {
    fn from(error: anyhow::Error) -> Self {
        LlmError::Unknown(error.to_string())
    }
}

impl LlmError {
    /// Check if the error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(self,
            LlmError::Timeout { .. }
            | LlmError::Network(_)
            | LlmError::RateLimitExceeded { .. }
            | LlmError::Http { status, .. } if matches!(status, 429 | 500 | 502 | 503 | 504)
        )
    }

    /// Get the retry delay in seconds
    pub fn retry_delay_secs(&self) -> u64 {
        match self {
            LlmError::RateLimitExceeded { retry_after: Some(delay), .. } => *delay,
            LlmError::RateLimitExceeded { .. } => 60,
            LlmError::Timeout { .. } => 5,
            LlmError::Network(_) => 2,
            LlmError::Http { status, .. } => {
                match status {
                    429 => 60,      // Rate limited
                    500 => 5,       // Internal server error
                    502 => 5,       // Bad gateway
                    503 => 10,      // Service unavailable
                    504 => 5,       // Gateway timeout
                    _ => 1,
                }
            }
            _ => 0,
        }
    }

    /// Get the provider name if available
    pub fn provider(&self) -> Option<&str> {
        match self {
            LlmError::ProviderNotFound(p) => Some(p),
            LlmError::ProviderNotAvailable(p) => Some(p),
            LlmError::ApiKeyMissing(p) => Some(p),
            LlmError::RateLimitExceeded { provider, .. } => Some(provider),
            LlmError::Timeout { provider, .. } => Some(provider),
            LlmError::Http { provider, .. } => Some(provider),
            LlmError::Provider { provider, .. } => Some(provider),
            LlmError::ContentFiltered { provider, .. } => Some(provider),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = LlmError::Configuration("test error".to_string());
        assert_eq!(err.to_string(), "Configuration error: test error");

        let err = LlmError::ProviderNotFound("openai".to_string());
        assert_eq!(err.to_string(), "Provider not found: openai");
    }

    #[test]
    fn test_is_retryable() {
        assert!(LlmError::Timeout { provider: "test".to_string(), duration_secs: 60 }.is_retryable());
        assert!(LlmError::Network("test".to_string()).is_retryable());
        assert!(LlmError::RateLimitExceeded { provider: "test".to_string(), retry_after: None }.is_retryable());
        assert!(LlmError::Http { status: 429, message: "test".to_string(), provider: "test".to_string() }.is_retryable());
        
        assert!(!LlmError::Configuration("test".to_string()).is_retryable());
        assert!(!LlmError::InvalidRequest("test".to_string()).is_retryable());
    }

    #[test]
    fn test_retry_delay() {
        let err = LlmError::RateLimitExceeded { provider: "test".to_string(), retry_after: Some(30) };
        assert_eq!(err.retry_delay_secs(), 30);

        let err = LlmError::RateLimitExceeded { provider: "test".to_string(), retry_after: None };
        assert_eq!(err.retry_delay_secs(), 60);

        let err = LlmError::Http { status: 429, message: "test".to_string(), provider: "test".to_string() };
        assert_eq!(err.retry_delay_secs(), 60);

        let err = LlmError::Http { status: 500, message: "test".to_string(), provider: "test".to_string() };
        assert_eq!(err.retry_delay_secs(), 5);
    }

    #[test]
    fn test_provider_extraction() {
        let err = LlmError::ProviderNotFound("openai".to_string());
        assert_eq!(err.provider(), Some("openai"));

        let err = LlmError::Configuration("test".to_string());
        assert_eq!(err.provider(), None);
    }
}
