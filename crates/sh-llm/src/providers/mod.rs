//! LLM Provider implementations
//!
//! This module provides implementations for various LLM providers:
//! - Ollama: Local model hosting
//! - OpenAI: GPT-4, GPT-3.5, and other OpenAI models
//! - Anthropic: Claude models

use async_trait::async_trait;
use futures::Stream;

use crate::error::Result;
use crate::types::*;

pub mod anthropic;
pub mod ollama;
pub mod openai;

pub use anthropic::AnthropicProvider;
pub use ollama::OllamaProvider;
pub use openai::OpenAiProvider;

/// Trait for LLM providers
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Get the provider name
    fn name(&self) -> &str;

    /// Send a chat completion request
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse>;

    /// Send a streaming chat completion request
    async fn chat_stream(
        &self,
        request: ChatRequest,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamChunk>> + Send>>>;

    /// Get available models
    async fn list_models(&self) -> Result<Vec<ModelInfo>>;

    /// Check if a model is available
    async fn is_model_available(&self, model: &str) -> Result<bool>;

    /// Get model info
    async fn get_model_info(&self, model: &str) -> Result<ModelInfo>;

    /// Create embeddings
    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse>;

    /// Check if embeddings are supported
    fn supports_embeddings(&self) -> bool;
}

/// Provider configuration trait
pub trait ProviderConfig: Send + Sync {
    /// Get the base URL
    fn base_url(&self) -> &str;

    /// Get the default model
    fn default_model(&self) -> &str;

    /// Get the timeout in seconds
    fn timeout_secs(&self) -> u64;

    /// Get the API key (if required)
    fn api_key(&self) -> Option<&str>;
}

/// Retry configuration
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retries
    pub max_retries: u32,
    /// Initial retry delay in milliseconds
    pub initial_delay_ms: u64,
    /// Maximum retry delay in milliseconds
    pub max_delay_ms: u64,
    /// Backoff multiplier
    pub backoff_multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 60000,
            backoff_multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Calculate delay for a specific retry attempt
    pub fn delay_for_attempt(&self, attempt: u32) -> u64 {
        let delay = self.initial_delay_ms as f64 * self.backoff_multiplier.powi(attempt as i32);
        std::cmp::min(delay as u64, self.max_delay_ms)
    }
}

/// Helper function to handle HTTP errors
pub fn handle_http_error(status: reqwest::StatusCode, body: &str, provider: &str) -> crate::error::LlmError {
    use crate::error::LlmError;

    let message = if body.is_empty() {
        format!("HTTP {}", status)
    } else {
        // Try to extract error message from JSON
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(error) = json.get("error") {
                if let Some(msg) = error.get("message").and_then(|m| m.as_str()) {
                    msg.to_string()
                } else if let Some(msg) = error.as_str() {
                    msg.to_string()
                } else {
                    body.to_string()
                }
            } else {
                body.to_string()
            }
        } else {
            body.to_string()
        }
    };

    match status.as_u16() {
        401 => LlmError::ApiKeyMissing(provider.to_string()),
        429 => LlmError::RateLimitExceeded {
            provider: provider.to_string(),
            retry_after: None,
        },
        404 => LlmError::ModelNotFound(message),
        400 => LlmError::InvalidRequest(message),
        _ => LlmError::Http {
            status: status.as_u16(),
            message,
            provider: provider.to_string(),
        },
    }
}

/// Helper function to parse SSE (Server-Sent Events) stream
pub fn parse_sse_line(line: &str) -> Option<serde_json::Value> {
    if line.starts_with("data: ") {
        let data = &line[6..];
        if data == "[DONE]" {
            return None;
        }
        serde_json::from_str(data).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config() {
        let config = RetryConfig::default();
        assert_eq!(config.delay_for_attempt(0), 1000);
        assert_eq!(config.delay_for_attempt(1), 2000);
        assert_eq!(config.delay_for_attempt(2), 4000);
    }

    #[test]
    fn test_parse_sse_line() {
        let line = "data: {\"key\": \"value\"}";
        let result = parse_sse_line(line);
        assert!(result.is_some());
        assert_eq!(result.unwrap()["key"], "value");

        let line = "data: [DONE]";
        let result = parse_sse_line(line);
        assert!(result.is_none());

        let line = "event: message";
        let result = parse_sse_line(line);
        assert!(result.is_none());
    }
}
