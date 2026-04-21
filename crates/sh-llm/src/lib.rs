//! # sh-llm - Production-Ready LLM Integration
//!
//! This crate provides a unified interface for interacting with various LLM providers
//! including Ollama (local models), OpenAI (GPT-4, GPT-3.5), and Anthropic (Claude).
//!
//! ## Features
//!
//! - **Multiple Provider Support**: Ollama, OpenAI, Anthropic
//! - **Streaming Responses**: Real-time token streaming with proper backpressure
//! - **Model Routing**: Intelligent routing based on model capabilities and availability
//! - **Production-Ready**: Rate limiting, retries, timeouts, and comprehensive error handling
//! - **Type-Safe**: Strongly typed API with serde serialization
//!
//! ## Example Usage
//!
//! ```rust
//! use sh_llm::{LlmClient, LlmConfig, Message, Role};
//!
//! async fn example() -> Result<(), sh_llm::LlmError> {
//!     let config = LlmConfig::default()
//!         .with_provider("openai")
//!         .with_model("gpt-4");
//!
//!     let client = LlmClient::new(config)?;
//!
//!     let response = client
//!         .chat(vec![
//!             Message::system("You are a helpful assistant."),
//!             Message::user("Hello, world!"),
//!         ])
//!         .await?;
//!
//!     println!("Response: {}", response.content);
//!     Ok(())
//! }
//! ```

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, trace, warn};

pub mod error;
pub mod inference;
pub mod providers;
pub mod routing;
pub mod types;

pub use error::{LlmError, Result};
pub use inference::{InferenceEngine, InferenceOptions, InferenceResult};
pub use providers::{AnthropicProvider, LlmProvider, OllamaProvider, OpenAiProvider};
pub use routing::{ModelRouter, RoutingConfig, RoutingStrategy};
pub use types::*;

/// Re-export commonly used types
pub mod prelude {
    pub use super::error::{LlmError, Result};
    pub use super::inference::{InferenceEngine, InferenceOptions, InferenceResult};
    pub use super::providers::{LlmProvider, ProviderConfig};
    pub use super::routing::{ModelRouter, RoutingConfig, RoutingStrategy};
    pub use super::types::*;
    pub use super::{LlmClient, LlmConfig};
}

/// Configuration for the LLM client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// Default provider to use
    pub provider: String,
    /// Default model to use
    pub model: String,
    /// Provider-specific configurations
    pub providers: ProviderConfigs,
    /// Routing configuration
    pub routing: RoutingConfig,
    /// Request timeout in seconds
    pub timeout_secs: u64,
    /// Maximum retries for failed requests
    pub max_retries: u32,
    /// Enable request logging
    pub enable_logging: bool,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: "ollama".to_string(),
            model: "llama2".to_string(),
            providers: ProviderConfigs::default(),
            routing: RoutingConfig::default(),
            timeout_secs: 60,
            max_retries: 3,
            enable_logging: true,
        }
    }
}

impl LlmConfig {
    /// Create a new configuration with the specified provider
    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = provider.into();
        self
    }

    /// Create a new configuration with the specified model
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Set the request timeout
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Set the maximum retries
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Configure Ollama provider
    pub fn with_ollama_config(mut self, config: OllamaConfig) -> Self {
        self.providers.ollama = Some(config);
        self
    }

    /// Configure OpenAI provider
    pub fn with_openai_config(mut self, config: OpenAiConfig) -> Self {
        self.providers.openai = Some(config);
        self
    }

    /// Configure Anthropic provider
    pub fn with_anthropic_config(mut self, config: AnthropicConfig) -> Self {
        self.providers.anthropic = Some(config);
        self
    }
}

/// Provider-specific configurations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderConfigs {
    pub ollama: Option<OllamaConfig>,
    pub openai: Option<OpenAiConfig>,
    pub anthropic: Option<AnthropicConfig>,
}

/// Ollama provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaConfig {
    /// Base URL for Ollama API
    pub base_url: String,
    /// Default model
    pub default_model: String,
    /// Request timeout in seconds
    pub timeout_secs: u64,
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:11434".to_string(),
            default_model: "llama2".to_string(),
            timeout_secs: 120,
        }
    }
}

/// OpenAI provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiConfig {
    /// API key (loaded from environment if not specified)
    pub api_key: Option<String>,
    /// Base URL for OpenAI API
    pub base_url: String,
    /// Default model
    pub default_model: String,
    /// Organization ID (optional)
    pub organization: Option<String>,
    /// Request timeout in seconds
    pub timeout_secs: u64,
}

impl Default for OpenAiConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            base_url: "https://api.openai.com/v1".to_string(),
            default_model: "gpt-4".to_string(),
            organization: None,
            timeout_secs: 60,
        }
    }
}

/// Anthropic provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicConfig {
    /// API key (loaded from environment if not specified)
    pub api_key: Option<String>,
    /// Base URL for Anthropic API
    pub base_url: String,
    /// Default model
    pub default_model: String,
    /// API version
    pub api_version: String,
    /// Request timeout in seconds
    pub timeout_secs: u64,
}

impl Default for AnthropicConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            base_url: "https://api.anthropic.com".to_string(),
            default_model: "claude-3-opus-20240229".to_string(),
            api_version: "2023-06-01".to_string(),
            timeout_secs: 60,
        }
    }
}

/// Unified LLM client
pub struct LlmClient {
    /// Configuration
    config: LlmConfig,
    /// Provider instances
    providers: Providers,
    /// Model router
    router: ModelRouter,
    /// HTTP client
    http_client: reqwest::Client,
}

struct Providers {
    ollama: Option<OllamaProvider>,
    openai: Option<OpenAiProvider>,
    anthropic: Option<AnthropicProvider>,
}

impl LlmClient {
    /// Create a new LLM client with the given configuration
    pub fn new(config: LlmConfig) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| LlmError::Configuration(format!("Failed to build HTTP client: {}", e)))?;

        let mut providers = Providers {
            ollama: None,
            openai: None,
            anthropic: None,
        };

        // Initialize Ollama provider if configured
        if let Some(ollama_config) = &config.providers.ollama {
            providers.ollama = Some(OllamaProvider::new(ollama_config.clone(), http_client.clone())?);
        }

        // Initialize OpenAI provider if configured
        if let Some(openai_config) = &config.providers.openai {
            providers.openai = Some(OpenAiProvider::new(openai_config.clone(), http_client.clone())?);
        }

        // Initialize Anthropic provider if configured
        if let Some(anthropic_config) = &config.providers.anthropic {
            providers.anthropic = Some(AnthropicProvider::new(anthropic_config.clone(), http_client.clone())?);
        }

        let router = ModelRouter::new(&config.routing);

        if config.enable_logging {
            info!("LLM client initialized with provider: {}", config.provider);
        }

        Ok(Self {
            config,
            providers,
            router,
            http_client,
        })
    }

    /// Create a new client from environment variables
    pub fn from_env() -> Result<Self> {
        let mut config = LlmConfig::default();

        // Load provider from environment
        if let Ok(provider) = std::env::var("LLM_PROVIDER") {
            config.provider = provider;
        }

        // Load model from environment
        if let Ok(model) = std::env::var("LLM_MODEL") {
            config.model = model;
        }

        // Load OpenAI config from environment
        if std::env::var("OPENAI_API_KEY").is_ok() {
            let openai_config = OpenAiConfig {
                api_key: std::env::var("OPENAI_API_KEY").ok(),
                base_url: std::env::var("OPENAI_BASE_URL")
                    .unwrap_or_else(|_| "https://api.openai.com/v1".to_string()),
                default_model: std::env::var("OPENAI_MODEL")
                    .unwrap_or_else(|_| "gpt-4".to_string()),
                organization: std::env::var("OPENAI_ORG_ID").ok(),
                timeout_secs: std::env::var("OPENAI_TIMEOUT_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(60),
            };
            config.providers.openai = Some(openai_config);
        }

        // Load Anthropic config from environment
        if std::env::var("ANTHROPIC_API_KEY").is_ok() {
            let anthropic_config = AnthropicConfig {
                api_key: std::env::var("ANTHROPIC_API_KEY").ok(),
                base_url: std::env::var("ANTHROPIC_BASE_URL")
                    .unwrap_or_else(|_| "https://api.anthropic.com".to_string()),
                default_model: std::env::var("ANTHROPIC_MODEL")
                    .unwrap_or_else(|_| "claude-3-opus-20240229".to_string()),
                api_version: std::env::var("ANTHROPIC_API_VERSION")
                    .unwrap_or_else(|_| "2023-06-01".to_string()),
                timeout_secs: std::env::var("ANTHROPIC_TIMEOUT_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(60),
            };
            config.providers.anthropic = Some(anthropic_config);
        }

        // Load Ollama config from environment
        let ollama_config = OllamaConfig {
            base_url: std::env::var("OLLAMA_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:11434".to_string()),
            default_model: std::env::var("OLLAMA_MODEL")
                .unwrap_or_else(|_| "llama2".to_string()),
            timeout_secs: std::env::var("OLLAMA_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(120),
        };
        config.providers.ollama = Some(ollama_config);

        Self::new(config)
    }

    /// Get the current configuration
    pub fn config(&self) -> &LlmConfig {
        &self.config
    }

    /// Send a chat completion request
    pub async fn chat(&self, messages: Vec<Message>) -> Result<ChatResponse> {
        let request = ChatRequest::new(messages).with_model(&self.config.model);
        self.chat_with_request(request).await
    }

    /// Send a chat completion request with custom options
    pub async fn chat_with_request(&self, request: ChatRequest) -> Result<ChatResponse> {
        let provider = self.get_provider(&request.model)?;
        
        if self.config.enable_logging {
            debug!("Sending chat request to {} with model {}", self.config.provider, request.model);
        }

        let response = provider.chat(request).await?;
        
        if self.config.enable_logging {
            info!("Received chat response with {} tokens", response.usage.total_tokens);
        }

        Ok(response)
    }

    /// Send a streaming chat completion request
    pub async fn chat_stream(&self, messages: Vec<Message>) -> Result<ChatStream> {
        let request = ChatRequest::new(messages)
            .with_model(&self.config.model)
            .with_stream(true);
        self.chat_stream_with_request(request).await
    }

    /// Send a streaming chat completion request with custom options
    pub async fn chat_stream_with_request(&self, request: ChatRequest) -> Result<ChatStream> {
        let provider = self.get_provider(&request.model)?;
        
        if self.config.enable_logging {
            debug!("Sending streaming chat request to {} with model {}", self.config.provider, request.model);
        }

        provider.chat_stream(request).await
    }

    /// Get available models from all configured providers
    pub async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        let mut models = Vec::new();

        if let Some(ref provider) = self.providers.ollama {
            match provider.list_models().await {
                Ok(ms) => models.extend(ms),
                Err(e) => warn!("Failed to list Ollama models: {}", e),
            }
        }

        if let Some(ref provider) = self.providers.openai {
            match provider.list_models().await {
                Ok(ms) => models.extend(ms),
                Err(e) => warn!("Failed to list OpenAI models: {}", e),
            }
        }

        if let Some(ref provider) = self.providers.anthropic {
            match provider.list_models().await {
                Ok(ms) => models.extend(ms),
                Err(e) => warn!("Failed to list Anthropic models: {}", e),
            }
        }

        Ok(models)
    }

    /// Get a provider by name
    fn get_provider(&self, model: &str) -> Result<&dyn LlmProvider> {
        // Use router to determine provider
        let provider_name = self.router.route(model)?;

        match provider_name.as_str() {
            "ollama" => self.providers.ollama.as_ref()
                .map(|p| p as &dyn LlmProvider)
                .ok_or_else(|| LlmError::ProviderNotAvailable("ollama".to_string())),
            "openai" => self.providers.openai.as_ref()
                .map(|p| p as &dyn LlmProvider)
                .ok_or_else(|| LlmError::ProviderNotAvailable("openai".to_string())),
            "anthropic" => self.providers.anthropic.as_ref()
                .map(|p| p as &dyn LlmProvider)
                .ok_or_else(|| LlmError::ProviderNotAvailable("anthropic".to_string())),
            _ => Err(LlmError::ProviderNotFound(provider_name)),
        }
    }

    /// Create an inference engine for advanced use cases
    pub fn inference_engine(&self) -> InferenceEngine {
        InferenceEngine::new(self)
    }
}

/// Streaming response wrapper
#[pin_project]
pub struct ChatStream {
    #[pin]
    inner: Pin<Box<dyn Stream<Item = Result<StreamChunk>> + Send>>,
}

impl ChatStream {
    pub fn new<S>(stream: S) -> Self
    where
        S: Stream<Item = Result<StreamChunk>> + Send + 'static,
    {
        Self {
            inner: Box::pin(stream),
        }
    }
}

impl Stream for ChatStream {
    type Item = Result<StreamChunk>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().inner.poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_llm_config_default() {
        let config = LlmConfig::default();
        assert_eq!(config.provider, "ollama");
        assert_eq!(config.model, "llama2");
        assert_eq!(config.timeout_secs, 60);
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_llm_config_builder() {
        let config = LlmConfig::default()
            .with_provider("openai")
            .with_model("gpt-4")
            .with_timeout(120)
            .with_max_retries(5);

        assert_eq!(config.provider, "openai");
        assert_eq!(config.model, "gpt-4");
        assert_eq!(config.timeout_secs, 120);
        assert_eq!(config.max_retries, 5);
    }

    #[test]
    fn test_message_creation() {
        let system_msg = Message::system("You are a helpful assistant.");
        assert_eq!(system_msg.role, Role::System);
        assert_eq!(system_msg.content, "You are a helpful assistant.");

        let user_msg = Message::user("Hello!");
        assert_eq!(user_msg.role, Role::User);
        assert_eq!(user_msg.content, "Hello!");

        let assistant_msg = Message::assistant("Hi there!");
        assert_eq!(assistant_msg.role, Role::Assistant);
        assert_eq!(assistant_msg.content, "Hi there!");
    }

    #[test]
    fn test_chat_request_builder() {
        let request = ChatRequest::new(vec![Message::user("Hello")])
            .with_model("gpt-4")
            .with_temperature(0.7)
            .with_max_tokens(100)
            .with_stream(true);

        assert_eq!(request.model, "gpt-4");
        assert_eq!(request.temperature, Some(0.7));
        assert_eq!(request.max_tokens, Some(100));
        assert_eq!(request.stream, Some(true));
    }
}
