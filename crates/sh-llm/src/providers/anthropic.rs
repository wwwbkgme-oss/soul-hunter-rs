//! Anthropic provider implementation
//!
//! This provider supports:
//! - Claude 3 models (Opus, Sonnet, Haiku)
//! - Claude 2.1, Claude 2, Claude Instant
//! - Chat completions
//! - Streaming responses
//! - Vision capabilities (for Claude 3)

use std::pin::Pin;

use async_trait::async_trait;
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, trace, warn};

use crate::error::{LlmError, Result};
use crate::providers::{handle_http_error, parse_sse_line, LlmProvider, ProviderConfig};
use crate::types::*;

/// Anthropic provider
pub struct AnthropicProvider {
    /// Configuration
    config: crate::AnthropicConfig,
    /// HTTP client
    client: reqwest::Client,
    /// Provider name
    name: String,
    /// API key
    api_key: String,
}

impl AnthropicProvider {
    /// Create a new Anthropic provider
    pub fn new(config: crate::AnthropicConfig, client: reqwest::Client) -> Result<Self> {
        let api_key = config
            .api_key
            .clone()
            .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
            .ok_or_else(|| LlmError::ApiKeyMissing("anthropic".to_string()))?;

        info!(
            "Initializing Anthropic provider with base URL: {}",
            config.base_url
        );

        Ok(Self {
            config,
            client,
            name: "anthropic".to_string(),
            api_key,
        })
    }

    /// Get the API URL for a specific endpoint
    fn api_url(&self, endpoint: &str) -> String {
        format!("{}/v1/{}", self.config.base_url, endpoint)
    }

    /// Build request headers
    fn build_headers(&self) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-api-key",
            self.api_key
                .parse()
                .expect("Invalid API key format"),
        );
        headers.insert(
            "anthropic-version",
            self.config
                .api_version
                .parse()
                .expect("Invalid API version"),
        );
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        headers
    }

    /// Convert messages to Anthropic format
    fn convert_messages(&self, messages: &[Message]) -> (Option<String>, Vec<AnthropicMessage>) {
        let mut system_prompt: Option<String> = None;
        let mut anthropic_messages: Vec<AnthropicMessage> = Vec::new();

        for msg in messages {
            match msg.role {
                Role::System => {
                    // Anthropic uses a separate system parameter
                    system_prompt = Some(msg.content.clone());
                }
                Role::User => {
                    anthropic_messages.push(AnthropicMessage {
                        role: "user".to_string(),
                        content: msg.content.clone(),
                    });
                }
                Role::Assistant => {
                    anthropic_messages.push(AnthropicMessage {
                        role: "assistant".to_string(),
                        content: msg.content.clone(),
                    });
                }
                Role::Tool => {
                    // Anthropic doesn't have a separate tool role in the same way
                    // Tool results are typically included as user messages
                    anthropic_messages.push(AnthropicMessage {
                        role: "user".to_string(),
                        content: format!("Tool result: {}", msg.content),
                    });
                }
            }
        }

        (system_prompt, anthropic_messages)
    }

    /// Convert Anthropic response to standard format
    fn convert_response(&self, response: AnthropicResponse, model: &str) -> ChatResponse {
        ChatResponse {
            id: response.id,
            object: "chat.completion".to_string(),
            created: chrono::Utc::now().timestamp() as u64,
            model: model.to_string(),
            choices: vec![Choice {
                index: 0,
                message: Message::assistant(response.content[0].text.clone()),
                finish_reason: response.stop_reason.map(|r| match r.as_str() {
                    "end_turn" => "stop".to_string(),
                    "max_tokens" => "length".to_string(),
                    "stop_sequence" => "stop".to_string(),
                    _ => r,
                }),
            }],
            usage: Usage {
                prompt_tokens: response.usage.input_tokens,
                completion_tokens: response.usage.output_tokens,
                total_tokens: response.usage.input_tokens + response.usage.output_tokens,
            },
        }
    }

    /// Convert streaming chunk to standard format
    fn convert_stream_chunk(&self, chunk: AnthropicStreamEvent, model: &str) -> Option<StreamChunk> {
        match chunk {
            AnthropicStreamEvent::MessageStart { message } => {
                // Initial message event, create empty chunk
                Some(StreamChunk {
                    id: message.id,
                    object: "chat.completion.chunk".to_string(),
                    created: chrono::Utc::now().timestamp() as u64,
                    model: model.to_string(),
                    choices: vec![StreamChoice {
                        index: 0,
                        delta: DeltaMessage {
                            role: Some(Role::Assistant),
                            content: None,
                            tool_calls: None,
                        },
                        finish_reason: None,
                    }],
                })
            }
            AnthropicStreamEvent::ContentBlockStart { index, content_block } => {
                // Content block start
                Some(StreamChunk {
                    id: format!("block_{}", index),
                    object: "chat.completion.chunk".to_string(),
                    created: chrono::Utc::now().timestamp() as u64,
                    model: model.to_string(),
                    choices: vec![StreamChoice {
                        index: 0,
                        delta: DeltaMessage {
                            role: None,
                            content: Some(content_block.text),
                            tool_calls: None,
                        },
                        finish_reason: None,
                    }],
                })
            }
            AnthropicStreamEvent::ContentBlockDelta { index, delta } => {
                // Content delta
                Some(StreamChunk {
                    id: format!("block_{}", index),
                    object: "chat.completion.chunk".to_string(),
                    created: chrono::Utc::now().timestamp() as u64,
                    model: model.to_string(),
                    choices: vec![StreamChoice {
                        index: 0,
                        delta: DeltaMessage {
                            role: None,
                            content: Some(delta.text),
                            tool_calls: None,
                        },
                        finish_reason: None,
                    }],
                })
            }
            AnthropicStreamEvent::ContentBlockStop { .. } => {
                // Content block end, no content
                None
            }
            AnthropicStreamEvent::MessageDelta { delta, .. } => {
                // Message delta (stop reason)
                Some(StreamChunk {
                    id: "message_delta".to_string(),
                    object: "chat.completion.chunk".to_string(),
                    created: chrono::Utc::now().timestamp() as u64,
                    model: model.to_string(),
                    choices: vec![StreamChoice {
                        index: 0,
                        delta: DeltaMessage::default(),
                        finish_reason: delta.stop_reason.map(|r| match r.as_str() {
                            "end_turn" => "stop".to_string(),
                            "max_tokens" => "length".to_string(),
                            "stop_sequence" => "stop".to_string(),
                            _ => r,
                        }),
                    }],
                })
            }
            AnthropicStreamEvent::MessageStop => {
                // Final message stop
                None
            }
            AnthropicStreamEvent::Ping => {
                // Keep-alive ping, ignore
                None
            }
            AnthropicStreamEvent::Error { error } => {
                error!("Anthropic stream error: {}", error.message);
                None
            }
        }
    }

    /// Check if a model supports vision
    fn supports_vision(&self, model: &str) -> bool {
        model.contains("claude-3")
    }

    /// Get context window size for a model
    fn get_context_window(&self, model: &str) -> u32 {
        if model.contains("claude-3-opus") {
            200000
        } else if model.contains("claude-3-sonnet") {
            200000
        } else if model.contains("claude-3-haiku") {
            200000
        } else if model.contains("claude-2.1") {
            200000
        } else if model.contains("claude-2") {
            100000
        } else if model.contains("claude-instant") {
            100000
        } else {
            100000 // Default
        }
    }

    /// Get max output tokens for a model
    fn get_max_tokens(&self, model: &str) -> u32 {
        if model.contains("claude-3-opus") {
            4096
        } else if model.contains("claude-3-sonnet") {
            4096
        } else if model.contains("claude-3-haiku") {
            4096
        } else {
            4096 // Default for most models
        }
    }
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse> {
        let model = if request.model == "default" {
            &self.config.default_model
        } else {
            &request.model
        };

        let (system, messages) = self.convert_messages(&request.messages);

        let anthropic_request = AnthropicChatRequest {
            model: model.to_string(),
            messages,
            system,
            max_tokens: request.max_tokens.unwrap_or_else(|| self.get_max_tokens(model)),
            temperature: request.temperature,
            top_p: request.top_p,
            stop_sequences: request.stop,
            stream: false,
        };

        trace!("Sending Anthropic chat request: {:?}", anthropic_request);

        let response = self
            .client
            .post(&self.api_url("messages"))
            .headers(self.build_headers())
            .json(&anthropic_request)
            .send()
            .await
            .map_err(|e| {
                error!("Anthropic request failed: {}", e);
                LlmError::Network(format!("Anthropic request failed: {}", e))
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(handle_http_error(status, &body, self.name()));
        }

        let anthropic_response: AnthropicResponse = response.json().await.map_err(|e| {
            error!("Failed to parse Anthropic response: {}", e);
            LlmError::Deserialization(format!("Failed to parse Anthropic response: {}", e))
        })?;

        debug!(
            "Anthropic response received: {} tokens",
            anthropic_response.usage.input_tokens + anthropic_response.usage.output_tokens
        );

        Ok(self.convert_response(anthropic_response, model))
    }

    async fn chat_stream(
        &self,
        request: ChatRequest,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamChunk>> + Send>>> {
        let model = if request.model == "default" {
            self.config.default_model.clone()
        } else {
            request.model.clone()
        };

        let (system, messages) = self.convert_messages(&request.messages);

        let anthropic_request = AnthropicChatRequest {
            model: model.clone(),
            messages,
            system,
            max_tokens: request.max_tokens.unwrap_or_else(|| self.get_max_tokens(&model)),
            temperature: request.temperature,
            top_p: request.top_p,
            stop_sequences: request.stop,
            stream: true,
        };

        trace!("Sending Anthropic streaming request");

        let response = self
            .client
            .post(&self.api_url("messages"))
            .headers(self.build_headers())
            .json(&anthropic_request)
            .send()
            .await
            .map_err(|e| {
                error!("Anthropic streaming request failed: {}", e);
                LlmError::Network(format!("Anthropic streaming request failed: {}", e))
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(handle_http_error(status, &body, self.name()));
        }

        let stream = response.bytes_stream().flat_map(move |result| {
            match result {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    let lines: Vec<_> = text.lines().collect();
                    
                    futures::stream::iter(lines.into_iter().filter_map(|line| {
                        if line.is_empty() {
                            return None;
                        }
                        
                        trace!("Anthropic SSE line: {}", line);
                        
                        if let Some(json) = parse_sse_line(line) {
                            match serde_json::from_value::<AnthropicStreamEvent>(json) {
                                Ok(event) => {
                                    self.convert_stream_chunk(event, &model).map(Ok)
                                }
                                Err(e) => {
                                    error!("Failed to parse Anthropic stream event: {}", e);
                                    Some(Err(LlmError::Deserialization(format!(
                                        "Failed to parse stream event: {}",
                                        e
                                    ))))
                                }
                            }
                        } else {
                            None
                        }
                    }))
                    .boxed()
                }
                Err(e) => {
                    error!("Anthropic stream error: {}", e);
                    futures::stream::iter(vec![Err(LlmError::Streaming(format!(
                        "Stream error: {}",
                        e
                    )))
                    .boxed()
                }
            }
        });

        Ok(Box::pin(stream))
    }

    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        // Anthropic doesn't have a models endpoint, so we return known models
        let models = vec![
            ModelInfo::new("claude-3-opus-20240229", "anthropic")
                .with_context_window(200000)
                .with_max_tokens(4096)
                .with_streaming(true)
                .with_functions(false)
                .with_vision(true),
            ModelInfo::new("claude-3-sonnet-20240229", "anthropic")
                .with_context_window(200000)
                .with_max_tokens(4096)
                .with_streaming(true)
                .with_functions(false)
                .with_vision(true),
            ModelInfo::new("claude-3-haiku-20240307", "anthropic")
                .with_context_window(200000)
                .with_max_tokens(4096)
                .with_streaming(true)
                .with_functions(false)
                .with_vision(true),
            ModelInfo::new("claude-2.1", "anthropic")
                .with_context_window(200000)
                .with_max_tokens(4096)
                .with_streaming(true)
                .with_functions(false)
                .with_vision(false),
            ModelInfo::new("claude-2.0", "anthropic")
                .with_context_window(100000)
                .with_max_tokens(4096)
                .with_streaming(true)
                .with_functions(false)
                .with_vision(false),
            ModelInfo::new("claude-instant-1.2", "anthropic")
                .with_context_window(100000)
                .with_max_tokens(4096)
                .with_streaming(true)
                .with_functions(false)
                .with_vision(false),
        ];

        info!("Returning {} known Anthropic models", models.len());
        Ok(models)
    }

    async fn is_model_available(&self, model: &str) -> Result<bool> {
        let models = self.list_models().await?;
        Ok(models.iter().any(|m| m.id == model))
    }

    async fn get_model_info(&self, model: &str) -> Result<ModelInfo> {
        let models = self.list_models().await?;
        models
            .into_iter()
            .find(|m| m.id == model)
            .ok_or_else(|| LlmError::ModelNotFound(model.to_string()))
    }

    async fn embed(&self, _request: EmbeddingRequest) -> Result<EmbeddingResponse> {
        // Anthropic doesn't currently support embeddings
        Err(LlmError::NotImplemented(
            "Anthropic does not support embeddings".to_string(),
        ))
    }

    fn supports_embeddings(&self) -> bool {
        false
    }
}

// Anthropic-specific types

#[derive(Debug, Clone, Serialize)]
struct AnthropicChatRequest {
    model: String,
    messages: Vec<AnthropicMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_sequences: Option<Vec<String>>,
    stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AnthropicResponse {
    id: String,
    #[serde(rename = "type")]
    response_type: String,
    role: String,
    content: Vec<AnthropicContent>,
    model: String,
    stop_reason: Option<String>,
    stop_sequence: Option<String>,
    usage: AnthropicUsage,
}

#[derive(Debug, Clone, Deserialize)]
struct AnthropicContent {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AnthropicUsage {
    input_tokens: u32,
    output_tokens: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
enum AnthropicStreamEvent {
    #[serde(rename = "message_start")]
    MessageStart { message: AnthropicMessageStart },
    #[serde(rename = "content_block_start")]
    ContentBlockStart {
        index: u32,
        content_block: AnthropicContentBlock,
    },
    #[serde(rename = "content_block_delta")]
    ContentBlockDelta { index: u32, delta: AnthropicDelta },
    #[serde(rename = "content_block_stop")]
    ContentBlockStop { index: u32 },
    #[serde(rename = "message_delta")]
    MessageDelta { delta: AnthropicMessageDelta, usage: AnthropicUsage },
    #[serde(rename = "message_stop")]
    MessageStop,
    #[serde(rename = "ping")]
    Ping,
    #[serde(rename = "error")]
    Error { error: AnthropicError },
}

#[derive(Debug, Clone, Deserialize)]
struct AnthropicMessageStart {
    id: String,
    #[serde(rename = "type")]
    message_type: String,
    role: String,
    content: Vec<serde_json::Value>,
    model: String,
    stop_reason: Option<String>,
    stop_sequence: Option<String>,
    usage: AnthropicUsage,
}

#[derive(Debug, Clone, Deserialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AnthropicDelta {
    #[serde(rename = "type")]
    delta_type: String,
    text: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AnthropicMessageDelta {
    stop_reason: Option<String>,
    stop_sequence: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AnthropicError {
    #[serde(rename = "type")]
    error_type: String,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_messages() {
        let config = crate::AnthropicConfig::default();
        let provider = AnthropicProvider {
            config,
            client: reqwest::Client::new(),
            name: "anthropic".to_string(),
            api_key: "test-key".to_string(),
        };

        let messages = vec![
            Message::system("You are a helpful assistant."),
            Message::user("Hello!"),
            Message::assistant("Hi there!"),
        ];

        let (system, anthropic_messages) = provider.convert_messages(&messages);
        assert_eq!(system, Some("You are a helpful assistant.".to_string()));
        assert_eq!(anthropic_messages.len(), 2);
        assert_eq!(anthropic_messages[0].role, "user");
        assert_eq!(anthropic_messages[1].role, "assistant");
    }

    #[test]
    fn test_get_context_window() {
        let config = crate::AnthropicConfig::default();
        let provider = AnthropicProvider {
            config,
            client: reqwest::Client::new(),
            name: "anthropic".to_string(),
            api_key: "test-key".to_string(),
        };

        assert_eq!(provider.get_context_window("claude-3-opus"), 200000);
        assert_eq!(provider.get_context_window("claude-3-sonnet"), 200000);
        assert_eq!(provider.get_context_window("claude-2.1"), 200000);
        assert_eq!(provider.get_context_window("claude-2"), 100000);
    }

    #[test]
    fn test_supports_vision() {
        let config = crate::AnthropicConfig::default();
        let provider = AnthropicProvider {
            config,
            client: reqwest::Client::new(),
            name: "anthropic".to_string(),
            api_key: "test-key".to_string(),
        };

        assert!(provider.supports_vision("claude-3-opus"));
        assert!(provider.supports_vision("claude-3-sonnet"));
        assert!(!provider.supports_vision("claude-2.1"));
        assert!(!provider.supports_vision("claude-2"));
    }
}
