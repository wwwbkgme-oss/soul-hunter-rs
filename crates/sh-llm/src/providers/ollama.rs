//! Ollama provider implementation
//!
//! Ollama allows running LLMs locally. This provider supports:
//! - Chat completions
//! - Streaming responses
//! - Model listing
//! - Embeddings (if the model supports it)

use std::pin::Pin;

use async_trait::async_trait;
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, trace, warn};

use crate::error::{LlmError, Result};
use crate::providers::{handle_http_error, LlmProvider, ProviderConfig};
use crate::types::*;

/// Ollama provider
pub struct OllamaProvider {
    /// Configuration
    config: crate::OllamaConfig,
    /// HTTP client
    client: reqwest::Client,
    /// Provider name
    name: String,
}

impl OllamaProvider {
    /// Create a new Ollama provider
    pub fn new(config: crate::OllamaConfig, client: reqwest::Client) -> Result<Self> {
        info!("Initializing Ollama provider with base URL: {}", config.base_url);
        
        Ok(Self {
            config,
            client,
            name: "ollama".to_string(),
        })
    }

    /// Get the API URL for a specific endpoint
    fn api_url(&self, endpoint: &str) -> String {
        format!("{}/api/{}", self.config.base_url, endpoint)
    }

    /// Convert messages to Ollama format
    fn convert_messages(&self, messages: &[Message]) -> Vec<OllamaMessage> {
        messages
            .iter()
            .map(|msg| OllamaMessage {
                role: match msg.role {
                    Role::System => "system".to_string(),
                    Role::User => "user".to_string(),
                    Role::Assistant => "assistant".to_string(),
                    Role::Tool => "tool".to_string(),
                },
                content: msg.content.clone(),
                images: None,
            })
            .collect()
    }

    /// Convert Ollama response to standard format
    fn convert_response(&self, response: OllamaResponse, model: &str) -> ChatResponse {
        ChatResponse {
            id: response.created_at.clone(),
            object: "chat.completion".to_string(),
            created: chrono::Utc::now().timestamp() as u64,
            model: model.to_string(),
            choices: vec![Choice {
                index: 0,
                message: Message::assistant(response.message.content),
                finish_reason: response.done_reason.clone(),
            }],
            usage: Usage {
                prompt_tokens: response.prompt_eval_count.unwrap_or(0) as u32,
                completion_tokens: response.eval_count.unwrap_or(0) as u32,
                total_tokens: (response.prompt_eval_count.unwrap_or(0) + response.eval_count.unwrap_or(0)) as u32,
            },
        }
    }

    /// Convert streaming chunk to standard format
    fn convert_stream_chunk(&self, chunk: OllamaStreamChunk, model: &str) -> StreamChunk {
        StreamChunk {
            id: chunk.created_at.clone(),
            object: "chat.completion.chunk".to_string(),
            created: chrono::Utc::now().timestamp() as u64,
            model: model.to_string(),
            choices: vec![StreamChoice {
                index: 0,
                delta: DeltaMessage {
                    role: if chunk.message.role == "assistant" {
                        Some(Role::Assistant)
                    } else {
                        None
                    },
                    content: Some(chunk.message.content),
                    tool_calls: None,
                },
                finish_reason: if chunk.done {
                    Some("stop".to_string())
                } else {
                    None
                },
            }],
        }
    }
}

#[async_trait]
impl LlmProvider for OllamaProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse> {
        let model = if request.model == "default" {
            &self.config.default_model
        } else {
            &request.model
        };

        let ollama_request = OllamaChatRequest {
            model: model.to_string(),
            messages: self.convert_messages(&request.messages),
            stream: false,
            options: OllamaOptions {
                temperature: request.temperature,
                top_p: request.top_p,
                num_predict: request.max_tokens.map(|t| t as i32),
                stop: request.stop,
                seed: request.seed.map(|s| s as i32),
            },
        };

        trace!("Sending Ollama chat request: {:?}", ollama_request);

        let response = self
            .client
            .post(&self.api_url("chat"))
            .json(&ollama_request)
            .send()
            .await
            .map_err(|e| {
                error!("Ollama request failed: {}", e);
                LlmError::Network(format!("Ollama request failed: {}", e))
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(handle_http_error(status, &body, self.name()));
        }

        let ollama_response: OllamaResponse = response.json().await.map_err(|e| {
            error!("Failed to parse Ollama response: {}", e);
            LlmError::Deserialization(format!("Failed to parse Ollama response: {}", e))
        })?;

        debug!("Ollama response received: {} tokens", 
            ollama_response.eval_count.unwrap_or(0));

        Ok(self.convert_response(ollama_response, model))
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

        let ollama_request = OllamaChatRequest {
            model: model.clone(),
            messages: self.convert_messages(&request.messages),
            stream: true,
            options: OllamaOptions {
                temperature: request.temperature,
                top_p: request.top_p,
                num_predict: request.max_tokens.map(|t| t as i32),
                stop: request.stop,
                seed: request.seed.map(|s| s as i32),
            },
        };

        trace!("Sending Ollama streaming request: {:?}", ollama_request);

        let response = self
            .client
            .post(&self.api_url("chat"))
            .json(&ollama_request)
            .send()
            .await
            .map_err(|e| {
                error!("Ollama streaming request failed: {}", e);
                LlmError::Network(format!("Ollama streaming request failed: {}", e))
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(handle_http_error(status, &body, self.name()));
        }

        let stream = response.bytes_stream().map(move |result| {
            match result {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    trace!("Ollama stream chunk: {}", text);
                    
                    // Ollama sends JSON objects, one per line
                    match serde_json::from_str::<OllamaStreamChunk>(&text) {
                        Ok(chunk) => {
                            let converted = self.convert_stream_chunk(chunk, &model);
                            Ok(converted)
                        }
                        Err(e) => {
                            error!("Failed to parse Ollama stream chunk: {}", e);
                            Err(LlmError::Deserialization(format!(
                                "Failed to parse stream chunk: {}",
                                e
                            )))
                        }
                    }
                }
                Err(e) => {
                    error!("Ollama stream error: {}", e);
                    Err(LlmError::Streaming(format!("Stream error: {}", e)))
                }
            }
        });

        Ok(Box::pin(stream))
    }

    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        let response = self
            .client
            .get(&self.api_url("tags"))
            .send()
            .await
            .map_err(|e| {
                error!("Failed to list Ollama models: {}", e);
                LlmError::Network(format!("Failed to list models: {}", e))
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(handle_http_error(status, &body, self.name()));
        }

        let tags_response: OllamaTagsResponse = response.json().await.map_err(|e| {
            error!("Failed to parse Ollama tags response: {}", e);
            LlmError::Deserialization(format!("Failed to parse tags response: {}", e))
        })?;

        let models: Vec<ModelInfo> = tags_response
            .models
            .into_iter()
            .map(|model| {
                ModelInfo::new(&model.name, "ollama")
                    .with_context_window(4096) // Default, varies by model
                    .with_streaming(true)
            })
            .collect();

        info!("Found {} Ollama models", models.len());
        Ok(models)
    }

    async fn is_model_available(&self, model: &str) -> Result<bool> {
        let models = self.list_models().await?;
        Ok(models.iter().any(|m| m.id == model))
    }

    async fn get_model_info(&self, model: &str) -> Result<ModelInfo> {
        // Ollama doesn't have a direct model info endpoint
        // We can try to get info from the tags endpoint
        let models = self.list_models().await?;
        models
            .into_iter()
            .find(|m| m.id == model)
            .ok_or_else(|| LlmError::ModelNotFound(model.to_string()))
    }

    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse> {
        let ollama_request = OllamaEmbedRequest {
            model: request.model,
            input: request.input,
        };

        let response = self
            .client
            .post(&self.api_url("embed"))
            .json(&ollama_request)
            .send()
            .await
            .map_err(|e| LlmError::Network(format!("Embedding request failed: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(handle_http_error(status, &body, self.name()));
        }

        let embed_response: OllamaEmbedResponse = response.json().await.map_err(|e| {
            LlmError::Deserialization(format!("Failed to parse embedding response: {}", e))
        })?;

        let data: Vec<EmbeddingData> = embed_response
            .embeddings
            .into_iter()
            .enumerate()
            .map(|(i, embedding)| EmbeddingData {
                object: "embedding".to_string(),
                embedding,
                index: i as u32,
            })
            .collect();

        let total_tokens: u32 = data.iter().map(|d| d.embedding.len() as u32).sum();

        Ok(EmbeddingResponse {
            object: "list".to_string(),
            data,
            model: ollama_request.model,
            usage: Usage {
                prompt_tokens: total_tokens,
                completion_tokens: 0,
                total_tokens: total_tokens,
            },
        })
    }

    fn supports_embeddings(&self) -> bool {
        true
    }
}

// Ollama-specific types

#[derive(Debug, Clone, Serialize)]
struct OllamaChatRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: OllamaOptions,
}

#[derive(Debug, Clone, Serialize, Default)]
struct OllamaOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OllamaMessage {
    role: String,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    images: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
struct OllamaResponse {
    model: String,
    created_at: String,
    message: OllamaMessage,
    done: bool,
    #[serde(default)]
    done_reason: Option<String>,
    #[serde(default)]
    prompt_eval_count: Option<usize>,
    #[serde(default)]
    eval_count: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
struct OllamaStreamChunk {
    model: String,
    created_at: String,
    message: OllamaMessage,
    done: bool,
    #[serde(default)]
    done_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OllamaTagsResponse {
    models: Vec<OllamaModel>,
}

#[derive(Debug, Clone, Deserialize)]
struct OllamaModel {
    name: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    digest: Option<String>,
    #[serde(default)]
    modified_at: Option<String>,
    #[serde(default)]
    details: Option<OllamaModelDetails>,
}

#[derive(Debug, Clone, Deserialize)]
struct OllamaModelDetails {
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    family: Option<String>,
    #[serde(default)]
    families: Option<Vec<String>>,
    #[serde(default)]
    parameter_size: Option<String>,
    #[serde(default)]
    quantization_level: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct OllamaEmbedRequest {
    model: String,
    input: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OllamaEmbedResponse {
    embeddings: Vec<Vec<f32>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_messages() {
        let config = crate::OllamaConfig::default();
        let provider = OllamaProvider {
            config,
            client: reqwest::Client::new(),
            name: "ollama".to_string(),
        };

        let messages = vec![
            Message::system("You are a helpful assistant."),
            Message::user("Hello!"),
            Message::assistant("Hi there!"),
        ];

        let ollama_messages = provider.convert_messages(&messages);
        assert_eq!(ollama_messages.len(), 3);
        assert_eq!(ollama_messages[0].role, "system");
        assert_eq!(ollama_messages[1].role, "user");
        assert_eq!(ollama_messages[2].role, "assistant");
    }

    #[test]
    fn test_convert_response() {
        let config = crate::OllamaConfig::default();
        let provider = OllamaProvider {
            config,
            client: reqwest::Client::new(),
            name: "ollama".to_string(),
        };

        let ollama_response = OllamaResponse {
            model: "llama2".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            message: OllamaMessage {
                role: "assistant".to_string(),
                content: "Hello!".to_string(),
                images: None,
            },
            done: true,
            done_reason: Some("stop".to_string()),
            prompt_eval_count: Some(10),
            eval_count: Some(5),
        };

        let response = provider.convert_response(ollama_response, "llama2");
        assert_eq!(response.model, "llama2");
        assert_eq!(response.choices.len(), 1);
        assert_eq!(response.choices[0].message.content, "Hello!");
        assert_eq!(response.usage.total_tokens, 15);
    }
}
