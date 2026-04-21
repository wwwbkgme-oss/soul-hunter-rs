//! OpenAI provider implementation
//!
//! This provider supports:
//! - GPT-4, GPT-4 Turbo, GPT-3.5 Turbo
//! - Chat completions
//! - Streaming responses
//! - Function calling
//! - Embeddings
//! - Vision capabilities (for GPT-4 Vision)

use std::pin::Pin;

use async_trait::async_trait;
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, trace, warn};

use crate::error::{LlmError, Result};
use crate::providers::{handle_http_error, parse_sse_line, LlmProvider, ProviderConfig};
use crate::types::*;

/// OpenAI provider
pub struct OpenAiProvider {
    /// Configuration
    config: crate::OpenAiConfig,
    /// HTTP client
    client: reqwest::Client,
    /// Provider name
    name: String,
    /// API key
    api_key: String,
}

impl OpenAiProvider {
    /// Create a new OpenAI provider
    pub fn new(config: crate::OpenAiConfig, client: reqwest::Client) -> Result<Self> {
        let api_key = config
            .api_key
            .clone()
            .or_else(|| std::env::var("OPENAI_API_KEY").ok())
            .ok_or_else(|| LlmError::ApiKeyMissing("openai".to_string()))?;

        info!("Initializing OpenAI provider with base URL: {}", config.base_url);

        Ok(Self {
            config,
            client,
            name: "openai".to_string(),
            api_key,
        })
    }

    /// Get the API URL for a specific endpoint
    fn api_url(&self, endpoint: &str) -> String {
        format!("{}/{}", self.config.base_url, endpoint)
    }

    /// Build request headers
    fn build_headers(&self) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", self.api_key)
                .parse()
                .expect("Invalid API key format"),
        );
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );

        if let Some(ref org) = self.config.organization {
            headers.insert(
                "OpenAI-Organization",
                org.parse().expect("Invalid organization format"),
            );
        }

        headers
    }

    /// Convert messages to OpenAI format
    fn convert_messages(&self, messages: &[Message]) -> Vec<OpenAiMessage> {
        messages
            .iter()
            .map(|msg| {
                let mut openai_msg = OpenAiMessage {
                    role: match msg.role {
                        Role::System => "system".to_string(),
                        Role::User => "user".to_string(),
                        Role::Assistant => "assistant".to_string(),
                        Role::Tool => "tool".to_string(),
                    },
                    content: Some(msg.content.clone()),
                    name: msg.name.clone(),
                    tool_calls: msg.tool_calls.as_ref().map(|calls| {
                        calls
                            .iter()
                            .map(|call| OpenAiToolCall {
                                id: call.id.clone(),
                                r#type: call.r#type.clone(),
                                function: OpenAiFunctionCall {
                                    name: call.function.name.clone(),
                                    arguments: call.function.arguments.clone(),
                                },
                            })
                            .collect()
                    }),
                    tool_call_id: msg.tool_call_id.clone(),
                };

                // For tool messages, content might be empty
                if msg.role == Role::Tool && openai_msg.content.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                    openai_msg.content = Some("".to_string());
                }

                openai_msg
            })
            .collect()
    }

    /// Convert tools to OpenAI format
    fn convert_tools(&self, tools: Option<&Vec<Tool>>) -> Option<Vec<OpenAiTool>> {
        tools.map(|tools| {
            tools
                .iter()
                .map(|tool| OpenAiTool {
                    r#type: tool.r#type.clone(),
                    function: OpenAiFunctionDefinition {
                        name: tool.function.name.clone(),
                        description: tool.function.description.clone(),
                        parameters: tool.function.parameters.clone(),
                    },
                })
                .collect()
        })
    }

    /// Convert tool choice to OpenAI format
    fn convert_tool_choice(&self, choice: Option<&ToolChoice>) -> Option<OpenAiToolChoice> {
        choice.map(|c| match c {
            ToolChoice::None => OpenAiToolChoice::String("none".to_string()),
            ToolChoice::Auto => OpenAiToolChoice::String("auto".to_string()),
            ToolChoice::Function { name } => OpenAiToolChoice::Object(OpenAiToolChoiceObject {
                r#type: "function".to_string(),
                function: OpenAiToolChoiceFunction { name: name.clone() },
            }),
        })
    }

    /// Convert OpenAI response to standard format
    fn convert_response(&self, response: OpenAiChatResponse) -> ChatResponse {
        ChatResponse {
            id: response.id,
            object: response.object,
            created: response.created,
            model: response.model,
            choices: response
                .choices
                .into_iter()
                .map(|choice| Choice {
                    index: choice.index,
                    message: Message {
                        role: match choice.message.role.as_str() {
                            "system" => Role::System,
                            "user" => Role::User,
                            "assistant" => Role::Assistant,
                            "tool" => Role::Tool,
                            _ => Role::Assistant,
                        },
                        content: choice.message.content.unwrap_or_default(),
                        name: choice.message.name,
                        tool_calls: choice.message.tool_calls.map(|calls| {
                            calls
                                .into_iter()
                                .map(|call| ToolCall {
                                    id: call.id,
                                    r#type: call.r#type,
                                    function: FunctionCall {
                                        name: call.function.name,
                                        arguments: call.function.arguments,
                                    },
                                })
                                .collect()
                        }),
                        tool_call_id: choice.message.tool_call_id,
                    },
                    finish_reason: choice.finish_reason,
                })
                .collect(),
            usage: Usage {
                prompt_tokens: response.usage.prompt_tokens,
                completion_tokens: response.usage.completion_tokens,
                total_tokens: response.usage.total_tokens,
            },
        }
    }

    /// Convert streaming chunk to standard format
    fn convert_stream_chunk(&self, chunk: OpenAiStreamChunk) -> StreamChunk {
        StreamChunk {
            id: chunk.id,
            object: chunk.object,
            created: chunk.created,
            model: chunk.model,
            choices: chunk
                .choices
                .into_iter()
                .map(|choice| StreamChoice {
                    index: choice.index,
                    delta: DeltaMessage {
                        role: choice.delta.role.as_ref().map(|r| match r.as_str() {
                            "system" => Role::System,
                            "user" => Role::User,
                            "assistant" => Role::Assistant,
                            "tool" => Role::Tool,
                            _ => Role::Assistant,
                        }),
                        content: choice.delta.content,
                        tool_calls: choice.delta.tool_calls.map(|calls| {
                            calls
                                .into_iter()
                                .map(|call| ToolCall {
                                    id: call.id,
                                    r#type: call.r#type,
                                    function: FunctionCall {
                                        name: call.function.name,
                                        arguments: call.function.arguments,
                                    },
                                })
                                .collect()
                        }),
                    },
                    finish_reason: choice.finish_reason,
                })
                .collect(),
        }
    }

    /// Check if a model supports function calling
    fn supports_functions(&self, model: &str) -> bool {
        let function_models = [
            "gpt-4",
            "gpt-4-turbo",
            "gpt-4-turbo-preview",
            "gpt-4-0125-preview",
            "gpt-4-1106-preview",
            "gpt-3.5-turbo",
            "gpt-3.5-turbo-0125",
            "gpt-3.5-turbo-1106",
        ];
        function_models.iter().any(|m| model.starts_with(m))
    }

    /// Check if a model supports vision
    fn supports_vision(&self, model: &str) -> bool {
        model.contains("vision") || model.contains("gpt-4-turbo")
    }
}

#[async_trait]
impl LlmProvider for OpenAiProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse> {
        let model = if request.model == "default" {
            &self.config.default_model
        } else {
            &request.model
        };

        let openai_request = OpenAiChatRequest {
            model: model.to_string(),
            messages: self.convert_messages(&request.messages),
            temperature: request.temperature,
            top_p: request.top_p,
            max_tokens: request.max_tokens,
            stop: request.stop,
            stream: Some(false),
            presence_penalty: request.presence_penalty,
            frequency_penalty: request.frequency_penalty,
            tools: self.convert_tools(request.tools.as_ref()),
            tool_choice: self.convert_tool_choice(request.tool_choice.as_ref()),
            seed: request.seed,
            response_format: request.response_format,
        };

        trace!("Sending OpenAI chat request: {:?}", openai_request);

        let response = self
            .client
            .post(&self.api_url("chat/completions"))
            .headers(self.build_headers())
            .json(&openai_request)
            .send()
            .await
            .map_err(|e| {
                error!("OpenAI request failed: {}", e);
                LlmError::Network(format!("OpenAI request failed: {}", e))
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(handle_http_error(status, &body, self.name()));
        }

        let openai_response: OpenAiChatResponse = response.json().await.map_err(|e| {
            error!("Failed to parse OpenAI response: {}", e);
            LlmError::Deserialization(format!("Failed to parse OpenAI response: {}", e))
        })?;

        debug!(
            "OpenAI response received: {} tokens",
            openai_response.usage.total_tokens
        );

        Ok(self.convert_response(openai_response))
    }

    async fn chat_stream(
        &self,
        request: ChatRequest,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamChunk>> + Send>>> {
        let openai_request = OpenAiChatRequest {
            model: request.model.clone(),
            messages: self.convert_messages(&request.messages),
            temperature: request.temperature,
            top_p: request.top_p,
            max_tokens: request.max_tokens,
            stop: request.stop,
            stream: Some(true),
            presence_penalty: request.presence_penalty,
            frequency_penalty: request.frequency_penalty,
            tools: self.convert_tools(request.tools.as_ref()),
            tool_choice: self.convert_tool_choice(request.tool_choice.as_ref()),
            seed: request.seed,
            response_format: request.response_format,
        };

        trace!("Sending OpenAI streaming request");

        let response = self
            .client
            .post(&self.api_url("chat/completions"))
            .headers(self.build_headers())
            .json(&openai_request)
            .send()
            .await
            .map_err(|e| {
                error!("OpenAI streaming request failed: {}", e);
                LlmError::Network(format!("OpenAI streaming request failed: {}", e))
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(handle_http_error(status, &body, self.name()));
        }

        let stream = response.bytes_stream().flat_map(|result| {
            match result {
                Ok(bytes) => {
                    let text = String::from_utf8_lossy(&bytes);
                    let lines: Vec<_> = text.lines().collect();
                    
                    futures::stream::iter(lines.into_iter().filter_map(|line| {
                        if line.is_empty() {
                            return None;
                        }
                        
                        trace!("OpenAI SSE line: {}", line);
                        
                        if let Some(json) = parse_sse_line(line) {
                            match serde_json::from_value::<OpenAiStreamChunk>(json) {
                                Ok(chunk) => Some(Ok(self.convert_stream_chunk(chunk))),
                                Err(e) => {
                                    error!("Failed to parse OpenAI stream chunk: {}", e);
                                    Some(Err(LlmError::Deserialization(format!(
                                        "Failed to parse stream chunk: {}",
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
                    error!("OpenAI stream error: {}", e);
                    futures::stream::iter(vec![Err(LlmError::Streaming(format!(
                        "Stream error: {}",
                        e
                    ))])
                    .boxed()
                }
            }
        });

        Ok(Box::pin(stream))
    }

    async fn list_models(&self) -> Result<Vec<ModelInfo>> {
        let response = self
            .client
            .get(&self.api_url("models"))
            .headers(self.build_headers())
            .send()
            .await
            .map_err(|e| {
                error!("Failed to list OpenAI models: {}", e);
                LlmError::Network(format!("Failed to list models: {}", e))
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(handle_http_error(status, &body, self.name()));
        }

        let models_response: OpenAiModelsResponse = response.json().await.map_err(|e| {
            error!("Failed to parse OpenAI models response: {}", e);
            LlmError::Deserialization(format!("Failed to parse models response: {}", e))
        })?;

        let models: Vec<ModelInfo> = models_response
            .data
            .into_iter()
            .filter(|m| m.id.starts_with("gpt-"))
            .map(|m| {
                let mut info = ModelInfo::new(&m.id, "openai")
                    .with_streaming(true)
                    .with_functions(self.supports_functions(&m.id))
                    .with_vision(self.supports_vision(&m.id));

                // Set context window based on model
                if m.id.starts_with("gpt-4") {
                    info = info.with_context_window(if m.id.contains("32k") {
                        32768
                    } else if m.id.contains("turbo") {
                        128000
                    } else {
                        8192
                    });
                } else if m.id.starts_with("gpt-3.5") {
                    info = info.with_context_window(if m.id.contains("16k") {
                        16384
                    } else {
                        4096
                    });
                }

                info
            })
            .collect();

        info!("Found {} OpenAI models", models.len());
        Ok(models)
    }

    async fn is_model_available(&self, model: &str) -> Result<bool> {
        let models = self.list_models().await?;
        Ok(models.iter().any(|m| m.id == model))
    }

    async fn get_model_info(&self, model: &str) -> Result<ModelInfo> {
        let response = self
            .client
            .get(&self.api_url(&format!("models/{}", model)))
            .headers(self.build_headers())
            .send()
            .await
            .map_err(|e| LlmError::Network(format!("Failed to get model info: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(handle_http_error(status, &body, self.name()));
        }

        let model_data: OpenAiModel = response.json().await.map_err(|e| {
            LlmError::Deserialization(format!("Failed to parse model info: {}", e))
        })?;

        Ok(ModelInfo::new(&model_data.id, "openai")
            .with_streaming(true)
            .with_functions(self.supports_functions(&model_data.id))
            .with_vision(self.supports_vision(&model_data.id)))
    }

    async fn embed(&self, request: EmbeddingRequest) -> Result<EmbeddingResponse> {
        let openai_request = OpenAiEmbedRequest {
            model: request.model,
            input: request.input,
        };

        let response = self
            .client
            .post(&self.api_url("embeddings"))
            .headers(self.build_headers())
            .json(&openai_request)
            .send()
            .await
            .map_err(|e| LlmError::Network(format!("Embedding request failed: {}", e)))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(handle_http_error(status, &body, self.name()));
        }

        let embed_response: OpenAiEmbedResponse = response.json().await.map_err(|e| {
            LlmError::Deserialization(format!("Failed to parse embedding response: {}", e))
        })?;

        Ok(EmbeddingResponse {
            object: embed_response.object,
            data: embed_response
                .data
                .into_iter()
                .map(|d| EmbeddingData {
                    object: d.object,
                    embedding: d.embedding,
                    index: d.index,
                })
                .collect(),
            model: embed_response.model,
            usage: Usage {
                prompt_tokens: embed_response.usage.prompt_tokens,
                completion_tokens: 0,
                total_tokens: embed_response.usage.total_tokens,
            },
        })
    }

    fn supports_embeddings(&self) -> bool {
        true
    }
}

// OpenAI-specific types

#[derive(Debug, Clone, Serialize)]
struct OpenAiChatRequest {
    model: String,
    messages: Vec<OpenAiMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    presence_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    frequency_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<OpenAiTool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<OpenAiToolChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OpenAiMessage {
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<OpenAiToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OpenAiToolCall {
    id: String,
    r#type: String,
    function: OpenAiFunctionCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OpenAiFunctionCall {
    name: String,
    arguments: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OpenAiTool {
    r#type: String,
    function: OpenAiFunctionDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OpenAiFunctionDefinition {
    name: String,
    description: String,
    parameters: FunctionParameters,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum OpenAiToolChoice {
    String(String),
    Object(OpenAiToolChoiceObject),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OpenAiToolChoiceObject {
    r#type: String,
    function: OpenAiToolChoiceFunction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OpenAiToolChoiceFunction {
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenAiChatResponse {
    id: String,
    object: String,
    created: u64,
    model: String,
    choices: Vec<OpenAiChoice>,
    usage: OpenAiUsage,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenAiChoice {
    index: u32,
    message: OpenAiMessage,
    finish_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenAiUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenAiStreamChunk {
    id: String,
    object: String,
    created: u64,
    model: String,
    choices: Vec<OpenAiStreamChoice>,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenAiStreamChoice {
    index: u32,
    delta: OpenAiDeltaMessage,
    finish_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct OpenAiDeltaMessage {
    role: Option<String>,
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<OpenAiToolCall>>,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenAiModelsResponse {
    object: String,
    data: Vec<OpenAiModel>,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenAiModel {
    id: String,
    object: String,
    created: u64,
    owned_by: String,
}

#[derive(Debug, Clone, Serialize)]
struct OpenAiEmbedRequest {
    model: String,
    input: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenAiEmbedResponse {
    object: String,
    data: Vec<OpenAiEmbeddingData>,
    model: String,
    usage: OpenAiUsage,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenAiEmbeddingData {
    object: String,
    embedding: Vec<f32>,
    index: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_messages() {
        let config = crate::OpenAiConfig::default();
        let provider = OpenAiProvider {
            config,
            client: reqwest::Client::new(),
            name: "openai".to_string(),
            api_key: "test-key".to_string(),
        };

        let messages = vec![
            Message::system("You are a helpful assistant."),
            Message::user("Hello!"),
            Message::assistant("Hi there!"),
        ];

        let openai_messages = provider.convert_messages(&messages);
        assert_eq!(openai_messages.len(), 3);
        assert_eq!(openai_messages[0].role, "system");
        assert_eq!(openai_messages[1].role, "user");
        assert_eq!(openai_messages[2].role, "assistant");
    }

    #[test]
    fn test_supports_functions() {
        let config = crate::OpenAiConfig::default();
        let provider = OpenAiProvider {
            config,
            client: reqwest::Client::new(),
            name: "openai".to_string(),
            api_key: "test-key".to_string(),
        };

        assert!(provider.supports_functions("gpt-4"));
        assert!(provider.supports_functions("gpt-4-turbo"));
        assert!(provider.supports_functions("gpt-3.5-turbo"));
        assert!(!provider.supports_functions("text-davinci-003"));
    }

    #[test]
    fn test_supports_vision() {
        let config = crate::OpenAiConfig::default();
        let provider = OpenAiProvider {
            config,
            client: reqwest::Client::new(),
            name: "openai".to_string(),
            api_key: "test-key".to_string(),
        };

        assert!(provider.supports_vision("gpt-4-vision-preview"));
        assert!(provider.supports_vision("gpt-4-turbo"));
        assert!(!provider.supports_vision("gpt-4"));
    }
}
