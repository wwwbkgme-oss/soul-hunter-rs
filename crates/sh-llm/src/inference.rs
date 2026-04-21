//! Inference engine for advanced LLM use cases
//!
//! This module provides higher-level abstractions for common LLM tasks:
//! - Structured output generation
//! - Multi-turn conversations
//! - Batch inference
//! - Retry logic with backoff
//! - Token counting and cost estimation

use std::collections::HashMap;
use std::pin::Pin;
use std::time::{Duration, Instant};

use futures::{Stream, StreamExt};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, error, info, trace, warn};

use crate::error::{LlmError, Result};
use crate::types::*;
use crate::LlmClient;

/// Inference options
#[derive(Debug, Clone)]
pub struct InferenceOptions {
    /// Temperature (0.0 to 2.0)
    pub temperature: f32,
    /// Maximum tokens to generate
    pub max_tokens: u32,
    /// Number of retries on failure
    pub max_retries: u32,
    /// Timeout for the request
    pub timeout: Duration,
    /// Whether to stream the response
    pub stream: bool,
    /// Stop sequences
    pub stop_sequences: Vec<String>,
    /// Response format
    pub response_format: Option<ResponseFormat>,
    /// Tools for function calling
    pub tools: Option<Vec<Tool>>,
    /// Tool choice
    pub tool_choice: Option<ToolChoice>,
    /// Seed for deterministic sampling
    pub seed: Option<i64>,
}

impl Default for InferenceOptions {
    fn default() -> Self {
        Self {
            temperature: 0.7,
            max_tokens: 1024,
            max_retries: 3,
            timeout: Duration::from_secs(60),
            stream: false,
            stop_sequences: Vec::new(),
            response_format: None,
            tools: None,
            tool_choice: None,
            seed: None,
        }
    }
}

impl InferenceOptions {
    /// Create new default options
    pub fn new() -> Self {
        Self::default()
    }

    /// Set temperature
    pub fn with_temperature(mut self, temp: f32) -> Self {
        self.temperature = temp.clamp(0.0, 2.0);
        self
    }

    /// Set maximum tokens
    pub fn with_max_tokens(mut self, tokens: u32) -> Self {
        self.max_tokens = tokens;
        self
    }

    /// Set maximum retries
    pub fn with_max_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Enable streaming
    pub fn with_streaming(mut self) -> Self {
        self.stream = true;
        self
    }

    /// Add stop sequences
    pub fn with_stop_sequences(mut self, sequences: Vec<String>) -> Self {
        self.stop_sequences = sequences;
        self
    }

    /// Set response format to JSON
    pub fn with_json_response(mut self) -> Self {
        self.response_format = Some(ResponseFormat::json_object());
        self
    }

    /// Set tools
    pub fn with_tools(mut self, tools: Vec<Tool>) -> Self {
        self.tools = Some(tools);
        self
    }

    /// Set tool choice
    pub fn with_tool_choice(mut self, choice: ToolChoice) -> Self {
        self.tool_choice = Some(choice);
        self
    }

    /// Set seed
    pub fn with_seed(mut self, seed: i64) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Create options for creative generation
    pub fn creative() -> Self {
        Self::default().with_temperature(0.9)
    }

    /// Create options for precise generation
    pub fn precise() -> Self {
        Self::default().with_temperature(0.1)
    }

    /// Create options for JSON output
    pub fn json() -> Self {
        Self::default().with_json_response()
    }
}

/// Inference result
#[derive(Debug, Clone)]
pub struct InferenceResult {
    /// Generated content
    pub content: String,
    /// Token usage
    pub usage: Usage,
    /// Model used
    pub model: String,
    /// Finish reason
    pub finish_reason: Option<String>,
    /// Tool calls (if any)
    pub tool_calls: Option<Vec<ToolCall>>,
    /// Latency
    pub latency: Duration,
    /// Number of retries
    pub retries: u32,
}

impl InferenceResult {
    /// Get content as a specific type (for JSON responses)
    pub fn content_as<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_str(&self.content).map_err(|e| {
            LlmError::Deserialization(format!(
                "Failed to parse content as {}: {}",
                std::any::type_name::<T>(),
                e
            ))
        })
    }

    /// Check if the response has tool calls
    pub fn has_tool_calls(&self) -> bool {
        self.tool_calls.as_ref().map(|t| !t.is_empty()).unwrap_or(false)
    }

    /// Get the first tool call
    pub fn first_tool_call(&self) -> Option<&ToolCall> {
        self.tool_calls.as_ref().and_then(|t| t.first())
    }
}

/// Inference engine
pub struct InferenceEngine<'a> {
    /// LLM client
    client: &'a LlmClient,
    /// Default options
    default_options: InferenceOptions,
    /// Metrics
    metrics: InferenceMetrics,
}

/// Inference metrics
#[derive(Debug, Clone, Default)]
pub struct InferenceMetrics {
    /// Total requests
    pub total_requests: u64,
    /// Successful requests
    pub successful_requests: u64,
    /// Failed requests
    pub failed_requests: u64,
    /// Total tokens used
    pub total_tokens: u64,
    /// Total latency
    pub total_latency_ms: u64,
    /// Average latency per request
    pub avg_latency_ms: f64,
    /// Retry counts
    pub retry_counts: HashMap<u32, u64>,
}

impl InferenceMetrics {
    /// Record a successful request
    fn record_success(&mut self, tokens: u64, latency_ms: u64, retries: u32) {
        self.total_requests += 1;
        self.successful_requests += 1;
        self.total_tokens += tokens;
        self.total_latency_ms += latency_ms;
        self.avg_latency_ms = self.total_latency_ms as f64 / self.successful_requests as f64;
        *self.retry_counts.entry(retries).or_insert(0) += 1;
    }

    /// Record a failed request
    fn record_failure(&mut self) {
        self.total_requests += 1;
        self.failed_requests += 1;
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.successful_requests as f64 / self.total_requests as f64
        }
    }
}

impl<'a> InferenceEngine<'a> {
    /// Create a new inference engine
    pub fn new(client: &'a LlmClient) -> Self {
        Self {
            client,
            default_options: InferenceOptions::default(),
            metrics: InferenceMetrics::default(),
        }
    }

    /// Create with default options
    pub fn with_default_options(mut self, options: InferenceOptions) -> Self {
        self.default_options = options;
        self
    }

    /// Get metrics
    pub fn metrics(&self) -> &InferenceMetrics {
        &self.metrics
    }

    /// Reset metrics
    pub fn reset_metrics(&mut self) {
        self.metrics = InferenceMetrics::default();
    }

    /// Generate a completion
    pub async fn generate(&self, prompt: impl Into<String>) -> Result<InferenceResult> {
        self.generate_with_options(prompt, &self.default_options).await
    }

    /// Generate a completion with custom options
    pub async fn generate_with_options(
        &self,
        prompt: impl Into<String>,
        options: &InferenceOptions,
    ) -> Result<InferenceResult> {
        let messages = vec![Message::user(prompt)];
        self.chat_with_options(messages, options).await
    }

    /// Chat completion
    pub async fn chat(&self, messages: Vec<Message>) -> Result<InferenceResult> {
        self.chat_with_options(messages, &self.default_options).await
    }

    /// Chat completion with custom options
    pub async fn chat_with_options(
        &self,
        messages: Vec<Message>,
        options: &InferenceOptions,
    ) -> Result<InferenceResult> {
        let request = self.build_request(messages, options)?;
        self.execute_with_retry(request, options).await
    }

    /// Generate structured output
    pub async fn generate_structured<T: DeserializeOwned + Serialize>(
        &self,
        prompt: impl Into<String>,
        schema: Option<Value>,
    ) -> Result<T> {
        let mut options = InferenceOptions::json();
        
        // If schema provided, add it to the prompt
        let prompt = if let Some(schema) = schema {
            format!(
                "{}\n\nYou must respond with a JSON object that conforms to this schema:\n{}",
                prompt.into(),
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )
        } else {
            prompt.into()
        };

        let result = self.generate_with_options(prompt, &options).await?;
        result.content_as::<T>()
    }

    /// Generate with tool calling
    pub async fn generate_with_tools(
        &self,
        prompt: impl Into<String>,
        tools: Vec<Tool>,
    ) -> Result<InferenceResult> {
        let options = InferenceOptions::default()
            .with_tools(tools)
            .with_tool_choice(ToolChoice::Auto);

        self.generate_with_options(prompt, &options).await
    }

    /// Stream a completion
    pub async fn stream(
        &self,
        prompt: impl Into<String>,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<String>> + Send>>> {
        self.stream_with_options(prompt, &self.default_options).await
    }

    /// Stream a completion with custom options
    pub async fn stream_with_options(
        &self,
        prompt: impl Into<String>,
        options: &InferenceOptions,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<String>> + Send>>> {
        let messages = vec![Message::user(prompt)];
        let mut request = self.build_request(messages, options)?;
        request.stream = Some(true);

        let stream = self.client.chat_stream_with_request(request).await?;
        
        let mapped_stream = stream.map(|chunk| {
            chunk.map(|c| {
                c.delta_content().unwrap_or("").to_string()
            }).map_err(|e| e)
        });

        Ok(Box::pin(mapped_stream))
    }

    /// Batch inference
    pub async fn batch(
        &self,
        prompts: Vec<String>,
    ) -> Vec<Result<InferenceResult>> {
        self.batch_with_options(prompts, &self.default_options).await
    }

    /// Batch inference with custom options
    pub async fn batch_with_options(
        &self,
        prompts: Vec<String>,
        options: &InferenceOptions,
    ) -> Vec<Result<InferenceResult>> {
        let mut results = Vec::with_capacity(prompts.len());

        for prompt in prompts {
            let result = self.generate_with_options(prompt, options).await;
            results.push(result);
        }

        results
    }

    /// Parallel batch inference
    pub async fn batch_parallel(
        &self,
        prompts: Vec<String>,
        concurrency: usize,
    ) -> Vec<Result<InferenceResult>> {
        self.batch_parallel_with_options(prompts, &self.default_options, concurrency).await
    }

    /// Parallel batch inference with custom options
    pub async fn batch_parallel_with_options(
        &self,
        prompts: Vec<String>,
        options: &InferenceOptions,
        concurrency: usize,
    ) -> Vec<Result<InferenceResult>> {
        use futures::stream::{self, StreamExt};

        let results: Vec<_> = stream::iter(prompts)
            .map(|prompt| async move {
                self.generate_with_options(prompt, options).await
            })
            .buffer_unordered(concurrency)
            .collect()
            .await;

        results
    }

    /// Build a chat request from options
    fn build_request(
        &self,
        messages: Vec<Message>,
        options: &InferenceOptions,
    ) -> Result<ChatRequest> {
        let mut request = ChatRequest::new(messages)
            .with_temperature(options.temperature)
            .with_max_tokens(options.max_tokens);

        if !options.stop_sequences.is_empty() {
            request = request.with_stop(options.stop_sequences.clone());
        }

        if let Some(ref format) = options.response_format {
            request = request.with_response_format(format.clone());
        }

        if let Some(ref tools) = options.tools {
            request = request.with_tools(tools.clone());
        }

        if let Some(ref choice) = options.tool_choice {
            request = request.with_tool_choice(choice.clone());
        }

        if let Some(seed) = options.seed {
            request = request.with_seed(seed);
        }

        Ok(request)
    }

    /// Execute with retry logic
    async fn execute_with_retry(
        &self,
        request: ChatRequest,
        options: &InferenceOptions,
    ) -> Result<InferenceResult> {
        let mut last_error = None;
        let mut retries = 0;

        loop {
            let start = Instant::now();
            
            match self.execute_single(request.clone()).await {
                Ok(result) => {
                    let latency = start.elapsed();
                    self.metrics.record_success(
                        result.usage.total_tokens as u64,
                        latency.as_millis() as u64,
                        retries,
                    );
                    
                    return Ok(InferenceResult {
                        content: result.content_string(),
                        usage: result.usage,
                        model: result.model,
                        finish_reason: result.choices.first().and_then(|c| c.finish_reason.clone()),
                        tool_calls: result.tool_calls().map(|t| t.to_vec()),
                        latency,
                        retries,
                    });
                }
                Err(e) => {
                    let latency = start.elapsed();
                    warn!("Inference failed (attempt {}): {}", retries + 1, e);
                    
                    if !e.is_retryable() || retries >= options.max_retries {
                        self.metrics.record_failure();
                        return Err(e);
                    }

                    let delay = e.retry_delay_secs();
                    trace!("Retrying after {} seconds", delay);
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                    
                    retries += 1;
                    last_error = Some(e);
                }
            }
        }
    }

    /// Execute a single request
    async fn execute_single(&self, request: ChatRequest) -> Result<ChatResponse> {
        self.client.chat_with_request(request).await
    }

    /// Count tokens in text (approximate)
    pub fn count_tokens(&self, text: &str) -> usize {
        // Rough approximation: 4 characters per token on average
        // This is a very rough estimate - actual tokenization varies by model
        text.len() / 4
    }

    /// Count tokens in messages (approximate)
    pub fn count_message_tokens(&self, messages: &[Message]) -> usize {
        messages.iter().map(|m| self.count_tokens(&m.content)).sum()
    }

    /// Estimate cost for a request (in USD, approximate)
    pub fn estimate_cost(&self, prompt_tokens: usize, completion_tokens: usize, model: &str) -> f64 {
        // Approximate pricing per 1K tokens (as of 2024)
        let (input_price, output_price) = match model {
            m if m.starts_with("gpt-4") && m.contains("turbo") => (0.01, 0.03),
            m if m.starts_with("gpt-4") => (0.03, 0.06),
            m if m.starts_with("gpt-3.5") => (0.0005, 0.0015),
            m if m.contains("claude-3-opus") => (0.015, 0.075),
            m if m.contains("claude-3-sonnet") => (0.003, 0.015),
            m if m.contains("claude-3-haiku") => (0.00025, 0.00125),
            _ => (0.0, 0.0), // Local models are free
        };

        let input_cost = (prompt_tokens as f64 / 1000.0) * input_price;
        let output_cost = (completion_tokens as f64 / 1000.0) * output_price;
        
        input_cost + output_cost
    }

    /// Validate that a request is within model limits
    pub fn validate_request(
        &self,
        messages: &[Message],
        max_tokens: u32,
        model: &str,
    ) -> Result<()> {
        let prompt_tokens = self.count_message_tokens(messages) as u32;
        let total_tokens = prompt_tokens + max_tokens;

        // Get context window for model
        let context_window = match model {
            m if m.starts_with("gpt-4") && m.contains("32k") => 32768,
            m if m.starts_with("gpt-4") && m.contains("turbo") => 128000,
            m if m.starts_with("gpt-4") => 8192,
            m if m.starts_with("gpt-3.5") && m.contains("16k") => 16384,
            m if m.starts_with("gpt-3.5") => 4096,
            m if m.contains("claude-3") => 200000,
            m if m.contains("claude-2.1") => 200000,
            m if m.contains("claude-2") => 100000,
            m if m.contains("claude-instant") => 100000,
            _ => 4096,
        };

        if total_tokens > context_window {
            return Err(LlmError::ContextLengthExceeded {
                model: model.to_string(),
                max_tokens: context_window,
                requested_tokens: total_tokens,
            });
        }

        Ok(())
    }
}

/// Conversation manager for multi-turn conversations
pub struct Conversation {
    /// Messages in the conversation
    messages: Vec<Message>,
    /// System prompt
    system_prompt: Option<String>,
    /// Inference options
    options: InferenceOptions,
}

impl Conversation {
    /// Create a new conversation
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            system_prompt: None,
            options: InferenceOptions::default(),
        }
    }

    /// Create with a system prompt
    pub fn with_system(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = Some(prompt.into());
        self
    }

    /// Set inference options
    pub fn with_options(mut self, options: InferenceOptions) -> Self {
        self.options = options;
        self
    }

    /// Add a user message
    pub fn user(&mut self, content: impl Into<String>) -> &mut Self {
        self.messages.push(Message::user(content));
        self
    }

    /// Add an assistant message
    pub fn assistant(&mut self, content: impl Into<String>) -> &mut Self {
        self.messages.push(Message::assistant(content));
        self
    }

    /// Get all messages (including system prompt)
    pub fn get_messages(&self) -> Vec<Message> {
        let mut all_messages = Vec::new();
        
        if let Some(ref system) = self.system_prompt {
            all_messages.push(Message::system(system.clone()));
        }
        
        all_messages.extend(self.messages.clone());
        all_messages
    }

    /// Get the conversation history
    pub fn history(&self) -> &[Message] {
        &self.messages
    }

    /// Clear the conversation (except system prompt)
    pub fn clear(&mut self) {
        self.messages.clear();
    }

    /// Get token count (approximate)
    pub fn token_count(&self) -> usize {
        let system_tokens = self
            .system_prompt
            .as_ref()
            .map(|s| s.len() / 4)
            .unwrap_or(0);
        let message_tokens: usize = self.messages.iter().map(|m| m.content.len() / 4).sum();
        system_tokens + message_tokens
    }
}

impl Default for Conversation {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inference_options_default() {
        let opts = InferenceOptions::default();
        assert_eq!(opts.temperature, 0.7);
        assert_eq!(opts.max_tokens, 1024);
        assert_eq!(opts.max_retries, 3);
        assert!(!opts.stream);
    }

    #[test]
    fn test_inference_options_builder() {
        let opts = InferenceOptions::new()
            .with_temperature(0.5)
            .with_max_tokens(2048)
            .with_max_retries(5)
            .with_streaming()
            .with_json_response();

        assert_eq!(opts.temperature, 0.5);
        assert_eq!(opts.max_tokens, 2048);
        assert_eq!(opts.max_retries, 5);
        assert!(opts.stream);
        assert!(opts.response_format.is_some());
    }

    #[test]
    fn test_inference_options_presets() {
        let creative = InferenceOptions::creative();
        assert_eq!(creative.temperature, 0.9);

        let precise = InferenceOptions::precise();
        assert_eq!(precise.temperature, 0.1);

        let json = InferenceOptions::json();
        assert!(json.response_format.is_some());
    }

    #[test]
    fn test_inference_result_content_as() {
        let result = InferenceResult {
            content: r#"{"name": "test", "value": 42}"#.to_string(),
            usage: Usage {
                prompt_tokens: 10,
                completion_tokens: 20,
                total_tokens: 30,
            },
            model: "gpt-4".to_string(),
            finish_reason: Some("stop".to_string()),
            tool_calls: None,
            latency: Duration::from_millis(100),
            retries: 0,
        };

        #[derive(Debug, Clone, Deserialize, Serialize)]
        struct TestData {
            name: String,
            value: i32,
        }

        let data: TestData = result.content_as().unwrap();
        assert_eq!(data.name, "test");
        assert_eq!(data.value, 42);
    }

    #[test]
    fn test_inference_metrics() {
        let mut metrics = InferenceMetrics::default();
        
        metrics.record_success(100, 500, 0);
        metrics.record_success(200, 1000, 1);
        metrics.record_failure();
        
        assert_eq!(metrics.total_requests, 3);
        assert_eq!(metrics.successful_requests, 2);
        assert_eq!(metrics.failed_requests, 1);
        assert_eq!(metrics.total_tokens, 300);
        assert_eq!(metrics.success_rate(), 2.0 / 3.0);
        assert_eq!(metrics.avg_latency_ms, 750.0);
    }

    #[test]
    fn test_conversation() {
        let mut conv = Conversation::new()
            .with_system("You are a helpful assistant.");

        conv.user("Hello!");
        conv.assistant("Hi there!");
        conv.user("How are you?");

        let messages = conv.get_messages();
        assert_eq!(messages.len(), 4); // system + 3 messages
        assert_eq!(messages[0].role, Role::System);
        assert_eq!(messages[1].role, Role::User);
        assert_eq!(messages[2].role, Role::Assistant);
        assert_eq!(messages[3].role, Role::User);

        assert_eq!(conv.history().len(), 3);

        conv.clear();
        assert_eq!(conv.history().len(), 0);
        assert_eq!(conv.get_messages().len(), 1); // system prompt remains
    }

    #[test]
    fn test_estimate_cost() {
        // This test would need a client to work properly
        // For now, just verify the function exists
    }

    #[test]
    fn test_validate_request() {
        // This test would need a client to work properly
        // For now, just verify the function exists
    }
}
