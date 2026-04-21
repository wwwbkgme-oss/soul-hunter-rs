//! Core types for LLM interactions

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Role of a message in a conversation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// System message (instructions to the model)
    System,
    /// User message
    User,
    /// Assistant message (model response)
    Assistant,
    /// Tool message (function/tool result)
    Tool,
}

impl Role {
    /// Convert role to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
            Role::Tool => "tool",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A message in a conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Role of the message sender
    pub role: Role,
    /// Content of the message
    pub content: String,
    /// Optional name (for multi-user conversations or tool calls)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional tool calls (for assistant messages with tool use)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    /// Optional tool call ID (for tool messages)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl Message {
    /// Create a new message
    pub fn new(role: Role, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        }
    }

    /// Create a system message
    pub fn system(content: impl Into<String>) -> Self {
        Self::new(Role::System, content)
    }

    /// Create a user message
    pub fn user(content: impl Into<String>) -> Self {
        Self::new(Role::User, content)
    }

    /// Create an assistant message
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new(Role::Assistant, content)
    }

    /// Create a tool message
    pub fn tool(content: impl Into<String>, tool_call_id: impl Into<String>) -> Self {
        Self {
            role: Role::Tool,
            content: content.into(),
            name: None,
            tool_calls: None,
            tool_call_id: Some(tool_call_id.into()),
        }
    }

    /// Set the name field
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set tool calls
    pub fn with_tool_calls(mut self, tool_calls: Vec<ToolCall>) -> Self {
        self.tool_calls = Some(tool_calls);
        self
    }

    /// Get the content length in characters
    pub fn content_len(&self) -> usize {
        self.content.len()
    }

    /// Check if the message is empty
    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }
}

/// Tool call from the assistant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// ID of the tool call
    pub id: String,
    /// Type of the tool call (usually "function")
    pub r#type: String,
    /// Function call details
    pub function: FunctionCall,
}

/// Function call details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    /// Name of the function
    pub name: String,
    /// Arguments as a JSON string
    pub arguments: String,
}

/// Tool definition for function calling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    /// Type of tool (usually "function")
    pub r#type: String,
    /// Function definition
    pub function: FunctionDefinition,
}

impl Tool {
    /// Create a new function tool
    pub fn function(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            r#type: "function".to_string(),
            function: FunctionDefinition {
                name: name.into(),
                description: description.into(),
                parameters: FunctionParameters::default(),
            },
        }
    }

    /// Add a parameter to the function
    pub fn with_parameter(
        mut self,
        name: impl Into<String>,
        description: impl Into<String>,
        param_type: impl Into<String>,
        required: bool,
    ) -> Self {
        let name = name.into();
        self.function.parameters.properties.insert(
            name.clone(),
            ParameterSchema {
                description: description.into(),
                r#type: param_type.into(),
            },
        );
        if required {
            self.function.parameters.required.push(name);
        }
        self
    }
}

/// Function definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDefinition {
    /// Name of the function
    pub name: String,
    /// Description of the function
    pub description: String,
    /// Parameters schema
    pub parameters: FunctionParameters,
}

/// Function parameters schema
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionParameters {
    /// Type of parameters (usually "object")
    pub r#type: String,
    /// Properties of the parameters
    pub properties: HashMap<String, ParameterSchema>,
    /// Required parameter names
    pub required: Vec<String>,
}

impl Default for FunctionParameters {
    fn default() -> Self {
        Self {
            r#type: "object".to_string(),
            properties: HashMap::new(),
            required: Vec::new(),
        }
    }
}

/// Parameter schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterSchema {
    /// Description of the parameter
    pub description: String,
    /// Type of the parameter
    pub r#type: String,
}

/// Chat completion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatRequest {
    /// Model to use
    pub model: String,
    /// Messages in the conversation
    pub messages: Vec<Message>,
    /// Temperature (0.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Top-p sampling (0.0 to 1.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Maximum tokens to generate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Stop sequences
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
    /// Stream response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Presence penalty (-2.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f32>,
    /// Frequency penalty (-2.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f32>,
    /// Tools available for function calling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    /// Tool choice ("none", "auto", or specific tool)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<ToolChoice>,
    /// Seed for deterministic sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<i64>,
    /// Response format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_format: Option<ResponseFormat>,
}

impl ChatRequest {
    /// Create a new chat request with messages
    pub fn new(messages: Vec<Message>) -> Self {
        Self {
            model: "default".to_string(),
            messages,
            temperature: None,
            top_p: None,
            max_tokens: None,
            stop: None,
            stream: None,
            presence_penalty: None,
            frequency_penalty: None,
            tools: None,
            tool_choice: None,
            seed: None,
            response_format: None,
        }
    }

    /// Set the model
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Set the temperature
    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    /// Set the top-p
    pub fn with_top_p(mut self, top_p: f32) -> Self {
        self.top_p = Some(top_p);
        self
    }

    /// Set the maximum tokens
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    /// Set stop sequences
    pub fn with_stop(mut self, stop: Vec<String>) -> Self {
        self.stop = Some(stop);
        self
    }

    /// Enable streaming
    pub fn with_stream(mut self, stream: bool) -> Self {
        self.stream = Some(stream);
        self
    }

    /// Set presence penalty
    pub fn with_presence_penalty(mut self, penalty: f32) -> Self {
        self.presence_penalty = Some(penalty);
        self
    }

    /// Set frequency penalty
    pub fn with_frequency_penalty(mut self, penalty: f32) -> Self {
        self.frequency_penalty = Some(penalty);
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

    /// Set response format
    pub fn with_response_format(mut self, format: ResponseFormat) -> Self {
        self.response_format = Some(format);
        self
    }

    /// Calculate approximate token count (rough estimate)
    pub fn approximate_tokens(&self) -> usize {
        // Rough estimate: 4 characters per token on average
        let content_len: usize = self.messages.iter().map(|m| m.content_len()).sum();
        content_len / 4
    }
}

/// Tool choice
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolChoice {
    /// Don't use any tools
    None,
    /// Let the model decide
    Auto,
    /// Force a specific tool
    #[serde(rename = "function")]
    Function { name: String },
}

/// Response format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseFormat {
    /// Type of response format ("text" or "json_object")
    pub r#type: String,
}

impl ResponseFormat {
    /// Create a JSON object response format
    pub fn json_object() -> Self {
        Self {
            r#type: "json_object".to_string(),
        }
    }

    /// Create a text response format
    pub fn text() -> Self {
        Self {
            r#type: "text".to_string(),
        }
    }
}

/// Chat completion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatResponse {
    /// Unique identifier for the completion
    pub id: String,
    /// Object type (usually "chat.completion")
    pub object: String,
    /// Creation timestamp
    pub created: u64,
    /// Model used
    pub model: String,
    /// Choices generated
    pub choices: Vec<Choice>,
    /// Usage statistics
    pub usage: Usage,
}

impl ChatResponse {
    /// Get the content of the first choice
    pub fn content(&self) -> Option<&str> {
        self.choices.first().map(|c| c.message.content.as_str())
    }

    /// Get the content as a string (empty if no choices)
    pub fn content_string(&self) -> String {
        self.content().unwrap_or("").to_string()
    }

    /// Check if the response has tool calls
    pub fn has_tool_calls(&self) -> bool {
        self.choices
            .first()
            .and_then(|c| c.message.tool_calls.as_ref())
            .map(|tc| !tc.is_empty())
            .unwrap_or(false)
    }

    /// Get tool calls from the first choice
    pub fn tool_calls(&self) -> Option<&Vec<ToolCall>> {
        self.choices.first().and_then(|c| c.message.tool_calls.as_ref())
    }
}

/// Choice in a chat completion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Choice {
    /// Index of the choice
    pub index: u32,
    /// Message generated
    pub message: Message,
    /// Finish reason
    pub finish_reason: Option<String>,
}

/// Usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    /// Number of tokens in the prompt
    pub prompt_tokens: u32,
    /// Number of tokens in the completion
    pub completion_tokens: u32,
    /// Total number of tokens
    pub total_tokens: u32,
}

/// Stream chunk for streaming responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunk {
    /// Unique identifier for the completion
    pub id: String,
    /// Object type (usually "chat.completion.chunk")
    pub object: String,
    /// Creation timestamp
    pub created: u64,
    /// Model used
    pub model: String,
    /// Choices in this chunk
    pub choices: Vec<StreamChoice>,
}

impl StreamChunk {
    /// Get the delta content from the first choice
    pub fn delta_content(&self) -> Option<&str> {
        self.choices.first().and_then(|c| c.delta.content.as_deref())
    }

    /// Check if this is the final chunk
    pub fn is_final(&self) -> bool {
        self.choices
            .first()
            .map(|c| c.finish_reason.is_some())
            .unwrap_or(false)
    }
}

/// Stream choice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChoice {
    /// Index of the choice
    pub index: u32,
    /// Delta content
    pub delta: DeltaMessage,
    /// Finish reason
    pub finish_reason: Option<String>,
}

/// Delta message for streaming
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeltaMessage {
    /// Role (usually only in first chunk)
    pub role: Option<Role>,
    /// Content delta
    pub content: Option<String>,
    /// Tool calls
    pub tool_calls: Option<Vec<ToolCall>>,
}

/// Model information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Model identifier
    pub id: String,
    /// Provider name
    pub provider: String,
    /// Object type (usually "model")
    pub object: String,
    /// Creation timestamp
    pub created: Option<u64>,
    /// Owned by
    pub owned_by: Option<String>,
    /// Context window size
    pub context_window: Option<u32>,
    /// Maximum output tokens
    pub max_tokens: Option<u32>,
    /// Whether the model supports streaming
    pub supports_streaming: bool,
    /// Whether the model supports function calling
    pub supports_functions: bool,
    /// Whether the model supports vision
    pub supports_vision: bool,
}

impl ModelInfo {
    /// Create a new model info
    pub fn new(id: impl Into<String>, provider: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            provider: provider.into(),
            object: "model".to_string(),
            created: None,
            owned_by: None,
            context_window: None,
            max_tokens: None,
            supports_streaming: true,
            supports_functions: false,
            supports_vision: false,
        }
    }

    /// Set context window
    pub fn with_context_window(mut self, tokens: u32) -> Self {
        self.context_window = Some(tokens);
        self
    }

    /// Set max tokens
    pub fn with_max_tokens(mut self, tokens: u32) -> Self {
        self.max_tokens = Some(tokens);
        self
    }

    /// Set streaming support
    pub fn with_streaming(mut self, supported: bool) -> Self {
        self.supports_streaming = supported;
        self
    }

    /// Set function calling support
    pub fn with_functions(mut self, supported: bool) -> Self {
        self.supports_functions = supported;
        self
    }

    /// Set vision support
    pub fn with_vision(mut self, supported: bool) -> Self {
        self.supports_vision = supported;
        self
    }
}

/// Embedding request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingRequest {
    /// Model to use
    pub model: String,
    /// Input text(s)
    pub input: Vec<String>,
}

/// Embedding response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingResponse {
    /// Object type (usually "list")
    pub object: String,
    /// Embedding data
    pub data: Vec<EmbeddingData>,
    /// Model used
    pub model: String,
    /// Usage statistics
    pub usage: Usage,
}

/// Embedding data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingData {
    /// Object type (usually "embedding")
    pub object: String,
    /// Embedding vector
    pub embedding: Vec<f32>,
    /// Index of the input
    pub index: u32,
}

/// Completion request (for non-chat completions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionRequest {
    /// Model to use
    pub model: String,
    /// Prompt text
    pub prompt: String,
    /// Temperature (0.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Maximum tokens to generate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    /// Stop sequences
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
    /// Stream response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
}

/// Completion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionResponse {
    /// Unique identifier
    pub id: String,
    /// Object type
    pub object: String,
    /// Creation timestamp
    pub created: u64,
    /// Model used
    pub model: String,
    /// Choices
    pub choices: Vec<CompletionChoice>,
    /// Usage statistics
    pub usage: Usage,
}

/// Completion choice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionChoice {
    /// Text generated
    pub text: String,
    /// Index
    pub index: u32,
    /// Finish reason
    pub finish_reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_display() {
        assert_eq!(Role::System.to_string(), "system");
        assert_eq!(Role::User.to_string(), "user");
        assert_eq!(Role::Assistant.to_string(), "assistant");
        assert_eq!(Role::Tool.to_string(), "tool");
    }

    #[test]
    fn test_message_creation() {
        let msg = Message::system("Test system message");
        assert_eq!(msg.role, Role::System);
        assert_eq!(msg.content, "Test system message");
        assert!(msg.name.is_none());

        let msg = Message::user("Test user message").with_name("Alice");
        assert_eq!(msg.role, Role::User);
        assert_eq!(msg.content, "Test user message");
        assert_eq!(msg.name, Some("Alice".to_string()));
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

    #[test]
    fn test_tool_creation() {
        let tool = Tool::function("get_weather", "Get the current weather")
            .with_parameter("location", "The city name", "string", true)
            .with_parameter("unit", "Temperature unit", "string", false);

        assert_eq!(tool.r#type, "function");
        assert_eq!(tool.function.name, "get_weather");
        assert_eq!(tool.function.parameters.properties.len(), 2);
        assert_eq!(tool.function.parameters.required.len(), 1);
    }

    #[test]
    fn test_model_info() {
        let model = ModelInfo::new("gpt-4", "openai")
            .with_context_window(8192)
            .with_max_tokens(4096)
            .with_streaming(true)
            .with_functions(true);

        assert_eq!(model.id, "gpt-4");
        assert_eq!(model.provider, "openai");
        assert_eq!(model.context_window, Some(8192));
        assert_eq!(model.max_tokens, Some(4096));
        assert!(model.supports_streaming);
        assert!(model.supports_functions);
    }

    #[test]
    fn test_response_format() {
        let json_format = ResponseFormat::json_object();
        assert_eq!(json_format.r#type, "json_object");

        let text_format = ResponseFormat::text();
        assert_eq!(text_format.r#type, "text");
    }
}
