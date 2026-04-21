//! Model routing module
//!
//! This module provides intelligent routing of requests to appropriate LLM providers
//! based on model capabilities, availability, and user preferences.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace, warn};

use crate::error::{LlmError, Result};
use crate::types::ModelInfo;

/// Routing strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingStrategy {
    /// Route to the explicitly specified provider
    Explicit,
    /// Route to the first available provider
    FirstAvailable,
    /// Route based on model capabilities
    CapabilityBased,
    /// Route based on cost optimization
    CostOptimized,
    /// Route based on latency requirements
    LatencyOptimized,
    /// Round-robin across providers
    RoundRobin,
    /// Random selection from available providers
    Random,
}

impl Default for RoutingStrategy {
    fn default() -> Self {
        RoutingStrategy::Explicit
    }
}

impl std::fmt::Display for RoutingStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingStrategy::Explicit => write!(f, "explicit"),
            RoutingStrategy::FirstAvailable => write!(f, "first_available"),
            RoutingStrategy::CapabilityBased => write!(f, "capability_based"),
            RoutingStrategy::CostOptimized => write!(f, "cost_optimized"),
            RoutingStrategy::LatencyOptimized => write!(f, "latency_optimized"),
            RoutingStrategy::RoundRobin => write!(f, "round_robin"),
            RoutingStrategy::Random => write!(f, "random"),
        }
    }
}

/// Routing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Default routing strategy
    pub strategy: RoutingStrategy,
    /// Provider priority (higher = preferred)
    pub provider_priority: HashMap<String, i32>,
    /// Model to provider mappings
    pub model_mappings: HashMap<String, String>,
    /// Fallback providers (in order of preference)
    pub fallback_providers: Vec<String>,
    /// Enable automatic failover
    pub enable_failover: bool,
    /// Maximum failover attempts
    pub max_failover_attempts: u32,
    /// Cost weights for cost-optimized routing
    pub cost_weights: HashMap<String, f32>,
    /// Latency weights for latency-optimized routing
    pub latency_weights: HashMap<String, f32>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        let mut provider_priority = HashMap::new();
        provider_priority.insert("ollama".to_string(), 100); // Local = highest priority
        provider_priority.insert("openai".to_string(), 80);
        provider_priority.insert("anthropic".to_string(), 70);

        let mut model_mappings = HashMap::new();
        // OpenAI models
        model_mappings.insert("gpt-4".to_string(), "openai".to_string());
        model_mappings.insert("gpt-4-turbo".to_string(), "openai".to_string());
        model_mappings.insert("gpt-3.5-turbo".to_string(), "openai".to_string());
        // Anthropic models
        model_mappings.insert("claude-3-opus".to_string(), "anthropic".to_string());
        model_mappings.insert("claude-3-sonnet".to_string(), "anthropic".to_string());
        model_mappings.insert("claude-3-haiku".to_string(), "anthropic".to_string());
        model_mappings.insert("claude-2".to_string(), "anthropic".to_string());
        // Ollama models (local)
        model_mappings.insert("llama2".to_string(), "ollama".to_string());
        model_mappings.insert("llama3".to_string(), "ollama".to_string());
        model_mappings.insert("mistral".to_string(), "ollama".to_string());
        model_mappings.insert("codellama".to_string(), "ollama".to_string());

        Self {
            strategy: RoutingStrategy::Explicit,
            provider_priority,
            model_mappings,
            fallback_providers: vec!["ollama".to_string()],
            enable_failover: true,
            max_failover_attempts: 2,
            cost_weights: HashMap::new(),
            latency_weights: HashMap::new(),
        }
    }
}

impl RoutingConfig {
    /// Create a new routing configuration with a specific strategy
    pub fn with_strategy(mut self, strategy: RoutingStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Add a provider priority
    pub fn with_provider_priority(mut self, provider: impl Into<String>, priority: i32) -> Self {
        self.provider_priority.insert(provider.into(), priority);
        self
    }

    /// Add a model mapping
    pub fn with_model_mapping(
        mut self,
        model: impl Into<String>,
        provider: impl Into<String>,
    ) -> Self {
        self.model_mappings.insert(model.into(), provider.into());
        self
    }

    /// Set fallback providers
    pub fn with_fallback_providers(mut self, providers: Vec<String>) -> Self {
        self.fallback_providers = providers;
        self
    }

    /// Enable or disable failover
    pub fn with_failover(mut self, enabled: bool) -> Self {
        self.enable_failover = enabled;
        self
    }

    /// Set maximum failover attempts
    pub fn with_max_failover_attempts(mut self, attempts: u32) -> Self {
        self.max_failover_attempts = attempts;
        self
    }
}

/// Model router
pub struct ModelRouter {
    /// Configuration
    config: RoutingConfig,
    /// Round-robin counter
    round_robin_counter: std::sync::atomic::AtomicUsize,
    /// Provider health status
    provider_health: HashMap<String, ProviderHealth>,
}

/// Provider health status
#[derive(Debug, Clone)]
struct ProviderHealth {
    /// Provider name
    name: String,
    /// Is the provider healthy
    healthy: bool,
    /// Last error time
    last_error: Option<chrono::DateTime<chrono::Utc>>,
    /// Error count
    error_count: u32,
    /// Success count
    success_count: u32,
    /// Average latency (ms)
    avg_latency_ms: f64,
}

impl ModelRouter {
    /// Create a new model router
    pub fn new(config: &RoutingConfig) -> Self {
        let mut provider_health = HashMap::new();
        
        // Initialize health for known providers
        for provider in ["ollama", "openai", "anthropic"] {
            provider_health.insert(
                provider.to_string(),
                ProviderHealth {
                    name: provider.to_string(),
                    healthy: true,
                    last_error: None,
                    error_count: 0,
                    success_count: 0,
                    avg_latency_ms: 0.0,
                },
            );
        }

        Self {
            config: config.clone(),
            round_robin_counter: std::sync::atomic::AtomicUsize::new(0),
            provider_health,
        }
    }

    /// Route a model to a provider
    pub fn route(&self, model: &str) -> Result<String> {
        trace!("Routing model: {} with strategy: {}", model, self.config.strategy);

        match self.config.strategy {
            RoutingStrategy::Explicit => self.route_explicit(model),
            RoutingStrategy::FirstAvailable => self.route_first_available(model),
            RoutingStrategy::CapabilityBased => self.route_capability_based(model),
            RoutingStrategy::CostOptimized => self.route_cost_optimized(model),
            RoutingStrategy::LatencyOptimized => self.route_latency_optimized(model),
            RoutingStrategy::RoundRobin => self.route_round_robin(),
            RoutingStrategy::Random => self.route_random(),
        }
    }

    /// Route based on explicit model mappings
    fn route_explicit(&self, model: &str) -> Result<String> {
        // First check exact model mapping
        if let Some(provider) = self.config.model_mappings.get(model) {
            trace!("Found explicit mapping for {} -> {}", model, provider);
            return Ok(provider.clone());
        }

        // Check for prefix matches
        for (mapped_model, provider) in &self.config.model_mappings {
            if model.starts_with(mapped_model) {
                trace!("Found prefix mapping for {} -> {}", model, provider);
                return Ok(provider.clone());
            }
        }

        // Try to infer from model name
        if model.starts_with("gpt-") {
            return Ok("openai".to_string());
        } else if model.starts_with("claude-") {
            return Ok("anthropic".to_string());
        } else if model.starts_with("llama") 
            || model.starts_with("mistral")
            || model.starts_with("codellama")
            || model.starts_with("phi")
            || model.starts_with("gemma") {
            return Ok("ollama".to_string());
        }

        // Default to first fallback provider
        if let Some(provider) = self.config.fallback_providers.first() {
            warn!("No explicit mapping for {}, using fallback: {}", model, provider);
            return Ok(provider.clone());
        }

        Err(LlmError::ModelNotFound(format!(
            "No provider found for model: {}",
            model
        )))
    }

    /// Route to the first available provider
    fn route_first_available(&self, _model: &str) -> Result<String> {
        // Sort providers by priority (highest first)
        let mut providers: Vec<_> = self.config.provider_priority.iter().collect();
        providers.sort_by(|a, b| b.1.cmp(a.1));

        for (provider, _) in providers {
            if self.is_provider_healthy(provider) {
                return Ok(provider.clone());
            }
        }

        // Fall back to first fallback provider
        if let Some(provider) = self.config.fallback_providers.first() {
            return Ok(provider.clone());
        }

        Err(LlmError::ProviderNotAvailable(
            "No healthy providers available".to_string(),
        ))
    }

    /// Route based on model capabilities
    fn route_capability_based(&self, model: &str) -> Result<String> {
        // Check if model needs specific capabilities
        let needs_vision = model.contains("vision");
        let needs_functions = model.contains("gpt-4") || model.contains("gpt-3.5");
        let needs_large_context = model.contains("32k") 
            || model.contains("128k") 
            || model.contains("200k")
            || model.contains("claude-3");

        trace!(
            "Capability requirements for {}: vision={}, functions={}, large_context={}",
            model, needs_vision, needs_functions, needs_large_context
        );

        // Route based on capabilities
        if needs_vision {
            // OpenAI and Anthropic support vision
            if self.is_provider_healthy("openai") {
                return Ok("openai".to_string());
            }
            if self.is_provider_healthy("anthropic") {
                return Ok("anthropic".to_string());
            }
        }

        if needs_functions {
            // OpenAI has the best function calling support
            if self.is_provider_healthy("openai") {
                return Ok("openai".to_string());
            }
        }

        if needs_large_context {
            // Anthropic has 200k context for Claude 3
            if self.is_provider_healthy("anthropic") && model.starts_with("claude-") {
                return Ok("anthropic".to_string());
            }
            // OpenAI has 128k for GPT-4 Turbo
            if self.is_provider_healthy("openai") {
                return Ok("openai".to_string());
            }
        }

        // Fall back to explicit routing
        self.route_explicit(model)
    }

    /// Route based on cost optimization
    fn route_cost_optimized(&self, model: &str) -> Result<String> {
        // Define cost tiers (lower = cheaper)
        let cost_tiers: HashMap<&str, f32> = [
            ("ollama", 0.0),      // Free (local)
            ("anthropic", 1.0),   // Claude Haiku is cheap
            ("openai", 2.0),      // GPT-3.5 is moderate
        ]
        .iter()
        .cloned()
        .collect();

        // Get cost weights from config or use defaults
        let mut provider_costs: Vec<_> = cost_tiers
            .iter()
            .map(|(provider, cost)| {
                let weight = self.config.cost_weights.get(*provider).copied().unwrap_or(1.0);
                (*provider, cost * weight)
            })
            .collect();

        // Sort by cost (lowest first)
        provider_costs.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        for (provider, _) in provider_costs {
            if self.is_provider_healthy(provider) {
                // Check if provider supports the model
                if let Ok(routed) = self.route_explicit(model) {
                    if routed == provider {
                        return Ok(provider.to_string());
                    }
                }
            }
        }

        // Fall back to explicit routing
        self.route_explicit(model)
    }

    /// Route based on latency optimization
    fn route_latency_optimized(&self, model: &str) -> Result<String> {
        // Local models have lowest latency
        if self.is_provider_healthy("ollama") {
            if let Ok(routed) = self.route_explicit(model) {
                if routed == "ollama" {
                    return Ok("ollama".to_string());
                }
            }
        }

        // Then check latency weights
        let mut provider_latencies: Vec<_> = self
            .config
            .latency_weights
            .iter()
            .map(|(p, w)| (p.clone(), *w))
            .collect();
        provider_latencies.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

        for (provider, _) in provider_latencies {
            if self.is_provider_healthy(&provider) {
                if let Ok(routed) = self.route_explicit(model) {
                    if routed == provider {
                        return Ok(provider);
                    }
                }
            }
        }

        // Fall back to explicit routing
        self.route_explicit(model)
    }

    /// Route using round-robin
    fn route_round_robin(&self) -> Result<String> {
        let providers: Vec<_> = self.config.provider_priority.keys().cloned().collect();
        
        if providers.is_empty() {
            return Err(LlmError::ProviderNotAvailable(
                "No providers configured".to_string(),
            ));
        }

        let counter = self
            .round_robin_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let index = counter % providers.len();
        
        Ok(providers[index].clone())
    }

    /// Route randomly
    fn route_random(&self) -> Result<String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let providers: Vec<_> = self.config.provider_priority.keys().cloned().collect();
        
        if providers.is_empty() {
            return Err(LlmError::ProviderNotAvailable(
                "No providers configured".to_string(),
            ));
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let index = (timestamp % providers.len() as u128) as usize;
        
        Ok(providers[index].clone())
    }

    /// Check if a provider is healthy
    fn is_provider_healthy(&self, provider: &str) -> bool {
        self.provider_health
            .get(provider)
            .map(|h| h.healthy)
            .unwrap_or(true)
    }

    /// Mark a provider as healthy
    pub fn mark_healthy(&mut self, provider: &str) {
        if let Some(health) = self.provider_health.get_mut(provider) {
            health.healthy = true;
            health.success_count += 1;
            info!("Provider {} marked as healthy", provider);
        }
    }

    /// Mark a provider as unhealthy
    pub fn mark_unhealthy(&mut self, provider: &str) {
        if let Some(health) = self.provider_health.get_mut(provider) {
            health.healthy = false;
            health.last_error = Some(chrono::Utc::now());
            health.error_count += 1;
            warn!("Provider {} marked as unhealthy", provider);
        }
    }

    /// Update provider latency
    pub fn update_latency(&mut self, provider: &str, latency_ms: f64) {
        if let Some(health) = self.provider_health.get_mut(provider) {
            // Exponential moving average
            let alpha = 0.1;
            health.avg_latency_ms = health.avg_latency_ms * (1.0 - alpha) + latency_ms * alpha;
        }
    }

    /// Get provider health status
    pub fn get_provider_health(&self, provider: &str) -> Option<bool> {
        self.provider_health.get(provider).map(|h| h.healthy)
    }

    /// Get all provider health statuses
    pub fn get_all_provider_health(&self) -> HashMap<String, bool> {
        self.provider_health
            .iter()
            .map(|(k, v)| (k.clone(), v.healthy))
            .collect()
    }

    /// Select the best model for a given task
    pub fn select_model(&self, requirements: ModelRequirements) -> Result<String> {
        trace!("Selecting model for requirements: {:?}", requirements);

        // Define model capabilities
        let models = vec![
            ("gpt-4", ModelCapabilities {
                context_window: 8192,
                supports_vision: false,
                supports_functions: true,
                supports_streaming: true,
                cost_tier: 3,
            }),
            ("gpt-4-turbo", ModelCapabilities {
                context_window: 128000,
                supports_vision: true,
                supports_functions: true,
                supports_streaming: true,
                cost_tier: 3,
            }),
            ("gpt-3.5-turbo", ModelCapabilities {
                context_window: 16385,
                supports_vision: false,
                supports_functions: true,
                supports_streaming: true,
                cost_tier: 1,
            }),
            ("claude-3-opus", ModelCapabilities {
                context_window: 200000,
                supports_vision: true,
                supports_functions: false,
                supports_streaming: true,
                cost_tier: 3,
            }),
            ("claude-3-sonnet", ModelCapabilities {
                context_window: 200000,
                supports_vision: true,
                supports_functions: false,
                supports_streaming: true,
                cost_tier: 2,
            }),
            ("claude-3-haiku", ModelCapabilities {
                context_window: 200000,
                supports_vision: true,
                supports_functions: false,
                supports_streaming: true,
                cost_tier: 1,
            }),
            ("llama3", ModelCapabilities {
                context_window: 8192,
                supports_vision: false,
                supports_functions: false,
                supports_streaming: true,
                cost_tier: 0,
            }),
        ];

        // Filter models by requirements
        let candidates: Vec<_> = models
            .into_iter()
            .filter(|(_, caps)| {
                if let Some(min_context) = requirements.min_context_window {
                    if caps.context_window < min_context {
                        return false;
                    }
                }
                if requirements.requires_vision && !caps.supports_vision {
                    return false;
                }
                if requirements.requires_functions && !caps.supports_functions {
                    return false;
                }
                if requirements.requires_streaming && !caps.supports_streaming {
                    return false;
                }
                if let Some(max_cost) = requirements.max_cost_tier {
                    if caps.cost_tier > max_cost {
                        return false;
                    }
                }
                true
            })
            .collect();

        if candidates.is_empty() {
            return Err(LlmError::ModelNotAvailable(
                "No models match the requirements".to_string(),
            ));
        }

        // Select best model based on strategy
        let selected = match self.config.strategy {
            RoutingStrategy::CostOptimized => {
                candidates.into_iter().min_by_key(|(_, caps)| caps.cost_tier)
            }
            RoutingStrategy::CapabilityBased => {
                candidates.into_iter().max_by_key(|(_, caps)| caps.context_window)
            }
            _ => candidates.first().cloned(),
        };

        selected
            .map(|(name, _)| name.to_string())
            .ok_or_else(|| LlmError::ModelNotAvailable("No suitable model found".to_string()))
    }
}

/// Model requirements for selection
#[derive(Debug, Clone, Default)]
pub struct ModelRequirements {
    /// Minimum context window required
    pub min_context_window: Option<u32>,
    /// Requires vision capabilities
    pub requires_vision: bool,
    /// Requires function calling
    pub requires_functions: bool,
    /// Requires streaming
    pub requires_streaming: bool,
    /// Maximum cost tier (0 = free, higher = more expensive)
    pub max_cost_tier: Option<u32>,
}

impl ModelRequirements {
    /// Create new requirements
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum context window
    pub fn with_min_context(mut self, tokens: u32) -> Self {
        self.min_context_window = Some(tokens);
        self
    }

    /// Require vision capabilities
    pub fn with_vision(mut self) -> Self {
        self.requires_vision = true;
        self
    }

    /// Require function calling
    pub fn with_functions(mut self) -> Self {
        self.requires_functions = true;
        self
    }

    /// Require streaming
    pub fn with_streaming(mut self) -> Self {
        self.requires_streaming = true;
        self
    }

    /// Set maximum cost tier
    pub fn with_max_cost(mut self, tier: u32) -> Self {
        self.max_cost_tier = Some(tier);
        self
    }
}

/// Model capabilities
#[derive(Debug, Clone)]
struct ModelCapabilities {
    context_window: u32,
    supports_vision: bool,
    supports_functions: bool,
    supports_streaming: bool,
    cost_tier: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_config_default() {
        let config = RoutingConfig::default();
        assert_eq!(config.strategy, RoutingStrategy::Explicit);
        assert!(config.enable_failover);
        assert_eq!(config.max_failover_attempts, 2);
    }

    #[test]
    fn test_routing_config_builder() {
        let config = RoutingConfig::default()
            .with_strategy(RoutingStrategy::CostOptimized)
            .with_provider_priority("openai", 90)
            .with_model_mapping("custom-model", "custom-provider")
            .with_failover(false)
            .with_max_failover_attempts(5);

        assert_eq!(config.strategy, RoutingStrategy::CostOptimized);
        assert_eq!(config.provider_priority.get("openai"), Some(&90));
        assert_eq!(
            config.model_mappings.get("custom-model"),
            Some(&"custom-provider".to_string())
        );
        assert!(!config.enable_failover);
        assert_eq!(config.max_failover_attempts, 5);
    }

    #[test]
    fn test_route_explicit() {
        let config = RoutingConfig::default();
        let router = ModelRouter::new(&config);

        assert_eq!(router.route("gpt-4").unwrap(), "openai");
        assert_eq!(router.route("claude-3-opus").unwrap(), "anthropic");
        assert_eq!(router.route("llama2").unwrap(), "ollama");
        assert_eq!(router.route("llama3").unwrap(), "ollama");
    }

    #[test]
    fn test_route_explicit_prefix() {
        let config = RoutingConfig::default();
        let router = ModelRouter::new(&config);

        assert_eq!(router.route("gpt-4-turbo-preview").unwrap(), "openai");
        assert_eq!(router.route("claude-3-sonnet-20240229").unwrap(), "anthropic");
    }

    #[test]
    fn test_route_inference() {
        let config = RoutingConfig::default();
        let router = ModelRouter::new(&config);

        assert_eq!(router.route("gpt-3.5-turbo-0125").unwrap(), "openai");
        assert_eq!(router.route("claude-2.1").unwrap(), "anthropic");
        assert_eq!(router.route("mistral-7b").unwrap(), "ollama");
    }

    #[test]
    fn test_model_requirements() {
        let req = ModelRequirements::new()
            .with_min_context(100000)
            .with_vision()
            .with_streaming();

        assert_eq!(req.min_context_window, Some(100000));
        assert!(req.requires_vision);
        assert!(req.requires_streaming);
        assert!(!req.requires_functions);
    }

    #[test]
    fn test_select_model() {
        let config = RoutingConfig::default();
        let router = ModelRouter::new(&config);

        // Test cost-optimized selection
        let req = ModelRequirements::new()
            .with_max_cost(1)
            .with_streaming();
        
        let model = router.select_model(req).unwrap();
        assert!(model == "gpt-3.5-turbo" || model == "claude-3-haiku" || model == "llama3");

        // Test vision requirement
        let req = ModelRequirements::new().with_vision();
        let model = router.select_model(req).unwrap();
        assert!(
            model == "gpt-4-turbo"
                || model == "claude-3-opus"
                || model == "claude-3-sonnet"
                || model == "claude-3-haiku"
        );
    }

    #[test]
    fn test_round_robin() {
        let config = RoutingConfig::default().with_strategy(RoutingStrategy::RoundRobin);
        let router = ModelRouter::new(&config);

        let provider1 = router.route("any-model").unwrap();
        let provider2 = router.route("any-model").unwrap();
        
        // Should cycle through providers
        assert_ne!(provider1, provider2);
    }

    #[test]
    fn test_provider_health() {
        let config = RoutingConfig::default();
        let mut router = ModelRouter::new(&config);

        assert!(router.is_provider_healthy("openai"));
        
        router.mark_unhealthy("openai");
        assert!(!router.is_provider_healthy("openai"));
        
        router.mark_healthy("openai");
        assert!(router.is_provider_healthy("openai"));
    }
}
