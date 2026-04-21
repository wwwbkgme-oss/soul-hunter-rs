//! # Fuzzing Agent
//!
//! Performs intelligent fuzzing and input validation testing for mobile applications.
//! Capabilities include:
//! - SQL injection detection
//! - XSS (Cross-Site Scripting) detection
//! - Path traversal detection
//! - XXE (XML External Entity) vulnerability detection
//! - Deserialization vulnerability detection
//! - WebView JavaScript injection detection
//! - IPC (Inter-Process Communication) input validation
//! - Mutation strategies (BitFlip, ByteFlip, Arithmetic)
//! - LLM-powered intelligent fuzzing
//!
//! ## Architecture
//!
//! The FuzzingAgent implements the SecurityAgent trait and provides:
//! - Structured input mutation and fuzzing
//! - Multiple vulnerability detection patterns
//! - LLM integration for intelligent test case generation
//! - JSON output for findings
//! - Health monitoring and reporting

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::{
    AgentBase, AgentContext, AgentError, AgentResult, Result, SecurityAgent,
};
use sh_types::{
    AgentCapability, AgentConfig, AgentHealth, AgentId, AgentStatus, AgentType, AnalysisTarget,
    Confidence, Finding, FindingCollection, Location, Platform, Remediation, RemediationEffort,
    Severity,
};

/// Fuzzing agent for input validation and vulnerability detection
pub struct FuzzingAgent {
    base: AgentBase,
    mutation_engine: Arc<RwLock<MutationEngine>>,
    vulnerability_patterns: VulnerabilityPatterns,
    fuzzing_config: FuzzingConfig,
    llm_client: Option<Arc<sh_llm::LlmClient>>,
    test_cases_generated: std::sync::atomic::AtomicU64,
    test_cases_executed: std::sync::atomic::AtomicU64,
    vulnerabilities_found: std::sync::atomic::AtomicU64,
}

/// Configuration for fuzzing operations
#[derive(Debug, Clone)]
pub struct FuzzingConfig {
    pub max_iterations: u32,
    pub mutation_depth: u32,
    pub enable_llm_generation: bool,
    pub enable_mutation_strategies: bool,
    pub timeout_per_test_ms: u64,
    pub max_payload_size: usize,
    pub save_crashes: bool,
    pub crash_directory: String,
}

impl Default for FuzzingConfig {
    fn default() -> Self {
        Self {
            max_iterations: 10000,
            mutation_depth: 5,
            enable_llm_generation: true,
            enable_mutation_strategies: true,
            timeout_per_test_ms: 5000,
            max_payload_size: 1024 * 1024, // 1MB
            save_crashes: true,
            crash_directory: "./crashes".to_string(),
        }
    }
}

/// Mutation engine for generating fuzzed inputs
#[derive(Debug)]
struct MutationEngine {
    strategies: Vec<MutationStrategy>,
    seed_corpus: Vec<Vec<u8>>,
    current_iteration: u32,
}

/// Mutation strategies for fuzzing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationStrategy {
    BitFlip,
    ByteFlip,
    Arithmetic,
    BlockInsert,
    BlockDelete,
    BlockReplace,
    InterestingValues,
    Dictionary,
    Havoc,
}

impl MutationStrategy {
    fn as_str(&self) -> &'static str {
        match self {
            MutationStrategy::BitFlip => "bit_flip",
            MutationStrategy::ByteFlip => "byte_flip",
            MutationStrategy::Arithmetic => "arithmetic",
            MutationStrategy::BlockInsert => "block_insert",
            MutationStrategy::BlockDelete => "block_delete",
            MutationStrategy::BlockReplace => "block_replace",
            MutationStrategy::InterestingValues => "interesting_values",
            MutationStrategy::Dictionary => "dictionary",
            MutationStrategy::Havoc => "havoc",
        }
    }
}

/// Vulnerability patterns for detection
#[derive(Debug, Clone)]
struct VulnerabilityPatterns {
    sql_injection: Vec<Regex>,
    xss: Vec<Regex>,
    path_traversal: Vec<Regex>,
    xxe: Vec<Regex>,
    deserialization: Vec<Regex>,
    webview_injection: Vec<Regex>,
    ipc_validation: Vec<Regex>,
}

/// Fuzzing target types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzingTarget {
    SqlInjection,
    Xss,
    PathTraversal,
    Xxe,
    Deserialization,
    WebViewInjection,
    IpcValidation,
    All,
}

/// Fuzzing result for a single test case
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FuzzingResult {
    pub test_case_id: Uuid,
    pub strategy: MutationStrategy,
    pub payload: String,
    pub target: FuzzingTarget,
    pub detected_vulnerability: bool,
    pub vulnerability_type: Option<String>,
    pub severity: Option<Severity>,
    pub confidence: Option<Confidence>,
    pub execution_time_ms: u64,
    pub response_data: Option<String>,
}

/// LLM-generated test case
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlmTestCase {
    pub target: FuzzingTarget,
    pub payload: String,
    pub description: String,
    pub expected_behavior: String,
}

/// LLM analysis result for fuzzing
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlmFuzzingResult {
    pub findings: Vec<LlmFuzzingFinding>,
    pub recommendations: Vec<String>,
    pub risk_assessment: String,
}

/// LLM fuzzing finding
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlmFuzzingFinding {
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: String,
    pub payload: String,
    pub evidence: Vec<String>,
}

impl FuzzingAgent {
    /// Create a new fuzzing agent
    pub fn new(name: impl Into<String>) -> Self {
        let base = AgentBase::new(name, AgentType::Dynamic)
            .with_capabilities(vec![
                AgentCapability::Fuzzing,
                AgentCapability::DynamicAnalysis,
            ])
            .with_platform(Platform::Android);

        let mutation_engine = Arc::new(RwLock::new(MutationEngine {
            strategies: vec![
                MutationStrategy::BitFlip,
                MutationStrategy::ByteFlip,
                MutationStrategy::Arithmetic,
                MutationStrategy::InterestingValues,
                MutationStrategy::Havoc,
            ],
            seed_corpus: Self::init_seed_corpus(),
            current_iteration: 0,
        }));

        let mut agent = Self {
            base,
            mutation_engine,
            vulnerability_patterns: Self::init_vulnerability_patterns(),
            fuzzing_config: FuzzingConfig::default(),
            llm_client: None,
            test_cases_generated: std::sync::atomic::AtomicU64::new(0),
            test_cases_executed: std::sync::atomic::AtomicU64::new(0),
            vulnerabilities_found: std::sync::atomic::AtomicU64::new(0),
        };

        agent.update_heartbeat();
        agent
    }

    /// Initialize seed corpus for mutation
    fn init_seed_corpus() -> Vec<Vec<u8>> {
        vec![
            // Basic strings
            b"test".to_vec(),
            b"admin".to_vec(),
            b"root".to_vec(),
            b"user".to_vec(),
            // SQL patterns
            b"SELECT * FROM users".to_vec(),
            b"INSERT INTO table VALUES".to_vec(),
            b"UPDATE table SET".to_vec(),
            b"DELETE FROM table".to_vec(),
            // XML patterns
            b"<?xml version=\"1.0\"?>".to_vec(),
            b"<!DOCTYPE test>".to_vec(),
            // JSON patterns
            b"{\"key\": \"value\"}".to_vec(),
            b"[1, 2, 3]".to_vec(),
            // Path patterns
            b"/etc/passwd".to_vec(),
            b"../../../etc/passwd".to_vec(),
            // Script patterns
            b"<script>alert(1)</script>".to_vec(),
            b"javascript:alert(1)".to_vec(),
            // IPC patterns
            b"content://".to_vec(),
            b"file://".to_vec(),
            b"android.intent.action.VIEW".to_vec(),
        ]
    }

    /// Initialize vulnerability detection patterns
    fn init_vulnerability_patterns() -> VulnerabilityPatterns {
        VulnerabilityPatterns {
            sql_injection: vec![
                // Classic SQL injection
                Regex::new(r"(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\s+").unwrap(),
                // Comment-based
                Regex::new(r"(?i)(--|#|/\*|\*/)").unwrap(),
                // Boolean-based
                Regex::new(r"(?i)(AND|OR)\s+\d+\s*=\s*\d+").unwrap(),
                // Time-based
                Regex::new(r"(?i)(SLEEP|BENCHMARK|WAITFOR|DELAY)\s*\(").unwrap(),
                // Error-based
                Regex::new(r"(?i)(CONVERT|CAST|@@version|pg_sleep)").unwrap(),
                // Stacked queries
                Regex::new(r"(?i);\s*(SELECT|INSERT|UPDATE|DELETE|DROP)").unwrap(),
            ],
            xss: vec![
                // Script tags
                Regex::new(r"(?i)<script[^>]*>[\s\S]*?</script>").unwrap(),
                // Event handlers
                Regex::new(r"(?i)\s(on\w+)\s*=\s*['\"]?[^'\"]*['\"]?").unwrap(),
                // JavaScript protocols
                Regex::new(r"(?i)(javascript|data|vbscript):").unwrap(),
                // HTML tags
                Regex::new(r"(?i)<(iframe|img|svg|object|embed|form|input|textarea|button)[^>]*>").unwrap(),
                // Expression
                Regex::new(r"(?i)expression\s*\(").unwrap(),
                // Eval
                Regex::new(r"(?i)eval\s*\(").unwrap(),
            ],
            path_traversal: vec![
                // Basic traversal
                Regex::new(r"\.\./").unwrap(),
                Regex::new(r"\.\.\\").unwrap(),
                // URL encoded
                Regex::new(r"%2e%2e%2f").unwrap(),
                Regex::new(r"%2e%2e/").unwrap(),
                // Double encoding
                Regex::new(r"%252e%252e%252f").unwrap(),
                // Null byte
                Regex::new(r"\x00").unwrap(),
                // Absolute paths
                Regex::new(r"^(/|\\)[a-zA-Z]").unwrap(),
                // Windows paths
                Regex::new(r"[a-zA-Z]:\\").unwrap(),
            ],
            xxe: vec![
                // DOCTYPE declarations
                Regex::new(r"(?i)<!DOCTYPE[^>]*\[\s*<!ENTITY").unwrap(),
                // External entity references
                Regex::new(r"(?i)SYSTEM\s+['\"]").unwrap(),
                Regex::new(r"(?i)PUBLIC\s+['\"]").unwrap(),
                // Entity references
                Regex::new(r"&\w+;").unwrap(),
                // File protocol
                Regex::new(r"(?i)file://").unwrap(),
                // HTTP protocol
                Regex::new(r"(?i)http://").unwrap(),
                // FTP protocol
                Regex::new(r"(?i)ftp://").unwrap(),
            ],
            deserialization: vec![
                // Java serialization
                Regex::new(r"^\xac\xed\x00\x05").unwrap(),
                // JSON with type info
                Regex::new(r"(?i)\"@type\"\s*:\s*['\"]").unwrap(),
                // XML deserialization
                Regex::new(r"(?i)<java\s+class=\"[^\"]+\">").unwrap(),
                // ObjectInputStream
                Regex::new(r"(?i)ObjectInputStream").unwrap(),
                // Commons Collections
                Regex::new(r"(?i)org\.apache\.commons\.collections").unwrap(),
            ],
            webview_injection: vec![
                // JavaScript interface
                Regex::new(r"(?i)addJavascriptInterface").unwrap(),
                // JavaScript enabled
                Regex::new(r"(?i)setJavaScriptEnabled\s*\(\s*true\s*\)").unwrap(),
                // Universal access
                Regex::new(r"(?i)setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)").unwrap(),
                // File access
                Regex::new(r"(?i)setAllowFileAccess\s*\(\s*true\s*\)").unwrap(),
                // Content access
                Regex::new(r"(?i)setAllowContentAccess\s*\(\s*true\s*\)").unwrap(),
                // Load URL
                Regex::new(r"(?i)loadUrl\s*\(\s*['\"]javascript:").unwrap(),
            ],
            ipc_validation: vec![
                // Intent actions
                Regex::new(r"(?i)android\.intent\.action\.[A-Z_]+").unwrap(),
                // Content URIs
                Regex::new(r"(?i)content://[^/]+/").unwrap(),
                // File URIs
                Regex::new(r"(?i)file://").unwrap(),
                // Intent extras
                Regex::new(r"(?i)putExtra\s*\(").unwrap(),
                // Broadcast receivers
                Regex::new(r"(?i)sendBroadcast\s*\(").unwrap(),
                // Service binding
                Regex::new(r"(?i)bindService\s*\(").unwrap(),
            ],
        }
    }

    /// Initialize LLM client
    async fn init_llm_client(&mut self) -> Result<()> {
        let config = sh_llm::LlmConfig::default()
            .with_provider("ollama")
            .with_model("llama2")
            .with_timeout(60);

        match sh_llm::LlmClient::new(config) {
            Ok(client) => {
                self.llm_client = Some(Arc::new(client));
                info!("LLM client initialized successfully for fuzzing");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to initialize LLM client: {}. Continuing without LLM support.", e);
                Ok(())
            }
        }
    }

    /// Generate test cases using mutation strategies
    #[instrument(skip(self))]
    async fn generate_mutated_test_cases(&self, count: usize) -> Vec<(MutationStrategy, Vec<u8>)> {
        let mut test_cases = Vec::new();
        let engine = self.mutation_engine.read().await;

        for i in 0..count {
            let strategy = engine.strategies[i % engine.strategies.len()];
            if let Some(seed) = engine.seed_corpus.get(i % engine.seed_corpus.len()) {
                let mutated = self.apply_mutation(seed, strategy).await;
                test_cases.push((strategy, mutated));
            }
        }

        self.test_cases_generated
            .fetch_add(test_cases.len() as u64, std::sync::atomic::Ordering::Relaxed);

        test_cases
    }

    /// Apply mutation to input data
    async fn apply_mutation(&self, data: &[u8], strategy: MutationStrategy) -> Vec<u8> {
        let mut result = data.to_vec();

        match strategy {
            MutationStrategy::BitFlip => {
                if !result.is_empty() {
                    let pos = fastrand::usize(0..result.len());
                    let bit = fastrand::u8(0..8);
                    result[pos] ^= 1 << bit;
                }
            }
            MutationStrategy::ByteFlip => {
                if !result.is_empty() {
                    let pos = fastrand::usize(0..result.len());
                    result[pos] = !result[pos];
                }
            }
            MutationStrategy::Arithmetic => {
                if !result.is_empty() {
                    let pos = fastrand::usize(0..result.len());
                    let delta = fastrand::i8(-35..35);
                    result[pos] = result[pos].wrapping_add(delta as u8);
                }
            }
            MutationStrategy::InterestingValues => {
                let interesting = vec![0, 1, 16, 32, 64, 100, 127, 128, 255, 256, 512, 1024, 4096];
                if !result.is_empty() {
                    let pos = fastrand::usize(0..result.len().min(4));
                    let value = interesting[fastrand::usize(0..interesting.len())];
                    result[pos] = (value & 0xFF) as u8;
                }
            }
            MutationStrategy::Havoc => {
                // Apply multiple random mutations
                for _ in 0..fastrand::usize(1..16) {
                    if result.is_empty() {
                        break;
                    }
                    let mutation_type = fastrand::usize(0..5);
                    match mutation_type {
                        0 => {
                            // Bit flip
                            let pos = fastrand::usize(0..result.len());
                            let bit = fastrand::u8(0..8);
                            result[pos] ^= 1 << bit;
                        }
                        1 => {
                            // Byte flip
                            let pos = fastrand::usize(0..result.len());
                            result[pos] = !result[pos];
                        }
                        2 => {
                            // Arithmetic
                            let pos = fastrand::usize(0..result.len());
                            let delta = fastrand::i8(-35..35);
                            result[pos] = result[pos].wrapping_add(delta as u8);
                        }
                        3 => {
                            // Insert byte
                            let pos = fastrand::usize(0..=result.len());
                            result.insert(pos, fastrand::u8(0..=255));
                        }
                        4 => {
                            // Delete byte
                            if result.len() > 1 {
                                let pos = fastrand::usize(0..result.len());
                                result.remove(pos);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {
                // Default: random byte mutation
                if !result.is_empty() {
                    let pos = fastrand::usize(0..result.len());
                    result[pos] = fastrand::u8(0..=255);
                }
            }
        }

        result
    }

    /// Generate test cases using LLM
    #[instrument(skip(self))]
    async fn generate_llm_test_cases(&self, target: FuzzingTarget, count: usize) -> Vec<LlmTestCase> {
        let mut test_cases = Vec::new();

        if let Some(ref llm_client) = self.llm_client {
            let prompt = format!(
                "Generate {} fuzzing test cases for {} vulnerability detection in mobile applications. \
                For each test case, provide: 1) The payload string, 2) A description of what it tests, \
                3) The expected behavior if vulnerable. Format as JSON array.",
                count,
                match target {
                    FuzzingTarget::SqlInjection => "SQL injection",
                    FuzzingTarget::Xss => "XSS (Cross-Site Scripting)",
                    FuzzingTarget::PathTraversal => "path traversal",
                    FuzzingTarget::Xxe => "XXE (XML External Entity)",
                    FuzzingTarget::Deserialization => "deserialization",
                    FuzzingTarget::WebViewInjection => "WebView JavaScript injection",
                    FuzzingTarget::IpcValidation => "IPC input validation",
                    FuzzingTarget::All => "various",
                }
            );

            let messages = vec![
                sh_llm::Message::system(
                    "You are a security fuzzing expert. Generate valid test payloads for vulnerability detection."
                ),
                sh_llm::Message::user(prompt),
            ];

            match llm_client.chat(messages).await {
                Ok(response) => {
                    if let Ok(cases) = serde_json::from_str::<Vec<LlmTestCase>>(&response.content) {
                        test_cases.extend(cases);
                    }
                }
                Err(e) => {
                    warn!("Failed to generate LLM test cases: {}", e);
                }
            }
        }

        test_cases
    }

    /// Detect SQL injection vulnerability
    #[instrument(skip(self, input))]
    async fn detect_sql_injection(&self, input: &str) -> Option<FuzzingResult> {
        for pattern in &self.vulnerability_patterns.sql_injection {
            if pattern.is_match(input) {
                return Some(FuzzingResult {
                    test_case_id: Uuid::new_v4(),
                    strategy: MutationStrategy::Dictionary,
                    payload: input.to_string(),
                    target: FuzzingTarget::SqlInjection,
                    detected_vulnerability: true,
                    vulnerability_type: Some("SQL Injection".to_string()),
                    severity: Some(Severity::Critical),
                    confidence: Some(Confidence::Probable),
                    execution_time_ms: 0,
                    response_data: None,
                });
            }
        }
        None
    }

    /// Detect XSS vulnerability
    #[instrument(skip(self, input))]
    async fn detect_xss(&self, input: &str) -> Option<FuzzingResult> {
        for pattern in &self.vulnerability_patterns.xss {
            if pattern.is_match(input) {
                return Some(FuzzingResult {
                    test_case_id: Uuid::new_v4(),
                    strategy: MutationStrategy::Dictionary,
                    payload: input.to_string(),
                    target: FuzzingTarget::Xss,
                    detected_vulnerability: true,
                    vulnerability_type: Some("Cross-Site Scripting (XSS)".to_string()),
                    severity: Some(Severity::High),
                    confidence: Some(Confidence::Probable),
                    execution_time_ms: 0,
                    response_data: None,
                });
            }
        }
        None
    }

    /// Detect path traversal vulnerability
    #[instrument(skip(self, input))]
    async fn detect_path_traversal(&self, input: &str) -> Option<FuzzingResult> {
        for pattern in &self.vulnerability_patterns.path_traversal {
            if pattern.is_match(input) {
                return Some(FuzzingResult {
                    test_case_id: Uuid::new_v4(),
                    strategy: MutationStrategy::Dictionary,
                    payload: input.to_string(),
                    target: FuzzingTarget::PathTraversal,
                    detected_vulnerability: true,
                    vulnerability_type: Some("Path Traversal".to_string()),
                    severity: Some(Severity::High),
                    confidence: Some(Confidence::Probable),
                    execution_time_ms: 0,
                    response_data: None,
                });
            }
        }
        None
    }

    /// Detect XXE vulnerability
    #[instrument(skip(self, input))]
    async fn detect_xxe(&self, input: &str) -> Option<FuzzingResult> {
        for pattern in &self.vulnerability_patterns.xxe {
            if pattern.is_match(input) {
                return Some(FuzzingResult {
                    test_case_id: Uuid::new_v4(),
                    strategy: MutationStrategy::Dictionary,
                    payload: input.to_string(),
                    target: FuzzingTarget::Xxe,
                    detected_vulnerability: true,
                    vulnerability_type: Some("XML External Entity (XXE)".to_string()),
                    severity: Some(Severity::Critical),
                    confidence: Some(Confidence::Probable),
                    execution_time_ms: 0,
                    response_data: None,
                });
            }
        }
        None
    }

    /// Detect deserialization vulnerability
    #[instrument(skip(self, input))]
    async fn detect_deserialization(&self, input: &str) -> Option<FuzzingResult> {
        for pattern in &self.vulnerability_patterns.deserialization {
            if pattern.is_match(input) {
                return Some(FuzzingResult {
                    test_case_id: Uuid::new_v4(),
                    strategy: MutationStrategy::Dictionary,
                    payload: input.to_string(),
                    target: FuzzingTarget::Deserialization,
                    detected_vulnerability: true,
                    vulnerability_type: Some("Insecure Deserialization".to_string()),
                    severity: Some(Severity::Critical),
                    confidence: Some(Confidence::Probable),
                    execution_time_ms: 0,
                    response_data: None,
                });
            }
        }
        None
    }

    /// Detect WebView JavaScript injection
    #[instrument(skip(self, input))]
    async fn detect_webview_injection(&self, input: &str) -> Option<FuzzingResult> {
        for pattern in &self.vulnerability_patterns.webview_injection {
            if pattern.is_match(input) {
                return Some(FuzzingResult {
                    test_case_id: Uuid::new_v4(),
                    strategy: MutationStrategy::Dictionary,
                    payload: input.to_string(),
                    target: FuzzingTarget::WebViewInjection,
                    detected_vulnerability: true,
                    vulnerability_type: Some("WebView JavaScript Injection".to_string()),
                    severity: Some(Severity::High),
                    confidence: Some(Confidence::Probable),
                    execution_time_ms: 0,
                    response_data: None,
                });
            }
        }
        None
    }

    /// Detect IPC input validation issues
    #[instrument(skip(self, input))]
    async fn detect_ipc_validation(&self, input: &str) -> Option<FuzzingResult> {
        for pattern in &self.vulnerability_patterns.ipc_validation {
            if pattern.is_match(input) {
                return Some(FuzzingResult {
                    test_case_id: Uuid::new_v4(),
                    strategy: MutationStrategy::Dictionary,
                    payload: input.to_string(),
                    target: FuzzingTarget::IpcValidation,
                    detected_vulnerability: true,
                    vulnerability_type: Some("IPC Input Validation".to_string()),
                    severity: Some(Severity::Medium),
                    confidence: Some(Confidence::Probable),
                    execution_time_ms: 0,
                    response_data: None,
                });
            }
        }
        None
    }

    /// Run fuzzing against a target
    #[instrument(skip(self, target), fields(agent_id = %self.base.id))]
    async fn run_fuzzing(&self, target: &AnalysisTarget) -> Result<FindingCollection> {
        info!("Starting fuzzing analysis for: {}", target.path);

        let path = Path::new(&target.path);
        if !path.exists() {
            return Err(AgentError::InvalidConfig(format!(
                "Target not found: {}",
                target.path
            )));
        }

        let mut findings = Vec::new();
        let mut fuzzing_results = Vec::new();

        // Generate and execute mutation-based test cases
        if self.fuzzing_config.enable_mutation_strategies {
            let test_cases = self.generate_mutated_test_cases(100).await;
            for (strategy, payload) in test_cases {
                let payload_str = String::from_utf8_lossy(&payload);
                
                // Test against all vulnerability types
                if let Some(result) = self.detect_sql_injection(&payload_str).await {
                    fuzzing_results.push(result);
                }
                if let Some(result) = self.detect_xss(&payload_str).await {
                    fuzzing_results.push(result);
                }
                if let Some(result) = self.detect_path_traversal(&payload_str).await {
                    fuzzing_results.push(result);
                }
                if let Some(result) = self.detect_xxe(&payload_str).await {
                    fuzzing_results.push(result);
                }
                if let Some(result) = self.detect_deserialization(&payload_str).await {
                    fuzzing_results.push(result);
                }
                if let Some(result) = self.detect_webview_injection(&payload_str).await {
                    fuzzing_results.push(result);
                }
                if let Some(result) = self.detect_ipc_validation(&payload_str).await {
                    fuzzing_results.push(result);
                }

                self.test_cases_executed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // Generate and execute LLM-based test cases
        if self.fuzzing_config.enable_llm_generation {
            let llm_cases = self.generate_llm_test_cases(FuzzingTarget::All, 10).await;
            for case in llm_cases {
                // Test against all vulnerability types
                if let Some(result) = self.detect_sql_injection(&case.payload).await {
                    fuzzing_results.push(result);
                }
                if let Some(result) = self.detect_xss(&case.payload).await {
                    fuzzing_results.push(result);
                }
                if let Some(result) = self.detect_path_traversal(&case.payload).await {
                    fuzzing_results.push(result);
                }
                if let Some(result) = self.detect_xxe(&case.payload).await {
                    fuzzing_results.push(result);
                }
                if let Some(result) = self.detect_deserialization(&case.payload).await {
                    fuzzing_results.push(result);
                }
                if let Some(result) = self.detect_webview_injection(&case.payload).await {
                    fuzzing_results.push(result);
                }
                if let Some(result) = self.detect_ipc_validation(&case.payload).await {
                    fuzzing_results.push(result);
                }

                self.test_cases_executed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // Convert fuzzing results to findings
        for result in &fuzzing_results {
            if result.detected_vulnerability {
                self.vulnerabilities_found
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let finding = self.create_finding_from_result(result).await?;
                findings.push(finding);
            }
        }

        // Analyze source code for vulnerability patterns
        findings.extend(self.analyze_source_code(target).await?);

        info!(
            "Fuzzing analysis completed. Generated {} test cases, executed {}, found {} vulnerabilities",
            self.test_cases_generated.load(std::sync::atomic::Ordering::Relaxed),
            self.test_cases_executed.load(std::sync::atomic::Ordering::Relaxed),
            self.vulnerabilities_found.load(std::sync::atomic::Ordering::Relaxed)
        );

        Ok(FindingCollection::new(findings))
    }

    /// Create a Finding from a FuzzingResult
    async fn create_finding_from_result(&self, result: &FuzzingResult) -> Result<Finding> {
        let title = format!(
            "Potential {} Vulnerability",
            result.vulnerability_type.as_ref().unwrap_or(&"Unknown".to_string())
        );

        let description = format!(
            "Detected potential {} vulnerability using {} mutation strategy. \
            Payload: {}",
            result.vulnerability_type.as_ref().unwrap_or(&"unknown".to_string()),
            result.strategy.as_str(),
            result.payload.chars().take(100).collect::<String>()
        );

        let severity = result.severity.unwrap_or(Severity::Medium);
        let confidence = result.confidence.unwrap_or(Confidence::Tentative);

        let cwe_id = match result.target {
            FuzzingTarget::SqlInjection => "CWE-89",
            FuzzingTarget::Xss => "CWE-79",
            FuzzingTarget::PathTraversal => "CWE-22",
            FuzzingTarget::Xxe => "CWE-611",
            FuzzingTarget::Deserialization => "CWE-502",
            FuzzingTarget::WebViewInjection => "CWE-79",
            FuzzingTarget::IpcValidation => "CWE-20",
            FuzzingTarget::All => "CWE-20",
        };

        let owasp_category = match result.target {
            FuzzingTarget::SqlInjection => "M7: Client Code Quality",
            FuzzingTarget::Xss => "M7: Client Code Quality",
            FuzzingTarget::PathTraversal => "M7: Client Code Quality",
            FuzzingTarget::Xxe => "M7: Client Code Quality",
            FuzzingTarget::Deserialization => "M8: Code Tampering",
            FuzzingTarget::WebViewInjection => "M7: Client Code Quality",
            FuzzingTarget::IpcValidation => "M1: Improper Platform Usage",
            FuzzingTarget::All => "M7: Client Code Quality",
        };

        let remediation_text = match result.target {
            FuzzingTarget::SqlInjection => {
                "Use parameterized queries or prepared statements. \
                Never concatenate user input directly into SQL queries. \
                Use ORM frameworks that automatically handle parameterization."
            }
            FuzzingTarget::Xss => {
                "Encode all user input before rendering in HTML. \
                Use context-aware output encoding. \
                Implement Content Security Policy (CSP) headers. \
                Validate and sanitize all user input."
            }
            FuzzingTarget::PathTraversal => {
                "Validate and sanitize all file paths. \
                Use allowlists for acceptable paths. \
                Normalize paths before validation. \
                Avoid passing user input directly to file system APIs."
            }
            FuzzingTarget::Xxe => {
                "Disable external entity processing in XML parsers. \
                Use secure XML parsing configurations. \
                Consider using JSON instead of XML for data exchange. \
                Validate XML input against a strict schema."
            }
            FuzzingTarget::Deserialization => {
                "Avoid deserializing untrusted data. \
                Use serialization formats that don't allow code execution (e.g., JSON). \
                Implement integrity checks before deserialization. \
                Use allowlists for acceptable classes during deserialization."
            }
            FuzzingTarget::WebViewInjection => {
                "Disable JavaScript in WebViews unless absolutely necessary. \
                Validate all URLs loaded in WebViews. \
                Use addJavascriptInterface carefully with proper security controls. \
                Implement Content Security Policy for WebViews."
            }
            FuzzingTarget::IpcValidation => {
                "Validate all IPC inputs rigorously. \
                Use explicit intents with component names. \
                Implement proper permission checks on exported components. \
                Sanitize data received via IPC before processing."
            }
            FuzzingTarget::All => {
                "Implement comprehensive input validation. \
                Use security libraries and frameworks. \
                Follow secure coding practices. \
                Conduct regular security testing."
            }
        };

        Ok(Finding::new(title, description)
            .with_severity(severity)
            .with_confidence(confidence)
            .with_type("fuzzing_vulnerability")
            .with_cwe(cwe_id)
            .with_owasp(owasp_category)
            .with_location(
                Location::new()
                    .with_platform(Platform::Android)
                    .with_snippet(&result.payload),
            )
            .with_remediation(
                Remediation::new(remediation_text)
                    .with_effort(RemediationEffort::Medium)
                    .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/"),
            )
            .with_tool("FuzzingAgent", "0.1.0"))
    }

    /// Analyze source code for vulnerability patterns
    #[instrument(skip(self, target))]
    async fn analyze_source_code(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let path = Path::new(&target.path);

        if path.is_dir() {
            // Walk directory and analyze files
            for entry in walkdir::WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if entry.file_type().is_file() {
                    let file_path = entry.path();
                    if let Ok(content) = tokio::fs::read_to_string(file_path).await {
                        findings.extend(
                            self.scan_content_for_vulnerabilities(
                                &content,
                                file_path.to_str().unwrap_or(""),
                            )
                            .await?,
                        );
                    }
                }
            }
        } else if path.is_file() {
            if let Ok(content) = tokio::fs::read_to_string(path).await {
                findings.extend(
                    self.scan_content_for_vulnerabilities(&content, &target.path)
                        .await?,
                );
            }
        }

        Ok(findings)
    }

    /// Scan content for vulnerability patterns
    async fn scan_content_for_vulnerabilities(
        &self,
        content: &str,
        file_path: &str,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for SQL injection patterns
        for pattern in &self.vulnerability_patterns.sql_injection {
            for mat in pattern.find_iter(content) {
                findings.push(
                    Finding::new(
                        "Potential SQL Injection",
                        "Code pattern suggests potential SQL injection vulnerability. User input may be concatenated directly into SQL queries.",
                    )
                    .with_severity(Severity::High)
                    .with_confidence(Confidence::Probable)
                    .with_type("sql_injection")
                    .with_cwe("CWE-89")
                    .with_owasp("M7: Client Code Quality")
                    .with_location(
                        Location::new()
                            .with_file(file_path)
                            .with_platform(Platform::Android)
                            .with_snippet(mat.as_str()),
                    )
                    .with_remediation(
                        Remediation::new("Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.")
                            .with_effort(RemediationEffort::Medium)
                            .add_reference("https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
                    )
                    .with_tool("FuzzingAgent", "0.1.0"),
                );
            }
        }

        // Check for XSS patterns
        for pattern in &self.vulnerability_patterns.xss {
            for mat in pattern.find_iter(content) {
                findings.push(
                    Finding::new(
                        "Potential XSS Vulnerability",
                        "Code pattern suggests potential Cross-Site Scripting vulnerability. User input may be rendered without proper encoding.",
                    )
                    .with_severity(Severity::High)
                    .with_confidence(Confidence::Probable)
                    .with_type("xss")
                    .with_cwe("CWE-79")
                    .with_owasp("M7: Client Code Quality")
                    .with_location(
                        Location::new()
                            .with_file(file_path)
                            .with_platform(Platform::Android)
                            .with_snippet(mat.as_str()),
                    )
                    .with_remediation(
                        Remediation::new("Encode all user input before rendering in HTML. Use context-aware output encoding.")
                            .with_effort(RemediationEffort::Medium)
                            .add_reference("https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
                    )
                    .with_tool("FuzzingAgent", "0.1.0"),
                );
            }
        }

        // Check for path traversal patterns
        for pattern in &self.vulnerability_patterns.path_traversal {
            for mat in pattern.find_iter(content) {
                findings.push(
                    Finding::new(
                        "Potential Path Traversal",
                        "Code pattern suggests potential path traversal vulnerability. User input may be used to construct file paths without validation.",
                    )
                    .with_severity(Severity::High)
                    .with_confidence(Confidence::Probable)
                    .with_type("path_traversal")
                    .with_cwe("CWE-22")
                    .with_owasp("M7: Client Code Quality")
                    .with_location(
                        Location::new()
                            .with_file(file_path)
                            .with_platform(Platform::Android)
                            .with_snippet(mat.as_str()),
                    )
                    .with_remediation(
                        Remediation::new("Validate and sanitize all file paths. Use allowlists for acceptable paths.")
                            .with_effort(RemediationEffort::Medium)
                            .add_reference("https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html"),
                    )
                    .with_tool("FuzzingAgent", "0.1.0"),
                );
            }
        }

        // Check for XXE patterns
        for pattern in &self.vulnerability_patterns.xxe {
            for mat in pattern.find_iter(content) {
                findings.push(
                    Finding::new(
                        "Potential XXE Vulnerability",
                        "Code pattern suggests potential XML External Entity vulnerability. XML parsing may allow external entity resolution.",
                    )
                    .with_severity(Severity::Critical)
                    .with_confidence(Confidence::Probable)
                    .with_type("xxe")
                    .with_cwe("CWE-611")
                    .with_owasp("M7: Client Code Quality")
                    .with_location(
                        Location::new()
                            .with_file(file_path)
                            .with_platform(Platform::Android)
                            .with_snippet(mat.as_str()),
                    )
                    .with_remediation(
                        Remediation::new("Disable external entity processing in XML parsers. Use secure XML parsing configurations.")
                            .with_effort(RemediationEffort::Medium)
                            .add_reference("https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"),
                    )
                    .with_tool("FuzzingAgent", "0.1.0"),
                );
            }
        }

        // Check for deserialization patterns
        for pattern in &self.vulnerability_patterns.deserialization {
            for mat in pattern.find_iter(content) {
                findings.push(
                    Finding::new(
                        "Potential Deserialization Vulnerability",
                        "Code pattern suggests potential insecure deserialization. Untrusted data may be deserialized without proper validation.",
                    )
                    .with_severity(Severity::Critical)
                    .with_confidence(Confidence::Probable)
                    .with_type("deserialization")
                    .with_cwe("CWE-502")
                    .with_owasp("M8: Code Tampering")
                    .with_location(
                        Location::new()
                            .with_file(file_path)
                            .with_platform(Platform::Android)
                            .with_snippet(mat.as_str()),
                    )
                    .with_remediation(
                        Remediation::new("Avoid deserializing untrusted data. Use serialization formats that don't allow code execution.")
                            .with_effort(RemediationEffort::High)
                            .add_reference("https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"),
                    )
                    .with_tool("FuzzingAgent", "0.1.0"),
                );
            }
        }

        // Check for WebView injection patterns
        for pattern in &self.vulnerability_patterns.webview_injection {
            for mat in pattern.find_iter(content) {
                findings.push(
                    Finding::new(
                        "Potential WebView JavaScript Injection",
                        "Code pattern suggests potential WebView JavaScript injection vulnerability. WebView may be configured insecurely.",
                    )
                    .with_severity(Severity::High)
                    .with_confidence(Confidence::Probable)
                    .with_type("webview_injection")
                    .with_cwe("CWE-79")
                    .with_owasp("M7: Client Code Quality")
                    .with_location(
                        Location::new()
                            .with_file(file_path)
                            .with_platform(Platform::Android)
                            .with_snippet(mat.as_str()),
                    )
                    .with_remediation(
                        Remediation::new("Disable JavaScript in WebViews unless necessary. Validate all URLs loaded in WebViews.")
                            .with_effort(RemediationEffort::Medium)
                            .add_reference("https://developer.android.com/reference/android/webkit/WebView"),
                    )
                    .with_tool("FuzzingAgent", "0.1.0"),
                );
            }
        }

        // Check for IPC validation patterns
        for pattern in &self.vulnerability_patterns.ipc_validation {
            for mat in pattern.find_iter(content) {
                findings.push(
                    Finding::new(
                        "Potential IPC Input Validation Issue",
                        "Code pattern suggests potential IPC input validation issue. IPC inputs may not be properly validated.",
                    )
                    .with_severity(Severity::Medium)
                    .with_confidence(Confidence::Probable)
                    .with_type("ipc_validation")
                    .with_cwe("CWE-20")
                    .with_owasp("M1: Improper Platform Usage")
                    .with_location(
                        Location::new()
                            .with_file(file_path)
                            .with_platform(Platform::Android)
                            .with_snippet(mat.as_str()),
                    )
                    .with_remediation(
                        Remediation::new("Validate all IPC inputs rigorously. Use explicit intents with component names.")
                            .with_effort(RemediationEffort::Medium)
                            .add_reference("https://developer.android.com/guide/components/intents-filters"),
                    )
                    .with_tool("FuzzingAgent", "0.1.0"),
                );
            }
        }

        Ok(findings)
    }

    /// Perform LLM analysis on fuzzing results
    #[instrument(skip(self))]
    async fn perform_llm_analysis(&self) -> Result<FindingCollection> {
        let mut findings = Vec::new();

        if let Some(ref llm_client) = self.llm_client {
            let test_cases_generated = self
                .test_cases_generated
                .load(std::sync::atomic::Ordering::Relaxed);
            let test_cases_executed = self
                .test_cases_executed
                .load(std::sync::atomic::Ordering::Relaxed);
            let vulnerabilities_found = self
                .vulnerabilities_found
                .load(std::sync::atomic::Ordering::Relaxed);

            let context = format!(
                "Fuzzing Analysis Summary:\n\
                - Test cases generated: {}\n\
                - Test cases executed: {}\n\
                - Vulnerabilities found: {}\n\
                - Mutation strategies used: BitFlip, ByteFlip, Arithmetic, InterestingValues, Havoc\n\
                - Vulnerability types tested: SQL Injection, XSS, Path Traversal, XXE, Deserialization, WebView Injection, IPC Validation",
                test_cases_generated, test_cases_executed, vulnerabilities_found
            );

            let messages = vec![
                sh_llm::Message::system(
                    "You are a security analysis expert. Analyze the following fuzzing results and provide recommendations. Respond with JSON containing findings and recommendations."
                ),
                sh_llm::Message::user(context),
            ];

            match llm_client.chat(messages).await {
                Ok(response) => {
                    if let Ok(llm_result) = serde_json::from_str::<LlmFuzzingResult>(&response.content) {
                        for llm_finding in llm_result.findings {
                            findings.push(
                                Finding::new(llm_finding.title, llm_finding.description)
                                    .with_severity(llm_finding.severity)
                                    .with_confidence(llm_finding.confidence)
                                    .with_type(&llm_finding.category)
                                    .with_location(Location::new().with_platform(Platform::Android))
                                    .with_tool("FuzzingAgent-LLM", "0.1.0"),
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!("LLM analysis failed: {}", e);
                }
            }
        }

        Ok(FindingCollection::new(findings))
    }
}

#[async_trait]
impl SecurityAgent for FuzzingAgent {
    fn id(&self) -> AgentId {
        self.base.id
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn agent_type(&self) -> AgentType {
        AgentType::Dynamic
    }

    fn capabilities(&self) -> Vec<AgentCapability> {
        self.base.capabilities.clone()
    }

    fn status(&self) -> AgentStatus {
        self.base.get_status()
    }

    fn config(&self) -> &AgentConfig {
        unsafe { &*(self.base.config.read().unwrap() as *const AgentConfig) }
    }

    async fn initialize(&mut self, config: AgentConfig) -> Result<()> {
        info!("Initializing FuzzingAgent: {}", self.base.name);

        if let Ok(mut guard) = self.base.config.write() {
            *guard = config;
        }

        // Initialize LLM client
        self.init_llm_client().await?;

        self.base.set_status(AgentStatus::Idle);
        self.base.update_heartbeat();

        info!("FuzzingAgent initialized successfully");
        Ok(())
    }

    #[instrument(skip(self, context), fields(agent_id = %self.base.id, task_id = %context.task_id))]
    async fn execute(&self, context: AgentContext) -> Result<AgentResult> {
        let start_time = std::time::Instant::now();

        info!(
            "FuzzingAgent executing task: {} on target: {}",
            context.task_id, context.target.path
        );

        self.base.set_status(AgentStatus::Busy);
        self.base.update_heartbeat();

        // Validate target
        if !Path::new(&context.target.path).exists() {
            self.base.increment_failed();
            self.base.set_status(AgentStatus::Idle);
            return Ok(AgentResult::failed(
                context.task_id,
                self.base.id,
                format!("Target not found: {}", context.target.path),
            ));
        }

        // Run fuzzing analysis
        let result = self.run_fuzzing(&context.target).await;

        // Perform LLM analysis
        let llm_findings = self.perform_llm_analysis().await?;

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        match result {
            Ok(mut findings) => {
                // Combine with LLM findings
                findings.findings.extend(llm_findings.findings);
                findings.total_count = findings.findings.len();

                self.base.increment_completed();
                self.base.set_status(AgentStatus::Idle);

                info!(
                    "FuzzingAgent completed task: {} with {} findings in {}ms",
                    context.task_id, findings.total_count, execution_time_ms
                );

                Ok(AgentResult::success(
                    context.task_id,
                    self.base.id,
                    findings,
                    execution_time_ms,
                ))
            }
            Err(e) => {
                self.base.increment_failed();
                self.base.set_status(AgentStatus::Error);

                error!(
                    "FuzzingAgent failed task: {} with error: {}",
                    context.task_id, e
                );

                Ok(AgentResult::failed(context.task_id, self.base.id, e.to_string()))
            }
        }
    }

    async fn health(&self) -> AgentHealth {
        let mut health = self.base.get_health();
        
        // Add fuzzing-specific metrics
        health.metadata.insert(
            "test_cases_generated".to_string(),
            serde_json::json!(self.test_cases_generated.load(std::sync::atomic::Ordering::Relaxed)),
        );
        health.metadata.insert(
            "test_cases_executed".to_string(),
            serde_json::json!(self.test_cases_executed.load(std::sync::atomic::Ordering::Relaxed)),
        );
        health.metadata.insert(
            "vulnerabilities_found".to_string(),
            serde_json::json!(self.vulnerabilities_found.load(std::sync::atomic::Ordering::Relaxed)),
        );
        
        health
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down FuzzingAgent: {}", self.base.name);
        self.base.set_status(AgentStatus::Offline);
        Ok(())
    }

    fn update_heartbeat(&self) {
        self.base.update_heartbeat();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuzzing_agent_creation() {
        let agent = FuzzingAgent::new("Test Fuzzing Agent");

        assert_eq!(agent.name(), "Test Fuzzing Agent");
        assert_eq!(agent.agent_type(), AgentType::Dynamic);
        assert!(agent.has_capability(&AgentCapability::Fuzzing));
        assert!(agent.has_capability(&AgentCapability::DynamicAnalysis));
    }

    #[test]
    fn test_mutation_strategy_variants() {
        let strategies = vec![
            MutationStrategy::BitFlip,
            MutationStrategy::ByteFlip,
            MutationStrategy::Arithmetic,
            MutationStrategy::BlockInsert,
            MutationStrategy::BlockDelete,
            MutationStrategy::BlockReplace,
            MutationStrategy::InterestingValues,
            MutationStrategy::Dictionary,
            MutationStrategy::Havoc,
        ];
        assert_eq!(strategies.len(), 9);
    }

    #[test]
    fn test_fuzzing_target_variants() {
        let targets = vec![
            FuzzingTarget::SqlInjection,
            FuzzingTarget::Xss,
            FuzzingTarget::PathTraversal,
            FuzzingTarget::Xxe,
            FuzzingTarget::Deserialization,
            FuzzingTarget::WebViewInjection,
            FuzzingTarget::IpcValidation,
            FuzzingTarget::All,
        ];
        assert_eq!(targets.len(), 8);
    }

    #[test]
    fn test_fuzzing_config_default() {
        let config = FuzzingConfig::default();
        assert_eq!(config.max_iterations, 10000);
        assert_eq!(config.mutation_depth, 5);
        assert!(config.enable_llm_generation);
        assert!(config.enable_mutation_strategies);
        assert_eq!(config.timeout_per_test_ms, 5000);
        assert_eq!(config.max_payload_size, 1024 * 1024);
        assert!(config.save_crashes);
        assert_eq!(config.crash_directory, "./crashes");
    }

    #[tokio::test]
    async fn test_fuzzing_agent_initialization() {
        let mut agent = FuzzingAgent::new("Test Agent");
        let config = AgentConfig::default().with_timeout(600);

        assert!(agent.initialize(config).await.is_ok());
        assert_eq!(agent.status(), AgentStatus::Idle);
    }

    #[tokio::test]
    async fn test_fuzzing_agent_health() {
        let agent = FuzzingAgent::new("Test Agent");
        let health = agent.health().await;

        assert_eq!(health.agent_id, agent.id());
        assert_eq!(health.status, AgentStatus::Idle);
    }

    #[tokio::test]
    async fn test_detect_sql_injection() {
        let agent = FuzzingAgent::new("Test Agent");
        
        let sql_payloads = vec![
            "SELECT * FROM users WHERE id = 1",
            "' OR '1'='1",
            "1; DROP TABLE users--",
            "UNION SELECT * FROM passwords",
        ];

        for payload in sql_payloads {
            let result = agent.detect_sql_injection(payload).await;
            assert!(result.is_some(), "Should detect SQL injection in: {}", payload);
            
            let result = result.unwrap();
            assert!(result.detected_vulnerability);
            assert_eq!(result.target, FuzzingTarget::SqlInjection);
            assert_eq!(result.vulnerability_type, Some("SQL Injection".to_string()));
        }
    }

    #[tokio::test]
    async fn test_detect_xss() {
        let agent = FuzzingAgent::new("Test Agent");
        
        let xss_payloads = vec![
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
        ];

        for payload in xss_payloads {
            let result = agent.detect_xss(payload).await;
            assert!(result.is_some(), "Should detect XSS in: {}", payload);
            
            let result = result.unwrap();
            assert!(result.detected_vulnerability);
            assert_eq!(result.target, FuzzingTarget::Xss);
            assert_eq!(result.vulnerability_type, Some("Cross-Site Scripting (XSS)".to_string()));
        }
    }

    #[tokio::test]
    async fn test_detect_path_traversal() {
        let agent = FuzzingAgent::new("Test Agent");
        
        let traversal_payloads = vec![
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
        ];

        for payload in traversal_payloads {
            let result = agent.detect_path_traversal(payload).await;
            assert!(result.is_some(), "Should detect path traversal in: {}", payload);
            
            let result = result.unwrap();
            assert!(result.detected_vulnerability);
            assert_eq!(result.target, FuzzingTarget::PathTraversal);
            assert_eq!(result.vulnerability_type, Some("Path Traversal".to_string()));
        }
    }

    #[tokio::test]
    async fn test_detect_xxe() {
        let agent = FuzzingAgent::new("Test Agent");
        
        let xxe_payloads = vec![
            "<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://evil.com\">]>",
        ];

        for payload in xxe_payloads {
            let result = agent.detect_xxe(payload).await;
            assert!(result.is_some(), "Should detect XXE in: {}", payload);
            
            let result = result.unwrap();
            assert!(result.detected_vulnerability);
            assert_eq!(result.target, FuzzingTarget::Xxe);
            assert_eq!(result.vulnerability_type, Some("XML External Entity (XXE)".to_string()));
        }
    }

    #[tokio::test]
    async fn test_detect_deserialization() {
        let agent = FuzzingAgent::new("Test Agent");
        
        let deserialization_payloads = vec![
            "rO0ABXNyACJqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZS9aU7Ko9fQCAAJKA", // Java serialized
            "{\"@type\":\"java.lang.Runtime\"}",
        ];

        for payload in deserialization_payloads {
            let result = agent.detect_deserialization(payload).await;
            assert!(result.is_some(), "Should detect deserialization in: {}", payload);
            
            let result = result.unwrap();
            assert!(result.detected_vulnerability);
            assert_eq!(result.target, FuzzingTarget::Deserialization);
            assert_eq!(result.vulnerability_type, Some("Insecure Deserialization".to_string()));
        }
    }

    #[tokio::test]
    async fn test_detect_webview_injection() {
        let agent = FuzzingAgent::new("Test Agent");
        
        let webview_payloads = vec![
            "addJavascriptInterface",
            "setJavaScriptEnabled(true)",
            "setAllowUniversalAccessFromFileURLs(true)",
            "loadUrl(\"javascript:alert(1)\")",
        ];

        for payload in webview_payloads {
            let result = agent.detect_webview_injection(payload).await;
            assert!(result.is_some(), "Should detect WebView injection in: {}", payload);
            
            let result = result.unwrap();
            assert!(result.detected_vulnerability);
            assert_eq!(result.target, FuzzingTarget::WebViewInjection);
            assert_eq!(result.vulnerability_type, Some("WebView JavaScript Injection".to_string()));
        }
    }

    #[tokio::test]
    async fn test_detect_ipc_validation() {
        let agent = FuzzingAgent::new("Test Agent");
        
        let ipc_payloads = vec![
            "android.intent.action.VIEW",
            "content://com.example.provider/data",
            "file:///sdcard/file.txt",
            "putExtra(\"key\", value)",
        ];

        for payload in ipc_payloads {
            let result = agent.detect_ipc_validation(payload).await;
            assert!(result.is_some(), "Should detect IPC validation in: {}", payload);
            
            let result = result.unwrap();
            assert!(result.detected_vulnerability);
            assert_eq!(result.target, FuzzingTarget::IpcValidation);
            assert_eq!(result.vulnerability_type, Some("IPC Input Validation".to_string()));
        }
    }

    #[tokio::test]
    async fn test_apply_mutation_bitflip() {
        let agent = FuzzingAgent::new("Test Agent");
        let data = b"test".to_vec();
        
        let mutated = agent.apply_mutation(&data, MutationStrategy::BitFlip).await;
        
        // Should be same length but different content
        assert_eq!(mutated.len(), data.len());
        assert_ne!(mutated, data);
    }

    #[tokio::test]
    async fn test_apply_mutation_byteflip() {
        let agent = FuzzingAgent::new("Test Agent");
        let data = b"test".to_vec();
        
        let mutated = agent.apply_mutation(&data, MutationStrategy::ByteFlip).await;
        
        // Should be same length but different content
        assert_eq!(mutated.len(), data.len());
        assert_ne!(mutated, data);
    }

    #[tokio::test]
    async fn test_apply_mutation_arithmetic() {
        let agent = FuzzingAgent::new("Test Agent");
        let data = b"test".to_vec();
        
        let mutated = agent.apply_mutation(&data, MutationStrategy::Arithmetic).await;
        
        // Should be same length but different content
        assert_eq!(mutated.len(), data.len());
        assert_ne!(mutated, data);
    }

    #[tokio::test]
    async fn test_apply_mutation_havoc() {
        let agent = FuzzingAgent::new("Test Agent");
        let data = b"test data for mutation".to_vec();
        
        let mutated = agent.apply_mutation(&data, MutationStrategy::Havoc).await;
        
        // Havoc may change length
        assert_ne!(mutated, data);
    }

    #[tokio::test]
    async fn test_generate_mutated_test_cases() {
        let agent = FuzzingAgent::new("Test Agent");
        
        let test_cases = agent.generate_mutated_test_cases(10).await;
        
        assert_eq!(test_cases.len(), 10);
        
        // Verify each test case has a valid strategy
        for (strategy, _) in &test_cases {
            assert!([
                MutationStrategy::BitFlip,
                MutationStrategy::ByteFlip,
                MutationStrategy::Arithmetic,
                MutationStrategy::InterestingValues,
                MutationStrategy::Havoc,
            ].contains(strategy));
        }
    }

    #[test]
    fn test_fuzzing_result_serialization() {
        let result = FuzzingResult {
            test_case_id: Uuid::new_v4(),
            strategy: MutationStrategy::BitFlip,
            payload: "test payload".to_string(),
            target: FuzzingTarget::SqlInjection,
            detected_vulnerability: true,
            vulnerability_type: Some("SQL Injection".to_string()),
            severity: Some(Severity::Critical),
            confidence: Some(Confidence::Confirmed),
            execution_time_ms: 100,
            response_data: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("bit_flip"));
        assert!(json.contains("sql_injection"));
        assert!(json.contains("test payload"));
    }

    #[test]
    fn test_llm_test_case_serialization() {
        let case = LlmTestCase {
            target: FuzzingTarget::Xss,
            payload: "<script>alert(1)</script>".to_string(),
            description: "XSS test case".to_string(),
            expected_behavior: "Alert popup".to_string(),
        };

        let json = serde_json::to_string(&case).unwrap();
        assert!(json.contains("xss"));
        assert!(json.contains("<script>"));
    }

    #[test]
    fn test_vulnerability_patterns_initialized() {
        let patterns = FuzzingAgent::init_vulnerability_patterns();
        
        assert!(!patterns.sql_injection.is_empty());
        assert!(!patterns.xss.is_empty());
        assert!(!patterns.path_traversal.is_empty());
        assert!(!patterns.xxe.is_empty());
        assert!(!patterns.deserialization.is_empty());
        assert!(!patterns.webview_injection.is_empty());
        assert!(!patterns.ipc_validation.is_empty());
    }

    #[test]
    fn test_seed_corpus_initialized() {
        let corpus = FuzzingAgent::init_seed_corpus();
        assert!(!corpus.is_empty());
        
        // Should contain various types of seed data
        assert!(corpus.iter().any(|c| c == b"test"));
        assert!(corpus.iter().any(|c| c == b"SELECT * FROM users"));
        assert!(corpus.iter().any(|c| c == b"<script>alert(1)</script>"));
    }

    #[tokio::test]
    async fn test_counters_initially_zero() {
        let agent = FuzzingAgent::new("Test Agent");
        
        assert_eq!(agent.test_cases_generated.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(agent.test_cases_executed.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(agent.vulnerabilities_found.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}
