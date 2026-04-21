//! Integration Tests for Soul Hunter RS
//!
//! These tests verify end-to-end workflows and feature integration.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use sh_core::prelude::*;
use sh_types::prelude::*;

/// Test end-to-end assessment workflow
#[tokio::test]
async fn test_end_to_end_assessment() {
    // Initialize orchestrator
    let config = Config::default();
    let orchestrator = Orchestrator::new(config).expect("Failed to create orchestrator");

    // Create assessment
    let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
    let assessment_config = AssessmentConfig::default();

    let assessment = orchestrator
        .create_assessment("Test Assessment".to_string(), target, assessment_config)
        .expect("Failed to create assessment");

    assert_eq!(assessment.name, "Test Assessment");
    assert_eq!(assessment.target.platform, Platform::Android);
    assert_eq!(assessment.status, AssessmentStatus::Created);
}

/// Test agent creation and management
#[tokio::test]
async fn test_agent_lifecycle() {
    use sh_agents::prelude::*;

    // Create different agent types
    let static_agent = AgentFactory::create_static_agent("Static Agent");
    let dynamic_agent = AgentFactory::create_dynamic_agent("Dynamic Agent");
    let network_agent = AgentFactory::create_network_agent("Network Agent");
    let crypto_agent = AgentFactory::create_crypto_agent("Crypto Agent");

    // Verify agent types
    assert_eq!(static_agent.agent_type(), AgentType::Static);
    assert_eq!(dynamic_agent.agent_type(), AgentType::Dynamic);
    assert_eq!(network_agent.agent_type(), AgentType::Network);
    assert_eq!(crypto_agent.agent_type(), AgentType::Crypto);
}

/// Test skill execution
#[tokio::test]
async fn test_skill_execution() {
    use sh_skills::prelude::*;

    let task_id = uuid::Uuid::new_v4();
    let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
    let ctx = SkillContext::new(task_id, target);

    // Verify context creation
    assert_eq!(ctx.task_id, task_id);
    assert_eq!(ctx.target.platform, Platform::Android);
}

/// Test finding processing
#[tokio::test]
async fn test_finding_processing() {
    use sh_finding::prelude::*;

    let engine = FindingEngine::default();

    // Create test findings
    let findings = vec![
        Finding::new("Test Finding 1", "Description 1").with_severity(Severity::High),
        Finding::new("Test Finding 2", "Description 2").with_severity(Severity::Medium),
    ];

    // Process findings
    let result = engine.process_batch(findings).await;
    assert!(result.is_ok());

    let collection = result.unwrap();
    assert_eq!(collection.total_count, 2);
}

/// Test evidence chain
#[tokio::test]
async fn test_evidence_chain() {
    use sh_evidence::prelude::*;

    let chain = EvidenceChain::new();
    let finding_id = uuid::Uuid::new_v4();

    // Add evidence
    let evidence_id = chain
        .add_evidence(
            finding_id,
            "test-tool",
            "1.0.0",
            serde_json::json!({ "test": "data" }),
            std::collections::HashMap::new(),
        )
        .expect("Failed to add evidence");

    // Verify chain
    let evidence = chain.get_evidence(finding_id);
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].id, evidence_id);

    // Verify chain integrity
    let verification = chain.verify_chain(finding_id).expect("Failed to verify chain");
    assert!(verification.is_valid);
}

/// Test risk scoring
#[tokio::test]
async fn test_risk_scoring() {
    use sh_risk::prelude::*;

    // Create risk score
    let score = RiskScore::new(7.5)
        .with_cvss(8.0)
        .with_business_impact(6.0)
        .with_threat_level(7.0);

    assert_eq!(score.overall, 7.5);
    assert_eq!(score.cvss_component, 8.0);
    assert_eq!(score.severity, Severity::High);
    assert!(score.is_high_or_above());
}

/// Test graph operations
#[tokio::test]
async fn test_attack_graph() {
    use sh_graph::prelude::*;

    let mut graph = AttackGraph::new();

    // Add nodes
    let entry_node = GraphNode::new(NodeType::EntryPoint, "Web Server")
        .with_property("port", 80)
        .with_risk_score(7.5);
    let entry_id = graph.add_node(entry_node).expect("Failed to add node");

    let target_node = GraphNode::new(NodeType::Asset, "Database")
        .with_property("sensitive", true)
        .with_risk_score(9.0);
    let target_id = graph.add_node(target_node).expect("Failed to add node");

    // Add edge
    let edge = GraphEdge::new(entry_id, target_id, "exploits")
        .with_property("cve", "CVE-2023-1234");
    graph.add_edge(edge).expect("Failed to add edge");

    // Find paths
    let paths = graph.find_paths(entry_id, target_id, 5).expect("Failed to find paths");
    assert!(!paths.is_empty());
}

/// Test policy engine
#[tokio::test]
async fn test_policy_engine() {
    use sh_policy::prelude::*;

    let config = PolicyEngineConfig::default();
    let engine = PolicyEngine::new(config).await.expect("Failed to create policy engine");

    // Create action
    let action = Action::new("scan", "/test/target").with_subject("test-user");

    // Validate action
    let result = engine.validate_action(&action, ValidationPhase::Pre).await;
    // Should succeed with default allow policy
    assert!(result.is_ok());
}

/// Test scheduler
#[tokio::test]
async fn test_scheduler() {
    use sh_scheduler::prelude::*;

    let config = SchedulerConfig::default();
    let scheduler = Scheduler::new(config);

    // Start scheduler
    scheduler.start().await.expect("Failed to start scheduler");

    // Submit job
    let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
    let job = Job::new("test_job", target);
    let job_id = scheduler.submit(job).await.expect("Failed to submit job");

    // Verify job was submitted
    let status = scheduler.get_status(job_id);
    assert!(status.is_some());

    // Shutdown
    scheduler.shutdown().await;
}

/// Test worker pool
#[tokio::test]
async fn test_worker_pool() {
    use sh_worker::prelude::*;

    let config = WorkerPoolConfig::default();
    let pool = WorkerPool::new(config);

    // Start pool
    pool.start().await.expect("Failed to start worker pool");

    // Get stats
    let stats = pool.get_stats().await;
    assert_eq!(stats.total_workers, config.min_workers);

    // Shutdown
    pool.shutdown().await.expect("Failed to shutdown worker pool");
}

/// Test executor
#[tokio::test]
async fn test_executor() {
    use sh_executor::prelude::*;

    let config = ExecutorConfig::default();
    let mut executor = Executor::new(config);

    // Start executor
    executor.start().await.expect("Failed to start executor");

    // Create and submit job
    let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
    let job = Job::new("test", target);

    // Note: Without a registered executor, this will fail
    // In a real test, we'd register a mock executor

    // Shutdown
    executor.shutdown().await.expect("Failed to shutdown executor");
}

/// Test event bus
#[tokio::test]
async fn test_event_bus() {
    use sh_event_bus::prelude::*;

    let bus = EventBus::new(100);

    // Subscribe to events
    let mut subscriber = bus.subscribe("test".to_string()).expect("Failed to subscribe");

    // Publish event
    let event = Event::new(EventType::AssessmentCreated, "test-data");
    bus.publish(event.clone()).expect("Failed to publish event");

    // Receive event (with timeout)
    let received = timeout(Duration::from_secs(1), subscriber.recv()).await;
    assert!(received.is_ok());
}

/// Test platform adapters
#[tokio::test]
async fn test_platform_adapters() {
    use sh_platform::prelude::*;

    // Test Android capabilities
    let android_caps = PlatformCapabilities::android();
    assert_eq!(android_caps.platform, Platform::Android);
    assert!(android_caps.static_analysis);
    assert!(android_caps.supports_extension("apk"));

    // Test iOS capabilities
    let ios_caps = PlatformCapabilities::ios();
    assert_eq!(ios_caps.platform, Platform::Ios);
    assert!(ios_caps.supports_extension("ipa"));

    // Test IoT capabilities
    let iot_caps = PlatformCapabilities::iot();
    assert_eq!(iot_caps.platform, Platform::Iot);
    assert!(!iot_caps.dynamic_analysis);
}

/// Test LLM integration
#[tokio::test]
async fn test_llm_config() {
    use sh_llm::prelude::*;

    let config = LlmConfig::default()
        .with_provider("ollama")
        .with_model("llama2")
        .with_timeout(120)
        .with_max_retries(5);

    assert_eq!(config.provider, "ollama");
    assert_eq!(config.model, "llama2");
    assert_eq!(config.timeout_secs, 120);
    assert_eq!(config.max_retries, 5);
}

/// Test WASM runtime
#[tokio::test]
async fn test_wasm_runtime() {
    use sh_wasm::prelude::*;

    let config = RuntimeConfig::new()
        .with_sandbox(SandboxConfig::new().with_max_memory(256 * 1024 * 1024));

    // Note: Creating actual runtime requires wasmtime which may not be available in tests
    // This test just verifies the config builder
    assert_eq!(config.sandbox.max_memory_bytes, 256 * 1024 * 1024);
}

/// Test distributed coordination
#[tokio::test]
async fn test_distributed_config() {
    use sh_distributed::prelude::*;

    let config = CoordinatorConfig {
        backend: BackendType::Redis,
        redis_url: "redis://localhost:6379".to_string(),
        worker_id: "test-worker".to_string(),
        ..Default::default()
    };

    assert_eq!(config.backend, BackendType::Redis);
    assert_eq!(config.worker_id, "test-worker");
}

/// Test dashboard configuration
#[tokio::test]
async fn test_dashboard_config() {
    use sh_dashboard::prelude::*;

    let config = DashboardConfig::default()
        .with_bind_addr("127.0.0.1:3000")
        .with_max_connections(50)
        .with_cors(false);

    assert_eq!(config.bind_addr, "127.0.0.1:3000");
    assert_eq!(config.max_connections, 50);
    assert!(!config.enable_cors);
}

/// Test orchestrator features
#[tokio::test]
async fn test_orchestrator_features() {
    use sh_orchestrator::prelude::*;

    // Test enhanced config
    let config = EnhancedConfig::default();
    assert!(config.enable_mvcc);
    assert!(config.enable_work_stealing);
    assert!(config.enable_hooks);

    // Test work-stealing config
    let ws_config = WorkStealingConfig::default();
    assert_eq!(ws_config.initial_capacity, 256);
}

/// Integration test: Full workflow simulation
#[tokio::test]
async fn test_full_workflow_simulation() {
    // This test simulates a complete analysis workflow

    // 1. Create assessment
    let config = Config::default();
    let orchestrator = Orchestrator::new(config).expect("Failed to create orchestrator");

    let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
    let assessment_config = AssessmentConfig::default();

    let assessment = orchestrator
        .create_assessment("Integration Test".to_string(), target.clone(), assessment_config)
        .expect("Failed to create assessment");

    // 2. Create findings
    let finding1 = Finding::new("Hardcoded Password", "Found credentials")
        .with_severity(Severity::High)
        .with_type("security");

    let finding2 = Finding::new("Insecure Network", "Cleartext HTTP")
        .with_severity(Severity::Medium)
        .with_type("network");

    // 3. Process findings
    use sh_finding::prelude::*;
    let engine = FindingEngine::default();
    let findings = vec![finding1, finding2];
    let result = engine.process_batch(findings).await.expect("Failed to process findings");

    // 4. Verify results
    assert_eq!(result.total_count, 2);
    assert_eq!(result.high().len(), 1);
    assert_eq!(result.medium().len(), 1);

    // 5. Calculate risk
    use sh_risk::prelude::*;
    let risk_score = RiskScore::new(7.0);
    assert_eq!(risk_score.severity, Severity::High);
}

/// Test error handling across components
#[tokio::test]
async fn test_error_handling() {
    // Test sh-types error
    let error = Error::InvalidTarget("test".to_string());
    assert!(error.to_string().contains("Invalid target"));

    // Test finding error
    use sh_finding::FindingError;
    let finding_error = FindingError::InvalidFinding("test".to_string());
    assert!(!finding_error.is_retryable());

    let io_error = FindingError::Io(std::io::Error::new(std::io::ErrorKind::Other, "test"));
    assert!(io_error.is_retryable());
}

/// Test serialization roundtrip
#[tokio::test]
async fn test_serialization_roundtrip() {
    // Test Assessment serialization
    let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
    let assessment = Assessment::new("Test", target);

    let json = serde_json::to_string(&assessment).expect("Failed to serialize");
    let deserialized: Assessment = serde_json::from_str(&json).expect("Failed to deserialize");

    assert_eq!(assessment.id, deserialized.id);
    assert_eq!(assessment.name, deserialized.name);

    // Test Finding serialization
    let finding = Finding::new("Test", "Description").with_severity(Severity::High);

    let json = serde_json::to_string(&finding).expect("Failed to serialize");
    let deserialized: Finding = serde_json::from_str(&json).expect("Failed to deserialize");

    assert_eq!(finding.title, deserialized.title);
    assert_eq!(finding.severity, deserialized.severity);
}

/// Test concurrent operations
#[tokio::test]
async fn test_concurrent_operations() {
    use tokio::task;

    let mut handles = vec![];

    // Spawn multiple concurrent tasks
    for i in 0..10 {
        let handle = task::spawn(async move {
            // Each task creates its own assessment
            let config = Config::default();
            let orchestrator = Orchestrator::new(config).expect("Failed to create orchestrator");

            let target = AnalysisTarget::new(format!("/test/app{}.apk", i), Platform::Android);
            let assessment_config = AssessmentConfig::default();

            orchestrator.create_assessment(
                format!("Test {}", i),
                target,
                assessment_config,
            )
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    let results = futures::future::join_all(handles).await;

    // Verify all succeeded
    for result in results {
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }
}
