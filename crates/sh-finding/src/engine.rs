//! Finding Processing Engine
//!
//! The core engine for processing security findings with support for:
//! - Configurable processing pipelines
//! - Batch operations with concurrency control
//! - Confidence score calculation
//! - Event publishing

use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{mpsc, RwLock, Semaphore};
use tracing::{debug, error, info, instrument, warn};

use sh_event_bus::{Event, EventBus, EventPayload, EventPriority, EventType};
use sh_types::{Confidence, Finding, FindingCollection, FindingId, Severity};

use crate::correlation::{CorrelationConfig, CorrelationEngine};
use crate::deduplication::{DeduplicationConfig, DeduplicationEngine};
use crate::{FindingError, Result};

/// Configuration for the finding engine
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Maximum concurrent processing operations
    pub max_concurrency: usize,
    /// Batch size for processing
    pub batch_size: usize,
    /// Enable correlation
    pub correlation_enabled: bool,
    /// Enable deduplication
    pub deduplication_enabled: bool,
    /// Correlation configuration
    pub correlation_config: CorrelationConfig,
    /// Deduplication configuration
    pub deduplication_config: DeduplicationConfig,
    /// Enable event publishing
    pub publish_events: bool,
    /// Confidence threshold for auto-confirmation
    pub auto_confirm_threshold: f64,
}

impl EngineConfig {
    /// Create a new configuration with sensible defaults
    pub fn new() -> Self {
        Self {
            max_concurrency: 10,
            batch_size: 100,
            correlation_enabled: true,
            deduplication_enabled: true,
            correlation_config: CorrelationConfig::default(),
            deduplication_config: DeduplicationConfig::default(),
            publish_events: true,
            auto_confirm_threshold: 0.9,
        }
    }
    
    /// Set maximum concurrency
    pub fn with_max_concurrency(mut self, concurrency: usize) -> Self {
        self.max_concurrency = concurrency.max(1);
        self
    }
    
    /// Set batch size
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size.max(1);
        self
    }
    
    /// Enable or disable correlation
    pub fn with_correlation_enabled(mut self, enabled: bool) -> Self {
        self.correlation_enabled = enabled;
        self
    }
    
    /// Enable or disable deduplication
    pub fn with_deduplication_enabled(mut self, enabled: bool) -> Self {
        self.deduplication_enabled = enabled;
        self
    }
    
    /// Set correlation configuration
    pub fn with_correlation_config(mut self, config: CorrelationConfig) -> Self {
        self.correlation_config = config;
        self
    }
    
    /// Set deduplication configuration
    pub fn with_deduplication_config(mut self, config: DeduplicationConfig) -> Self {
        self.deduplication_config = config;
        self
    }
    
    /// Enable or disable event publishing
    pub fn with_publish_events(mut self, enabled: bool) -> Self {
        self.publish_events = enabled;
        self
    }
    
    /// Set auto-confirm threshold
    pub fn with_auto_confirm_threshold(mut self, threshold: f64) -> Self {
        self.auto_confirm_threshold = threshold.clamp(0.0, 1.0);
        self
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Processing stage in the pipeline
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingStage {
    /// Initial validation
    Validation,
    /// Enrichment with additional data
    Enrichment,
    /// Correlation with other findings
    Correlation,
    /// Deduplication
    Deduplication,
    /// Confidence scoring
    Scoring,
    /// Finalization
    Finalization,
}

impl std::fmt::Display for ProcessingStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessingStage::Validation => write!(f, "validation"),
            ProcessingStage::Enrichment => write!(f, "enrichment"),
            ProcessingStage::Correlation => write!(f, "correlation"),
            ProcessingStage::Deduplication => write!(f, "deduplication"),
            ProcessingStage::Scoring => write!(f, "scoring"),
            ProcessingStage::Finalization => write!(f, "finalization"),
        }
    }
}

/// Processing pipeline for findings
#[derive(Debug)]
pub struct ProcessingPipeline {
    stages: Vec<ProcessingStage>,
    current: std::sync::atomic::AtomicUsize,
}

impl ProcessingPipeline {
    /// Create a new default pipeline
    pub fn new() -> Self {
        Self {
            stages: vec![
                ProcessingStage::Validation,
                ProcessingStage::Enrichment,
                ProcessingStage::Correlation,
                ProcessingStage::Deduplication,
                ProcessingStage::Scoring,
                ProcessingStage::Finalization,
            ],
            current: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    
    /// Create a custom pipeline with specific stages
    pub fn with_stages(stages: Vec<ProcessingStage>) -> Self {
        Self {
            stages,
            current: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    
    /// Get the next stage
    pub fn next_stage(&self) -> Option<ProcessingStage> {
        let current = self.current.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.stages.get(current).copied()
    }
    
    /// Reset the pipeline
    pub fn reset(&self) {
        self.current.store(0, std::sync::atomic::Ordering::SeqCst);
    }
    
    /// Get all stages
    pub fn stages(&self) -> &[ProcessingStage] {
        &self.stages
    }
}

impl Default for ProcessingPipeline {
    fn default() -> Self {
        Self::new()
    }
}

/// Main finding processing engine
#[derive(Debug)]
pub struct FindingEngine {
    config: EngineConfig,
    findings: DashMap<FindingId, Finding>,
    correlation_engine: Option<CorrelationEngine>,
    deduplication_engine: Option<DeduplicationEngine>,
    event_bus: Option<Arc<dyn EventBus>>,
    shutdown: RwLock<bool>,
    processing_count: std::sync::atomic::AtomicUsize,
}

impl FindingEngine {
    /// Create a new finding engine with the given configuration
    pub fn new(config: EngineConfig) -> Self {
        let correlation_engine = if config.correlation_enabled {
            Some(CorrelationEngine::new(config.correlation_config.clone()))
        } else {
            None
        };
        
        let deduplication_engine = if config.deduplication_enabled {
            Some(DeduplicationEngine::new(config.deduplication_config.clone()))
        } else {
            None
        };
        
        Self {
            config,
            findings: DashMap::new(),
            correlation_engine,
            deduplication_engine,
            event_bus: None,
            shutdown: RwLock::new(false),
            processing_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    
    /// Set the event bus for publishing events
    pub fn with_event_bus(mut self, event_bus: Arc<dyn EventBus>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }
    
    /// Check if the engine is shutdown
    pub fn is_shutdown(&self) -> bool {
        *self.shutdown.blocking_read()
    }
    
    /// Get the number of findings being processed
    pub fn processing_count(&self) -> usize {
        self.processing_count.load(std::sync::atomic::Ordering::SeqCst)
    }
    
    /// Process a single finding through the pipeline
    #[instrument(skip(self, finding), fields(finding_id = %finding.id))]
    pub async fn process(&self, finding: Finding) -> Result<Finding> {
        // Check if shutdown
        if *self.shutdown.read().await {
            return Err(FindingError::Processing("Engine is shutdown".to_string()));
        }
        
        self.processing_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        
        let result = self.process_internal(finding).await;
        
        self.processing_count.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        
        result
    }
    
    /// Internal processing logic
    async fn process_internal(&self, finding: Finding) -> Result<Finding> {
        let mut finding = finding;
        let pipeline = ProcessingPipeline::new();
        
        while let Some(stage) = pipeline.next_stage() {
            debug!("Processing finding {} through stage: {}", finding.id, stage);
            
            finding = match stage {
                ProcessingStage::Validation => self.validate(finding).await?,
                ProcessingStage::Enrichment => self.enrich(finding).await?,
                ProcessingStage::Correlation => self.correlate(finding).await?,
                ProcessingStage::Deduplication => self.deduplicate(finding).await?,
                ProcessingStage::Scoring => self.score(finding).await?,
                ProcessingStage::Finalization => self.finalize(finding).await?,
            };
        }
        
        // Store the finding
        self.findings.insert(finding.id, finding.clone());
        
        // Publish event
        if self.config.publish_events {
            self.publish_finding_event(&finding, EventType::FindingCreated).await;
        }
        
        info!("Successfully processed finding: {}", finding.id);
        Ok(finding)
    }
    
    /// Process a batch of findings with concurrency control
    #[instrument(skip(self, findings), fields(batch_size = findings.len()))]
    pub async fn process_batch(&self, findings: Vec<Finding>) -> Result<FindingCollection> {
        if findings.is_empty() {
            return Ok(FindingCollection::new(Vec::new()));
        }
        
        info!("Processing batch of {} findings", findings.len());
        
        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrency));
        let mut handles = Vec::with_capacity(findings.len());
        
        for finding in findings {
            let permit = semaphore.clone().acquire_owned().await.map_err(|e| {
                FindingError::Processing(format!("Failed to acquire semaphore: {}", e))
            })?;
            
            let handle = tokio::spawn(async move {
                let _permit = permit;
                self.process(finding).await
            });
            
            handles.push(handle);
        }
        
        let mut processed = Vec::with_capacity(handles.len());
        let mut errors = Vec::new();
        
        for handle in handles {
            match handle.await {
                Ok(Ok(finding)) => processed.push(finding),
                Ok(Err(e)) => {
                    error!("Finding processing failed: {}", e);
                    errors.push(e);
                }
                Err(e) => {
                    error!("Task join failed: {}", e);
                    errors.push(FindingError::Processing(format!("Task failed: {}", e)));
                }
            }
        }
        
        // Handle partial failures
        if !errors.is_empty() && !processed.is_empty() {
            return Err(FindingError::BatchPartial {
                success: processed.len(),
                failed: errors.len(),
                message: format!("First error: {}", errors[0]),
            });
        }
        
        if !errors.is_empty() {
            return Err(errors.into_iter().next().unwrap());
        }
        
        info!("Successfully processed {} findings", processed.len());
        Ok(FindingCollection::new(processed))
    }
    
    /// Get a finding by ID
    pub fn get(&self, id: FindingId) -> Option<Finding> {
        self.findings.get(&id).map(|f| f.clone())
    }
    
    /// Get all findings
    pub fn get_all(&self) -> Vec<Finding> {
        self.findings.iter().map(|f| f.clone()).collect()
    }
    
    /// Get findings by severity
    pub fn get_by_severity(&self, severity: Severity) -> Vec<Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .map(|f| f.clone())
            .collect()
    }
    
    /// Get findings by confidence level
    pub fn get_by_confidence(&self, confidence: Confidence) -> Vec<Finding> {
        self.findings
            .iter()
            .filter(|f| f.confidence == confidence)
            .map(|f| f.clone())
            .collect()
    }
    
    /// Get correlated findings
    pub fn get_correlated(&self, id: FindingId) -> Vec<Finding> {
        let mut correlated = Vec::new();
        
        if let Some(finding) = self.findings.get(&id) {
            for correlated_id in &finding.correlated_ids {
                if let Some(cf) = self.findings.get(correlated_id) {
                    correlated.push(cf.clone());
                }
            }
        }
        
        correlated
    }
    
    /// Get duplicate findings
    pub fn get_duplicates(&self, id: FindingId) -> Vec<Finding> {
        let mut duplicates = Vec::new();
        
        if let Some(finding) = self.findings.get(&id) {
            if let Some(duplicate_of) = finding.duplicate_of {
                // This is a duplicate, get the original
                if let Some(original) = self.findings.get(&duplicate_of) {
                    duplicates.push(original.clone());
                }
            } else {
                // This might be an original, find its duplicates
                for f in self.findings.iter() {
                    if let Some(dup_of) = f.duplicate_of {
                        if dup_of == id {
                            duplicates.push(f.clone());
                        }
                    }
                }
            }
        }
        
        duplicates
    }
    
    /// Remove a finding
    pub fn remove(&self, id: FindingId) -> Option<Finding> {
        self.findings.remove(&id).map(|(_, f)| f)
    }
    
    /// Clear all findings
    pub fn clear(&self) {
        self.findings.clear();
    }
    
    /// Get the count of stored findings
    pub fn len(&self) -> usize {
        self.findings.len()
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
    
    /// Shutdown the engine
    pub async fn shutdown(&self) {
        let mut shutdown = self.shutdown.write().await;
        *shutdown = true;
        info!("Finding engine shutdown");
    }
    
    /// Validation stage
    async fn validate(&self, finding: Finding) -> Result<Finding> {
        if finding.title.is_empty() {
            return Err(FindingError::InvalidFinding("Title cannot be empty".to_string()));
        }
        
        if finding.description.is_empty() {
            return Err(FindingError::InvalidFinding("Description cannot be empty".to_string()));
        }
        
        if finding.finding_type.is_empty() {
            return Err(FindingError::InvalidFinding("Finding type cannot be empty".to_string()));
        }
        
        Ok(finding)
    }
    
    /// Enrichment stage
    async fn enrich(&self, mut finding: Finding) -> Result<Finding> {
        // Add default metadata if missing
        if finding.metadata.is_none() {
            finding.metadata = Some(serde_json::json!({
                "processed_by": "sh-finding",
                "processing_version": env!("CARGO_PKG_VERSION"),
            }));
        }
        
        Ok(finding)
    }
    
    /// Correlation stage
    async fn correlate(&self, mut finding: Finding) -> Result<Finding> {
        if let Some(ref engine) = self.correlation_engine {
            let correlated = engine.find_correlations(&finding, &self.get_all()).await;
            
            for correlated_id in correlated {
                finding.correlated_ids.push(correlated_id);
                
                // Update the correlated finding as well
                if let Some(mut cf) = self.findings.get_mut(&correlated_id) {
                    if !cf.correlated_ids.contains(&finding.id) {
                        cf.correlated_ids.push(finding.id);
                    }
                }
                
                if self.config.publish_events {
                    self.publish_finding_event(&finding, EventType::FindingCorrelated).await;
                }
            }
        }
        
        Ok(finding)
    }
    
    /// Deduplication stage
    async fn deduplicate(&self, mut finding: Finding) -> Result<Finding> {
        if let Some(ref engine) = self.deduplication_engine {
            if let Some(duplicate_of) = engine.find_duplicate(&finding, &self.get_all()).await {
                finding.duplicate_of = Some(duplicate_of);
                
                if self.config.publish_events {
                    self.publish_finding_event(&finding, EventType::FindingDuplicateDetected).await;
                }
            }
        }
        
        Ok(finding)
    }
    
    /// Scoring stage
    async fn score(&self, mut finding: Finding) -> Result<Finding> {
        let confidence_score = self.calculate_confidence_score(&finding);
        
        // Auto-confirm if confidence is high enough
        if confidence_score >= self.config.auto_confirm_threshold {
            finding.confidence = Confidence::Confirmed;
        } else if confidence_score >= 0.6 {
            finding.confidence = Confidence::Probable;
        } else {
            finding.confidence = Confidence::Tentative;
        }
        
        Ok(finding)
    }
    
    /// Finalization stage
    async fn finalize(&self, finding: Finding) -> Result<Finding> {
        // Any final processing
        Ok(finding)
    }
    
    /// Calculate confidence score for a finding
    fn calculate_confidence_score(&self, finding: &Finding) -> f64 {
        let mut score = 0.0;
        let mut weights = 0.0;
        
        // Base confidence from finding
        let base_score = match finding.confidence {
            Confidence::Confirmed => 1.0,
            Confidence::Probable => 0.7,
            Confidence::Tentative => 0.4,
        };
        score += base_score * 0.3;
        weights += 0.3;
        
        // Evidence bonus
        let evidence_bonus = (finding.evidence.len() as f64 * 0.1).min(0.3);
        score += evidence_bonus;
        weights += 0.3;
        
        // Tool reputation (simplified - would be configurable)
        let tool_factor = 0.85;
        score += tool_factor * 0.2;
        weights += 0.2;
        
        // Severity correlation (higher severity often means more confident detection)
        let severity_score = match finding.severity {
            Severity::Critical => 1.0,
            Severity::High => 0.9,
            Severity::Medium => 0.8,
            Severity::Low => 0.7,
            Severity::Info => 0.6,
        };
        score += severity_score * 0.2;
        weights += 0.2;
        
        if weights > 0.0 {
            score / weights
        } else {
            0.5
        }
    }
    
    /// Publish a finding event
    async fn publish_finding_event(&self, finding: &Finding, event_type: EventType) {
        if let Some(ref bus) = self.event_bus {
            let event = Event::new(
                event_type,
                "sh-finding",
                EventPayload::FindingCreated {
                    finding_id: finding.id,
                    title: finding.title.clone(),
                    severity: finding.severity,
                },
            )
            .with_priority(if finding.severity == Severity::Critical {
                EventPriority::Critical
            } else if finding.severity == Severity::High {
                EventPriority::High
            } else {
                EventPriority::Normal
            });
            
            if let Err(e) = bus.publish(event).await {
                warn!("Failed to publish finding event: {}", e);
            }
        }
    }
}

impl Default for FindingEngine {
    fn default() -> Self {
        Self::new(EngineConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::Location;

    #[test]
    fn test_engine_config() {
        let config = EngineConfig::new()
            .with_max_concurrency(20)
            .with_batch_size(50)
            .with_correlation_enabled(false);
        
        assert_eq!(config.max_concurrency, 20);
        assert_eq!(config.batch_size, 50);
        assert!(!config.correlation_enabled);
    }

    #[test]
    fn test_processing_pipeline() {
        let pipeline = ProcessingPipeline::new();
        assert_eq!(pipeline.stages().len(), 6);
        
        let custom = ProcessingPipeline::with_stages(vec![
            ProcessingStage::Validation,
            ProcessingStage::Scoring,
        ]);
        assert_eq!(custom.stages().len(), 2);
    }

    #[tokio::test]
    async fn test_validation() {
        let engine = FindingEngine::default();
        
        let valid = Finding::new("Test", "Description").with_type("test");
        let result = engine.validate(valid).await;
        assert!(result.is_ok());
        
        let invalid = Finding::new("", "Description");
        let result = engine.validate(invalid).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_confidence_scoring() {
        let engine = FindingEngine::default();
        
        let finding = Finding::new("Test", "Description")
            .with_severity(Severity::Critical)
            .with_type("test")
            .add_evidence(sh_types::Evidence::new("code", "evidence data"));
        
        let scored = engine.score(finding).await.unwrap();
        assert_eq!(scored.confidence, Confidence::Confirmed);
    }
}
