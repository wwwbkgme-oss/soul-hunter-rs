//! Job types for task scheduling and execution

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{AnalysisTarget, Platform};

/// Unique identifier for jobs
pub type JobId = Uuid;

/// Job status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Timeout,
}

impl Default for JobStatus {
    fn default() -> Self {
        JobStatus::Pending
    }
}

/// Priority levels for jobs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobPriority {
    Lowest = 0,
    Low = 25,
    Normal = 50,
    High = 75,
    Critical = 100,
}

impl Default for JobPriority {
    fn default() -> Self {
        JobPriority::Normal
    }
}

/// A job to be executed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: JobId,
    pub job_type: String,
    pub target: AnalysisTarget,
    pub status: JobStatus,
    pub priority: JobPriority,
    
    // Timing
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub timeout_secs: Option<u64>,
    
    // Execution
    pub max_retries: u32,
    pub retry_count: u32,
    pub worker_id: Option<String>,
    
    // Configuration
    pub config: JobConfig,
    
    // Results
    pub result: Option<JobResult>,
    pub error: Option<String>,
    
    // Metadata
    pub metadata: HashMap<String, String>,
    pub tags: Vec<String>,
}

impl Job {
    pub fn new(job_type: impl Into<String>, target: AnalysisTarget) -> Self {
        Self {
            id: Uuid::new_v4(),
            job_type: job_type.into(),
            target,
            status: JobStatus::Pending,
            priority: JobPriority::Normal,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            timeout_secs: None,
            max_retries: 3,
            retry_count: 0,
            worker_id: None,
            config: JobConfig::default(),
            result: None,
            error: None,
            metadata: HashMap::new(),
            tags: Vec::new(),
        }
    }

    pub fn with_priority(mut self, priority: JobPriority) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = Some(timeout_secs);
        self
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn with_config(mut self, config: JobConfig) -> Self {
        self.config = config;
        self
    }

    pub fn add_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    pub fn add_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn mark_started(&mut self, worker_id: impl Into<String>) {
        self.status = JobStatus::Running;
        self.started_at = Some(Utc::now());
        self.worker_id = Some(worker_id.into());
    }

    pub fn mark_completed(&mut self, result: JobResult) {
        self.status = JobStatus::Completed;
        self.completed_at = Some(Utc::now());
        self.result = Some(result);
    }

    pub fn mark_failed(&mut self, error: impl Into<String>) {
        self.status = JobStatus::Failed;
        self.completed_at = Some(Utc::now());
        self.error = Some(error.into());
    }

    pub fn mark_timeout(&mut self) {
        self.status = JobStatus::Timeout;
        self.completed_at = Some(Utc::now());
    }

    pub fn can_retry(&self) -> bool {
        self.retry_count < self.max_retries && 
        matches!(self.status, JobStatus::Failed | JobStatus::Timeout)
    }

    pub fn duration(&self) -> Option<chrono::Duration> {
        match (self.started_at, self.completed_at) {
            (Some(start), Some(end)) => Some(end - start),
            _ => None,
        }
    }
}

/// Job configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JobConfig {
    pub features: Vec<String>,
    pub options: HashMap<String, serde_json::Value>,
    pub output_format: OutputFormat,
    pub enable_evidence: bool,
    pub enable_risk_scoring: bool,
}

impl JobConfig {
    pub fn with_feature(mut self, feature: impl Into<String>) -> Self {
        self.features.push(feature.into());
        self
    }

    pub fn with_option(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.options.insert(key.into(), value);
        self
    }

    pub fn with_output_format(mut self, format: OutputFormat) -> Self {
        self.output_format = format;
        self
    }
}

/// Output format for job results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Json,
    Sarif,
    Html,
    Markdown,
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Json
    }
}

/// Job execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub findings_count: usize,
    pub risk_score: Option<f64>,
    pub output_data: serde_json::Value,
    pub artifacts: Vec<Artifact>,
    pub metrics: JobMetrics,
}

impl JobResult {
    pub fn new(findings_count: usize) -> Self {
        Self {
            findings_count,
            risk_score: None,
            output_data: serde_json::Value::Null,
            artifacts: Vec::new(),
            metrics: JobMetrics::default(),
        }
    }

    pub fn with_risk_score(mut self, score: f64) -> Self {
        self.risk_score = Some(score);
        self
    }

    pub fn with_output(mut self, data: serde_json::Value) -> Self {
        self.output_data = data;
        self
    }

    pub fn add_artifact(mut self, artifact: Artifact) -> Self {
        self.artifacts.push(artifact);
        self
    }
}

/// Artifact produced by a job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: Uuid,
    pub artifact_type: String,
    pub path: String,
    pub size: u64,
    pub hash: Option<String>,
}

/// Job execution metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JobMetrics {
    pub queue_time_ms: u64,
    pub execution_time_ms: u64,
    pub total_time_ms: u64,
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f64,
}

/// Job queue statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueueStats {
    pub pending: usize,
    pub running: usize,
    pub completed: usize,
    pub failed: usize,
    pub total: usize,
    pub avg_wait_time_ms: u64,
    pub avg_execution_time_ms: u64,
}

/// Job filter for querying
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JobFilter {
    pub status: Option<JobStatus>,
    pub job_type: Option<String>,
    pub platform: Option<Platform>,
    pub tags: Vec<String>,
    pub created_after: Option<DateTime<Utc>>,
    pub created_before: Option<DateTime<Utc>>,
}

impl JobFilter {
    pub fn with_status(mut self, status: JobStatus) -> Self {
        self.status = Some(status);
        self
    }

    pub fn with_type(mut self, job_type: impl Into<String>) -> Self {
        self.job_type = Some(job_type.into());
        self
    }

    pub fn with_platform(mut self, platform: Platform) -> Self {
        self.platform = Some(platform);
        self
    }

    pub fn add_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_builder() {
        let target = AnalysisTarget::new("/path/to/app.apk", Platform::Android);
        let job = Job::new("static_analysis", target)
            .with_priority(JobPriority::High)
            .with_timeout(300)
            .add_tag("security");

        assert_eq!(job.job_type, "static_analysis");
        assert_eq!(job.priority, JobPriority::High);
        assert_eq!(job.timeout_secs, Some(300));
        assert!(job.tags.contains(&"security".to_string()));
    }

    #[test]
    fn test_job_lifecycle() {
        let target = AnalysisTarget::new("/path/to/app.apk", Platform::Android);
        let mut job = Job::new("test", target);

        assert_eq!(job.status, JobStatus::Pending);
        
        job.mark_started("worker-1");
        assert_eq!(job.status, JobStatus::Running);
        assert_eq!(job.worker_id, Some("worker-1".to_string()));
        
        let result = JobResult::new(5);
        job.mark_completed(result);
        assert_eq!(job.status, JobStatus::Completed);
        assert!(job.result.is_some());
    }

    #[test]
    fn test_job_retry() {
        let target = AnalysisTarget::new("/path/to/app.apk", Platform::Android);
        let mut job = Job::new("test", target)
            .with_max_retries(3);

        assert!(job.can_retry());
        
        job.mark_failed("error");
        assert!(job.can_retry());
        
        job.retry_count = 3;
        assert!(!job.can_retry());
    }

    #[test]
    fn test_priority_ordering() {
        assert!(JobPriority::Low < JobPriority::Normal);
        assert!(JobPriority::Normal < JobPriority::High);
        assert!(JobPriority::High < JobPriority::Critical);
    }
}
