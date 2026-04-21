//! NATS backend for distributed job queue

use async_nats::jetstream::consumer::PullConsumer;
use async_nats::jetstream::context::Context;
use async_nats::jetstream::stream::{Config as StreamConfig, DiscardPolicy, RetentionPolicy};
use async_nats::{Client, ConnectOptions, HeaderMap};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::error::{DistributedError, Result};
use crate::worker::{WorkerInfo, WorkerRegistry, WorkerStatus};
use sh_types::{Job, JobId, JobPriority, JobResult, JobStatus};

/// NATS configuration
#[derive(Debug, Clone)]
pub struct NatsConfig {
    /// NATS server URL (e.g., "nats://localhost:4222")
    pub url: String,
    /// Connection name
    pub connection_name: String,
    /// Stream name for jobs
    pub stream_name: String,
    /// Subject prefix for jobs
    pub subject_prefix: String,
    /// Consumer name
    pub consumer_name: String,
    /// Max delivery attempts (for retries)
    pub max_deliver: i64,
    /// Ack wait duration in seconds
    pub ack_wait_secs: u64,
    /// Max messages in flight
    pub max_in_flight: i64,
    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
    /// Worker discovery subject
    pub discovery_subject: String,
    /// Results subject
    pub results_subject: String,
    /// Enable authentication
    pub auth_enabled: bool,
    /// Username for authentication
    pub username: Option<String>,
    /// Password for authentication
    pub password: Option<String>,
    /// Token for authentication
    pub token: Option<String>,
    /// TLS certificate file
    pub tls_cert: Option<String>,
    /// TLS key file
    pub tls_key: Option<String>,
    /// TLS CA file
    pub tls_ca: Option<String>,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: "nats://localhost:4222".to_string(),
            connection_name: "sh-distributed".to_string(),
            stream_name: "SH_JOBS".to_string(),
            subject_prefix: "sh.jobs".to_string(),
            consumer_name: "sh-workers".to_string(),
            max_deliver: 3,
            ack_wait_secs: 300,
            max_in_flight: 10,
            heartbeat_interval_secs: 10,
            discovery_subject: "sh.discovery".to_string(),
            results_subject: "sh.results".to_string(),
            auth_enabled: false,
            username: None,
            password: None,
            token: None,
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
        }
    }
}

impl NatsConfig {
    /// Create new config with URL
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Default::default()
        }
    }

    /// Set connection name
    pub fn with_connection_name(mut self, name: impl Into<String>) -> Self {
        self.connection_name = name.into();
        self
    }

    /// Set stream name
    pub fn with_stream_name(mut self, name: impl Into<String>) -> Self {
        self.stream_name = name.into();
        self
    }

    /// Set max delivery attempts
    pub fn with_max_deliver(mut self, max: i64) -> Self {
        self.max_deliver = max;
        self
    }

    /// Set authentication
    pub fn with_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.auth_enabled = true;
        self.username = Some(username.into());
        self.password = Some(password.into());
        self
    }

    /// Set token authentication
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.auth_enabled = true;
        self.token = Some(token.into());
        self
    }

    /// Get full subject for a job type
    fn job_subject(&self, job_type: &str) -> String {
        format!("{}.{}.{}", self.subject_prefix, "pending", job_type)
    }

    /// Get results subject for a job
    fn result_subject(&self, job_id: &str) -> String {
        format!("{}.{}.{}", self.subject_prefix, "results", job_id)
    }

    /// Get worker subject
    fn worker_subject(&self, worker_id: &str) -> String {
        format!("{}.{}", self.discovery_subject, worker_id)
    }
}

/// NATS job message
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NatsJobMessage {
    job: Job,
    submitted_at: String,
    retry_count: u32,
}

impl NatsJobMessage {
    fn new(job: Job) -> Self {
        Self {
            job,
            submitted_at: Utc::now().to_rfc3339(),
            retry_count: 0,
        }
    }
}

/// NATS result message
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NatsResultMessage {
    job_id: String,
    result: JobResult,
    completed_at: String,
    worker_id: String,
}

/// NATS backend for distributed execution
#[derive(Clone)]
pub struct NatsBackend {
    config: NatsConfig,
    client: Arc<RwLock<Client>>,
    jetstream: Arc<RwLock<Context>>,
    worker_registry: WorkerRegistry,
    worker_id: String,
    running: Arc<RwLock<bool>>,
}

impl NatsBackend {
    /// Create a new NATS backend
    pub async fn new(config: NatsConfig, worker_id: impl Into<String>) -> Result<Self> {
        let worker_id = worker_id.into();
        info!("Connecting to NATS at {}", config.url);

        // Build connection options
        let mut opts = ConnectOptions::new().name(&config.connection_name);

        if config.auth_enabled {
            if let (Some(user), Some(pass)) = (&config.username, &config.password) {
                opts = opts.user_and_password(user.clone(), pass.clone());
            } else if let Some(token) = &config.token {
                opts = opts.token(token.clone());
            }
        }

        // Connect to NATS
        let client = async_nats::connect_with_options(&config.url, opts)
            .await
            .map_err(|e| DistributedError::Nats(format!("Failed to connect: {}", e)))?;

        info!("Connected to NATS successfully");

        // Create JetStream context
        let jetstream = async_nats::jetstream::new(client.clone());

        // Create stream if it doesn't exist
        Self::create_stream(&jetstream, &config).await?;

        Ok(Self {
            config,
            client: Arc::new(RwLock::new(client)),
            jetstream: Arc::new(RwLock::new(jetstream)),
            worker_registry: WorkerRegistry::new(),
            worker_id,
            running: Arc::new(RwLock::new(false)),
        })
    }

    /// Create JetStream stream
    async fn create_stream(js: &Context, config: &NatsConfig) -> Result<()> {
        let stream_config = StreamConfig {
            name: config.stream_name.clone(),
            subjects: vec![format!("{}.*.*", config.subject_prefix)],
            retention: RetentionPolicy::WorkQueue,
            discard: DiscardPolicy::Old,
            max_msgs: 1_000_000,
            max_bytes: 1024 * 1024 * 1024, // 1GB
            max_age: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            storage: async_nats::jetstream::stream::StorageType::File,
            num_replicas: 1,
            ..Default::default()
        };

        match js.create_stream(stream_config).await {
            Ok(_) => info!("Created JetStream stream: {}", config.stream_name),
            Err(e) => {
                // Stream might already exist
                debug!("Stream creation result: {}", e);
            }
        }

        Ok(())
    }

    /// Start the backend
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        *running = true;
        drop(running);

        // Register worker
        self.register_worker().await?;

        // Start heartbeat task
        self.start_heartbeat().await;

        info!("NATS backend started for worker {}", self.worker_id);
        Ok(())
    }

    /// Stop the backend
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        *running = false;
        drop(running);

        // Unregister worker
        self.unregister_worker().await?;

        // Drain connection
        let client = self.client.read().await;
        client.flush().await.ok();
        drop(client);

        info!("NATS backend stopped for worker {}", self.worker_id);
        Ok(())
    }

    /// Submit a job to the stream
    pub async fn submit_job(&self, job: Job) -> Result<JobId> {
        let message = NatsJobMessage::new(job.clone());
        let payload = serde_json::to_vec(&message)
            .map_err(|e| DistributedError::Serialization(e))?;

        let subject = self.config.job_subject(&job.job_type);
        let js = self.jetstream.read().await;

        // Publish to JetStream
        js.publish(subject, payload.into())
            .await
            .map_err(|e| DistributedError::Nats(format!("Failed to publish job: {}", e)))?;

        info!("Submitted job {} to NATS stream", job.id);
        Ok(job.id)
    }

    /// Claim a job from the stream
    pub async fn claim_job(&self) -> Result<Option<Job>> {
        let js = self.jetstream.read().await;

        // Create consumer for this worker
        let consumer_config = async_nats::jetstream::consumer::pull::Config {
            durable_name: Some(format!("{}-{}", self.config.consumer_name, self.worker_id)),
            max_deliver: self.config.max_deliver,
            ack_wait: Duration::from_secs(self.config.ack_wait_secs),
            max_messages: self.config.max_in_flight,
            ..Default::default()
        };

        let stream = js.get_stream(&self.config.stream_name).await.map_err(|e| {
            DistributedError::Nats(format!("Failed to get stream: {}", e))
        })?;

        let consumer: PullConsumer = stream
            .create_consumer(consumer_config)
            .await
            .map_err(|e| DistributedError::Nats(format!("Failed to create consumer: {}", e)))?;

        // Try to get a message
        match consumer.fetch().max_messages(1).messages().await {
            Ok(mut messages) => {
                if let Some(message) = messages.next().await {
                    match message {
                        Ok(msg) => {
                            let payload: Vec<u8> = msg.payload.to_vec();
                            let nats_msg: NatsJobMessage = serde_json::from_slice(&payload)
                                .map_err(|e| DistributedError::Serialization(e))?;

                            // Acknowledge the message
                            msg.ack().await.ok();

                            debug!("Claimed job {} from NATS", nats_msg.job.id);
                            Ok(Some(nats_msg.job))
                        }
                        Err(e) => {
                            error!("Error receiving message: {}", e);
                            Ok(None)
                        }
                    }
                } else {
                    Ok(None)
                }
            }
            Err(e) => {
                debug!("No messages available: {}", e);
                Ok(None)
            }
        }
    }

    /// Complete a job
    pub async fn complete_job(&self, job_id: JobId, result: JobResult) -> Result<()> {
        let result_msg = NatsResultMessage {
            job_id: job_id.to_string(),
            result,
            completed_at: Utc::now().to_rfc3339(),
            worker_id: self.worker_id.clone(),
        };

        let payload = serde_json::to_vec(&result_msg)
            .map_err(|e| DistributedError::Serialization(e))?;

        let subject = self.config.result_subject(&job_id.to_string());
        let client = self.client.read().await;

        client
            .publish(subject, payload.into())
            .await
            .map_err(|e| DistributedError::Nats(format!("Failed to publish result: {}", e)))?;

        // Update worker stats
        if let Some(mut worker) = self.worker_registry.get(&self.worker_id) {
            worker.record_success();
            self.publish_worker_update(&worker).await?;
        }

        info!("Completed job {}", job_id);
        Ok(())
    }

    /// Fail a job (NATS handles retries automatically)
    pub async fn fail_job(&self, job_id: JobId, error: impl Into<String>) -> Result<()> {
        let error_msg = error.into();
        error!("Job {} failed: {}", job_id, error_msg);

        // Update worker stats
        if let Some(mut worker) = self.worker_registry.get(&self.worker_id) {
            worker.record_failure();
            self.publish_worker_update(&worker).await?;
        }

        // Note: NATS JetStream handles retries automatically based on max_deliver
        // The message will be redelivered if not acknowledged
        Ok(())
    }

    /// Get job result
    pub async fn get_result(&self, job_id: JobId) -> Result<Option<JobResult>> {
        // Results are published to a subject, we need to subscribe and wait
        // For now, return None - results should be retrieved via subscription
        // This is a simplified implementation
        Ok(None)
    }

    /// Wait for job completion with timeout
    pub async fn wait_for_job(&self, job_id: JobId, timeout_secs: u64) -> Result<JobResult> {
        let subject = self.config.result_subject(&job_id.to_string());
        let client = self.client.read().await;

        // Subscribe to results subject
        let mut subscriber = client
            .subscribe(subject)
            .await
            .map_err(|e| DistributedError::Nats(format!("Failed to subscribe: {}", e)))?;

        drop(client);

        // Wait for result with timeout
        let timeout = tokio::time::Duration::from_secs(timeout_secs);

        match tokio::time::timeout(timeout, subscriber.next()).await {
            Ok(Some(message)) => {
                let payload: Vec<u8> = message.payload.to_vec();
                let result_msg: NatsResultMessage = serde_json::from_slice(&payload)
                    .map_err(|e| DistributedError::Serialization(e))?;
                Ok(result_msg.result)
            }
            Ok(None) => Err(DistributedError::Nats("Subscription closed".to_string())),
            Err(_) => Err(DistributedError::Timeout(format!(
                "Job {} did not complete within {} seconds",
                job_id, timeout_secs
            ))),
        }
    }

    /// Get stream info
    pub async fn get_stream_info(&self) -> Result<async_nats::jetstream::stream::Info> {
        let js = self.jetstream.read().await;
        let stream = js
            .get_stream(&self.config.stream_name)
            .await
            .map_err(|e| DistributedError::Nats(format!("Failed to get stream: {}", e)))?;

        stream
            .info()
            .await
            .map_err(|e| DistributedError::Nats(format!("Failed to get stream info: {}", e)))
    }

    /// Get pending message count
    pub async fn pending_count(&self) -> Result<u64> {
        let info = self.get_stream_info().await?;
        Ok(info.state.messages)
    }

    /// Register worker
    async fn register_worker(&self) -> Result<()> {
        let worker = WorkerInfo::new(&self.worker_id, "127.0.0.1:0");
        self.worker_registry.register(worker.clone())?;
        self.publish_worker_update(&worker).await?;

        info!("Registered worker {} in NATS", self.worker_id);
        Ok(())
    }

    /// Unregister worker
    async fn unregister_worker(&self) -> Result<()> {
        if let Some(mut worker) = self.worker_registry.get(&self.worker_id) {
            worker.mark_offline();
            self.publish_worker_update(&worker).await?;
        }

        self.worker_registry.unregister(&self.worker_id)?;
        info!("Unregistered worker {} from NATS", self.worker_id);
        Ok(())
    }

    /// Publish worker update
    async fn publish_worker_update(&self, worker: &WorkerInfo) -> Result<()> {
        let subject = self.config.worker_subject(&worker.id);
        let payload = serde_json::to_vec(worker)
            .map_err(|e| DistributedError::Serialization(e))?;

        let client = self.client.read().await;
        client
            .publish(subject, payload.into())
            .await
            .map_err(|e| DistributedError::Nats(format!("Failed to publish worker update: {}", e)))?;

        Ok(())
    }

    /// Start heartbeat task
    async fn start_heartbeat(&self) {
        let worker_id = self.worker_id.clone();
        let config = self.config.clone();
        let worker_registry = self.worker_registry.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(config.heartbeat_interval_secs));

            loop {
                interval.tick().await;

                let is_running = *running.read().await;
                if !is_running {
                    break;
                }

                // Update heartbeat
                if let Some(mut worker) = worker_registry.get(&worker_id) {
                    worker.update_heartbeat();
                }
            }

            debug!("Heartbeat task stopped for worker {}", worker_id);
        });
    }

    /// Get all workers
    pub async fn get_workers(&self) -> Result<Vec<WorkerInfo>> {
        Ok(self.worker_registry.get_all())
    }

    /// Get worker count
    pub async fn get_worker_count(&self) -> Result<usize> {
        Ok(self.worker_registry.count())
    }

    /// Purge stream (use with caution)
    pub async fn purge_stream(&self) -> Result<()> {
        let js = self.jetstream.read().await;
        let stream = js
            .get_stream(&self.config.stream_name)
            .await
            .map_err(|e| DistributedError::Nats(format!("Failed to get stream: {}", e)))?;

        stream
            .purge()
            .await
            .map_err(|e| DistributedError::Nats(format!("Failed to purge stream: {}", e)))?;

        info!("Purged NATS stream {}", self.config.stream_name);
        Ok(())
    }

    /// Delete stream (use with caution)
    pub async fn delete_stream(&self) -> Result<()> {
        let js = self.jetstream.read().await;

        js.delete_stream(&self.config.stream_name)
            .await
            .map_err(|e| DistributedError::Nats(format!("Failed to delete stream: {}", e)))?;

        info!("Deleted NATS stream {}", self.config.stream_name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nats_config() {
        let config = NatsConfig::new("nats://localhost:4222").with_max_deliver(5);
        assert_eq!(config.url, "nats://localhost:4222");
        assert_eq!(config.max_deliver, 5);
        assert_eq!(config.job_subject("static_analysis"), "sh.jobs.pending.static_analysis");
    }

    #[test]
    fn test_nats_job_message() {
        use sh_types::{AnalysisTarget, Platform};

        let target = AnalysisTarget::new("/test", Platform::Android);
        let job = Job::new("test", target);
        let msg = NatsJobMessage::new(job);
        assert_eq!(msg.retry_count, 0);
    }
}
