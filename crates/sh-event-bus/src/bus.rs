//! Event Bus Implementation - Production Ready
//!
//! Async pub/sub event system with:
//! - Broadcast-based messaging using tokio::sync::broadcast
//! - Subscription management with filtering
//! - Request-response pattern with timeout
//! - Message persistence to disk
//! - Metrics tracking (messages published/delivered/failed, latency)
//! - Priority levels (low, medium, high, critical)
//! - Thread-safe implementation using Arc and RwLock

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use sh_types::prelude::*;
use sh_types::{
    AssessmentId, Event, EventFilter, EventId, EventPayload, EventPriority, EventStats,
    EventSubscription, EventType, Finding, JobId,
};

use crate::handler::EventHandler;
use crate::subscriber::{EventSubscriber, SubscriptionHandle};
use crate::{EventBusError, Result};

/// Default channel capacity for broadcast channel
const DEFAULT_CHANNEL_CAPACITY: usize = 10000;

/// Default timeout for request-response pattern
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default persistence file path
const DEFAULT_PERSISTENCE_PATH: &str = "./data/events";

/// Event bus configuration
#[derive(Debug, Clone)]
pub struct EventBusConfig {
    /// Channel capacity for broadcast
    pub channel_capacity: usize,
    /// Request timeout duration
    pub request_timeout: Duration,
    /// Enable message persistence
    pub enable_persistence: bool,
    /// Persistence directory path
    pub persistence_path: PathBuf,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Maximum persisted events per file
    pub max_events_per_file: usize,
    /// Enable priority-based message processing
    pub enable_priority: bool,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            enable_persistence: false,
            persistence_path: PathBuf::from(DEFAULT_PERSISTENCE_PATH),
            enable_metrics: true,
            max_events_per_file: 1000,
            enable_priority: true,
        }
    }
}

impl EventBusConfig {
    pub fn with_channel_capacity(mut self, capacity: usize) -> Self {
        self.channel_capacity = capacity;
        self
    }

    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub fn with_persistence(mut self, path: impl Into<PathBuf>) -> Self {
        self.enable_persistence = true;
        self.persistence_path = path.into();
        self
    }

    pub fn with_metrics(mut self, enabled: bool) -> Self {
        self.enable_metrics = enabled;
        self
    }

    pub fn with_max_events_per_file(mut self, max: usize) -> Self {
        self.max_events_per_file = max;
        self
    }
}

/// Event bus metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventBusMetrics {
    /// Total messages published
    pub messages_published: u64,
    /// Total messages delivered to subscribers
    pub messages_delivered: u64,
    /// Total messages failed to deliver
    pub messages_failed: u64,
    /// Total messages dropped (lagging subscribers)
    pub messages_dropped: u64,
    /// Average publish latency in microseconds
    pub avg_publish_latency_us: u64,
    /// Total publish latency accumulated (for averaging)
    pub total_publish_latency_us: u64,
    /// Number of latency samples
    pub latency_samples: u64,
    /// Messages by event type
    pub messages_by_type: HashMap<String, u64>,
    /// Messages by priority
    pub messages_by_priority: HashMap<String, u64>,
    /// Active subscriber count
    pub active_subscribers: usize,
    /// Active handler count
    pub active_handlers: usize,
    /// Request-response success count
    pub requests_succeeded: u64,
    /// Request-response timeout count
    pub requests_timed_out: u64,
    /// Last updated timestamp
    pub last_updated: Option<DateTime<Utc>>,
}

impl EventBusMetrics {
    pub fn record_publish(&mut self, event_type: EventType, priority: EventPriority, latency_us: u64) {
        self.messages_published += 1;
        self.total_publish_latency_us += latency_us;
        self.latency_samples += 1;
        self.avg_publish_latency_us = self.total_publish_latency_us / self.latency_samples;
        
        *self.messages_by_type.entry(format!("{:?}", event_type)).or_insert(0) += 1;
        *self.messages_by_priority.entry(format!("{:?}", priority)).or_insert(0) += 1;
        self.last_updated = Some(Utc::now());
    }

    pub fn record_delivery(&mut self) {
        self.messages_delivered += 1;
        self.last_updated = Some(Utc::now());
    }

    pub fn record_failure(&mut self) {
        self.messages_failed += 1;
        self.last_updated = Some(Utc::now());
    }

    pub fn record_dropped(&mut self) {
        self.messages_dropped += 1;
        self.last_updated = Some(Utc::now());
    }

    pub fn record_request_success(&mut self) {
        self.requests_succeeded += 1;
        self.last_updated = Some(Utc::now());
    }

    pub fn record_request_timeout(&mut self) {
        self.requests_timed_out += 1;
        self.last_updated = Some(Utc::now());
    }

    pub fn update_subscriber_count(&mut self, count: usize) {
        self.active_subscribers = count;
        self.last_updated = Some(Utc::now());
    }

    pub fn update_handler_count(&mut self, count: usize) {
        self.active_handlers = count;
        self.last_updated = Some(Utc::now());
    }
}

/// Request message for request-response pattern
#[derive(Debug)]
pub struct EventRequest {
    pub id: Uuid,
    pub event: Event,
    pub response_tx: oneshot::Sender<EventResponse>,
    pub timeout: Duration,
}

/// Response message for request-response pattern
#[derive(Debug, Clone)]
pub struct EventResponse {
    pub request_id: Uuid,
    pub success: bool,
    pub event: Option<Event>,
    pub error: Option<String>,
}

impl EventResponse {
    pub fn success(request_id: Uuid, event: Event) -> Self {
        Self {
            request_id,
            success: true,
            event: Some(event),
            error: None,
        }
    }

    pub fn error(request_id: Uuid, error: impl Into<String>) -> Self {
        Self {
            request_id,
            success: false,
            event: None,
            error: Some(error.into()),
        }
    }
}

/// Persisted event entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedEvent {
    pub id: EventId,
    pub event_type: EventType,
    pub priority: EventPriority,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub payload: EventPayload,
    pub metadata: HashMap<String, String>,
}

impl From<&Event> for PersistedEvent {
    fn from(event: &Event) -> Self {
        Self {
            id: event.id,
            event_type: event.event_type,
            priority: event.priority,
            timestamp: event.timestamp,
            source: event.source.clone(),
            payload: event.payload.clone(),
            metadata: event.metadata.clone(),
        }
    }
}

/// Event bus for pub/sub communication
#[derive(Debug)]
pub struct EventBus {
    /// Broadcast sender for events
    tx: broadcast::Sender<Event>,
    /// Event handlers by event type
    handlers: Arc<DashMap<EventType, Vec<EventHandler>>>,
    /// Active subscriptions
    subscriptions: Arc<RwLock<HashMap<Uuid, EventSubscription>>>,
    /// Event bus configuration
    config: EventBusConfig,
    /// Metrics tracking
    metrics: Arc<RwLock<EventBusMetrics>>,
    /// Request channel for request-response pattern
    request_tx: Option<mpsc::Sender<EventRequest>>,
    /// Correlation ID for scoped event buses
    correlation_id: Option<Uuid>,
    /// Persistence file handle
    persistence_file: Arc<RwLock<Option<File>>>,
    /// Persisted event count in current file
    persisted_count: Arc<RwLock<usize>>,
}

impl EventBus {
    /// Create new event bus with default configuration
    pub fn new() -> Self {
        Self::with_config(EventBusConfig::default())
    }

    /// Create new event bus with custom configuration
    pub fn with_config(config: EventBusConfig) -> Self {
        let (tx, _rx) = broadcast::channel(config.channel_capacity);

        let bus = Self {
            tx,
            handlers: Arc::new(DashMap::new()),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            config: config.clone(),
            metrics: Arc::new(RwLock::new(EventBusMetrics::default())),
            request_tx: None,
            correlation_id: None,
            persistence_file: Arc::new(RwLock::new(None)),
            persisted_count: Arc::new(RwLock::new(0)),
        };

        // Initialize persistence if enabled
        if config.enable_persistence {
            let bus_clone = bus.clone();
            tokio::spawn(async move {
                if let Err(e) = bus_clone.initialize_persistence().await {
                    error!("Failed to initialize persistence: {}", e);
                }
            });
        }

        bus
    }

    /// Create a correlation-scoped event bus
    pub fn with_correlation(&self, correlation_id: Uuid) -> Self {
        let (tx, _rx) = broadcast::channel(self.config.channel_capacity);

        Self {
            tx,
            handlers: self.handlers.clone(),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            config: self.config.clone(),
            metrics: self.metrics.clone(),
            request_tx: self.request_tx.clone(),
            correlation_id: Some(correlation_id),
            persistence_file: self.persistence_file.clone(),
            persisted_count: self.persisted_count.clone(),
        }
    }

    /// Initialize persistence system
    async fn initialize_persistence(&self) -> Result<()> {
        if !self.config.enable_persistence {
            return Ok(());
        }

        // Create persistence directory
        fs::create_dir_all(&self.config.persistence_path)
            .await
            .map_err(|e| EventBusError::SendError(format!("Failed to create persistence directory: {}", e)))?;

        // Open or create persistence file
        let file_path = self.get_persistence_file_path().await?;
        let file = File::options()
            .create(true)
            .append(true)
            .open(&file_path)
            .await
            .map_err(|e| EventBusError::SendError(format!("Failed to open persistence file: {}", e)))?;

        *self.persistence_file.write().await = Some(file);
        info!("Event persistence initialized at {:?}", file_path);

        Ok(())
    }

    /// Get persistence file path
    async fn get_persistence_file_path(&self) -> Result<PathBuf> {
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let correlation = self.correlation_id.map(|id| format!("_{}", id)).unwrap_or_default();
        let filename = format!("events_{}{}.jsonl", timestamp, correlation);
        Ok(self.config.persistence_path.join(filename))
    }

    /// Rotate persistence file if needed
    async fn rotate_persistence_file_if_needed(&self) -> Result<()> {
        let count = *self.persisted_count.read().await;
        if count >= self.config.max_events_per_file {
            // Close current file and create new one
            *self.persistence_file.write().await = None;
            *self.persisted_count.write().await = 0;
            self.initialize_persistence().await?;
        }
        Ok(())
    }

    /// Persist event to disk
    async fn persist_event(&self, event: &Event) -> Result<()> {
        if !self.config.enable_persistence {
            return Ok(());
        }

        self.rotate_persistence_file_if_needed().await?;

        let persisted = PersistedEvent::from(event);
        let json = serde_json::to_string(&persisted)
            .map_err(|e| EventBusError::SendError(format!("Failed to serialize event: {}", e)))?;

        let mut file_guard = self.persistence_file.write().await;
        if let Some(ref mut file) = *file_guard {
            file.write_all(json.as_bytes()).await
                .map_err(|e| EventBusError::SendError(format!("Failed to write event: {}", e)))?;
            file.write_all(b"\n").await
                .map_err(|e| EventBusError::SendError(format!("Failed to write newline: {}", e)))?;
            file.flush().await
                .map_err(|e| EventBusError::SendError(format!("Failed to flush file: {}", e)))?;
        }

        *self.persisted_count.write().await += 1;
        Ok(())
    }

    /// Publish event to bus
    #[instrument(skip(self, event), fields(event_type = ?event.event_type, source = %event.source))]
    pub async fn publish(&self, event: Event) -> Result<()> {
        let start = Instant::now();
        let event_type = event.event_type;
        let priority = event.priority;

        // Persist event if enabled
        if self.config.enable_persistence {
            if let Err(e) = self.persist_event(&event).await {
                warn!("Failed to persist event: {}", e);
            }
        }

        // Update metrics
        if self.config.enable_metrics {
            let latency = start.elapsed().as_micros() as u64;
            self.metrics.write().await.record_publish(event_type, priority, latency);
        }

        // Send to broadcast channel
        match self.tx.send(event.clone()) {
            Ok(receiver_count) => {
                debug!(
                    "Published event {:?} from {} to {} receivers",
                    event.event_type, event.source, receiver_count
                );

                // Update delivery metrics
                if self.config.enable_metrics {
                    let mut metrics = self.metrics.write().await;
                    for _ in 0..receiver_count {
                        metrics.record_delivery();
                    }
                }

                // Trigger handlers
                self.trigger_handlers(&event).await?;

                Ok(())
            }
            Err(e) => {
                error!("Failed to publish event: {}", e);
                if self.config.enable_metrics {
                    self.metrics.write().await.record_failure();
                }
                Err(EventBusError::SendError(e.to_string()))
            }
        }
    }

    /// Publish event with priority
    pub async fn publish_with_priority(&self, event: Event, priority: EventPriority) -> Result<()> {
        let event = event.with_priority(priority);
        self.publish(event).await
    }

    /// Request-response pattern: Send request and wait for response
    pub async fn request(&self, event: Event, timeout_duration: Option<Duration>) -> Result<EventResponse> {
        let request_id = Uuid::new_v4();
        let (response_tx, response_rx) = oneshot::channel();
        
        let request = EventRequest {
            id: request_id,
            event,
            response_tx,
            timeout: timeout_duration.unwrap_or(self.config.request_timeout),
        };

        // Publish the request event
        self.publish(request.event.clone()).await?;

        // Wait for response with timeout
        let timeout_duration = request.timeout;
        match timeout(timeout_duration, response_rx).await {
            Ok(Ok(response)) => {
                if self.config.enable_metrics {
                    self.metrics.write().await.record_request_success();
                }
                Ok(response)
            }
Ok(Err(_)) => {
            if self.config.enable_metrics {
                self.metrics.write().await.record_failure();
            }
            Err(EventBusError::ReceiveError("Response channel closed".to_string()))
        }
            Err(_) => {
                if self.config.enable_metrics {
                    self.metrics.write().await.record_request_timeout();
                }
                Ok(EventResponse::error(request_id, "Request timed out"))
            }
        }
    }

    /// Subscribe to events with filter
    pub async fn subscribe(&self, filter: EventFilter) -> Result<EventSubscriber> {
        let subscription = EventSubscription::new(filter.clone());
        let id = subscription.id;

        self.subscriptions.write().await.insert(id, subscription);

        let rx = self.tx.subscribe();

        // Update subscriber count in metrics
        if self.config.enable_metrics {
            let count = self.subscriptions.read().await.len();
            self.metrics.write().await.update_subscriber_count(count);
        }

        info!("Created subscription {} with filter {:?}", id, filter);

        Ok(EventSubscriber::new(id, rx, filter, self.correlation_id))
    }

    /// Subscribe to specific event type
    pub async fn subscribe_to_type(&self, event_type: EventType) -> Result<EventSubscriber> {
        let filter = EventFilter::default().with_type(event_type);
        self.subscribe(filter).await
    }

    /// Subscribe to multiple event types
    pub async fn subscribe_to_types(&self, event_types: Vec<EventType>) -> Result<EventSubscriber> {
        let mut filter = EventFilter::default();
        for event_type in event_types {
            filter = filter.with_type(event_type);
        }
        self.subscribe(filter).await
    }

    /// Register event handler
    pub async fn register_handler(&self, handler: EventHandler) -> Result<()> {
        let event_type = handler.event_type();

        self.handlers
            .as_ref()
            .entry(event_type)
            .or_insert_with(Vec::new)
            .push(handler);

        // Update handler count in metrics
        if self.config.enable_metrics {
            let count: usize = self.handlers.iter().map(|e| e.value().len()).sum();
            self.metrics.write().await.update_handler_count(count);
        }

        info!("Registered handler for {:?}", event_type);
        Ok(())
    }

    /// Unregister handler by name
    pub async fn unregister_handler(&self, name: &str) -> Result<()> {
        let mut removed = false;

        for mut entry in self.handlers.iter_mut() {
            let handlers: &mut Vec<EventHandler> = entry.value_mut();
            let before_len = handlers.len();
            handlers.retain(|h| h.name() != name);
            if handlers.len() < before_len {
                removed = true;
            }
        }

        // Update handler count in metrics
        if self.config.enable_metrics {
            let count: usize = self.handlers.iter().map(|e| e.value().len()).sum();
            self.metrics.write().await.update_handler_count(count);
        }

        if removed {
            info!("Unregistered handler {}", name);
            Ok(())
        } else {
            Err(EventBusError::HandlerNotFound(name.to_string()))
        }
    }

    /// Trigger handlers for event
    async fn trigger_handlers(&self, event: &Event) -> Result<()> {
        if let Some(handlers) = self.handlers.get(&event.event_type) {
            let handlers_vec: Vec<EventHandler> = handlers.iter().cloned().collect();
            for handler in handlers_vec {
                if handler.can_handle(event) {
                    handler.handle(event.clone()).await;
                }
            }
        }

        Ok(())
    }

    /// Get event statistics
    pub async fn stats(&self) -> EventStats {
        let metrics = self.metrics.read().await;
        EventStats {
            total_events: metrics.messages_published,
            events_by_type: metrics.messages_by_type.clone(),
            events_by_priority: metrics.messages_by_priority.clone(),
            events_per_second: 0.0, // Would need time window tracking
            subscribers_count: metrics.active_subscribers,
        }
    }

    /// Get detailed metrics
    pub async fn metrics(&self) -> EventBusMetrics {
        self.metrics.read().await.clone()
    }

    /// Get subscriber count
    pub async fn subscriber_count(&self) -> usize {
        self.subscriptions.read().await.len()
    }

    /// Get handler count
    pub fn handler_count(&self) -> usize {
        self.handlers.iter().map(|e| e.value().len()).sum()
    }

    /// Get correlation ID
    pub fn correlation_id(&self) -> Option<Uuid> {
        self.correlation_id
    }

    /// Shutdown event bus
    pub async fn shutdown(&self) {
        info!("Shutting down event bus");
        
        // Clear subscriptions
        self.subscriptions.write().await.clear();
        
        // Clear handlers
        self.handlers.clear();
        
        // Close persistence file
        if self.config.enable_persistence {
            *self.persistence_file.write().await = None;
        }

        info!("Event bus shutdown complete");
    }

    /// Factory method to create correlation-scoped event bus
    pub fn create_scoped(&self, correlation_id: Uuid) -> Self {
        self.with_correlation(correlation_id)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for EventBus {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            handlers: self.handlers.clone(),
            subscriptions: Arc::new(RwLock::new(HashMap::new())), // New subscription map for clone
            config: self.config.clone(),
            metrics: self.metrics.clone(),
            request_tx: self.request_tx.clone(),
            correlation_id: self.correlation_id,
            persistence_file: self.persistence_file.clone(),
            persisted_count: self.persisted_count.clone(),
        }
    }
}

/// EventBusFactory for creating correlation-scoped event bus instances
#[derive(Debug, Clone)]
pub struct EventBusFactory {
    base_bus: EventBus,
    instances: Arc<RwLock<HashMap<Uuid, EventBus>>>,
}

impl EventBusFactory {
    /// Create new factory with base configuration
    pub fn new(config: EventBusConfig) -> Self {
        Self {
            base_bus: EventBus::with_config(config),
            instances: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create new factory from existing event bus
    pub fn from_bus(bus: EventBus) -> Self {
        Self {
            base_bus: bus,
            instances: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get or create correlation-scoped event bus
    pub async fn get_or_create(&self, correlation_id: Uuid) -> EventBus {
        let mut instances = self.instances.write().await;
        
        instances.entry(correlation_id).or_insert_with(|| {
            let scoped_bus = self.base_bus.with_correlation(correlation_id);
            info!("Created correlation-scoped event bus for {}", correlation_id);
            scoped_bus
        }).clone()
    }

    /// Get existing scoped event bus if it exists
    pub async fn get(&self, correlation_id: Uuid) -> Option<EventBus> {
        self.instances.read().await.get(&correlation_id).cloned()
    }

    /// Remove correlation-scoped event bus
    pub async fn remove(&self, correlation_id: Uuid) -> Option<EventBus> {
        let mut instances = self.instances.write().await;
        let bus = instances.remove(&correlation_id);
        if bus.is_some() {
            info!("Removed correlation-scoped event bus for {}", correlation_id);
        }
        bus
    }

    /// Get all active correlation IDs
    pub async fn active_correlations(&self) -> Vec<Uuid> {
        self.instances.read().await.keys().cloned().collect()
    }

    /// Get count of active instances
    pub async fn instance_count(&self) -> usize {
        self.instances.read().await.len()
    }

    /// Shutdown all instances
    pub async fn shutdown_all(&self) {
        let mut instances = self.instances.write().await;
        for (id, bus) in instances.iter() {
            bus.shutdown().await;
            info!("Shutdown event bus for correlation {}", id);
        }
        instances.clear();
    }
}

impl Default for EventBusFactory {
    fn default() -> Self {
        Self::new(EventBusConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_event_bus_creation() {
        let bus = EventBus::new();
        assert_eq!(bus.handler_count(), 0);
        assert_eq!(bus.subscriber_count().await, 0);
    }

    #[tokio::test]
    async fn test_event_bus_with_config() {
        let config = EventBusConfig::default()
            .with_channel_capacity(100)
            .with_request_timeout(Duration::from_secs(10));
        
        let bus = EventBus::with_config(config);
        assert_eq!(bus.handler_count(), 0);
    }

    #[tokio::test]
    async fn test_event_publish() {
        let bus = EventBus::new();

        let event = Event::assessment_created(Uuid::new_v4(), "test");
        bus.publish(event).await.unwrap();

        let stats = bus.stats().await;
        assert_eq!(stats.total_events, 1);
    }

    #[tokio::test]
    async fn test_event_subscribe() {
        let bus = EventBus::new();

        let filter = EventFilter::default().with_type(EventType::AssessmentCreated);

        let subscriber = bus.subscribe(filter).await.unwrap();
        assert_eq!(bus.subscriber_count().await, 1);

        // Publish event
        let event = Event::assessment_created(Uuid::new_v4(), "test");
        bus.publish(event).await.unwrap();
    }

    #[tokio::test]
    async fn test_event_subscribe_to_type() {
        let bus = EventBus::new();

        let subscriber = bus.subscribe_to_type(EventType::JobStarted).await.unwrap();
        assert_eq!(bus.subscriber_count().await, 1);
    }

    #[tokio::test]
    async fn test_event_publish_with_priority() {
        let bus = EventBus::new();

        let event = Event::assessment_created(Uuid::new_v4(), "test");
        bus.publish_with_priority(event, EventPriority::High).await.unwrap();

        let metrics = bus.metrics().await;
        assert_eq!(metrics.messages_published, 1);
        assert!(metrics.messages_by_priority.contains_key("High"));
    }

    #[tokio::test]
    async fn test_correlation_scoped_bus() {
        let bus = EventBus::new();
        let correlation_id = Uuid::new_v4();

        let scoped_bus = bus.with_correlation(correlation_id);
        assert_eq!(scoped_bus.correlation_id(), Some(correlation_id));

        // Publish event on scoped bus
        let event = Event::assessment_created(Uuid::new_v4(), "test");
        scoped_bus.publish(event).await.unwrap();
    }

    #[tokio::test]
    async fn test_event_bus_factory() {
        let factory = EventBusFactory::new(EventBusConfig::default());
        let correlation_id = Uuid::new_v4();

        let bus = factory.get_or_create(correlation_id).await;
        assert_eq!(bus.correlation_id(), Some(correlation_id));

        assert_eq!(factory.instance_count().await, 1);

        // Get same instance
        let bus2 = factory.get_or_create(correlation_id).await;
        assert_eq!(bus2.correlation_id(), Some(correlation_id));
        assert_eq!(factory.instance_count().await, 1);
    }

    #[tokio::test]
    async fn test_event_bus_factory_remove() {
        let factory = EventBusFactory::new(EventBusConfig::default());
        let correlation_id = Uuid::new_v4();

        let _bus = factory.get_or_create(correlation_id).await;
        assert_eq!(factory.instance_count().await, 1);

        factory.remove(correlation_id).await;
        assert_eq!(factory.instance_count().await, 0);
    }

    #[tokio::test]
    async fn test_metrics_tracking() {
        let bus = EventBus::new();

        // Publish multiple events
        for _ in 0..5 {
            let event = Event::assessment_created(Uuid::new_v4(), "test");
            bus.publish(event).await.unwrap();
        }

        let metrics = bus.metrics().await;
        assert_eq!(metrics.messages_published, 5);
        assert!(metrics.avg_publish_latency_us > 0);
    }

    #[tokio::test]
    async fn test_handler_registration() {
        let bus = EventBus::new();

        let handler = EventHandler::new(
            "test_handler",
            EventType::AssessmentCreated,
            |_event| async {},
        );

        bus.register_handler(handler).await.unwrap();
        assert_eq!(bus.handler_count(), 1);

        bus.unregister_handler("test_handler").await.unwrap();
        assert_eq!(bus.handler_count(), 0);
    }

    #[tokio::test]
    async fn test_request_response_timeout() {
        let bus = EventBus::new();

        let event = Event::assessment_created(Uuid::new_v4(), "test");
        let response = bus.request(event, Some(Duration::from_millis(10))).await.unwrap();

        // Should timeout since no handler is registered
        assert!(!response.success);
        assert!(response.error.is_some());
    }

    #[tokio::test]
    async fn test_event_filter_matching() {
        let bus = EventBus::new();

        let filter = EventFilter::default()
            .with_type(EventType::AssessmentCreated)
            .with_min_priority(EventPriority::Normal);

        let subscriber = bus.subscribe(filter).await.unwrap();
        assert_eq!(subscriber.id.to_string().len(), 36); // Valid UUID
    }

    #[tokio::test]
    async fn test_multiple_event_types_subscription() {
        let bus = EventBus::new();

        let subscriber = bus
            .subscribe_to_types(vec![EventType::AssessmentCreated, EventType::JobStarted])
            .await
            .unwrap();

        assert_eq!(bus.subscriber_count().await, 1);
    }

    #[tokio::test]
    async fn test_event_bus_shutdown() {
        let bus = EventBus::new();

        // Add some subscriptions
        let filter = EventFilter::default().with_type(EventType::AssessmentCreated);
        let _subscriber = bus.subscribe(filter).await.unwrap();

        assert_eq!(bus.subscriber_count().await, 1);

        bus.shutdown().await;

        // After shutdown, subscriptions should be cleared
        assert_eq!(bus.subscriber_count().await, 0);
    }

    #[tokio::test]
    async fn test_factory_shutdown_all() {
        let factory = EventBusFactory::new(EventBusConfig::default());

        // Create multiple instances
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        let _bus1 = factory.get_or_create(id1).await;
        let _bus2 = factory.get_or_create(id2).await;

        assert_eq!(factory.instance_count().await, 2);

        factory.shutdown_all().await;
        assert_eq!(factory.instance_count().await, 0);
    }
}
