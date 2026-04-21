//! Event Handler - Production Ready
//!
//! Async event handlers with filtering and priority support

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use sh_types::{Event, EventFilter, EventPriority, EventType};

/// Handler function type
pub type HandlerFn = Arc<
    dyn Fn(Event) -> Pin<Box<dyn Future<Output = HandlerResult> + Send>> + Send + Sync,
>;

/// Handler result
#[derive(Debug, Clone)]
pub enum HandlerResult {
    Success,
    SuccessWithEvent(Event),
    Error(String),
    Ignored,
}

impl HandlerResult {
    pub fn is_success(&self) -> bool {
        matches!(self, HandlerResult::Success | HandlerResult::SuccessWithEvent(_))
    }

    pub fn is_error(&self) -> bool {
        matches!(self, HandlerResult::Error(_))
    }

    pub fn is_ignored(&self) -> bool {
        matches!(self, HandlerResult::Ignored)
    }
}

/// Event handler trait
#[async_trait]
pub trait EventHandlerTrait: Send + Sync {
    /// Get handler name
    fn name(&self) -> &str;

    /// Get handled event type
    fn event_type(&self) -> EventType;

    /// Get handler filter (optional additional filtering)
    fn filter(&self) -> Option<&EventFilter>;

    /// Get handler priority
    fn priority(&self) -> EventPriority;

    /// Check if handler can handle event
    fn can_handle(&self, event: &Event) -> bool {
        if event.event_type != self.event_type() {
            return false;
        }

        if let Some(filter) = self.filter() {
            filter.matches(event)
        } else {
            true
        }
    }

    /// Handle event
    async fn handle(&self, event: Event) -> HandlerResult;
}

/// Concrete event handler
#[derive(Clone)]
pub struct EventHandler {
    name: String,
    event_type: EventType,
    filter: Option<EventFilter>,
    priority: EventPriority,
    handler: HandlerFn,
    metrics: Arc<RwLock<HandlerMetrics>>,
}

/// Handler metrics
#[derive(Debug, Clone, Default)]
pub struct HandlerMetrics {
    pub events_processed: u64,
    pub events_succeeded: u64,
    pub events_failed: u64,
    pub events_ignored: u64,
    pub total_processing_time_ms: u64,
    pub last_processed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl HandlerMetrics {
    pub fn record_processed(&mut self, duration_ms: u64) {
        self.events_processed += 1;
        self.total_processing_time_ms += duration_ms;
        self.last_processed_at = Some(chrono::Utc::now());
    }

    pub fn record_success(&mut self) {
        self.events_succeeded += 1;
    }

    pub fn record_failure(&mut self) {
        self.events_failed += 1;
    }

    pub fn record_ignored(&mut self) {
        self.events_ignored += 1;
    }

    pub fn avg_processing_time_ms(&self) -> f64 {
        if self.events_processed == 0 {
            0.0
        } else {
            self.total_processing_time_ms as f64 / self.events_processed as f64
        }
    }
}

impl EventHandler {
    /// Create new event handler
    pub fn new<F, Fut>(
        name: impl Into<String>,
        event_type: EventType,
        handler: F,
    ) -> Self
    where
        F: Fn(Event) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let name = name.into();
        let wrapped_handler: HandlerFn = Arc::new(move |event| {
            let fut = handler(event);
            Box::pin(async move {
                fut.await;
                HandlerResult::Success
            })
        });

        Self {
            name,
            event_type,
            filter: None,
            priority: EventPriority::Normal,
            handler: wrapped_handler,
            metrics: Arc::new(RwLock::new(HandlerMetrics::default())),
        }
    }

    /// Create new event handler with result
    pub fn with_result<F, Fut>(
        name: impl Into<String>,
        event_type: EventType,
        handler: F,
    ) -> Self
    where
        F: Fn(Event) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = HandlerResult> + Send + 'static,
    {
        Self {
            name: name.into(),
            event_type,
            filter: None,
            priority: EventPriority::Normal,
            handler: Arc::new(move |event| Box::pin(handler(event))),
            metrics: Arc::new(RwLock::new(HandlerMetrics::default())),
        }
    }

    /// Create new event handler with filter
    pub fn with_filter<F, Fut>(
        name: impl Into<String>,
        event_type: EventType,
        filter: EventFilter,
        handler: F,
    ) -> Self
    where
        F: Fn(Event) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut handler = Self::new(name, event_type, handler);
        handler.filter = Some(filter);
        handler
    }

    /// Set handler priority
    pub fn with_priority(mut self, priority: EventPriority) -> Self {
        self.priority = priority;
        self
    }

    /// Get handler name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get handled event type
    pub fn event_type(&self) -> EventType {
        self.event_type
    }

    /// Get handler filter
    pub fn filter(&self) -> Option<&EventFilter> {
        self.filter.as_ref()
    }

    /// Get handler priority
    pub fn priority(&self) -> EventPriority {
        self.priority
    }

    /// Check if handler can handle event
    pub fn can_handle(&self, event: &Event) -> bool {
        if event.event_type != self.event_type {
            return false;
        }

        if let Some(ref filter) = self.filter {
            filter.matches(event)
        } else {
            true
        }
    }

    /// Handle event
    #[instrument(skip(self, event), fields(handler = %self.name, event_type = ?event.event_type))]
    pub async fn handle(&self, event: Event) -> HandlerResult {
        let start = std::time::Instant::now();
        
        debug!("Handler {} processing event {:?}", self.name, event.event_type);

        let result = (self.handler)(event).await;
        let duration = start.elapsed().as_millis() as u64;

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.record_processed(duration);
        
        match &result {
            HandlerResult::Success | HandlerResult::SuccessWithEvent(_) => {
                metrics.record_success();
                debug!("Handler {} successfully processed event in {}ms", self.name, duration);
            }
            HandlerResult::Error(e) => {
                metrics.record_failure();
                error!("Handler {} failed to process event: {}", self.name, e);
            }
            HandlerResult::Ignored => {
                metrics.record_ignored();
                debug!("Handler {} ignored event", self.name);
            }
        }

        result
    }

    /// Get handler metrics
    pub async fn metrics(&self) -> HandlerMetrics {
        self.metrics.read().await.clone()
    }
}

impl std::fmt::Debug for EventHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventHandler")
            .field("name", &self.name)
            .field("event_type", &self.event_type)
            .field("filter", &self.filter.is_some())
            .field("priority", &self.priority)
            .finish()
    }
}

/// Handler builder for fluent API
pub struct HandlerBuilder {
    name: String,
    event_type: EventType,
    filter: Option<EventFilter>,
    priority: EventPriority,
}

impl HandlerBuilder {
    pub fn new(name: impl Into<String>, event_type: EventType) -> Self {
        Self {
            name: name.into(),
            event_type,
            filter: None,
            priority: EventPriority::Normal,
        }
    }

    pub fn with_filter(mut self, filter: EventFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    pub fn with_priority(mut self, priority: EventPriority) -> Self {
        self.priority = priority;
        self
    }

    pub fn build<F, Fut>(self, handler: F) -> EventHandler
    where
        F: Fn(Event) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut h = EventHandler::new(self.name, self.event_type, handler);
        h.filter = self.filter;
        h.priority = self.priority;
        h
    }

    pub fn build_with_result<F, Fut>(self, handler: F) -> EventHandler
    where
        F: Fn(Event) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = HandlerResult> + Send + 'static,
    {
        let mut h = EventHandler::with_result(self.name, self.event_type, handler);
        h.filter = self.filter;
        h.priority = self.priority;
        h
    }
}

/// Handler registry for managing multiple handlers
#[derive(Debug, Clone)]
pub struct HandlerRegistry {
    handlers: Arc<RwLock<Vec<EventHandler>>>,
}

impl HandlerRegistry {
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register handler
    pub async fn register(&self, handler: EventHandler) {
        self.handlers.write().await.push(handler);
    }

    /// Unregister handler by name
    pub async fn unregister(&self, name: &str) -> bool {
        let mut handlers = self.handlers.write().await;
        let before_len = handlers.len();
        handlers.retain(|h| h.name() != name);
        handlers.len() < before_len
    }

    /// Get handlers for event type
    pub async fn get_handlers(&self, event_type: EventType) -> Vec<EventHandler> {
        self.handlers
            .read()
            .await
            .iter()
            .filter(|h| h.event_type() == event_type)
            .cloned()
            .collect()
    }

    /// Get all handlers
    pub async fn get_all(&self) -> Vec<EventHandler> {
        self.handlers.read().await.clone()
    }

    /// Get handler count
    pub async fn count(&self) -> usize {
        self.handlers.read().await.len()
    }

    /// Clear all handlers
    pub async fn clear(&self) {
        self.handlers.write().await.clear();
    }

    /// Execute all handlers for event
    pub async fn execute(&self, event: &Event) -> Vec<HandlerResult> {
        let handlers = self.get_handlers(event.event_type).await;
        let mut results = Vec::new();

        for handler in handlers {
            if handler.can_handle(event) {
                let result = handler.handle(event.clone()).await;
                results.push(result);
            }
        }

        results
    }
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{Event, EventPayload, EventType};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    #[tokio::test]
    async fn test_handler_creation() {
        let handler = EventHandler::new(
            "test_handler",
            EventType::AssessmentCreated,
            |_event| async {},
        );

        assert_eq!(handler.name(), "test_handler");
        assert_eq!(handler.event_type(), EventType::AssessmentCreated);
        assert_eq!(handler.priority(), EventPriority::Normal);
    }

    #[tokio::test]
    async fn test_handler_with_priority() {
        let handler = EventHandler::new(
            "test_handler",
            EventType::AssessmentCreated,
            |_event| async {},
        )
        .with_priority(EventPriority::High);

        assert_eq!(handler.priority(), EventPriority::High);
    }

    #[tokio::test]
    async fn test_handler_can_handle() {
        let handler = EventHandler::new(
            "test_handler",
            EventType::AssessmentCreated,
            |_event| async {},
        );

        let event = Event::assessment_created(Uuid::new_v4(), "test");
        assert!(handler.can_handle(&event));

        let other_event = Event::new(
            EventType::JobStarted,
            "test",
            EventPayload::Custom {
                data: serde_json::json!({}),
            },
        );
        assert!(!handler.can_handle(&other_event));
    }

    #[tokio::test]
    async fn test_handler_execution() {
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let handler = EventHandler::new(
            "test_handler",
            EventType::AssessmentCreated,
            move |_event| {
                let c = counter_clone.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                }
            },
        );

        let event = Event::assessment_created(Uuid::new_v4(), "test");
        let result = handler.handle(event).await;

        assert!(result.is_success());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_handler_with_result() {
        let handler = EventHandler::with_result(
            "test_handler",
            EventType::AssessmentCreated,
            |_event| async { HandlerResult::Success },
        );

        let event = Event::assessment_created(Uuid::new_v4(), "test");
        let result = handler.handle(event).await;

        assert!(result.is_success());
    }

    #[tokio::test]
    async fn test_handler_metrics() {
        let handler = EventHandler::new(
            "test_handler",
            EventType::AssessmentCreated,
            |_event| async {},
        );

        let event = Event::assessment_created(Uuid::new_v4(), "test");
        handler.handle(event).await;

        let metrics = handler.metrics().await;
        assert_eq!(metrics.events_processed, 1);
        assert_eq!(metrics.events_succeeded, 1);
    }

    #[tokio::test]
    async fn test_handler_builder() {
        let handler = HandlerBuilder::new("test_handler", EventType::AssessmentCreated)
            .with_priority(EventPriority::High)
            .build(|_event| async {});

        assert_eq!(handler.name(), "test_handler");
        assert_eq!(handler.priority(), EventPriority::High);
    }

    #[tokio::test]
    async fn test_handler_registry() {
        let registry = HandlerRegistry::new();

        let handler = EventHandler::new(
            "test_handler",
            EventType::AssessmentCreated,
            |_event| async {},
        );

        registry.register(handler).await;
        assert_eq!(registry.count().await, 1);

        let handlers = registry.get_handlers(EventType::AssessmentCreated).await;
        assert_eq!(handlers.len(), 1);

        registry.unregister("test_handler").await;
        assert_eq!(registry.count().await, 0);
    }

    #[tokio::test]
    async fn test_handler_registry_execute() {
        let registry = HandlerRegistry::new();
        let counter = Arc::new(AtomicUsize::new(0));

        for i in 0..3 {
            let c = counter.clone();
            let handler = EventHandler::new(
                format!("handler_{}", i),
                EventType::AssessmentCreated,
                move |_event| {
                    let c = c.clone();
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                    }
                },
            );
            registry.register(handler).await;
        }

        let event = Event::assessment_created(Uuid::new_v4(), "test");
        let results = registry.execute(&event).await;

        assert_eq!(results.len(), 3);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_handler_result_variants() {
        assert!(HandlerResult::Success.is_success());
        assert!(!HandlerResult::Success.is_error());
        assert!(!HandlerResult::Success.is_ignored());

        assert!(!HandlerResult::Error("test".to_string()).is_success());
        assert!(HandlerResult::Error("test".to_string()).is_error());

        assert!(!HandlerResult::Ignored.is_success());
        assert!(HandlerResult::Ignored.is_ignored());
    }
}
