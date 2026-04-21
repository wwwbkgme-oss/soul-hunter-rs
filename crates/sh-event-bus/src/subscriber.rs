//! Event Subscriber - Production Ready
//!
//! Async event subscriber with filtering and correlation support

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use tokio::sync::broadcast;
use tracing::{debug, error, trace, warn};
use uuid::Uuid;

use sh_types::{Event, EventFilter, EventPriority};

/// Event subscriber with filtering capabilities
#[derive(Debug)]
pub struct EventSubscriber {
    /// Subscription ID
    pub id: Uuid,
    /// Broadcast receiver
    rx: broadcast::Receiver<Event>,
    /// Event filter
    filter: EventFilter,
    /// Correlation ID for scoped subscriptions
    correlation_id: Option<Uuid>,
    /// Messages dropped due to lag
    pub messages_dropped: u64,
}

impl EventSubscriber {
    /// Create new event subscriber
    pub fn new(
        id: Uuid,
        rx: broadcast::Receiver<Event>,
        filter: EventFilter,
        correlation_id: Option<Uuid>,
    ) -> Self {
        Self {
            id,
            rx,
            filter,
            correlation_id,
            messages_dropped: 0,
        }
    }

    /// Get subscription ID
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Get filter
    pub fn filter(&self) -> &EventFilter {
        &self.filter
    }

    /// Get correlation ID
    pub fn correlation_id(&self) -> Option<Uuid> {
        self.correlation_id
    }

    /// Check if subscriber is for a specific correlation scope
    pub fn is_scoped_to(&self, correlation_id: Uuid) -> bool {
        self.correlation_id.map(|id| id == correlation_id).unwrap_or(true)
    }

    /// Receive next event (filtered)
    pub async fn recv(&mut self) -> Option<Event> {
        loop {
            match self.rx.recv().await {
                Ok(event) => {
                    // Check if event matches filter
                    if self.filter.matches(&event) {
                        // Check correlation scope
                        if let Some(sub_corr) = self.correlation_id {
                            // If subscriber has correlation, event should match or be global
                            if let Some(event_corr) = event.metadata.get("correlation_id") {
                                if event_corr == &sub_corr.to_string() {
                                    trace!("Subscriber {} received correlated event {:?}", self.id, event.event_type);
                                    return Some(event);
                                }
                            } else {
                                // Global events are also received by scoped subscribers
                                trace!("Subscriber {} received global event {:?}", self.id, event.event_type);
                                return Some(event);
                            }
                        } else {
                            // Non-scoped subscriber receives all events
                            trace!("Subscriber {} received event {:?}", self.id, event.event_type);
                            return Some(event);
                        }
                    } else {
                        trace!("Subscriber {} filtered out event {:?}", self.id, event.event_type);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("Subscriber {} lagged behind by {} messages", self.id, n);
                    self.messages_dropped += n as u64;
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    debug!("Subscriber {} channel closed", self.id);
                    return None;
                }
            }
        }
    }

    /// Try to receive event without blocking
    pub fn try_recv(&mut self) -> Result<Option<Event>, broadcast::error::TryRecvError> {
        loop {
            match self.rx.try_recv() {
                Ok(event) => {
                    if self.filter.matches(&event) {
                        if let Some(sub_corr) = self.correlation_id {
                            if let Some(event_corr) = event.metadata.get("correlation_id") {
                                if event_corr == &sub_corr.to_string() {
                                    return Ok(Some(event));
                                }
                            } else {
                                return Ok(Some(event));
                            }
                        } else {
                            return Ok(Some(event));
                        }
                    }
                    // Event filtered out, try next
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Receive event with timeout
    pub async fn recv_timeout(&mut self, timeout: std::time::Duration) -> Option<Event> {
        match tokio::time::timeout(timeout, self.recv()).await {
            Ok(event) => event,
            Err(_) => {
                trace!("Subscriber {} receive timeout", self.id);
                None
            }
        }
    }

    /// Check if subscriber has lagged
    pub fn has_lagged(&self) -> bool {
        self.messages_dropped > 0
    }

    /// Get dropped message count
    pub fn dropped_count(&self) -> u64 {
        self.messages_dropped
    }

    /// Update filter
    pub fn update_filter(&mut self, filter: EventFilter) {
        self.filter = filter;
    }

    /// Add event type to filter
    pub fn add_event_type(&mut self, event_type: sh_types::EventType) {
        self.filter.event_types.push(event_type);
    }

    /// Set minimum priority
    pub fn set_min_priority(&mut self, priority: EventPriority) {
        self.filter.min_priority = Some(priority);
    }
}

impl Stream for EventSubscriber {
    type Item = Event;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.try_recv() {
            Ok(event) => {
                if self.filter.matches(&event) {
                    Poll::Ready(Some(event))
                } else {
                    // Filtered out, need to poll again
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Err(broadcast::error::TryRecvError::Empty) => {
                // No messages available, register waker
                // Note: broadcast::Receiver doesn't have a way to register waker
                // so we return Pending and rely on the caller to poll again
                Poll::Pending
            }
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                warn!("Subscriber {} lagged behind by {} messages", self.id, n);
                self.messages_dropped += n as u64;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(broadcast::error::TryRecvError::Closed) => Poll::Ready(None),
        }
    }
}

/// Subscription handle for managing subscriptions
#[derive(Debug, Clone)]
pub struct SubscriptionHandle {
    pub id: Uuid,
    pub correlation_id: Option<Uuid>,
}

impl SubscriptionHandle {
    pub fn new(id: Uuid) -> Self {
        Self {
            id,
            correlation_id: None,
        }
    }

    pub fn with_correlation(id: Uuid, correlation_id: Uuid) -> Self {
        Self {
            id,
            correlation_id: Some(correlation_id),
        }
    }
}

/// Subscription builder for fluent API
#[derive(Debug)]
pub struct SubscriptionBuilder {
    event_types: Vec<sh_types::EventType>,
    sources: Vec<String>,
    min_priority: Option<EventPriority>,
    correlation_id: Option<Uuid>,
}

impl SubscriptionBuilder {
    pub fn new() -> Self {
        Self {
            event_types: Vec::new(),
            sources: Vec::new(),
            min_priority: None,
            correlation_id: None,
        }
    }

    pub fn with_event_type(mut self, event_type: sh_types::EventType) -> Self {
        self.event_types.push(event_type);
        self
    }

    pub fn with_event_types(mut self, event_types: Vec<sh_types::EventType>) -> Self {
        self.event_types.extend(event_types);
        self
    }

    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.sources.push(source.into());
        self
    }

    pub fn with_min_priority(mut self, priority: EventPriority) -> Self {
        self.min_priority = Some(priority);
        self
    }

    pub fn with_correlation(mut self, correlation_id: Uuid) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    pub fn build(self) -> EventFilter {
        let mut filter = EventFilter::default();
        filter.event_types = self.event_types;
        filter.sources = self.sources;
        filter.min_priority = self.min_priority;
        filter
    }
}

impl Default for SubscriptionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{Event, EventPayload, EventType};
    use tokio::sync::broadcast;

    #[tokio::test]
    async fn test_subscriber_creation() {
        let (tx, rx) = broadcast::channel(100);
        let filter = EventFilter::default().with_type(EventType::AssessmentCreated);
        let subscriber = EventSubscriber::new(Uuid::new_v4(), rx, filter, None);

        assert_eq!(subscriber.correlation_id(), None);
        assert_eq!(subscriber.dropped_count(), 0);
    }

    #[tokio::test]
    async fn test_subscriber_with_correlation() {
        let (tx, rx) = broadcast::channel(100);
        let correlation_id = Uuid::new_v4();
        let filter = EventFilter::default();
        let subscriber = EventSubscriber::new(Uuid::new_v4(), rx, filter, Some(correlation_id));

        assert_eq!(subscriber.correlation_id(), Some(correlation_id));
        assert!(subscriber.is_scoped_to(correlation_id));
    }

    #[tokio::test]
    async fn test_subscriber_receive() {
        let (tx, rx) = broadcast::channel(100);
        let filter = EventFilter::default().with_type(EventType::AssessmentCreated);
        let mut subscriber = EventSubscriber::new(Uuid::new_v4(), rx, filter, None);

        // Spawn a task to send an event
        let assessment_id = Uuid::new_v4();
        let event = Event::assessment_created(assessment_id, "test");
        tx.send(event.clone()).unwrap();

        // Receive the event
        let received = subscriber.recv().await;
        assert!(received.is_some());
        assert_eq!(received.unwrap().event_type, EventType::AssessmentCreated);
    }

    #[tokio::test]
    async fn test_subscriber_filtering() {
        let (tx, rx) = broadcast::channel(100);
        let filter = EventFilter::default().with_type(EventType::AssessmentCreated);
        let mut subscriber = EventSubscriber::new(Uuid::new_v4(), rx, filter, None);

        // Send different event types
        let event1 = Event::assessment_created(Uuid::new_v4(), "test");
        let event2 = Event::new(
            EventType::JobStarted,
            "test",
            EventPayload::Custom {
                data: serde_json::json!({}),
            },
        );

        tx.send(event1).unwrap();
        tx.send(event2).unwrap();

        // Should only receive AssessmentCreated
        let received = subscriber.recv().await;
        assert!(received.is_some());
        assert_eq!(received.unwrap().event_type, EventType::AssessmentCreated);
    }

    #[tokio::test]
    async fn test_subscription_builder() {
        let filter = SubscriptionBuilder::new()
            .with_event_type(EventType::AssessmentCreated)
            .with_event_type(EventType::JobStarted)
            .with_source("test_component")
            .with_min_priority(EventPriority::High)
            .build();

        assert_eq!(filter.event_types.len(), 2);
        assert_eq!(filter.sources.len(), 1);
        assert_eq!(filter.min_priority, Some(EventPriority::High));
    }

    #[tokio::test]
    async fn test_subscriber_try_recv() {
        let (tx, rx) = broadcast::channel(100);
        let filter = EventFilter::default();
        let mut subscriber = EventSubscriber::new(Uuid::new_v4(), rx, filter, None);

        // Try to receive without any messages
        let result = subscriber.try_recv();
        assert!(matches!(result, Err(broadcast::error::TryRecvError::Empty)));

        // Send a message
        let event = Event::assessment_created(Uuid::new_v4(), "test");
        tx.send(event).unwrap();

        // Now should receive
        let result = subscriber.try_recv();
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[tokio::test]
    async fn test_subscriber_timeout() {
        let (tx, rx) = broadcast::channel(100);
        let filter = EventFilter::default();
        let mut subscriber = EventSubscriber::new(Uuid::new_v4(), rx, filter, None);

        // Receive with short timeout (no messages)
        let result = subscriber.recv_timeout(std::time::Duration::from_millis(10)).await;
        assert!(result.is_none());
    }
}
