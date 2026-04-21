//! Event Bus - Production Ready
//!
//! Async pub/sub event system for component communication with:
//! - Broadcast-based messaging using tokio::sync::broadcast
//! - Event type enum with 20+ variants
//! - Subscription management with filtering
//! - Request-response pattern with timeout
//! - Message persistence to disk
//! - Metrics tracking (messages published/delivered/failed, latency)
//! - Priority levels (low, medium, high, critical)
//! - Thread-safe implementation using Arc and RwLock
//! - EventBusFactory for correlation-scoped instances
//!
//! Based on opencode-security-plugin/runtime/event-bus.ts

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, info, warn};

pub mod bus;
pub mod handler;
pub mod subscriber;

pub use bus::{EventBus, EventBusConfig, EventBusFactory, EventBusMetrics, EventRequest, EventResponse};
pub use handler::{EventHandler, HandlerBuilder, HandlerFn, HandlerRegistry, HandlerResult};
pub use subscriber::{EventSubscriber, SubscriptionBuilder, SubscriptionHandle};

use sh_types::prelude::*;
use sh_types::{Event, EventFilter, EventId, EventPriority, EventStats, EventSubscription, EventType, EventPayload};

/// Event bus error types
#[derive(thiserror::Error, Debug, Clone)]
pub enum EventBusError {
    #[error("Event bus closed")]
    BusClosed,

    #[error("Subscription not found: {0}")]
    SubscriptionNotFound(String),

    #[error("Handler not found: {0}")]
    HandlerNotFound(String),

    #[error("Send error: {0}")]
    SendError(String),

    #[error("Receive error: {0}")]
    ReceiveError(String),

    #[error("Persistence error: {0}")]
    PersistenceError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Timeout error: {0}")]
    TimeoutError(String),

    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
}

impl From<sh_types::Error> for EventBusError {
    fn from(e: sh_types::Error) -> Self {
        EventBusError::SendError(e.to_string())
    }
}

impl From<std::io::Error> for EventBusError {
    fn from(e: std::io::Error) -> Self {
        EventBusError::PersistenceError(e.to_string())
    }
}

impl From<serde_json::Error> for EventBusError {
    fn from(e: serde_json::Error) -> Self {
        EventBusError::SerializationError(e.to_string())
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, EventBusError>;

/// Event type variants for easy access
pub mod event_types {
    pub use sh_types::EventType;

    // Assessment events
    pub const ASSESSMENT_CREATED: EventType = EventType::AssessmentCreated;
    pub const ASSESSMENT_STARTED: EventType = EventType::AssessmentStarted;
    pub const ASSESSMENT_COMPLETED: EventType = EventType::AssessmentCompleted;
    pub const ASSESSMENT_FAILED: EventType = EventType::AssessmentFailed;
    pub const ASSESSMENT_CANCELLED: EventType = EventType::AssessmentCancelled;

    // Job events
    pub const JOB_CREATED: EventType = EventType::JobCreated;
    pub const JOB_QUEUED: EventType = EventType::JobQueued;
    pub const JOB_STARTED: EventType = EventType::JobStarted;
    pub const JOB_COMPLETED: EventType = EventType::JobCompleted;
    pub const JOB_FAILED: EventType = EventType::JobFailed;
    pub const JOB_CANCELLED: EventType = EventType::JobCancelled;
    pub const JOB_TIMEOUT: EventType = EventType::JobTimeout;

    // Finding events
    pub const FINDING_DISCOVERED: EventType = EventType::FindingDiscovered;
    pub const FINDING_CORRELATED: EventType = EventType::FindingCorrelated;
    pub const FINDING_MERGED: EventType = EventType::FindingMerged;

    // Agent events
    pub const AGENT_REGISTERED: EventType = EventType::AgentRegistered;
    pub const AGENT_DEREGISTERED: EventType = EventType::AgentDeregistered;
    pub const AGENT_STATUS_CHANGED: EventType = EventType::AgentStatusChanged;
    pub const AGENT_HEARTBEAT: EventType = EventType::AgentHeartbeat;

    // System events
    pub const SYSTEM_STARTUP: EventType = EventType::SystemStartup;
    pub const SYSTEM_SHUTDOWN: EventType = EventType::SystemShutdown;
    pub const SYSTEM_ERROR: EventType = EventType::SystemError;

    // Custom events
    pub const CUSTOM: EventType = EventType::Custom;
}

/// Event priority levels for easy access
pub mod priorities {
    pub use sh_types::EventPriority;

    pub const LOW: EventPriority = EventPriority::Low;
    pub const NORMAL: EventPriority = EventPriority::Normal;
    pub const HIGH: EventPriority = EventPriority::High;
    pub const CRITICAL: EventPriority = EventPriority::Critical;
}

/// Prelude module for convenient imports
pub mod prelude {
    pub use super::{
        EventBus, EventBusConfig, EventBusError, EventBusFactory, EventBusMetrics,
        EventHandler, EventRequest, EventResponse, EventSubscriber, HandlerBuilder,
        HandlerRegistry, HandlerResult, Result, SubscriptionBuilder, SubscriptionHandle,
    };
    pub use super::event_types::*;
    pub use super::priorities::*;
    pub use sh_types::{
        Event, EventFilter, EventId, EventPayload, EventPriority, EventStats,
        EventSubscription, EventType,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_event_bus_module() {
        // Module compiles successfully
        let bus = EventBus::new();
        assert_eq!(bus.handler_count(), 0);
    }

    #[tokio::test]
    async fn test_event_types() {
        // Test that event types are accessible
        let _ = event_types::ASSESSMENT_STARTED;
        let _ = event_types::FINDING_DISCOVERED;
        let _ = event_types::JOB_COMPLETED;
        let _ = event_types::AGENT_REGISTERED;
        let _ = event_types::SYSTEM_STARTUP;
    }

    #[tokio::test]
    async fn test_priorities() {
        // Test that priorities are accessible
        let _ = priorities::LOW;
        let _ = priorities::NORMAL;
        let _ = priorities::HIGH;
        let _ = priorities::CRITICAL;
    }

    #[tokio::test]
    async fn test_error_types() {
        let err = EventBusError::BusClosed;
        assert_eq!(err.to_string(), "Event bus closed");

        let err = EventBusError::SendError("test".to_string());
        assert!(err.to_string().contains("Send error"));
    }

    #[tokio::test]
    async fn test_prelude_imports() {
        // Test that prelude types are accessible
        use prelude::*;

        let bus = EventBus::new();
        let _ = bus.handler_count();
    }

    #[tokio::test]
    async fn test_event_creation() {
        let event = Event::assessment_created(Uuid::new_v4(), "test");
        assert_eq!(event.event_type, EventType::AssessmentCreated);
    }

    #[tokio::test]
    async fn test_event_with_priority() {
        let event = Event::assessment_created(Uuid::new_v4(), "test")
            .with_priority(EventPriority::High);
        assert_eq!(event.priority, EventPriority::High);
    }
}
