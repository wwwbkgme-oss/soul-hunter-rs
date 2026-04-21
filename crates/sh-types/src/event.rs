//! Event types for the event bus system

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{AgentId, AssessmentId, Finding, JobId, JobStatus};

/// Unique identifier for events
pub type EventId = Uuid;

/// Event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    // Assessment events
    AssessmentCreated,
    AssessmentStarted,
    AssessmentCompleted,
    AssessmentFailed,
    AssessmentCancelled,
    
    // Job events
    JobCreated,
    JobQueued,
    JobStarted,
    JobCompleted,
    JobFailed,
    JobCancelled,
    JobTimeout,
    
    // Finding events
    FindingDiscovered,
    FindingCorrelated,
    FindingMerged,
    
    // Agent events
    AgentRegistered,
    AgentDeregistered,
    AgentStatusChanged,
    AgentHeartbeat,
    
    // System events
    SystemStartup,
    SystemShutdown,
    SystemError,
    
    // Custom events
    Custom,
}

/// Event priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventPriority {
    Low = 0,
    Normal = 50,
    High = 75,
    Critical = 100,
}

impl Default for EventPriority {
    fn default() -> Self {
        EventPriority::Normal
    }
}

/// An event in the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: EventId,
    pub event_type: EventType,
    pub priority: EventPriority,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub payload: EventPayload,
    pub metadata: HashMap<String, String>,
}

impl Event {
    pub fn new(event_type: EventType, source: impl Into<String>, payload: EventPayload) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_type,
            priority: EventPriority::Normal,
            timestamp: Utc::now(),
            source: source.into(),
            payload,
            metadata: HashMap::new(),
        }
    }

    pub fn with_priority(mut self, priority: EventPriority) -> Self {
        self.priority = priority;
        self
    }

    pub fn add_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    // Factory methods for common events
    pub fn assessment_created(assessment_id: AssessmentId, source: impl Into<String>) -> Self {
        Self::new(
            EventType::AssessmentCreated,
            source,
            EventPayload::AssessmentCreated { assessment_id },
        )
    }

    pub fn assessment_started(assessment_id: AssessmentId, source: impl Into<String>) -> Self {
        Self::new(
            EventType::AssessmentStarted,
            source,
            EventPayload::AssessmentStarted { assessment_id },
        )
    }

    pub fn assessment_completed(assessment_id: AssessmentId, findings_count: usize, source: impl Into<String>) -> Self {
        Self::new(
            EventType::AssessmentCompleted,
            source,
            EventPayload::AssessmentCompleted { assessment_id, findings_count },
        )
    }

    pub fn job_started(job_id: JobId, agent_id: Option<AgentId>, source: impl Into<String>) -> Self {
        Self::new(
            EventType::JobStarted,
            source,
            EventPayload::JobStarted { job_id, agent_id },
        )
    }

    pub fn job_completed(job_id: JobId, duration_ms: u64, source: impl Into<String>) -> Self {
        Self::new(
            EventType::JobCompleted,
            source,
            EventPayload::JobCompleted { job_id, duration_ms },
        )
    }

    pub fn finding_discovered(finding: Finding, source: impl Into<String>) -> Self {
        Self::new(
            EventType::FindingDiscovered,
            source,
            EventPayload::FindingDiscovered { finding },
        )
        .with_priority(EventPriority::High)
    }

    pub fn agent_status_changed(agent_id: AgentId, old_status: String, new_status: String, source: impl Into<String>) -> Self {
        Self::new(
            EventType::AgentStatusChanged,
            source,
            EventPayload::AgentStatusChanged { agent_id, old_status, new_status },
        )
    }
}

/// Event payload variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EventPayload {
    // Assessment events
    AssessmentCreated { assessment_id: AssessmentId },
    AssessmentStarted { assessment_id: AssessmentId },
    AssessmentCompleted { assessment_id: AssessmentId, findings_count: usize },
    AssessmentFailed { assessment_id: AssessmentId, error: String },
    AssessmentCancelled { assessment_id: AssessmentId },
    
    // Job events
    JobCreated { job_id: JobId, job_type: String },
    JobQueued { job_id: JobId },
    JobStarted { job_id: JobId, agent_id: Option<AgentId> },
    JobCompleted { job_id: JobId, duration_ms: u64 },
    JobFailed { job_id: JobId, error: String },
    JobCancelled { job_id: JobId },
    JobTimeout { job_id: JobId },
    
    // Finding events
    FindingDiscovered { finding: Finding },
    FindingCorrelated { finding_id: Uuid, correlated_ids: Vec<Uuid> },
    FindingMerged { source_ids: Vec<Uuid>, merged_id: Uuid },
    
    // Agent events
    AgentRegistered { agent_id: AgentId },
    AgentDeregistered { agent_id: AgentId },
    AgentStatusChanged { agent_id: AgentId, old_status: String, new_status: String },
    AgentHeartbeat { agent_id: AgentId },
    
    // System events
    SystemStartup { version: String },
    SystemShutdown { reason: Option<String> },
    SystemError { component: String, error: String },
    
    // Custom events
    Custom { data: serde_json::Value },
}

/// Event filter for subscriptions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EventFilter {
    pub event_types: Vec<EventType>,
    pub sources: Vec<String>,
    pub min_priority: Option<EventPriority>,
    pub after: Option<DateTime<Utc>>,
    pub before: Option<DateTime<Utc>>,
}

impl EventFilter {
    pub fn with_type(mut self, event_type: EventType) -> Self {
        self.event_types.push(event_type);
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

    pub fn matches(&self, event: &Event) -> bool {
        // Check event type
        if !self.event_types.is_empty() && !self.event_types.contains(&event.event_type) {
            return false;
        }

        // Check source
        if !self.sources.is_empty() && !self.sources.contains(&event.source) {
            return false;
        }

        // Check priority
        if let Some(min_priority) = self.min_priority {
            if event.priority < min_priority {
                return false;
            }
        }

        // Check time range
        if let Some(after) = self.after {
            if event.timestamp < after {
                return false;
            }
        }

        if let Some(before) = self.before {
            if event.timestamp > before {
                return false;
            }
        }

        true
    }
}

/// Event subscription
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSubscription {
    pub id: Uuid,
    pub filter: EventFilter,
    pub callback_url: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl EventSubscription {
    pub fn new(filter: EventFilter) -> Self {
        Self {
            id: Uuid::new_v4(),
            filter,
            callback_url: None,
            created_at: Utc::now(),
        }
    }

    pub fn with_callback(mut self, url: impl Into<String>) -> Self {
        self.callback_url = Some(url.into());
        self
    }
}

/// Event statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventStats {
    pub total_events: u64,
    pub events_by_type: HashMap<String, u64>,
    pub events_by_priority: HashMap<String, u64>,
    pub events_per_second: f64,
    pub subscribers_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let assessment_id = Uuid::new_v4();
        let event = Event::assessment_created(assessment_id, "test_component");

        assert_eq!(event.event_type, EventType::AssessmentCreated);
        assert_eq!(event.source, "test_component");
        
        match event.payload {
            EventPayload::AssessmentCreated { assessment_id: id } => {
                assert_eq!(id, assessment_id);
            }
            _ => panic!("Wrong payload type"),
        }
    }

    #[test]
    fn test_event_filter() {
        let filter = EventFilter::default()
            .with_type(EventType::AssessmentCreated)
            .with_min_priority(EventPriority::Normal);

        let event = Event::assessment_created(Uuid::new_v4(), "test");
        assert!(filter.matches(&event));

        let other_event = Event::new(EventType::JobStarted, "test", EventPayload::Custom { data: serde_json::json!({}) });
        assert!(!filter.matches(&other_event));
    }

    #[test]
    fn test_event_priority_ordering() {
        assert!(EventPriority::Low < EventPriority::Normal);
        assert!(EventPriority::Normal < EventPriority::High);
        assert!(EventPriority::High < EventPriority::Critical);
    }
}
