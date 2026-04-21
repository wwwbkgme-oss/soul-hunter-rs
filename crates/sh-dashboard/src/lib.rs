//! # Soul Hunter Dashboard
//!
//! Production-ready WebSocket dashboard for real-time security analysis monitoring.
//! Provides HTTP endpoints and WebSocket connections for streaming findings,
//! assessment progress, and system metrics.
//!
//! ## Features
//!
//! - Real-time WebSocket streaming of findings and events
//! - HTTP REST API for session management and queries
//! - Static file serving for dashboard UI
//! - Session-based progress tracking
//! - Production-grade error handling and logging
//!
//! ## Example Usage
//!
//! ```rust
//! use sh_dashboard::DashboardServer;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let dashboard = DashboardServer::new("0.0.0.0:8080");
//!     dashboard.start().await?;
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use sh_core::session_manager::{AssessmentSession, SessionManager};
use sh_types::{
    Assessment, AssessmentId, AssessmentStatus, AssessmentSummary, Finding, FindingCollection,
    Platform, Severity,
};

pub mod dashboard_api;
pub mod error;
pub mod server;
pub mod state;
pub mod websocket;
pub mod websocket_server;

pub use dashboard_api::{DashboardApi, requests, responses};
pub use error::{DashboardError, Result};
pub use server::DashboardServer;
pub use state::{
    AssessmentState, AssessmentStateStatus, GlobalStats, PhaseState, PhaseStateStatus,
    SkillState, SkillStateStatus, StateManager, StateUpdateEvent, StateUpdateType, StateUpdateData,
};
pub use websocket::{DashboardEvent, DashboardMetrics, WebSocketManager};
pub use websocket_server::{
    EventFilterType, WebSocketServer, WebSocketServerState, ConnectionStats,
};

/// Dashboard configuration
#[derive(Debug, Clone)]
pub struct DashboardConfig {
    /// HTTP server bind address
    pub bind_addr: String,
    /// Maximum number of WebSocket connections
    pub max_connections: usize,
    /// Broadcast channel capacity for events
    pub event_channel_capacity: usize,
    /// Broadcast channel capacity for metrics
    pub metrics_channel_capacity: usize,
    /// Enable CORS for all origins
    pub enable_cors: bool,
    /// Static files directory (None for embedded)
    pub static_dir: Option<String>,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".to_string(),
            max_connections: 100,
            event_channel_capacity: 1000,
            metrics_channel_capacity: 100,
            enable_cors: true,
            static_dir: None,
        }
    }
}

impl DashboardConfig {
    /// Create config with custom bind address
    pub fn with_bind_addr(mut self, addr: impl Into<String>) -> Self {
        self.bind_addr = addr.into();
        self
    }

    /// Set maximum WebSocket connections
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set event channel capacity
    pub fn with_event_channel_capacity(mut self, capacity: usize) -> Self {
        self.event_channel_capacity = capacity;
        self
    }

    /// Set metrics channel capacity
    pub fn with_metrics_channel_capacity(mut self, capacity: usize) -> Self {
        self.metrics_channel_capacity = capacity;
        self
    }

    /// Enable/disable CORS
    pub fn with_cors(mut self, enable: bool) -> Self {
        self.enable_cors = enable;
        self
    }

    /// Set static files directory
    pub fn with_static_dir(mut self, dir: impl Into<String>) -> Self {
        self.static_dir = Some(dir.into());
        self
    }
}

/// Dashboard state shared across all connections
pub struct DashboardState {
    /// Active WebSocket connections count
    pub connection_count: Arc<RwLock<usize>>,
    /// Event broadcaster
    pub event_tx: broadcast::Sender<DashboardEvent>,
    /// Metrics broadcaster
    pub metrics_tx: broadcast::Sender<DashboardMetrics>,
    /// Session manager reference
    pub session_manager: Arc<SessionManager>,
    /// Active sessions cache
    pub sessions: Arc<DashMap<AssessmentId, DashboardSession>>,
    /// Server start time
    pub start_time: DateTime<Utc>,
}

impl std::fmt::Debug for DashboardState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DashboardState")
            .field("connection_count", &self.connection_count)
            .field("sessions_count", &self.sessions.len())
            .field("start_time", &self.start_time)
            .finish_non_exhaustive()
    }
}

/// Dashboard session with real-time state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSession {
    pub assessment_id: AssessmentId,
    pub name: String,
    pub status: AssessmentStatus,
    pub target_path: String,
    pub platform: Platform,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub progress_percent: u8,
    pub current_phase: String,
    pub findings_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub error: Option<String>,
}

impl From<&Assessment> for DashboardSession {
    fn from(assessment: &Assessment) -> Self {
        let (findings_count, critical_count, high_count) = match &assessment.findings {
            Some(findings) => (
                findings.total_count,
                findings.critical().len(),
                findings.high().len(),
            ),
            None => (0, 0, 0),
        };

        Self {
            assessment_id: assessment.id,
            name: assessment.name.clone(),
            status: assessment.status,
            target_path: assessment.target.path.clone(),
            platform: assessment.target.platform,
            created_at: assessment.created_at,
            started_at: assessment.started_at,
            completed_at: assessment.completed_at,
            progress_percent: 0,
            current_phase: "initialized".to_string(),
            findings_count,
            critical_count,
            high_count,
            error: assessment.error.clone(),
        }
    }
}

impl DashboardSession {
    /// Update progress information
    pub fn update_progress(&mut self, phase: impl Into<String>, percent: u8) {
        self.current_phase = phase.into();
        self.progress_percent = percent.min(100);
    }

    /// Update findings counts
    pub fn update_findings(&mut self, collection: &FindingCollection) {
        self.findings_count = collection.total_count;
        self.critical_count = collection.critical().len();
        self.high_count = collection.high().len();
    }

    /// Mark as failed
    pub fn mark_failed(&mut self, error: impl Into<String>) {
        self.status = AssessmentStatus::Failed;
        self.error = Some(error.into());
        self.completed_at = Some(Utc::now());
    }
}

/// System status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub version: String,
    pub uptime_seconds: u64,
    pub active_sessions: usize,
    pub total_findings: usize,
    pub websocket_connections: usize,
    pub timestamp: DateTime<Utc>,
}

/// Dashboard statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub completed_sessions: usize,
    pub failed_sessions: usize,
    pub total_findings: usize,
    pub findings_by_severity: HashMap<Severity, usize>,
    pub websocket_connections: usize,
}

/// WebSocket client message types
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Subscribe to events for a specific session
    Subscribe { session_id: Option<AssessmentId> },
    /// Unsubscribe from events
    Unsubscribe,
    /// Request session list
    GetSessions,
    /// Request specific session details
    GetSession { session_id: AssessmentId },
    /// Request system status
    GetStatus,
    /// Ping/keepalive
    Ping,
}

/// WebSocket server response types
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Event notification
    Event(DashboardEvent),
    /// Metrics update
    Metrics(DashboardMetrics),
    /// Session list response
    SessionsList { sessions: Vec<DashboardSession> },
    /// Single session response
    Session { session: DashboardSession },
    /// System status response
    Status(SystemStatus),
    /// Pong response
    Pong,
    /// Error response
    Error { message: String, code: String },
    /// Subscription confirmed
    Subscribed { session_id: Option<AssessmentId> },
}

/// Re-export commonly used types
pub mod prelude {
    pub use super::{
        ClientMessage, DashboardConfig, DashboardEvent, DashboardMetrics, DashboardServer,
        DashboardSession, DashboardStats, ServerMessage, SystemStatus,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::AnalysisTarget;

    #[test]
    fn test_dashboard_config_default() {
        let config = DashboardConfig::default();
        assert_eq!(config.bind_addr, "0.0.0.0:8080");
        assert_eq!(config.max_connections, 100);
        assert_eq!(config.event_channel_capacity, 1000);
        assert!(config.enable_cors);
    }

    #[test]
    fn test_dashboard_config_builder() {
        let config = DashboardConfig::default()
            .with_bind_addr("127.0.0.1:3000")
            .with_max_connections(50)
            .with_cors(false);

        assert_eq!(config.bind_addr, "127.0.0.1:3000");
        assert_eq!(config.max_connections, 50);
        assert!(!config.enable_cors);
    }

    #[test]
    fn test_dashboard_session_from_assessment() {
        let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
        let assessment = Assessment::new("Test Assessment", target);

        let session = DashboardSession::from(&assessment);

        assert_eq!(session.assessment_id, assessment.id);
        assert_eq!(session.name, "Test Assessment");
        assert_eq!(session.target_path, "/test/app.apk");
        assert_eq!(session.platform, Platform::Android);
        assert_eq!(session.status, AssessmentStatus::Created);
    }

    #[test]
    fn test_dashboard_session_progress() {
        let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
        let assessment = Assessment::new("Test", target);
        let mut session = DashboardSession::from(&assessment);

        session.update_progress("analysis", 50);
        assert_eq!(session.progress_percent, 50);
        assert_eq!(session.current_phase, "analysis");

        // Should cap at 100
        session.update_progress("complete", 150);
        assert_eq!(session.progress_percent, 100);
    }

    #[tokio::test]
    async fn test_system_status() {
        let status = SystemStatus {
            version: "0.1.0".to_string(),
            uptime_seconds: 60,
            active_sessions: 5,
            total_findings: 100,
            websocket_connections: 3,
            timestamp: Utc::now(),
        };

        assert_eq!(status.active_sessions, 5);
        assert_eq!(status.total_findings, 100);
    }
}
