//! WebSocket Handler - Production Ready
//!
//! Manages WebSocket connections for real-time streaming of findings,
//! assessment progress, and system metrics. Supports bidirectional
//! communication with clients for session management and queries.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use warp::ws::{Message, WebSocket};

use crate::{
    ClientMessage, DashboardConfig, DashboardError, DashboardSession, DashboardState,
    Result, ServerMessage,
};
use sh_types::{AssessmentId, AssessmentStatus, Severity};

/// Dashboard event for WebSocket streaming
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardEvent {
    /// Event type identifier
    pub event_type: String,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Associated session ID
    pub session_id: String,
    /// Event payload (type-specific data)
    pub payload: serde_json::Value,
}

impl DashboardEvent {
    /// Create a new finding discovered event
    pub fn finding_discovered(finding: &sh_types::Finding, session_id: &str) -> Self {
        Self {
            event_type: "finding_discovered".to_string(),
            timestamp: Utc::now(),
            session_id: session_id.to_string(),
            payload: serde_json::json!({
                "finding": finding,
                "severity": finding.severity.to_string(),
                "title": finding.title,
                "description": finding.description,
            }),
        }
    }

    /// Create an assessment progress event
    pub fn assessment_progress(
        session_id: &str,
        phase: &str,
        percent: u8,
        status: AssessmentStatus,
    ) -> Self {
        Self {
            event_type: "assessment_progress".to_string(),
            timestamp: Utc::now(),
            session_id: session_id.to_string(),
            payload: serde_json::json!({
                "phase": phase,
                "percent": percent,
                "status": status,
            }),
        }
    }

    /// Create a session status change event
    pub fn session_status_changed(session_id: &str, old_status: AssessmentStatus, new_status: AssessmentStatus) -> Self {
        Self {
            event_type: "session_status_changed".to_string(),
            timestamp: Utc::now(),
            session_id: session_id.to_string(),
            payload: serde_json::json!({
                "old_status": old_status,
                "new_status": new_status,
            }),
        }
    }

    /// Create a system event
    pub fn system_event(event_type: &str, data: serde_json::Value) -> Self {
        Self {
            event_type: format!("system_{}", event_type),
            timestamp: Utc::now(),
            session_id: "system".to_string(),
            payload: data,
        }
    }
}

/// Dashboard metrics for real-time monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardMetrics {
    /// Session ID these metrics belong to
    pub session_id: String,
    /// Number of completed jobs
    pub jobs_completed: usize,
    /// Number of failed jobs
    pub jobs_failed: usize,
    /// Findings discovered per second
    pub findings_per_second: f32,
    /// Number of active workers
    pub active_workers: usize,
    /// Current queue depth
    pub queue_depth: usize,
    /// Memory usage in MB
    pub memory_usage_mb: u64,
    /// CPU usage percentage
    pub cpu_usage_percent: f32,
}

impl DashboardMetrics {
    /// Create system-wide metrics
    pub fn system_metrics() -> Self {
        Self {
            session_id: "system".to_string(),
            jobs_completed: 0,
            jobs_failed: 0,
            findings_per_second: 0.0,
            active_workers: 0,
            queue_depth: 0,
            memory_usage_mb: 0,
            cpu_usage_percent: 0.0,
        }
    }

    /// Create metrics for a specific session
    pub fn for_session(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
            jobs_completed: 0,
            jobs_failed: 0,
            findings_per_second: 0.0,
            active_workers: 0,
            queue_depth: 0,
            memory_usage_mb: 0,
            cpu_usage_percent: 0.0,
        }
    }
}

/// WebSocket connection state
#[derive(Debug)]
struct WebSocketConnection {
    /// Connection ID
    id: Uuid,
    /// Client address
    addr: Option<SocketAddr>,
    /// Subscribed session IDs (None = all sessions)
    subscriptions: HashSet<AssessmentId>,
    /// Connection start time
    connected_at: DateTime<Utc>,
    /// Last activity timestamp
    last_activity: DateTime<Utc>,
}

impl WebSocketConnection {
    fn new(id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id,
            addr: None,
            subscriptions: HashSet::new(),
            connected_at: now,
            last_activity: now,
        }
    }

    fn is_subscribed(&self, session_id: &AssessmentId) -> bool {
        self.subscriptions.is_empty() || self.subscriptions.contains(session_id)
    }

    fn subscribe(&mut self, session_id: Option<AssessmentId>) {
        if let Some(id) = session_id {
            self.subscriptions.insert(id);
        } else {
            // Subscribe to all - clear specific subscriptions
            self.subscriptions.clear();
        }
    }

    fn unsubscribe(&mut self, session_id: &AssessmentId) {
        self.subscriptions.remove(session_id);
    }

    fn touch(&mut self) {
        self.last_activity = Utc::now();
    }
}

/// WebSocket manager for handling connections
pub struct WebSocketManager {
    state: Arc<DashboardState>,
}

impl WebSocketManager {
    pub fn new(state: Arc<DashboardState>) -> Self {
        Self { state }
    }

    /// Handle a new WebSocket connection
    pub async fn handle_connection(
        &self,
        websocket: WebSocket,
        addr: Option<SocketAddr>,
    ) -> Result<()> {
        let conn_id = Uuid::new_v4();
        let mut connection = WebSocketConnection::new(conn_id);
        connection.addr = addr;

        info!(
            "WebSocket connection {} established from {:?}",
            conn_id, addr
        );

        // Increment connection count
        {
            let mut count = self.state.connection_count.write().await;
            *count += 1;
        }

        // Split the WebSocket
        let (mut ws_tx, mut ws_rx) = websocket.split();

        // Subscribe to broadcast channels
        let mut event_rx = self.state.event_tx.subscribe();
        let mut metrics_rx = self.state.metrics_tx.subscribe();

        // Send welcome message
        let welcome = ServerMessage::Status(crate::SystemStatus {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: (Utc::now() - self.state.start_time).num_seconds() as u64,
            active_sessions: self.state.sessions.len(),
            total_findings: self
                .state
                .sessions
                .iter()
                .map(|s| s.findings_count)
                .sum(),
            websocket_connections: *self.state.connection_count.read().await,
            timestamp: Utc::now(),
        });

        if let Ok(json) = serde_json::to_string(&welcome) {
            let _ = ws_tx.send(Message::text(json)).await;
        }

        // Main message loop
        loop {
            tokio::select! {
                // Handle incoming events from broadcast channel
                Ok(event) = event_rx.recv() => {
                    // Check if subscribed to this session
                    if let Ok(session_id) = event.session_id.parse::<Uuid>() {
                        if connection.is_subscribed(&session_id) {
                            let msg = ServerMessage::Event(event);
                            if let Ok(json) = serde_json::to_string(&msg) {
                                if ws_tx.send(Message::text(json)).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }

                // Handle incoming metrics from broadcast channel
                Ok(metrics) = metrics_rx.recv() => {
                    if connection.is_subscribed(&Uuid::parse_str(&metrics.session_id).unwrap_or_else(|_| Uuid::nil()))
                        || metrics.session_id == "system" {
                        let msg = ServerMessage::Metrics(metrics);
                        if let Ok(json) = serde_json::to_string(&msg) {
                            if ws_tx.send(Message::text(json)).await.is_err() {
                                break;
                            }
                        }
                    }
                }

                // Handle client messages
                result = ws_rx.next() => {
                    match result {
                        Some(Ok(msg)) => {
                            if msg.is_close() {
                                debug!("WebSocket {} received close frame", conn_id);
                                break;
                            }

                            if let Ok(text) = msg.to_str() {
                                connection.touch();

                                if let Err(e) = self.handle_client_message(
                                    text,
                                    &mut connection,
                                    &mut ws_tx,
                                ).await {
                                    warn!("Error handling client message: {}", e);
                                }
                            }
                        }
                        Some(Err(e)) => {
                            error!("WebSocket {} error: {}", conn_id, e);
                            break;
                        }
                        None => {
                            debug!("WebSocket {} closed by client", conn_id);
                            break;
                        }
                    }
                }
            }
        }

        // Cleanup
        {
            let mut count = self.state.connection_count.write().await;
            *count = count.saturating_sub(1);
        }

        info!(
            "WebSocket connection {} closed (duration: {}s)",
            conn_id,
            (Utc::now() - connection.connected_at).num_seconds()
        );

        Ok(())
    }

    /// Handle a message from the client
    async fn handle_client_message(
        &self,
        text: &str,
        connection: &mut WebSocketConnection,
        ws_tx: &mut futures::stream::SplitSink<WebSocket, Message>,
    ) -> Result<()> {
        let msg: ClientMessage = match serde_json::from_str(text) {
            Ok(msg) => msg,
            Err(e) => {
                let error = ServerMessage::Error {
                    message: format!("Invalid message format: {}", e),
                    code: "invalid_message".to_string(),
                };
                let _ = ws_tx
                    .send(Message::text(serde_json::to_string(&error).unwrap()))
                    .await;
                return Ok(());
            }
        };

        match msg {
            ClientMessage::Subscribe { session_id } => {
                connection.subscribe(session_id);

                let response = ServerMessage::Subscribed { session_id };
                let _ = ws_tx
                    .send(Message::text(serde_json::to_string(&response).unwrap()))
                    .await;

                debug!(
                    "Connection {} subscribed to session {:?}",
                    connection.id, session_id
                );
            }

            ClientMessage::Unsubscribe => {
                connection.subscriptions.clear();
                debug!("Connection {} unsubscribed from all", connection.id);
            }

            ClientMessage::GetSessions => {
                let sessions: Vec<DashboardSession> = self
                    .state
                    .sessions
                    .iter()
                    .map(|s| s.clone())
                    .collect();

                let response = ServerMessage::SessionsList { sessions };
                let _ = ws_tx
                    .send(Message::text(serde_json::to_string(&response).unwrap()))
                    .await;
            }

            ClientMessage::GetSession { session_id } => {
                let response = if let Some(session) = self.state.sessions.get(&session_id) {
                    ServerMessage::Session {
                        session: session.clone(),
                    }
                } else {
                    ServerMessage::Error {
                        message: format!("Session not found: {}", session_id),
                        code: "session_not_found".to_string(),
                    }
                };

                let _ = ws_tx
                    .send(Message::text(serde_json::to_string(&response).unwrap()))
                    .await;
            }

            ClientMessage::GetStatus => {
                let uptime = Utc::now() - self.state.start_time;
                let status = crate::SystemStatus {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    uptime_seconds: uptime.num_seconds() as u64,
                    active_sessions: self.state.sessions.len(),
                    total_findings: self
                        .state
                        .sessions
                        .iter()
                        .map(|s| s.findings_count)
                        .sum(),
                    websocket_connections: *self.state.connection_count.read().await,
                    timestamp: Utc::now(),
                };

                let response = ServerMessage::Status(status);
                let _ = ws_tx
                    .send(Message::text(serde_json::to_string(&response).unwrap()))
                    .await;
            }

            ClientMessage::Ping => {
                let response = ServerMessage::Pong;
                let _ = ws_tx
                    .send(Message::text(serde_json::to_string(&response).unwrap()))
                    .await;
            }
        }

        Ok(())
    }
}

/// Handle WebSocket upgrade (called from server.rs)
pub async fn handle_websocket(
    websocket: WebSocket,
    state: Arc<DashboardState>,
    _config: DashboardConfig,
) {
    let manager = WebSocketManager::new(state);

    if let Err(e) = manager.handle_connection(websocket, None).await {
        error!("WebSocket handler error: {}", e);
    }
}

/// WebSocket message types for internal use
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WebSocketMessage {
    /// Client subscription request
    Subscribe { session_id: Option<String> },
    /// Client unsubscription
    Unsubscribe,
    /// Server event notification
    Event(DashboardEvent),
    /// Server metrics update
    Metrics(DashboardMetrics),
    /// Error message
    Error { message: String, code: String },
    /// Ping/Pong for keepalive
    Ping,
    Pong,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{AnalysisTarget, Finding, Platform};

    #[test]
    fn test_dashboard_event_creation() {
        let finding = Finding::new("Test Finding", "Test description")
            .with_severity(Severity::High);

        let event = DashboardEvent::finding_discovered(&finding, "test-session");

        assert_eq!(event.event_type, "finding_discovered");
        assert_eq!(event.session_id, "test-session");
        assert!(event.payload.get("finding").is_some());
    }

    #[test]
    fn test_dashboard_event_progress() {
        let event = DashboardEvent::assessment_progress(
            "test-session",
            "analysis",
            50,
            AssessmentStatus::Running,
        );

        assert_eq!(event.event_type, "assessment_progress");
        assert_eq!(event.payload["phase"], "analysis");
        assert_eq!(event.payload["percent"], 50);
    }

    #[test]
    fn test_dashboard_metrics() {
        let metrics = DashboardMetrics::system_metrics();

        assert_eq!(metrics.session_id, "system");
        assert_eq!(metrics.jobs_completed, 0);
        assert_eq!(metrics.memory_usage_mb, 0);
    }

    #[test]
    fn test_websocket_connection() {
        let conn = WebSocketConnection::new(Uuid::new_v4());

        assert!(conn.subscriptions.is_empty());
        assert!(conn.is_subscribed(&Uuid::new_v4())); // Empty = all

        let session_id = Uuid::new_v4();
        let mut conn = conn;
        conn.subscribe(Some(session_id));

        assert!(conn.is_subscribed(&session_id));
        assert!(!conn.is_subscribed(&Uuid::new_v4()));
    }

    #[test]
    fn test_websocket_connection_unsubscribe() {
        let session_id = Uuid::new_v4();
        let mut conn = WebSocketConnection::new(Uuid::new_v4());

        conn.subscribe(Some(session_id));
        assert!(conn.is_subscribed(&session_id));

        conn.unsubscribe(&session_id);
        assert!(!conn.is_subscribed(&session_id));
    }

    #[test]
    fn test_websocket_message_serialization() {
        let msg = WebSocketMessage::Ping;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("ping"));

        let msg = WebSocketMessage::Pong;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("pong"));
    }

    #[tokio::test]
    async fn test_websocket_manager_creation() {
        let (event_tx, _) = broadcast::channel(100);
        let (metrics_tx, _) = broadcast::channel(100);

        let state = Arc::new(DashboardState {
            connection_count: Arc::new(tokio::sync::RwLock::new(0)),
            event_tx,
            metrics_tx,
            session_manager: Arc::new(sh_core::session_manager::SessionManager::new()),
            sessions: Arc::new(dashmap::DashMap::new()),
            start_time: Utc::now(),
        });

        let manager = WebSocketManager::new(state);
        assert_eq!(manager.state.sessions.len(), 0);
    }
}
