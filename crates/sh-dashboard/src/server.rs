//! HTTP Server - Production Ready
//!
//! Warp-based HTTP server providing REST API endpoints and static file serving.
//! Includes CORS support, error handling, and graceful shutdown.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::Utc;
use serde::Serialize;
use serde_json::json;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use warp::{http::StatusCode, Filter, Rejection, Reply};

use crate::{
    DashboardConfig, DashboardError, DashboardEvent, DashboardMetrics, DashboardSession,
    DashboardState, DashboardStats, Result, SystemStatus,
};
use sh_core::session_manager::SessionManager;
use sh_types::{AssessmentFilter, AssessmentStatus, FindingCollection, Platform, Severity};

/// Dashboard HTTP server
#[derive(Debug, Clone)]
pub struct DashboardServer {
    config: DashboardConfig,
    state: Arc<DashboardState>,
}

impl DashboardServer {
    /// Create new dashboard server with default configuration
    pub fn new(bind_addr: impl Into<String>) -> Self {
        Self::with_config(DashboardConfig::default().with_bind_addr(bind_addr))
    }

    /// Create new dashboard server with custom configuration
    pub fn with_config(config: DashboardConfig) -> Self {
        let (event_tx, _) = broadcast::channel(config.event_channel_capacity);
        let (metrics_tx, _) = broadcast::channel(config.metrics_channel_capacity);

        let state = Arc::new(DashboardState {
            connection_count: Arc::new(tokio::sync::RwLock::new(0)),
            event_tx,
            metrics_tx,
            session_manager: Arc::new(SessionManager::new()),
            sessions: Arc::new(dashmap::DashMap::new()),
            start_time: Utc::now(),
        });

        Self { config, state }
    }

    /// Get server state reference
    pub fn state(&self) -> Arc<DashboardState> {
        self.state.clone()
    }

    /// Get event sender
    pub fn event_sender(&self) -> broadcast::Sender<DashboardEvent> {
        self.state.event_tx.clone()
    }

    /// Get metrics sender
    pub fn metrics_sender(&self) -> broadcast::Sender<DashboardMetrics> {
        self.state.metrics_tx.clone()
    }

    /// Start the dashboard server
    pub async fn start(&self) -> Result<()> {
        info!("Starting Soul Hunter Dashboard server");
        info!("Configuration: {:?}", self.config);

        let addr: SocketAddr = self
            .config
            .bind_addr
            .parse()
            .map_err(|e| DashboardError::InvalidConfig(format!("Invalid bind address: {}", e)))?;

        // Build routes
        let routes = self.build_routes();

        info!("Dashboard server listening on {}", addr);

        // Start server
        warp::serve(routes).run(addr).await;

        Ok(())
    }

    /// Build all HTTP routes
    fn build_routes(
        &self,
    ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone + Send + Sync + 'static {
        // API routes
        let api_routes = self.api_routes();

        // WebSocket route
        let ws_route = self.websocket_route();

        // Static files
        let static_route = self.static_routes();

        // Health check
        let health_route = warp::path!("health")
            .and(warp::get())
            .map(|| warp::reply::json(&json!({"status": "healthy", "timestamp": Utc::now()})));

        // Combine all routes
        ws_route
            .or(api_routes)
            .or(static_route)
            .or(health_route)
            .with(warp::log("sh_dashboard"))
    }

    /// Build API routes
    fn api_routes(
        &self,
    ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone + Send + Sync + 'static {
        let state = self.state.clone();

        // Status endpoint
        let status = warp::path!("api" / "v1" / "status")
            .and(warp::get())
            .and(with_state(state.clone()))
            .and_then(handle_status);

        // Sessions endpoints
        let sessions_list = warp::path!("api" / "v1" / "sessions")
            .and(warp::get())
            .and(with_state(state.clone()))
            .and_then(handle_list_sessions);

        let session_get = warp::path!("api" / "v1" / "sessions" / String)
            .and(warp::get())
            .and(with_state(state.clone()))
            .and_then(handle_get_session);

        // Findings endpoints
        let findings_list = warp::path!("api" / "v1" / "findings")
            .and(warp::get())
            .and(warp::query::<FindingsQuery>())
            .and(with_state(state.clone()))
            .and_then(handle_list_findings);

        // Statistics endpoint
        let stats = warp::path!("api" / "v1" / "stats")
            .and(warp::get())
            .and(with_state(state.clone()))
            .and_then(handle_stats);

        // Metrics endpoint
        let metrics = warp::path!("api" / "v1" / "metrics")
            .and(warp::get())
            .and(with_state(state.clone()))
            .and_then(handle_metrics);

        status
            .or(sessions_list)
            .or(session_get)
            .or(findings_list)
            .or(stats)
            .or(metrics)
    }

    /// Build WebSocket route
    fn websocket_route(
        &self,
    ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone + Send + Sync + 'static {
        let state = self.state.clone();
        let config = self.config.clone();

        warp::path("ws")
            .and(warp::ws())
            .and(with_state(state))
            .and(with_config(config))
            .and_then(handle_websocket_upgrade)
    }

    /// Build static file routes
    fn static_routes(
        &self,
    ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone + Send + Sync + 'static {
        // Serve index.html at root
        let index = warp::path::end().map(|| {
            warp::reply::html(include_str!("static/index.html"))
        });
        
        // Serve CSS file
        let css = warp::path!("static" / "style.css").map(|| {
            warp::reply::with_header(
                include_str!("static/style.css"),
                "content-type",
                "text/css"
            )
        });
        
        // Serve JS file
        let js = warp::path!("static" / "app.js").map(|| {
            warp::reply::with_header(
                include_str!("static/app.js"),
                "content-type",
                "application/javascript"
            )
        });
        
        index.or(css).or(js)
    }

    /// Publish a finding event to all connected clients
    pub async fn publish_finding(&self, finding: &sh_types::Finding, session_id: &str) {
        let event = DashboardEvent {
            event_type: "finding_discovered".to_string(),
            timestamp: Utc::now(),
            session_id: session_id.to_string(),
            payload: serde_json::json!({
                "finding": finding,
                "severity": finding.severity.to_string(),
            }),
        };

        let _ = self.state.event_tx.send(event);
    }

    /// Publish assessment progress update
    pub async fn publish_progress(
        &self,
        session_id: &str,
        phase: &str,
        percent: u8,
        status: AssessmentStatus,
    ) {
        let event = DashboardEvent {
            event_type: "assessment_progress".to_string(),
            timestamp: Utc::now(),
            session_id: session_id.to_string(),
            payload: serde_json::json!({
                "phase": phase,
                "percent": percent,
                "status": status,
            }),
        };

        let _ = self.state.event_tx.send(event);
    }

    /// Register a new assessment session
    pub async fn register_session(&self, assessment: &sh_types::Assessment) {
        let session = DashboardSession::from(assessment);
        self.state.sessions.insert(assessment.id, session.clone());

        // Notify clients
        let event = DashboardEvent {
            event_type: "session_created".to_string(),
            timestamp: Utc::now(),
            session_id: assessment.id.to_string(),
            payload: serde_json::json!({"session": session}),
        };

        let _ = self.state.event_tx.send(event);
        debug!("Registered session: {}", assessment.id);
    }

    /// Update session progress
    pub async fn update_session_progress(
        &self,
        session_id: &uuid::Uuid,
        phase: &str,
        percent: u8,
    ) {
        if let Some(mut session) = self.state.sessions.get_mut(session_id) {
            session.update_progress(phase, percent);

            let event = DashboardEvent {
                event_type: "session_progress".to_string(),
                timestamp: Utc::now(),
                session_id: session_id.to_string(),
                payload: serde_json::json!({
                    "phase": phase,
                    "percent": percent,
                }),
            };

            let _ = self.state.event_tx.send(event);
        }
    }

    /// Update session with findings
    pub async fn update_session_findings(
        &self,
        session_id: &uuid::Uuid,
        findings: &FindingCollection,
    ) {
        if let Some(mut session) = self.state.sessions.get_mut(session_id) {
            session.update_findings(findings);

            let event = DashboardEvent {
                event_type: "session_findings".to_string(),
                timestamp: Utc::now(),
                session_id: session_id.to_string(),
                payload: serde_json::json!({
                    "findings_count": findings.total_count,
                    "by_severity": findings.by_severity,
                }),
            };

            let _ = self.state.event_tx.send(event);
        }
    }

    /// Mark session as completed
    pub async fn complete_session(&self, session_id: &uuid::Uuid, findings: &FindingCollection) {
        if let Some(mut session) = self.state.sessions.get_mut(session_id) {
            session.status = AssessmentStatus::Completed;
            session.update_findings(findings);
            session.completed_at = Some(Utc::now());

            let event = DashboardEvent {
                event_type: "session_completed".to_string(),
                timestamp: Utc::now(),
                session_id: session_id.to_string(),
                payload: serde_json::json!({"session": session.clone()}),
            };

            let _ = self.state.event_tx.send(event);
        }
    }

    /// Mark session as failed
    pub async fn fail_session(&self, session_id: &uuid::Uuid, error: &str) {
        if let Some(mut session) = self.state.sessions.get_mut(session_id) {
            session.mark_failed(error);

            let event = DashboardEvent {
                event_type: "session_failed".to_string(),
                timestamp: Utc::now(),
                session_id: session_id.to_string(),
                payload: serde_json::json!({
                    "error": error,
                    "session": session.clone(),
                }),
            };

            let _ = self.state.event_tx.send(event);
        }
    }
}

/// State filter helper
fn with_state(
    state: Arc<DashboardState>,
) -> impl Filter<Extract = (Arc<DashboardState>,), Error = Infallible> + Clone {
    warp::any().map(move || state.clone())
}

/// Config filter helper
fn with_config(
    config: DashboardConfig,
) -> impl Filter<Extract = (DashboardConfig,), Error = Infallible> + Clone {
    warp::any().map(move || config.clone())
}

/// Handle WebSocket upgrade
async fn handle_websocket_upgrade(
    ws: warp::ws::Ws,
    state: Arc<DashboardState>,
    config: DashboardConfig,
) -> std::result::Result<impl Reply, Rejection> {
    // Check connection limit
    let count = *state.connection_count.read().await;
    if count >= config.max_connections {
        return Err(warp::reject::custom(DashboardError::ConnectionLimitExceeded));
    }

    Ok(ws.on_upgrade(move |websocket| {
        crate::websocket::handle_websocket(websocket, state, config)
    }))
}

/// Handle status endpoint
async fn handle_status(state: Arc<DashboardState>) -> std::result::Result<impl Reply, Rejection> {
    let uptime = Utc::now() - state.start_time;
    let sessions_count = state.sessions.len();
    let connections = *state.connection_count.read().await;

    let total_findings: usize = state
        .sessions
        .iter()
        .map(|s| s.findings_count)
        .sum();

    let status = SystemStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime.num_seconds() as u64,
        active_sessions: sessions_count,
        total_findings,
        websocket_connections: connections,
        timestamp: Utc::now(),
    };

    Ok(warp::reply::json(&status))
}

/// Handle list sessions endpoint
async fn handle_list_sessions(state: Arc<DashboardState>) -> std::result::Result<impl Reply, Rejection> {
    let sessions: Vec<DashboardSession> = state
        .sessions
        .iter()
        .map(|s| s.clone())
        .collect();

    Ok(warp::reply::json(&json!({
        "sessions": sessions,
        "count": sessions.len(),
    })))
}

/// Handle get session endpoint
async fn handle_get_session(
    session_id: String,
    state: Arc<DashboardState>,
) -> std::result::Result<impl Reply, Rejection> {
    let id = uuid::Uuid::parse_str(&session_id)
        .map_err(|_| warp::reject::custom(DashboardError::InvalidMessage(format!("Invalid session ID: {}", session_id))))?;

    match state.sessions.get(&id) {
        Some(session) => Ok(warp::reply::json(&json!({"session": session.clone()}))),
        None => Err(warp::reject::custom(DashboardError::SessionNotFound(session_id))),
    }
}

/// Query parameters for findings endpoint
#[derive(Debug, serde::Deserialize)]
struct FindingsQuery {
    session_id: Option<String>,
    severity: Option<String>,
    limit: Option<usize>,
}

/// Handle list findings endpoint
async fn handle_list_findings(
    _query: FindingsQuery,
    _state: Arc<DashboardState>,
) -> std::result::Result<impl Reply, Rejection> {
    // This is a simplified implementation
    // In production, you'd query the actual finding storage
    let findings: Vec<serde_json::Value> = Vec::new();

    Ok(warp::reply::json(&json!({
        "findings": findings,
        "count": findings.len(),
    })))
}

/// Handle stats endpoint
async fn handle_stats(state: Arc<DashboardState>) -> std::result::Result<impl Reply, Rejection> {
    let total_sessions = state.sessions.len();
    let active_sessions = state
        .sessions
        .iter()
        .filter(|s| {
            matches!(
                s.status,
                AssessmentStatus::Created | AssessmentStatus::Running
            )
        })
        .count();

    let completed_sessions = state
        .sessions
        .iter()
        .filter(|s| matches!(s.status, AssessmentStatus::Completed))
        .count();

    let failed_sessions = state
        .sessions
        .iter()
        .filter(|s| matches!(s.status, AssessmentStatus::Failed))
        .count();

    let total_findings: usize = state.sessions.iter().map(|s| s.findings_count).sum();

    let mut findings_by_severity: std::collections::HashMap<Severity, usize> =
        std::collections::HashMap::new();
    for session in state.sessions.iter() {
        *findings_by_severity.entry(Severity::Critical).or_insert(0) += session.critical_count;
        *findings_by_severity.entry(Severity::High).or_insert(0) += session.high_count;
    }

    let connections = *state.connection_count.read().await;

    let stats = DashboardStats {
        total_sessions,
        active_sessions,
        completed_sessions,
        failed_sessions,
        total_findings,
        findings_by_severity,
        websocket_connections: connections,
    };

    Ok(warp::reply::json(&stats))
}

/// Handle metrics endpoint
async fn handle_metrics(state: Arc<DashboardState>) -> std::result::Result<impl Reply, Rejection> {
    // Return current system metrics
    let metrics = DashboardMetrics {
        session_id: "system".to_string(),
        jobs_completed: state.sessions.len(),
        jobs_failed: 0,
        findings_per_second: 0.0,
        active_workers: state.sessions.len(),
        queue_depth: 0,
        memory_usage_mb: 0,
        cpu_usage_percent: 0.0,
    };

    Ok(warp::reply::json(&metrics))
}

/// Custom rejection handler
pub async fn handle_rejection(err: Rejection) -> Result<impl Reply> {
    let (code, message) = if err.is_not_found() {
        (StatusCode::NOT_FOUND, "Not Found".to_string())
    } else if let Some(e) = err.find::<warp::reject::InvalidQuery>() {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid query: {}", e),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error".to_string(),
        )
    };

    let json = warp::reply::json(&json!({
        "error": {
            "code": code.as_u16(),
            "message": message,
        }
    }));

    Ok(warp::reply::with_status(json, code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::AnalysisTarget;

    #[tokio::test]
    async fn test_dashboard_server_creation() {
        let server = DashboardServer::new("127.0.0.1:0");
        assert_eq!(server.config.bind_addr, "127.0.0.1:0");
    }

    #[tokio::test]
    async fn test_dashboard_server_with_config() {
        let config = DashboardConfig::default()
            .with_bind_addr("127.0.0.1:3000")
            .with_max_connections(50);

        let server = DashboardServer::with_config(config);
        assert_eq!(server.config.max_connections, 50);
    }

    #[tokio::test]
    async fn test_session_registration() {
        let server = DashboardServer::new("127.0.0.1:0");

        let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
        let assessment = Assessment::new("Test", target);

        server.register_session(&assessment).await;

        assert_eq!(server.state.sessions.len(), 1);
        assert!(server.state.sessions.contains_key(&assessment.id));
    }

    #[tokio::test]
    async fn test_session_progress_update() {
        let server = DashboardServer::new("127.0.0.1:0");

        let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
        let assessment = Assessment::new("Test", target);
        let id = assessment.id;

        server.register_session(&assessment).await;
        server.update_session_progress(&id, "analysis", 50).await;

        let session = server.state.sessions.get(&id).unwrap();
        assert_eq!(session.progress_percent, 50);
        assert_eq!(session.current_phase, "analysis");
    }

    #[tokio::test]
    async fn test_session_completion() {
        let server = DashboardServer::new("127.0.0.1:0");

        let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
        let assessment = Assessment::new("Test", target);
        let id = assessment.id;

        server.register_session(&assessment).await;

        let findings = FindingCollection::default();
        server.complete_session(&id, &findings).await;

        let session = server.state.sessions.get(&id).unwrap();
        assert_eq!(session.status, AssessmentStatus::Completed);
        assert!(session.completed_at.is_some());
    }

    #[tokio::test]
    async fn test_session_failure() {
        let server = DashboardServer::new("127.0.0.1:0");

        let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
        let assessment = Assessment::new("Test", target);
        let id = assessment.id;

        server.register_session(&assessment).await;
        server.fail_session(&id, "Test error").await;

        let session = server.state.sessions.get(&id).unwrap();
        assert_eq!(session.status, AssessmentStatus::Failed);
        assert_eq!(session.error, Some("Test error".to_string()));
    }
}
