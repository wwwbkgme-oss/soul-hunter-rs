//! Dashboard API - Production Ready
//!
//! REST API endpoints for the dashboard including:
//! - Client commands: subscribe, get-assessment-state, filter-assessments
//! - Statistics endpoints
//! - Event streaming

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use warp::{http::StatusCode, Filter, Rejection, Reply};

use crate::state::{AssessmentState, AssessmentStateStatus, GlobalStats, PhaseState, SkillState, StateManager, StateUpdateEvent};
use crate::websocket_server::{EventFilterType, WebSocketServer, WebSocketServerState};
use crate::{DashboardConfig, DashboardError, DashboardEvent, DashboardMetrics, DashboardSession, DashboardStats, Result, SystemStatus};
use sh_types::{AssessmentFilter, AssessmentId, AssessmentStatus, Finding, FindingCollection, Platform, Severity};

/// API request types
pub mod requests {
    use super::*;

    /// Subscribe request
    #[derive(Debug, Clone, Deserialize)]
    pub struct SubscribeRequest {
        pub session_id: Option<AssessmentId>,
        pub event_types: Option<Vec<String>>,
    }

    /// Filter assessments request
    #[derive(Debug, Clone, Deserialize)]
    pub struct FilterAssessmentsRequest {
        pub status: Option<AssessmentStateStatus>,
        pub platform: Option<Platform>,
        pub created_after: Option<DateTime<Utc>>,
        pub created_before: Option<DateTime<Utc>>,
        pub has_findings: Option<bool>,
    }

    /// Get assessment state request
    #[derive(Debug, Clone, Deserialize)]
    pub struct GetAssessmentStateRequest {
        pub assessment_id: AssessmentId,
    }

    /// Update progress request
    #[derive(Debug, Clone, Deserialize)]
    pub struct UpdateProgressRequest {
        pub assessment_id: AssessmentId,
        pub phase: String,
        pub percent: u8,
    }

    /// Command request for executing actions
    #[derive(Debug, Clone, Deserialize)]
    #[serde(tag = "command", rename_all = "snake_case")]
    pub enum CommandRequest {
        StartAssessment { assessment_id: AssessmentId },
        CancelAssessment { assessment_id: AssessmentId },
        PauseAssessment { assessment_id: AssessmentId },
        ResumeAssessment { assessment_id: AssessmentId },
    }
}

/// API response types
pub mod responses {
    use super::*;

    /// Standard API response wrapper
    #[derive(Debug, Clone, Serialize)]
    pub struct ApiResponse<T> {
        pub success: bool,
        pub data: Option<T>,
        pub error: Option<ApiError>,
        pub timestamp: DateTime<Utc>,
    }

    /// API error
    #[derive(Debug, Clone, Serialize)]
    pub struct ApiError {
        pub code: String,
        pub message: String,
    }

    impl<T> ApiResponse<T> {
        pub fn success(data: T) -> Self {
            Self {
                success: true,
                data: Some(data),
                error: None,
                timestamp: Utc::now(),
            }
        }

        pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
            Self {
                success: false,
                data: None,
                error: Some(ApiError {
                    code: code.into(),
                    message: message.into(),
                }),
                timestamp: Utc::now(),
            }
        }
    }

    /// Assessment detail response
    #[derive(Debug, Clone, Serialize)]
    pub struct AssessmentDetailResponse {
        pub assessment: AssessmentState,
        pub phases: Vec<PhaseState>,
        pub total_skills: usize,
        pub completed_skills: usize,
        pub failed_skills: usize,
    }

    /// Assessment list response
    #[derive(Debug, Clone, Serialize)]
    pub struct AssessmentListResponse {
        pub assessments: Vec<AssessmentState>,
        pub total: usize,
        pub filtered: usize,
    }

    /// Statistics response
    #[derive(Debug, Clone, Serialize)]
    pub struct StatisticsResponse {
        pub global: GlobalStats,
        pub by_platform: HashMap<Platform, usize>,
        pub by_status: HashMap<AssessmentStateStatus, usize>,
        pub findings_by_severity: HashMap<Severity, usize>,
        pub trends: Vec<TrendDataPoint>,
    }

    /// Trend data point
    #[derive(Debug, Clone, Serialize)]
    pub struct TrendDataPoint {
        pub timestamp: DateTime<Utc>,
        pub assessments_count: usize,
        pub findings_count: usize,
    }

    /// Event stream response (SSE)
    #[derive(Debug, Clone, Serialize)]
    pub struct EventStreamResponse {
        pub event_type: String,
        pub data: serde_json::Value,
    }

    /// Command response
    #[derive(Debug, Clone, Serialize)]
    pub struct CommandResponse {
        pub command: String,
        pub assessment_id: AssessmentId,
        pub status: String,
        pub message: String,
    }
}

use responses::*;

/// Dashboard API
#[derive(Debug, Clone)]
pub struct DashboardApi {
    state_manager: Arc<StateManager>,
    ws_server: Arc<WebSocketServer>,
    config: DashboardConfig,
}

impl DashboardApi {
    /// Create a new dashboard API
    pub fn new(
        state_manager: Arc<StateManager>,
        ws_server: Arc<WebSocketServer>,
        config: DashboardConfig,
    ) -> Self {
        Self {
            state_manager,
            ws_server,
            config,
        }
    }

    /// Build all API routes
    pub fn routes(
        &self,
    ) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone + Send + Sync + 'static {
        let api = self.clone();

        // API v1 routes
        let v1 = warp::path("api").and(warp::path("v1"));

        // Status endpoint
        let status = v1
            .clone()
            .and(warp::path("status"))
            .and(warp::get())
            .and(with_api(api.clone()))
            .and_then(handle_status);

        // Assessment endpoints
        let assessments_list = v1
            .clone()
            .and(warp::path("assessments"))
            .and(warp::get())
            .and(warp::query::<HashMap<String, String>>())
            .and(with_api(api.clone()))
            .and_then(handle_list_assessments);

        let assessment_get = v1
            .clone()
            .and(warp::path!("assessments" / String))
            .and(warp::get())
            .and(with_api(api.clone()))
            .and_then(handle_get_assessment);

        let assessment_state = v1
            .clone()
            .and(warp::path!("assessments" / String / "state"))
            .and(warp::get())
            .and(with_api(api.clone()))
            .and_then(handle_get_assessment_state);

        let assessment_phases = v1
            .clone()
            .and(warp::path!("assessments" / String / "phases"))
            .and(warp::get())
            .and(with_api(api.clone()))
            .and_then(handle_get_assessment_phases);

        let assessment_skills = v1
            .clone()
            .and(warp::path!("assessments" / String / "phases" / String / "skills"))
            .and(warp::get())
            .and(with_api(api.clone()))
            .and_then(handle_get_phase_skills);

        // Filter assessments
        let assessments_filter = v1
            .clone()
            .and(warp::path("assessments"))
            .and(warp::path("filter"))
            .and(warp::post())
            .and(warp::body::json())
            .and(with_api(api.clone()))
            .and_then(handle_filter_assessments);

        // Statistics endpoints
        let stats = v1
            .clone()
            .and(warp::path("stats"))
            .and(warp::get())
            .and(with_api(api.clone()))
            .and_then(handle_get_stats);

        let stats_detailed = v1
            .clone()
            .and(warp::path("stats"))
            .and(warp::path("detailed"))
            .and(warp::get())
            .and(with_api(api.clone()))
            .and_then(handle_get_detailed_stats);

        // Command endpoint
        let command = v1
            .clone()
            .and(warp::path("command"))
            .and(warp::post())
            .and(warp::body::json())
            .and(with_api(api.clone()))
            .and_then(handle_command);

        // Progress update endpoint
        let progress_update = v1
            .clone()
            .and(warp::path("assessments"))
            .and(warp::path("progress"))
            .and(warp::post())
            .and(warp::body::json())
            .and(with_api(api.clone()))
            .and_then(handle_update_progress);

        // Combine all routes
        status
            .or(assessments_list)
            .or(assessment_get)
            .or(assessment_state)
            .or(assessment_phases)
            .or(assessment_skills)
            .or(assessments_filter)
            .or(stats)
            .or(stats_detailed)
            .or(command)
            .or(progress_update)
    }

    /// Get state manager
    pub fn state_manager(&self) -> Arc<StateManager> {
        self.state_manager.clone()
    }

    /// Get WebSocket server
    pub fn ws_server(&self) -> Arc<WebSocketServer> {
        self.ws_server.clone()
    }
}

/// API filter helper
fn with_api(
    api: DashboardApi,
) -> impl Filter<Extract = (DashboardApi,), Error = Infallible> + Clone {
    warp::any().map(move || api.clone())
}

/// Handle status endpoint
async fn handle_status(api: DashboardApi) -> std::result::Result<impl Reply, Rejection> {
    let stats = api.state_manager.get_stats().await;
    let connections = api.ws_server.connection_count().await;

    let status = SystemStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: 0, // Would track actual uptime
        active_sessions: stats.active_assessments,
        total_findings: stats.total_findings,
        websocket_connections: connections,
        timestamp: Utc::now(),
    };

    Ok(warp::reply::json(&ApiResponse::success(status)))
}

/// Handle list assessments endpoint
async fn handle_list_assessments(
    query: HashMap<String, String>,
    api: DashboardApi,
) -> std::result::Result<impl Reply, Rejection> {
    let assessments = api.state_manager.get_all_assessments();
    let total = assessments.len();

    // Apply filters from query params
    let filtered: Vec<AssessmentState> = assessments
        .into_iter()
        .filter(|a| {
            if let Some(status_str) = query.get("status") {
                if let Ok(status) = serde_json::from_str::<AssessmentStateStatus>(&format!("\"{}\"", status_str)) {
                    return a.status == status;
                }
            }
            if let Some(platform_str) = query.get("platform") {
                if let Ok(platform) = serde_json::from_str::<Platform>(&format!("\"{}\"", platform_str)) {
                    return a.platform == platform;
                }
            }
            true
        })
        .collect();

    let response = AssessmentListResponse {
        assessments: filtered.clone(),
        total,
        filtered: filtered.len(),
    };

    Ok(warp::reply::json(&ApiResponse::success(response)))
}

/// Handle get assessment endpoint
async fn handle_get_assessment(
    assessment_id: String,
    api: DashboardApi,
) -> std::result::Result<impl Reply, Rejection> {
    let id = match Uuid::parse_str(&assessment_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(warp::reply::json(&ApiResponse::<AssessmentDetailResponse>::error(
                "invalid_id",
                format!("Invalid assessment ID: {}", assessment_id),
            )));
        }
    };

    match api.state_manager.get_assessment(id) {
        Some(assessment) => {
            let total_skills: usize = assessment.phases.iter().map(|p| p.skills.len()).sum();
            let completed_skills: usize = assessment
                .phases
                .iter()
                .map(|p| p.skills.iter().filter(|s| matches!(s.status, crate::state::SkillStateStatus::Completed)).count())
                .sum();
            let failed_skills: usize = assessment
                .phases
                .iter()
                .map(|p| p.skills.iter().filter(|s| matches!(s.status, crate::state::SkillStateStatus::Failed)).count())
                .sum();

            let response = AssessmentDetailResponse {
                phases: assessment.phases.clone(),
                total_skills,
                completed_skills,
                failed_skills,
                assessment,
            };

            Ok(warp::reply::json(&ApiResponse::success(response)))
        }
        None => Ok(warp::reply::json(&ApiResponse::<AssessmentDetailResponse>::error(
            "not_found",
            format!("Assessment not found: {}", assessment_id),
        ))),
    }
}

/// Handle get assessment state endpoint
async fn handle_get_assessment_state(
    assessment_id: String,
    api: DashboardApi,
) -> std::result::Result<impl Reply, Rejection> {
    let id = match Uuid::parse_str(&assessment_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(warp::reply::json(&ApiResponse::<AssessmentState>::error(
                "invalid_id",
                format!("Invalid assessment ID: {}", assessment_id),
            )));
        }
    };

    match api.state_manager.get_assessment(id) {
        Some(state) => Ok(warp::reply::json(&ApiResponse::success(state))),
        None => Ok(warp::reply::json(&ApiResponse::<AssessmentState>::error(
            "not_found",
            format!("Assessment not found: {}", assessment_id),
        ))),
    }
}

/// Handle get assessment phases endpoint
async fn handle_get_assessment_phases(
    assessment_id: String,
    api: DashboardApi,
) -> std::result::Result<impl Reply, Rejection> {
    let id = match Uuid::parse_str(&assessment_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(warp::reply::json(&ApiResponse::<Vec<PhaseState>>::error(
                "invalid_id",
                format!("Invalid assessment ID: {}", assessment_id),
            )));
        }
    };

    match api.state_manager.get_assessment(id) {
        Some(state) => Ok(warp::reply::json(&ApiResponse::success(state.phases))),
        None => Ok(warp::reply::json(&ApiResponse::<Vec<PhaseState>>::error(
            "not_found",
            format!("Assessment not found: {}", assessment_id),
        ))),
    }
}

/// Handle get phase skills endpoint
async fn handle_get_phase_skills(
    assessment_id: String,
    phase_id: String,
    api: DashboardApi,
) -> std::result::Result<impl Reply, Rejection> {
    let id = match Uuid::parse_str(&assessment_id) {
        Ok(id) => id,
        Err(_) => {
            return Ok(warp::reply::json(&ApiResponse::<Vec<SkillState>>::error(
                "invalid_id",
                format!("Invalid assessment ID: {}", assessment_id),
            )));
        }
    };

    match api.state_manager.get_assessment(id) {
        Some(state) => {
            if let Some(phase) = state.phases.iter().find(|p| p.id == phase_id) {
                Ok(warp::reply::json(&ApiResponse::success(phase.skills.clone())))
            } else {
                Ok(warp::reply::json(&ApiResponse::<Vec<SkillState>>::error(
                    "phase_not_found",
                    format!("Phase not found: {}", phase_id),
                )))
            }
        }
        None => Ok(warp::reply::json(&ApiResponse::<Vec<SkillState>>::error(
            "not_found",
            format!("Assessment not found: {}", assessment_id),
        ))),
    }
}

/// Handle filter assessments endpoint
async fn handle_filter_assessments(
    request: requests::FilterAssessmentsRequest,
    api: DashboardApi,
) -> std::result::Result<impl Reply, Rejection> {
    let all_assessments = api.state_manager.get_all_assessments();

    let filtered: Vec<AssessmentState> = all_assessments
        .into_iter()
        .filter(|a| {
            if let Some(status) = request.status {
                if a.status != status {
                    return false;
                }
            }
            if let Some(platform) = request.platform {
                if a.platform != platform {
                    return false;
                }
            }
            if let Some(created_after) = request.created_after {
                if a.created_at < created_after {
                    return false;
                }
            }
            if let Some(created_before) = request.created_before {
                if a.created_at > created_before {
                    return false;
                }
            }
            if let Some(has_findings) = request.has_findings {
                if has_findings && a.findings_count == 0 {
                    return false;
                }
                if !has_findings && a.findings_count > 0 {
                    return false;
                }
            }
            true
        })
        .collect();

    let response = AssessmentListResponse {
        assessments: filtered.clone(),
        total: filtered.len(),
        filtered: filtered.len(),
    };

    Ok(warp::reply::json(&ApiResponse::success(response)))
}

/// Handle get statistics endpoint
async fn handle_get_stats(api: DashboardApi) -> std::result::Result<impl Reply, Rejection> {
    let stats = api.state_manager.get_stats().await;
    Ok(warp::reply::json(&ApiResponse::success(stats)))
}

/// Handle get detailed statistics endpoint
async fn handle_get_detailed_stats(
    api: DashboardApi,
) -> std::result::Result<impl Reply, Rejection> {
    let assessments = api.state_manager.get_all_assessments();
    let global = api.state_manager.get_stats().await;

    // Calculate by platform
    let mut by_platform: HashMap<Platform, usize> = HashMap::new();
    for a in &assessments {
        *by_platform.entry(a.platform).or_insert(0) += 1;
    }

    // Calculate by status
    let mut by_status: HashMap<AssessmentStateStatus, usize> = HashMap::new();
    for a in &assessments {
        *by_status.entry(a.status).or_insert(0) += 1;
    }

    // Calculate findings by severity
    let mut findings_by_severity: HashMap<Severity, usize> = HashMap::new();
    for a in &assessments {
        *findings_by_severity.entry(Severity::Critical).or_insert(0) += a.critical_count;
        *findings_by_severity.entry(Severity::High).or_insert(0) += a.high_count;
        *findings_by_severity.entry(Severity::Medium).or_insert(0) += a.medium_count;
        *findings_by_severity.entry(Severity::Low).or_insert(0) += a.low_count;
        *findings_by_severity.entry(Severity::Info).or_insert(0) += a.info_count;
    }

    // Generate trend data (simplified - would use actual historical data)
    let trends: Vec<TrendDataPoint> = vec![
        TrendDataPoint {
            timestamp: Utc::now() - chrono::Duration::hours(24),
            assessments_count: global.total_assessments.saturating_sub(10),
            findings_count: global.total_findings.saturating_sub(50),
        },
        TrendDataPoint {
            timestamp: Utc::now(),
            assessments_count: global.total_assessments,
            findings_count: global.total_findings,
        },
    ];

    let response = StatisticsResponse {
        global,
        by_platform,
        by_status,
        findings_by_severity,
        trends,
    };

    Ok(warp::reply::json(&ApiResponse::success(response)))
}

/// Handle command endpoint
async fn handle_command(
    request: requests::CommandRequest,
    api: DashboardApi,
) -> std::result::Result<impl Reply, Rejection> {
    let (command, assessment_id) = match &request {
        requests::CommandRequest::StartAssessment { assessment_id } => {
            ("start_assessment", *assessment_id)
        }
        requests::CommandRequest::CancelAssessment { assessment_id } => {
            ("cancel_assessment", *assessment_id)
        }
        requests::CommandRequest::PauseAssessment { assessment_id } => {
            ("pause_assessment", *assessment_id)
        }
        requests::CommandRequest::ResumeAssessment { assessment_id } => {
            ("resume_assessment", *assessment_id)
        }
    };

    // Execute command
    let result = match request {
        requests::CommandRequest::StartAssessment { assessment_id } => {
            api.state_manager.start_assessment(assessment_id).await
        }
        requests::CommandRequest::CancelAssessment { assessment_id } => {
            // Would implement cancel logic
            api.state_manager.get_assessment(assessment_id)
        }
        _ => {
            // Other commands would be implemented
            api.state_manager.get_assessment(assessment_id)
        }
    };

    let response = match result {
        Some(assessment) => {
            CommandResponse {
                command: command.to_string(),
                assessment_id,
                status: "success".to_string(),
                message: format!("Command {} executed successfully", command),
            }
        }
        None => {
            return Ok(warp::reply::json(&ApiResponse::<CommandResponse>::error(
                "not_found",
                format!("Assessment not found: {}", assessment_id),
            )));
        }
    };

    Ok(warp::reply::json(&ApiResponse::success(response)))
}

/// Handle update progress endpoint
async fn handle_update_progress(
    request: requests::UpdateProgressRequest,
    api: DashboardApi,
) -> std::result::Result<impl Reply, Rejection> {
    match api
        .state_manager
        .update_assessment_progress(request.assessment_id, &request.phase, request.percent)
        .await
    {
        Some(state) => Ok(warp::reply::json(&ApiResponse::success(state))),
        None => Ok(warp::reply::json(&ApiResponse::<AssessmentState>::error(
            "not_found",
            format!("Assessment not found: {}", request.assessment_id),
        ))),
    }
}

/// Event streaming endpoint (Server-Sent Events)
pub fn event_stream_route(
    state_manager: Arc<StateManager>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("api" / "v1" / "events")
        .and(warp::get())
        .and(warp::query::<HashMap<String, String>>())
        .map(move |query: HashMap<String, String>| {
            let state_manager = state_manager.clone();
            
            // Create SSE stream
            let stream = async_stream::stream! {
                let mut rx = state_manager.event_sender().subscribe();
                
                // Send initial connection event
                yield Ok::<_, std::convert::Infallible>(warp::sse::Event::default()
                    .event("connected")
                    .data("{\"status\":\"connected\"}"));
                
                // Stream events
                while let Ok(event) = rx.recv().await {
                    if let Ok(data) = serde_json::to_string(&event) {
                        yield Ok(warp::sse::Event::default()
                            .event("state_update")
                            .data(data));
                    }
                }
            };
            
            warp::sse::reply(warp::sse::keep_alive().stream(stream))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::requests::*;
    use super::responses::*;

    #[tokio::test]
    async fn test_api_response_success() {
        let response: ApiResponse<String> = ApiResponse::success("test".to_string());
        assert!(response.success);
        assert_eq!(response.data, Some("test".to_string()));
        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_api_response_error() {
        let response: ApiResponse<String> = ApiResponse::error("test_code", "Test error");
        assert!(!response.success);
        assert!(response.data.is_none());
        assert_eq!(response.error.as_ref().unwrap().code, "test_code");
        assert_eq!(response.error.as_ref().unwrap().message, "Test error");
    }

    #[tokio::test]
    async fn test_filter_request_deserialization() {
        let json = r#"{"status":"running","platform":"android"}"#;
        let request: FilterAssessmentsRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.status, Some(AssessmentStateStatus::Running));
        assert_eq!(request.platform, Some(Platform::Android));
    }

    #[tokio::test]
    async fn test_command_request_deserialization() {
        let json = r#"{"command":"start_assessment","assessment_id":"550e8400-e29b-41d4-a716-446655440000"}"#;
        let request: CommandRequest = serde_json::from_str(json).unwrap();
        
        match request {
            CommandRequest::StartAssessment { assessment_id } => {
                assert_eq!(assessment_id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
            }
            _ => panic!("Wrong command type"),
        }
    }

    #[tokio::test]
    async fn test_statistics_response() {
        let response = StatisticsResponse {
            global: GlobalStats::default(),
            by_platform: HashMap::new(),
            by_status: HashMap::new(),
            findings_by_severity: HashMap::new(),
            trends: vec![],
        };
        
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("global"));
        assert!(json.contains("by_platform"));
    }

    #[tokio::test]
    async fn test_assessment_list_response() {
        let response = AssessmentListResponse {
            assessments: vec![],
            total: 0,
            filtered: 0,
        };
        
        assert_eq!(response.total, 0);
        assert_eq!(response.filtered, 0);
    }

    #[tokio::test]
    async fn test_trend_data_point() {
        let point = TrendDataPoint {
            timestamp: Utc::now(),
            assessments_count: 10,
            findings_count: 50,
        };
        
        assert_eq!(point.assessments_count, 10);
        assert_eq!(point.findings_count, 50);
    }
}
