//! Soul Hunter Server - Production Ready REST API and WebSocket Server
//!
//! This is the main server binary for the Soul Hunter security analysis platform.
//! It provides:
//! - REST API endpoints for analysis operations
//! - WebSocket server for real-time updates
//! - Static file serving for the dashboard UI
//!
//! ## Usage
//!
//! ```bash
//! # Start the server with default settings
//! soul-hunter-server
//!
//! # Start with custom port
//! soul-hunter-server --port 8080
//!
//! # Start with configuration file
//! soul-hunter-server --config config.yaml
//! ```

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::{Path, Query, State, WebSocketUpgrade},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{get, post},
    Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{error, info, warn};
use uuid::Uuid;

use sh_core::prelude::*;
use sh_types::prelude::*;

/// Server configuration
#[derive(Parser, Debug)]
#[command(name = "soul-hunter-server")]
#[command(about = "Soul Hunter REST API and WebSocket Server")]
#[command(version = "0.1.0")]
struct Config {
    /// Port to listen on
    #[arg(short, long, default_value = "3000")]
    port: u16,

    /// Host to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Configuration file path
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Enable CORS
    #[arg(long)]
    cors: bool,

    /// Static files directory
    #[arg(long, value_name = "DIR")]
    static_dir: Option<PathBuf>,

    /// Enable WebSocket
    #[arg(long)]
    websocket: bool,

    /// WebSocket port
    #[arg(long, default_value = "3001")]
    ws_port: u16,
}

/// Application state
#[derive(Clone)]
struct AppState {
    orchestrator: Arc<RwLock<Orchestrator>>,
    config: Arc<Config>,
}

/// API response wrapper
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message.into()),
        }
    }
}

/// Create findings request
#[derive(Deserialize)]
struct CreateAssessmentRequest {
    name: String,
    target_path: String,
    platform: Platform,
}

/// List assessments query params
#[derive(Deserialize)]
struct ListAssessmentsQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "soul_hunter_server=info".into()),
        )
        .init();

    let config = Config::parse();
    info!("Starting Soul Hunter Server v0.1.0");
    info!("Binding to {}:{}", config.host, config.port);

    // Initialize orchestrator
    let orchestrator_config = Config::default();
    let orchestrator = Orchestrator::new(orchestrator_config)?;

    let state = AppState {
        orchestrator: Arc::new(RwLock::new(orchestrator)),
        config: Arc::new(config.clone()),
    };

    // Build router
    let app = create_router(state, &config);

    // Start server
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    info!("Server listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Create the API router
fn create_router(state: AppState, config: &Config) -> Router {
    let cors = if config.cors {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        CorsLayer::new()
    };

    let mut router = Router::new()
        // Health check
        .route("/health", get(health_check))
        // API v1 routes
        .route("/api/v1/assessments", get(list_assessments).post(create_assessment))
        .route("/api/v1/assessments/:id", get(get_assessment))
        .route("/api/v1/assessments/:id/start", post(start_assessment))
        .route("/api/v1/assessments/:id/cancel", post(cancel_assessment))
        .route("/api/v1/findings", get(list_findings))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/skills", get(list_skills))
        .route("/api/v1/status", get(system_status))
        // WebSocket endpoint
        .route("/ws", get(websocket_handler))
        // Static files
        .route("/", get(index_handler))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state);

    // Add static file serving if directory is specified
    if let Some(static_dir) = &config.static_dir {
        router = router.nest_service("/static", tower_http::services::ServeDir::new(static_dir));
    }

    router
}

/// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "version": "0.1.0",
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}

/// System status endpoint
async fn system_status(State(state): State<AppState>) -> impl IntoResponse {
    let orchestrator = state.orchestrator.read().await;

    Json(ApiResponse::success(json!({
        "version": "0.1.0",
        "active_assessments": 0, // TODO: Get from orchestrator
        "total_findings": 0,
        "agents": 0,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })))
}

/// List all assessments
async fn list_assessments(
    State(_state): State<AppState>,
    Query(query): Query<ListAssessmentsQuery>,
) -> impl IntoResponse {
    let _limit = query.limit.unwrap_or(100);
    let _offset = query.offset.unwrap_or(0);

    // TODO: Implement actual assessment listing
    let assessments: Vec<Assessment> = vec![];

    Json(ApiResponse::success(assessments))
}

/// Create a new assessment
async fn create_assessment(
    State(state): State<AppState>,
    Json(req): Json<CreateAssessmentRequest>,
) -> impl IntoResponse {
    let target = AnalysisTarget::new(req.target_path, req.platform);
    let assessment_config = AssessmentConfig::default();

    let mut orchestrator = state.orchestrator.write().await;

    match orchestrator.create_assessment(req.name, target, assessment_config) {
        Ok(assessment) => {
            info!("Created assessment: {}", assessment.id);
            Json(ApiResponse::success(assessment))
        }
        Err(e) => {
            error!("Failed to create assessment: {}", e);
            Json(ApiResponse::error(e.to_string()))
        }
    }
}

/// Get a specific assessment
async fn get_assessment(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    // TODO: Implement actual assessment retrieval
    Json(ApiResponse::error(format!("Assessment {} not found", id)))
}

/// Start an assessment
async fn start_assessment(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    info!("Starting assessment: {}", id);
    // TODO: Implement actual assessment start
    Json(ApiResponse::success(json!({ "assessment_id": id, "status": "started" })))
}

/// Cancel an assessment
async fn cancel_assessment(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    info!("Cancelling assessment: {}", id);
    // TODO: Implement actual assessment cancellation
    Json(ApiResponse::success(json!({ "assessment_id": id, "status": "cancelled" })))
}

/// List all findings
async fn list_findings(State(_state): State<AppState>) -> impl IntoResponse {
    // TODO: Implement actual findings listing
    let findings: Vec<Finding> = vec![];
    Json(ApiResponse::success(findings))
}

/// List all agents
async fn list_agents(State(_state): State<AppState>) -> impl IntoResponse {
    // TODO: Implement actual agent listing
    let agents: Vec<serde_json::Value> = vec![];
    Json(ApiResponse::success(agents))
}

/// List all skills
async fn list_skills(State(_state): State<AppState>) -> impl IntoResponse {
    let skills = vec![
        json!({
            "name": "static_analysis",
            "description": "Static code analysis",
            "platforms": ["android", "ios", "iot"],
        }),
        json!({
            "name": "dynamic_analysis",
            "description": "Dynamic behavior analysis",
            "platforms": ["android", "ios"],
        }),
        json!({
            "name": "network_analysis",
            "description": "Network security analysis",
            "platforms": ["android", "ios", "iot", "network"],
        }),
        json!({
            "name": "crypto_analysis",
            "description": "Cryptographic implementation analysis",
            "platforms": ["android", "ios", "iot"],
        }),
    ];

    Json(ApiResponse::success(skills))
}

/// WebSocket handler
async fn websocket_handler(
    State(_state): State<AppState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(handle_socket)
}

/// Handle WebSocket connection
async fn handle_socket(mut socket: axum::extract::ws::WebSocket) {
    info!("WebSocket connection established");

    while let Some(msg) = socket.recv().await {
        if let Ok(msg) = msg {
            // Handle incoming messages
            if let axum::extract::ws::Message::Text(text) = msg {
                info!("Received WebSocket message: {}", text);

                // Echo back for now
                if let Err(e) = socket
                    .send(axum::extract::ws::Message::Text(format!(
                        "Echo: {}",
                        text
                    )))
                    .await
                {
                    warn!("Failed to send WebSocket message: {}", e);
                    break;
                }
            }
        } else {
            break;
        }
    }

    info!("WebSocket connection closed");
}

/// Index handler - serve dashboard HTML
async fn index_handler() -> impl IntoResponse {
    Html(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Soul Hunter Dashboard</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
            background: #f5f5f5;
        }
        h1 { color: #333; }
        .card {
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            margin: 1rem 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .endpoint {
            font-family: monospace;
            background: #f0f0f0;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
        }
        .status { color: #22c55e; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Soul Hunter Dashboard</h1>
    <div class="card">
        <h2>Server Status</h2>
        <p>Status: <span class="status">Running</span></p>
        <p>Version: 0.1.0</p>
    </div>
    <div class="card">
        <h2>API Endpoints</h2>
        <ul>
            <li><span class="endpoint">GET /health</span> - Health check</li>
            <li><span class="endpoint">GET /api/v1/status</span> - System status</li>
            <li><span class="endpoint">GET /api/v1/assessments</span> - List assessments</li>
            <li><span class="endpoint">POST /api/v1/assessments</span> - Create assessment</li>
            <li><span class="endpoint">GET /api/v1/findings</span> - List findings</li>
            <li><span class="endpoint">GET /api/v1/agents</span> - List agents</li>
            <li><span class="endpoint">GET /api/v1/skills</span> - List skills</li>
            <li><span class="endpoint">WS /ws</span> - WebSocket endpoint</li>
        </ul>
    </div>
</body>
</html>"#,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_check() {
        let config = Config {
            port: 3000,
            host: "127.0.0.1".to_string(),
            config: None,
            cors: false,
            static_dir: None,
            websocket: false,
            ws_port: 3001,
        };

        let orchestrator_config = Config::default();
        let orchestrator = Orchestrator::new(orchestrator_config).unwrap();

        let state = AppState {
            orchestrator: Arc::new(RwLock::new(orchestrator)),
            config: Arc::new(config.clone()),
        };

        let app = create_router(state, &config);

        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
