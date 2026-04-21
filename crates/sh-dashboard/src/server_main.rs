//! Soul Hunter Dashboard Server Binary
//!
//! Production-ready HTTP server with WebSocket support for real-time
//! security analysis monitoring. Provides REST API endpoints and
//! serves the web dashboard UI.
//!
//! ## Usage
//!
//! ```bash
//! # Run with default configuration (port 8080)
//! cargo run --bin sh-dashboard-server
//!
//! # Run with custom port
//! SOUL_HUNTER_PORT=3000 cargo run --bin sh-dashboard-server
//!
//! # Run with specific bind address
//! SOUL_HUNTER_BIND=127.0.0.1:3000 cargo run --bin sh-dashboard-server
//! ```

use std::sync::Arc;

use tracing::{error, info, warn};
use chrono::Utc;

use sh_dashboard::{
    DashboardConfig, DashboardServer, DashboardState,
};

/// Default server port
const DEFAULT_PORT: u16 = 8080;

/// Default bind address
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8080";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║           Soul Hunter Dashboard Server v{}              ║", env!("CARGO_PKG_VERSION"));
    info!("╚══════════════════════════════════════════════════════════════╝");

    // Parse configuration from environment
    let config = parse_config_from_env()?;

    info!("Configuration:");
    info!("  Bind Address: {}", config.bind_addr);
    info!("  Max Connections: {}", config.max_connections);
    info!("  Event Channel Capacity: {}", config.event_channel_capacity);
    info!("  Metrics Channel Capacity: {}", config.metrics_channel_capacity);
    info!("  CORS Enabled: {}", config.enable_cors);

    // Create and start the dashboard server
    let server = DashboardServer::with_config(config);

    // Setup graceful shutdown
    let state = server.state();
    setup_shutdown_handler(state).await;

    // Start the server
    info!("Starting server...");
    if let Err(e) = server.start().await {
        error!("Server error: {}", e);
        return Err(e.into());
    }

    info!("Server shutdown complete");
    Ok(())
}

/// Parse configuration from environment variables
fn parse_config_from_env() -> anyhow::Result<DashboardConfig> {
    let mut config = DashboardConfig::default();

    // Check for bind address
    if let Ok(bind_addr) = std::env::var("SOUL_HUNTER_BIND") {
        config.bind_addr = bind_addr;
    } else if let Ok(port) = std::env::var("SOUL_HUNTER_PORT") {
        // Parse port number
        let port: u16 = port
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid port number: {}", e))?;
        config.bind_addr = format!("0.0.0.0:{}", port);
    }

    // Check for max connections
    if let Ok(max_conn) = std::env::var("SOUL_HUNTER_MAX_CONNECTIONS") {
        config.max_connections = max_conn
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid max connections: {}", e))?;
    }

    // Check for CORS setting
    if let Ok(cors) = std::env::var("SOUL_HUNTER_CORS") {
        config.enable_cors = cors.parse().unwrap_or(true);
    }

    // Check for static files directory
    if let Ok(static_dir) = std::env::var("SOUL_HUNTER_STATIC_DIR") {
        config.static_dir = Some(static_dir);
    }

    Ok(config)
}

/// Setup graceful shutdown handler
async fn setup_shutdown_handler(state: Arc<DashboardState>) {
    let state_clone = state.clone();

    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                info!("\nReceived shutdown signal, initiating graceful shutdown...");

                // Log final statistics
                let uptime = Utc::now() - state_clone.start_time;
                let sessions_count = state_clone.sessions.len();
                let connections = *state_clone.connection_count.read().await;

                info!("Final Statistics:");
                info!("  Uptime: {} seconds", uptime.num_seconds());
                info!("  Total Sessions: {}", sessions_count);
                info!("  Active WebSocket Connections: {}", connections);

                // Give connections time to close gracefully
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

                std::process::exit(0);
            }
            Err(e) => {
                warn!("Failed to listen for shutdown signal: {}", e);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DashboardConfig::default();
        assert_eq!(config.bind_addr, "0.0.0.0:8080");
        assert_eq!(config.max_connections, 100);
        assert!(config.enable_cors);
    }

    #[test]
    fn test_config_with_bind_addr() {
        let config = DashboardConfig::default()
            .with_bind_addr("127.0.0.1:3000");
        assert_eq!(config.bind_addr, "127.0.0.1:3000");
    }

    #[test]
    fn test_config_with_max_connections() {
        let config = DashboardConfig::default()
            .with_max_connections(50);
        assert_eq!(config.max_connections, 50);
    }
}
