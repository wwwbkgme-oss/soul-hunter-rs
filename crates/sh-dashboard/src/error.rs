//! Dashboard error types
//!
//! Comprehensive error handling for the dashboard server,
//! including HTTP, WebSocket, and serialization errors.

use std::fmt;

/// Dashboard result type alias
pub type Result<T> = std::result::Result<T, DashboardError>;

/// Dashboard-specific error types
#[derive(Debug)]
pub enum DashboardError {
    /// HTTP server error
    Http(String),
    /// WebSocket error
    WebSocket(String),
    /// Serialization error
    Serialization(serde_json::Error),
    /// Broadcast channel error
    Broadcast(String),
    /// Session not found
    SessionNotFound(String),
    /// Invalid configuration
    InvalidConfig(String),
    /// IO error
    Io(std::io::Error),
    /// Connection limit exceeded
    ConnectionLimitExceeded,
    /// Invalid message format
    InvalidMessage(String),
    /// Internal error
    Internal(String),
}

impl fmt::Display for DashboardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DashboardError::Http(msg) => write!(f, "HTTP error: {}", msg),
            DashboardError::WebSocket(msg) => write!(f, "WebSocket error: {}", msg),
            DashboardError::Serialization(e) => write!(f, "Serialization error: {}", e),
            DashboardError::Broadcast(msg) => write!(f, "Broadcast error: {}", msg),
            DashboardError::SessionNotFound(id) => write!(f, "Session not found: {}", id),
            DashboardError::InvalidConfig(msg) => write!(f, "Invalid configuration: {}", msg),
            DashboardError::Io(e) => write!(f, "IO error: {}", e),
            DashboardError::ConnectionLimitExceeded => {
                write!(f, "Maximum connection limit exceeded")
            }
            DashboardError::InvalidMessage(msg) => write!(f, "Invalid message: {}", msg),
            DashboardError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for DashboardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DashboardError::Serialization(e) => Some(e),
            DashboardError::Io(e) => Some(e),
            _ => None,
        }
    }
}

// Implement warp::reject::Reject for DashboardError
impl warp::reject::Reject for DashboardError {}

impl From<serde_json::Error> for DashboardError {
    fn from(err: serde_json::Error) -> Self {
        DashboardError::Serialization(err)
    }
}

impl From<std::io::Error> for DashboardError {
    fn from(err: std::io::Error) -> Self {
        DashboardError::Io(err)
    }
}

impl From<warp::Error> for DashboardError {
    fn from(err: warp::Error) -> Self {
        DashboardError::Http(err.to_string())
    }
}

impl From<std::net::AddrParseError> for DashboardError {
    fn from(err: std::net::AddrParseError) -> Self {
        DashboardError::InvalidConfig(format!("Invalid address: {}", err))
    }
}

impl From<tokio::sync::broadcast::error::SendError<crate::DashboardEvent>> for DashboardError {
    fn from(_err: tokio::sync::broadcast::error::SendError<crate::DashboardEvent>) -> Self {
        DashboardError::Broadcast("Failed to broadcast event".to_string())
    }
}

impl From<tokio::sync::broadcast::error::SendError<crate::DashboardMetrics>> for DashboardError {
    fn from(_err: tokio::sync::broadcast::error::SendError<crate::DashboardMetrics>) -> Self {
        DashboardError::Broadcast("Failed to broadcast metrics".to_string())
    }
}

impl From<anyhow::Error> for DashboardError {
    fn from(err: anyhow::Error) -> Self {
        DashboardError::Internal(err.to_string())
    }
}

/// Convert DashboardError to JSON response
impl DashboardError {
    /// Get HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            DashboardError::SessionNotFound(_) => 404,
            DashboardError::InvalidConfig(_) => 400,
            DashboardError::InvalidMessage(_) => 400,
            DashboardError::ConnectionLimitExceeded => 503,
            DashboardError::Http(_) => 500,
            DashboardError::WebSocket(_) => 500,
            DashboardError::Serialization(_) => 400,
            DashboardError::Broadcast(_) => 500,
            DashboardError::Io(_) => 500,
            DashboardError::Internal(_) => 500,
        }
    }

    /// Get error code string for API responses
    pub fn error_code(&self) -> &'static str {
        match self {
            DashboardError::Http(_) => "http_error",
            DashboardError::WebSocket(_) => "websocket_error",
            DashboardError::Serialization(_) => "serialization_error",
            DashboardError::Broadcast(_) => "broadcast_error",
            DashboardError::SessionNotFound(_) => "session_not_found",
            DashboardError::InvalidConfig(_) => "invalid_config",
            DashboardError::Io(_) => "io_error",
            DashboardError::ConnectionLimitExceeded => "connection_limit_exceeded",
            DashboardError::InvalidMessage(_) => "invalid_message",
            DashboardError::Internal(_) => "internal_error",
        }
    }

    /// Convert to JSON error response
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "error": {
                "code": self.error_code(),
                "message": self.to_string(),
                "status": self.status_code(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DashboardError::SessionNotFound("test-id".to_string());
        assert_eq!(err.to_string(), "Session not found: test-id");
    }

    #[test]
    fn test_error_status_code() {
        assert_eq!(
            DashboardError::SessionNotFound("test".to_string()).status_code(),
            404
        );
        assert_eq!(
            DashboardError::InvalidConfig("test".to_string()).status_code(),
            400
        );
        assert_eq!(DashboardError::ConnectionLimitExceeded.status_code(), 503);
    }

    #[test]
    fn test_error_code() {
        assert_eq!(
            DashboardError::SessionNotFound("test".to_string()).error_code(),
            "session_not_found"
        );
        assert_eq!(
            DashboardError::InvalidMessage("test".to_string()).error_code(),
            "invalid_message"
        );
    }

    #[test]
    fn test_error_to_json() {
        let err = DashboardError::SessionNotFound("test-id".to_string());
        let json = err.to_json();

        assert_eq!(json["error"]["code"], "session_not_found");
        assert_eq!(json["error"]["message"], "Session not found: test-id");
        assert_eq!(json["error"]["status"], 404);
    }

    #[test]
    fn test_from_serde_error() {
        let json = "{ invalid json";
        let result: Result<serde_json::Value> = serde_json::from_str(json).map_err(|e| e.into());
        assert!(matches!(result, Err(DashboardError::Serialization(_))));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: DashboardError = io_err.into();
        assert!(matches!(err, DashboardError::Io(_)));
    }
}
