//! # Soul Hunter Types
//! 
//! Core type definitions for the Soul Hunter security analysis platform.
//! Merges types from newbie-rs, tracker-brain-rs, and zero-hero-rs.

pub mod agent;
pub mod assessment;
pub mod event;
pub mod finding;
pub mod job;
pub mod policy;
pub mod risk;

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::agent::*;
    pub use crate::assessment::*;
    pub use crate::event::*;
    pub use crate::finding::*;
    pub use crate::job::*;
    pub use crate::policy::*;
    pub use crate::risk::*;
    pub use crate::{AnalysisTarget, Confidence, Error, Platform, Result, Severity};
}

// Re-export commonly used types
pub use agent::*;
pub use assessment::*;
pub use event::*;
pub use finding::*;
pub use job::*;
pub use policy::*;
pub use risk::*;

use serde::{Deserialize, Serialize};
use std::fmt;

/// Platform type for analysis targets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Android,
    Ios,
    Iot,
    Network,
    Web,
    Unknown,
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Platform::Android => write!(f, "android"),
            Platform::Ios => write!(f, "ios"),
            Platform::Iot => write!(f, "iot"),
            Platform::Network => write!(f, "network"),
            Platform::Web => write!(f, "web"),
            Platform::Unknown => write!(f, "unknown"),
        }
    }
}

impl Default for Platform {
    fn default() -> Self {
        Platform::Unknown
    }
}

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Info
    }
}

/// Confidence levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Tentative,
    Probable,
    Confirmed,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Confidence::Tentative => write!(f, "tentative"),
            Confidence::Probable => write!(f, "probable"),
            Confidence::Confirmed => write!(f, "confirmed"),
        }
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Confidence::Tentative
    }
}

/// Analysis target representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisTarget {
    pub path: String,
    pub platform: Platform,
    pub metadata: Option<serde_json::Value>,
}

impl AnalysisTarget {
    pub fn new(path: impl Into<String>, platform: Platform) -> Self {
        Self {
            path: path.into(),
            platform,
            metadata: None,
        }
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Common error types
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Invalid target: {0}")]
    InvalidTarget(String),
    
    #[error("Analysis error: {0}")]
    Analysis(String),
    
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Result type alias for Soul Hunter types
pub type ShResult<T> = std::result::Result<T, Error>;

/// Deprecated: Use ShResult instead
pub type Result<T> = ShResult<T>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_platform_display() {
        assert_eq!(Platform::Android.to_string(), "android");
        assert_eq!(Platform::Ios.to_string(), "ios");
    }

    #[test]
    fn test_analysis_target() {
        let target = AnalysisTarget::new("/path/to/app.apk", Platform::Android);
        assert_eq!(target.path, "/path/to/app.apk");
        assert_eq!(target.platform, Platform::Android);
    }
}
