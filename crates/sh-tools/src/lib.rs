//! # Soul Hunter Tools
//!
//! Production-ready APK and security analysis tools for the Soul Hunter platform.
//!
//! ## Modules
//!
//! - `apk`: APK file parsing and analysis
//! - `secrets`: Secret detection and extraction
//! - `network`: Network security analysis
//!
//! ## Example
//!
//! ```rust
//! use sh_tools::apk::ApkAnalyzer;
//! use sh_tools::secrets::SecretScanner;
//!
//! async fn analyze_apk(path: &str) -> anyhow::Result<()> {
//!     let analyzer = ApkAnalyzer::new();
//!     let manifest = analyzer.parse_manifest(path).await?;
//!     println!("Package: {}", manifest.package_name);
//!     Ok(())
//! }
//! ```

pub mod apk;
pub mod apk_parser;
pub mod network;
pub mod secrets;

// Re-export commonly used types
pub use apk::{ApkAnalyzer, ApkInfo as ApkAnalyzerInfo, ManifestAnalysis};
pub use apk_parser::{ApkParser, ApkInfo, CertificateInfo, ComponentInfo, DexInfo, ExportedComponent, IntentFilterInfo, NativeLibInfo, NetworkSecurityConfig, ResourceInfo, SecretFinding};
pub use network::{NetworkAnalyzer, NetworkSecurityConfig as NetworkConfig};
pub use secrets::{SecretFinding as SecretFindingLegacy, SecretScanner, SecretType};

use thiserror::Error;

/// Errors that can occur in the tools crate
#[derive(Error, Debug)]
pub enum ToolsError {
    #[error("APK analysis error: {0}")]
    ApkAnalysis(String),

    #[error("Manifest parsing error: {0}")]
    ManifestParsing(String),

    #[error("Secret detection error: {0}")]
    SecretDetection(String),

    #[error("Network analysis error: {0}")]
    NetworkAnalysis(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("XML parsing error: {0}")]
    XmlParsing(String),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Result type alias for tools operations
pub type Result<T> = std::result::Result<T, ToolsError>;

/// Tool version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Tool capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    ApkAnalysis,
    ManifestParsing,
    SecretDetection,
    NetworkAnalysis,
    CertificatePinning,
    PermissionAnalysis,
}

impl Capability {
    /// Get the capability name
    pub fn name(&self) -> &'static str {
        match self {
            Capability::ApkAnalysis => "apk_analysis",
            Capability::ManifestParsing => "manifest_parsing",
            Capability::SecretDetection => "secret_detection",
            Capability::NetworkAnalysis => "network_analysis",
            Capability::CertificatePinning => "certificate_pinning",
            Capability::PermissionAnalysis => "permission_analysis",
        }
    }
}

/// Get all available capabilities
pub fn capabilities() -> Vec<Capability> {
    vec![
        Capability::ApkAnalysis,
        Capability::ManifestParsing,
        Capability::SecretDetection,
        Capability::NetworkAnalysis,
        Capability::CertificatePinning,
        Capability::PermissionAnalysis,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities() {
        let caps = capabilities();
        assert!(!caps.is_empty());
        assert!(caps.contains(&Capability::ApkAnalysis));
        assert!(caps.contains(&Capability::SecretDetection));
    }

    #[test]
    fn test_capability_names() {
        assert_eq!(Capability::ApkAnalysis.name(), "apk_analysis");
        assert_eq!(Capability::SecretDetection.name(), "secret_detection");
    }
}
