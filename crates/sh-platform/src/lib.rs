//! # Soul Hunter Platform Adapters
//!
//! Production-ready platform adapters for security analysis of:
//! - Android applications (APK, AAB)
//! - iOS applications (IPA)
//! - IoT firmware and embedded systems
//!
//! Each adapter implements the `PlatformAdapter` trait for consistent
//! analysis across different target platforms.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, instrument, warn};

use sh_types::{AnalysisTarget, Platform, Result as ShResult, Error as ShError};

#[cfg(feature = "android")]
pub mod android;
#[cfg(feature = "ios")]
pub mod ios;
#[cfg(feature = "iot")]
pub mod iot;

#[cfg(feature = "android")]
pub use android::AndroidAdapter;
#[cfg(feature = "ios")]
pub use ios::IosAdapter;
#[cfg(feature = "iot")]
pub use iot::IotAdapter;

/// Re-export commonly used types
pub mod prelude {
    pub use super::{PlatformAdapter, PlatformMetadata, PlatformCapabilities, ParseResult};
    pub use super::{PlatformError, PlatformResult};
    #[cfg(feature = "android")]
    pub use super::AndroidAdapter;
    #[cfg(feature = "ios")]
    pub use super::IosAdapter;
    #[cfg(feature = "iot")]
    pub use super::IotAdapter;
}

/// Platform-specific error types
#[derive(thiserror::Error, Debug)]
pub enum PlatformError {
    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),

    #[error("Invalid target format: {0}")]
    InvalidFormat(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Analysis error: {0}")]
    Analysis(String),

    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Result type alias for platform operations
pub type PlatformResult<T> = std::result::Result<T, PlatformError>;

/// Platform capabilities and features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    /// Platform type
    pub platform: Platform,
    /// Supports static analysis
    pub static_analysis: bool,
    /// Supports dynamic analysis
    pub dynamic_analysis: bool,
    /// Supports network analysis
    pub network_analysis: bool,
    /// Supports binary analysis
    pub binary_analysis: bool,
    /// Supports source analysis
    pub source_analysis: bool,
    /// Supported file extensions
    pub supported_extensions: Vec<String>,
    /// Maximum file size supported (in bytes)
    pub max_file_size: u64,
}

impl PlatformCapabilities {
    /// Create capabilities for Android platform
    pub fn android() -> Self {
        Self {
            platform: Platform::Android,
            static_analysis: true,
            dynamic_analysis: true,
            network_analysis: true,
            binary_analysis: true,
            source_analysis: true,
            supported_extensions: vec![
                "apk".to_string(),
                "aab".to_string(),
                "dex".to_string(),
                "jar".to_string(),
            ],
            max_file_size: 2 * 1024 * 1024 * 1024, // 2GB
        }
    }

    /// Create capabilities for iOS platform
    pub fn ios() -> Self {
        Self {
            platform: Platform::Ios,
            static_analysis: true,
            dynamic_analysis: true,
            network_analysis: true,
            binary_analysis: true,
            source_analysis: true,
            supported_extensions: vec![
                "ipa".to_string(),
                "app".to_string(),
                "dylib".to_string(),
                "framework".to_string(),
            ],
            max_file_size: 2 * 1024 * 1024 * 1024, // 2GB
        }
    }

    /// Create capabilities for IoT platform
    pub fn iot() -> Self {
        Self {
            platform: Platform::Iot,
            static_analysis: true,
            dynamic_analysis: false,
            network_analysis: true,
            binary_analysis: true,
            source_analysis: true,
            supported_extensions: vec![
                "bin".to_string(),
                "elf".to_string(),
                "hex".to_string(),
                "fw".to_string(),
                "img".to_string(),
            ],
            max_file_size: 512 * 1024 * 1024, // 512MB
        }
    }

    /// Check if a file extension is supported
    pub fn supports_extension(&self, ext: &str) -> bool {
        self.supported_extensions
            .iter()
            .any(|e| e.eq_ignore_ascii_case(ext))
    }
}

/// Platform metadata extracted from target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformMetadata {
    /// Platform type
    pub platform: Platform,
    /// Application/package name
    pub name: Option<String>,
    /// Version string
    pub version: Option<String>,
    /// Package identifier (bundle ID, package name, etc.)
    pub package_id: Option<String>,
    /// Target SDK/API version
    pub target_version: Option<String>,
    /// Minimum supported version
    pub min_version: Option<String>,
    /// Architecture (arm64, x86_64, etc.)
    pub architecture: Option<String>,
    /// File size in bytes
    pub file_size: u64,
    /// Checksum (SHA-256)
    pub checksum: Option<String>,
    /// Additional platform-specific metadata
    pub extra: HashMap<String, serde_json::Value>,
    /// Timestamp when metadata was extracted
    pub extracted_at: chrono::DateTime<chrono::Utc>,
}

impl PlatformMetadata {
    /// Create new metadata for a platform
    pub fn new(platform: Platform) -> Self {
        Self {
            platform,
            name: None,
            version: None,
            package_id: None,
            target_version: None,
            min_version: None,
            architecture: None,
            file_size: 0,
            checksum: None,
            extra: HashMap::new(),
            extracted_at: chrono::Utc::now(),
        }
    }

    /// Set the application name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set the package ID
    pub fn with_package_id(mut self, id: impl Into<String>) -> Self {
        self.package_id = Some(id.into());
        self
    }

    /// Set the target version
    pub fn with_target_version(mut self, version: impl Into<String>) -> Self {
        self.target_version = Some(version.into());
        self
    }

    /// Set the minimum version
    pub fn with_min_version(mut self, version: impl Into<String>) -> Self {
        self.min_version = Some(version.into());
        self
    }

    /// Set the architecture
    pub fn with_architecture(mut self, arch: impl Into<String>) -> Self {
        self.architecture = Some(arch.into());
        self
    }

    /// Set the file size
    pub fn with_file_size(mut self, size: u64) -> Self {
        self.file_size = size;
        self
    }

    /// Set the checksum
    pub fn with_checksum(mut self, checksum: impl Into<String>) -> Self {
        self.checksum = Some(checksum.into());
        self
    }

    /// Add extra metadata
    pub fn with_extra(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }
}

/// Result of parsing a platform target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseResult {
    /// Original target path
    pub target_path: PathBuf,
    /// Extracted metadata
    pub metadata: PlatformMetadata,
    /// Extracted files (for archive formats)
    pub extracted_files: Vec<PathBuf>,
    /// Entry points for analysis
    pub entry_points: Vec<PathBuf>,
    /// Configuration files found
    pub config_files: Vec<PathBuf>,
    /// Binary files found
    pub binary_files: Vec<PathBuf>,
    /// Source files found (if decompiled)
    pub source_files: Vec<PathBuf>,
}

impl ParseResult {
    /// Create a new parse result
    pub fn new(target_path: impl Into<PathBuf>, metadata: PlatformMetadata) -> Self {
        Self {
            target_path: target_path.into(),
            metadata,
            extracted_files: Vec::new(),
            entry_points: Vec::new(),
            config_files: Vec::new(),
            binary_files: Vec::new(),
            source_files: Vec::new(),
        }
    }

    /// Add an extracted file
    pub fn add_extracted_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.extracted_files.push(path.into());
        self
    }

    /// Add an entry point
    pub fn add_entry_point(mut self, path: impl Into<PathBuf>) -> Self {
        self.entry_points.push(path.into());
        self
    }

    /// Add a config file
    pub fn add_config_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_files.push(path.into());
        self
    }

    /// Add a binary file
    pub fn add_binary_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.binary_files.push(path.into());
        self
    }

    /// Add a source file
    pub fn add_source_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.source_files.push(path.into());
        self
    }
}

/// Platform adapter trait for analyzing different target types
#[async_trait]
pub trait PlatformAdapter: Send + Sync {
    /// Get the platform type
    fn platform(&self) -> Platform;

    /// Get platform capabilities
    fn capabilities(&self) -> PlatformCapabilities;

    /// Check if this adapter can handle the given target
    fn can_handle(&self, target: &AnalysisTarget) -> bool;

    /// Validate the target before analysis
    async fn validate(&self, target: &AnalysisTarget) -> PlatformResult<()>;

    /// Parse the target and extract metadata
    async fn parse(&self, target: &AnalysisTarget) -> PlatformResult<ParseResult>;

    /// Extract the target to a working directory
    async fn extract(&self, target: &AnalysisTarget, output_dir: &Path) -> PlatformResult<PathBuf>;

    /// Get platform-specific analysis configuration
    fn analysis_config(&self) -> serde_json::Value;
}

/// Factory for creating platform adapters
pub struct PlatformAdapterFactory;

impl PlatformAdapterFactory {
    /// Create an adapter for the given platform
    pub fn create(platform: Platform) -> PlatformResult<Box<dyn PlatformAdapter>> {
        match platform {
            #[cfg(feature = "android")]
            Platform::Android => Ok(Box::new(AndroidAdapter::new())),
            #[cfg(feature = "ios")]
            Platform::Ios => Ok(Box::new(IosAdapter::new())),
            #[cfg(feature = "iot")]
            Platform::Iot => Ok(Box::new(IotAdapter::new())),
            _ => Err(PlatformError::UnsupportedPlatform(format!("{:?}", platform))),
        }
    }

    /// Create an adapter based on file extension
    pub fn from_extension(ext: &str) -> PlatformResult<Box<dyn PlatformAdapter>> {
        match ext.to_lowercase().as_str() {
            #[cfg(feature = "android")]
            "apk" | "aab" | "dex" => Ok(Box::new(AndroidAdapter::new())),
            #[cfg(feature = "ios")]
            "ipa" | "app" => Ok(Box::new(IosAdapter::new())),
            #[cfg(feature = "iot")]
            "bin" | "elf" | "hex" | "fw" | "img" => Ok(Box::new(IotAdapter::new())),
            _ => Err(PlatformError::UnsupportedPlatform(format!(
                "Extension: {}",
                ext
            ))),
        }
    }

    /// Create an adapter for a target path (auto-detect)
    pub fn from_path(path: &Path) -> PlatformResult<Box<dyn PlatformAdapter>> {
        if let Some(ext) = path.extension() {
            Self::from_extension(&ext.to_string_lossy())
        } else {
            Err(PlatformError::InvalidFormat(
                "No file extension found".to_string(),
            ))
        }
    }
}

/// Utility functions for platform adapters
pub mod utils {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs::File;
    use std::io::{BufReader, Read};

    /// Calculate SHA-256 checksum of a file
    pub fn calculate_checksum(path: &Path) -> PlatformResult<String> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
        }

        let result = hasher.finalize();
        Ok(format!("{:x}", result))
    }

    /// Get file size in bytes
    pub fn get_file_size(path: &Path) -> PlatformResult<u64> {
        let metadata = std::fs::metadata(path)?;
        Ok(metadata.len())
    }

    /// Check if file is a valid archive
    pub fn is_archive(path: &Path) -> bool {
        if let Some(ext) = path.extension() {
            matches!(
                ext.to_string_lossy().to_lowercase().as_str(),
                "zip" | "apk" | "ipa" | "aab" | "jar" | "war" | "ear"
            )
        } else {
            false
        }
    }

    /// Sanitize a filename for safe extraction
    pub fn sanitize_filename(name: &str) -> String {
        name.chars()
            .map(|c| match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => c,
                _ => '_',
            })
            .collect()
    }

    /// Create a working directory for extraction
    pub fn create_work_dir(base: &Path, prefix: &str) -> PlatformResult<PathBuf> {
        let timestamp = chrono::Utc::now().timestamp_millis();
        let dir_name = format!("{}_{}", prefix, timestamp);
        let work_dir = base.join(dir_name);
        std::fs::create_dir_all(&work_dir)?;
        Ok(work_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_platform_capabilities() {
        let android_caps = PlatformCapabilities::android();
        assert_eq!(android_caps.platform, Platform::Android);
        assert!(android_caps.static_analysis);
        assert!(android_caps.supports_extension("apk"));
        assert!(!android_caps.supports_extension("ipa"));

        let ios_caps = PlatformCapabilities::ios();
        assert_eq!(ios_caps.platform, Platform::Ios);
        assert!(ios_caps.supports_extension("ipa"));
    }

    #[test]
    fn test_platform_metadata_builder() {
        let metadata = PlatformMetadata::new(Platform::Android)
            .with_name("TestApp")
            .with_version("1.0.0")
            .with_package_id("com.test.app")
            .with_file_size(1024);

        assert_eq!(metadata.name, Some("TestApp".to_string()));
        assert_eq!(metadata.version, Some("1.0.0".to_string()));
        assert_eq!(metadata.package_id, Some("com.test.app".to_string()));
        assert_eq!(metadata.file_size, 1024);
    }

    #[test]
    fn test_parse_result_builder() {
        let metadata = PlatformMetadata::new(Platform::Android);
        let result = ParseResult::new("/path/to/app.apk", metadata)
            .add_entry_point("classes.dex")
            .add_config_file("AndroidManifest.xml");

        assert_eq!(result.entry_points.len(), 1);
        assert_eq!(result.config_files.len(), 1);
    }

    #[test]
    fn test_utils_sanitize_filename() {
        assert_eq!(utils::sanitize_filename("test.apk"), "test.apk");
        assert_eq!(utils::sanitize_filename("test file.apk"), "test_file.apk");
        assert_eq!(utils::sanitize_filename("../test.apk"), "__test.apk");
    }

    #[test]
    fn test_utils_is_archive() {
        assert!(utils::is_archive(Path::new("test.apk")));
        assert!(utils::is_archive(Path::new("test.ipa")));
        assert!(!utils::is_archive(Path::new("test.bin")));
    }
}
