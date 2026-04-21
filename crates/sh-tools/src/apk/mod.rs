//! # APK Analysis Module
//!
//! Provides comprehensive APK file analysis including:
//! - ZIP archive parsing
//! - AndroidManifest.xml extraction and parsing
//! - Resource analysis
//! - Certificate inspection
//! - Permission analysis
//!
//! ## Example
//!
//! ```rust
//! use sh_tools::apk::ApkAnalyzer;
//!
//! async fn example() -> anyhow::Result<()> {
//!     let analyzer = ApkAnalyzer::new();
//!     let info = analyzer.analyze("app.apk").await?;
//!     println!("Package: {}", info.manifest.package_name);
//!     Ok(())
//! }
//! ```

pub mod manifest;
pub mod parser;

pub use manifest::{AndroidManifest, ManifestAnalysis, Permission, UsesSdk};
pub use parser::{ApkEntry, ApkParser};

use crate::{Result, ToolsError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, instrument, warn};

/// Main APK analyzer for comprehensive APK file analysis
#[derive(Debug, Clone)]
pub struct ApkAnalyzer {
    /// Parser for APK file operations
    parser: ApkParser,
}

impl Default for ApkAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ApkAnalyzer {
    /// Create a new APK analyzer
    pub fn new() -> Self {
        Self {
            parser: ApkParser::new(),
        }
    }

    /// Perform comprehensive APK analysis
    #[instrument(skip(self), fields(path = %path.as_ref().display()))]
    pub async fn analyze<P: AsRef<Path>>(&self, path: P) -> Result<ApkInfo> {
        let path = path.as_ref();
        info!("Starting APK analysis for: {}", path.display());

        // Parse the APK file
        let entries = self.parser.list_entries(path).await?;
        debug!("Found {} entries in APK", entries.len());

        // Extract and parse manifest
        let manifest = self.parse_manifest(path).await?;

        // Analyze certificates
        let certificates = self.extract_certificates(path).await?;

        // Analyze resources
        let resources = self.analyze_resources(path, &entries).await?;

        // Check for native libraries
        let native_libs = self.detect_native_libraries(&entries);

        // Analyze dex files
        let dex_info = self.analyze_dex_files(&entries);

        // Check for network security config
        let network_config = self.extract_network_security_config(path).await.ok();

        info!("APK analysis completed for: {}", path.display());

        Ok(ApkInfo {
            path: path.to_path_buf(),
            manifest,
            certificates,
            resources,
            native_libs,
            dex_info,
            network_config,
            entry_count: entries.len(),
        })
    }

    /// Parse AndroidManifest.xml from APK
    #[instrument(skip(self), fields(path = %path.as_ref().display()))]
    pub async fn parse_manifest<P: AsRef<Path>>(&self, path: P) -> Result<AndroidManifest> {
        let path = path.as_ref();
        debug!("Parsing AndroidManifest.xml from: {}", path.display());

        let manifest_data = self
            .parser
            .extract_file(path, "AndroidManifest.xml")
            .await
            .map_err(|e| ToolsError::ApkAnalysis(format!("Failed to extract manifest: {}", e)))?;

        let manifest = manifest::parse_manifest(&manifest_data)
            .map_err(|e| ToolsError::ManifestParsing(e.to_string()))?;

        info!("Successfully parsed manifest for package: {}", manifest.package_name);
        Ok(manifest)
    }

    /// Extract and analyze certificates from the APK
    #[instrument(skip(self), fields(path = %path.as_ref().display()))]
    pub async fn extract_certificates<P: AsRef<Path>>(&self, path: P) -> Result<Vec<CertificateInfo>> {
        let path = path.as_ref();
        debug!("Extracting certificates from: {}", path.display());

        let mut certificates = Vec::new();

        // Look for certificate entries in META-INF/
        let entries = self.parser.list_entries(path).await?;
        for entry in entries {
            if entry.name.starts_with("META-INF/") {
                let name_lower = entry.name.to_lowercase();
                if name_lower.ends_with(".rsa") || name_lower.ends_with(".dsa") || name_lower.ends_with(".ec") {
                    debug!("Found certificate file: {}", entry.name);
                    match self.extract_certificate_info(path, &entry.name).await {
                        Ok(cert_info) => certificates.push(cert_info),
                        Err(e) => warn!("Failed to extract certificate {}: {}", entry.name, e),
                    }
                }
            }
        }

        info!("Extracted {} certificates", certificates.len());
        Ok(certificates)
    }

    /// Extract a specific file from the APK
    pub async fn extract_file<P: AsRef<Path>>(&self, apk_path: P, file_name: &str) -> Result<Vec<u8>> {
        self.parser.extract_file(apk_path, file_name).await
    }

    /// List all entries in the APK
    pub async fn list_entries<P: AsRef<Path>>(&self, path: P) -> Result<Vec<ApkEntry>> {
        self.parser.list_entries(path).await
    }

    /// Extract network security config if present
    pub async fn extract_network_security_config<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<crate::network::NetworkSecurityConfig> {
        let path = path.as_ref();
        debug!("Extracting network security config from: {}", path.display());

        // Try common locations for network_security_config.xml
        let config_paths = [
            "res/xml/network_security_config.xml",
            "res/xml-v21/network_security_config.xml",
        ];

        for config_path in &config_paths {
            if let Ok(data) = self.parser.extract_file(path, config_path).await {
                return crate::network::parse_network_security_config(&data)
                    .map_err(|e| ToolsError::NetworkAnalysis(e.to_string()));
            }
        }

        Err(ToolsError::NetworkAnalysis(
            "Network security config not found".to_string(),
        ))
    }

    /// Analyze resources in the APK
    async fn analyze_resources<P: AsRef<Path>>(
        &self,
        path: P,
        entries: &[ApkEntry],
    ) -> Result<ResourceInfo> {
        let mut drawable_count = 0;
        let mut layout_count = 0;
        let mut raw_count = 0;
        let mut asset_count = 0;

        for entry in entries {
            if entry.name.starts_with("res/") {
                if entry.name.contains("/drawable") {
                    drawable_count += 1;
                } else if entry.name.contains("/layout") {
                    layout_count += 1;
                } else if entry.name.contains("/raw") {
                    raw_count += 1;
                }
            } else if entry.name.starts_with("assets/") {
                asset_count += 1;
            }
        }

        Ok(ResourceInfo {
            drawable_count,
            layout_count,
            raw_count,
            asset_count,
        })
    }

    /// Detect native libraries in the APK
    fn detect_native_libraries(&self, entries: &[ApkEntry]) -> Vec<NativeLibInfo> {
        let mut libs = Vec::new();

        for entry in entries {
            if entry.name.starts_with("lib/") && entry.name.ends_with(".so") {
                // Parse path like lib/arm64-v8a/libname.so
                let parts: Vec<&str> = entry.name.split('/').collect();
                if parts.len() >= 3 {
                    let arch = parts[1].to_string();
                    let name = parts[2].to_string();
                    libs.push(NativeLibInfo {
                        name,
                        architecture: arch,
                        path: entry.name.clone(),
                        size: entry.size,
                    });
                }
            }
        }

        libs
    }

    /// Analyze DEX files
    fn analyze_dex_files(&self, entries: &[ApkEntry]) -> DexInfo {
        let mut dex_count = 0;
        let mut total_dex_size = 0u64;

        for entry in entries {
            if entry.name.starts_with("classes") && entry.name.ends_with(".dex") {
                dex_count += 1;
                total_dex_size += entry.size;
            }
        }

        DexInfo {
            dex_count,
            total_dex_size,
        }
    }

    /// Extract certificate information
    async fn extract_certificate_info<P: AsRef<Path>>(
        &self,
        path: P,
        cert_path: &str,
    ) -> Result<CertificateInfo> {
        let cert_data = self.parser.extract_file(path, cert_path).await?;

        // Calculate certificate hash
        let hash = Sha256::digest(&cert_data);
        let hash_hex = hex::encode(hash);

        Ok(CertificateInfo {
            path: cert_path.to_string(),
            size: cert_data.len(),
            sha256_hash: hash_hex,
        })
    }
}

/// Comprehensive APK information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkInfo {
    /// Path to the APK file
    pub path: PathBuf,

    /// Parsed AndroidManifest.xml
    pub manifest: AndroidManifest,

    /// Certificate information
    pub certificates: Vec<CertificateInfo>,

    /// Resource information
    pub resources: ResourceInfo,

    /// Native libraries
    pub native_libs: Vec<NativeLibInfo>,

    /// DEX file information
    pub dex_info: DexInfo,

    /// Network security configuration
    pub network_config: Option<crate::network::NetworkSecurityConfig>,

    /// Total number of entries in the APK
    pub entry_count: usize,
}

/// Certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Path to the certificate in the APK
    pub path: String,

    /// Certificate size in bytes
    pub size: usize,

    /// SHA-256 hash of the certificate
    pub sha256_hash: String,
}

/// Resource information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    /// Number of drawable resources
    pub drawable_count: usize,

    /// Number of layout resources
    pub layout_count: usize,

    /// Number of raw resources
    pub raw_count: usize,

    /// Number of assets
    pub asset_count: usize,
}

/// Native library information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeLibInfo {
    /// Library name
    pub name: String,

    /// Target architecture
    pub architecture: String,

    /// Path in the APK
    pub path: String,

    /// Size in bytes
    pub size: u64,
}

/// DEX file information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DexInfo {
    /// Number of DEX files
    pub dex_count: usize,

    /// Total size of all DEX files
    pub total_dex_size: u64,
}

#[async_trait]
/// Trait for APK analysis plugins
pub trait ApkAnalysisPlugin: Send + Sync {
    /// Plugin name
    fn name(&self) -> &str;

    /// Analyze APK and return findings
    async fn analyze(&self, apk_info: &ApkInfo) -> crate::Result<Vec<sh_types::Finding>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_native_lib_detection() {
        let analyzer = ApkAnalyzer::new();
        let entries = vec![
            ApkEntry {
                name: "lib/arm64-v8a/libtest.so".to_string(),
                size: 1024,
                compressed_size: 512,
                is_file: true,
                is_dir: false,
            },
            ApkEntry {
                name: "lib/armeabi-v7a/libtest.so".to_string(),
                size: 2048,
                compressed_size: 1024,
                is_file: true,
                is_dir: false,
            },
        ];

        let libs = analyzer.detect_native_libraries(&entries);
        assert_eq!(libs.len(), 2);
        assert_eq!(libs[0].architecture, "arm64-v8a");
        assert_eq!(libs[1].architecture, "armeabi-v7a");
    }

    #[test]
    fn test_dex_analysis() {
        let analyzer = ApkAnalyzer::new();
        let entries = vec![
            ApkEntry {
                name: "classes.dex".to_string(),
                size: 1000,
                compressed_size: 500,
                is_file: true,
                is_dir: false,
            },
            ApkEntry {
                name: "classes2.dex".to_string(),
                size: 2000,
                compressed_size: 1000,
                is_file: true,
                is_dir: false,
            },
        ];

        let dex_info = analyzer.analyze_dex_files(&entries);
        assert_eq!(dex_info.dex_count, 2);
        assert_eq!(dex_info.total_dex_size, 3000);
    }
}
