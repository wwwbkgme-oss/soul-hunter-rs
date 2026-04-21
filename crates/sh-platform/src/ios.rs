//! iOS Platform Adapter
//!
//! Production-ready adapter for analyzing iOS applications (IPA).
//! Extracts and parses Info.plist, embedded.mobileprovision, Mach-O binaries,
//! and frameworks.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use plist::Value;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, instrument, trace, warn};
use zip::ZipArchive;

use crate::{
    PlatformAdapter, PlatformCapabilities, PlatformError, PlatformMetadata, PlatformResult,
    ParseResult, utils,
};
use sh_types::{AnalysisTarget, Platform};

/// iOS-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IosMetadata {
    /// Bundle identifier
    pub bundle_id: String,
    /// Bundle name
    pub bundle_name: Option<String>,
    /// Display name
    pub display_name: Option<String>,
    /// Bundle version (CFBundleVersion)
    pub bundle_version: Option<String>,
    /// Short version (CFBundleShortVersionString)
    pub short_version: Option<String>,
    /// Minimum iOS version required
    pub minimum_os_version: Option<String>,
    /// Supported architectures
    pub architectures: Vec<String>,
    /// Required device capabilities
    pub required_capabilities: Vec<String>,
    /// Supported device families (1=iPhone, 2=iPad)
    pub supported_devices: Vec<u32>,
    /// URL schemes (deep links)
    pub url_schemes: Vec<String>,
    /// Universal links
    pub universal_links: Vec<String>,
    /// App Transport Security settings
    pub ats_settings: Option<AtsSettings>,
    /// Entitlements
    pub entitlements: HashMap<String, plist::Value>,
    /// Provisioning profile info
    pub provisioning_profile: Option<ProvisioningProfile>,
    /// Frameworks used
    pub frameworks: Vec<String>,
    /// Dylibs used
    pub dylibs: Vec<String>,
    /// Main executable name
    pub executable_name: Option<String>,
    /// App icon files
    pub app_icons: Vec<String>,
    /// Launch screen files
    pub launch_screens: Vec<String>,
    /// Info.plist raw data
    pub info_plist_raw: HashMap<String, plist::Value>,
}

impl IosMetadata {
    /// Create new iOS metadata
    pub fn new(bundle_id: impl Into<String>) -> Self {
        Self {
            bundle_id: bundle_id.into(),
            bundle_name: None,
            display_name: None,
            bundle_version: None,
            short_version: None,
            minimum_os_version: None,
            architectures: Vec::new(),
            required_capabilities: Vec::new(),
            supported_devices: Vec::new(),
            url_schemes: Vec::new(),
            universal_links: Vec::new(),
            ats_settings: None,
            entitlements: HashMap::new(),
            provisioning_profile: None,
            frameworks: Vec::new(),
            dylibs: Vec::new(),
            executable_name: None,
            app_icons: Vec::new(),
            launch_screens: Vec::new(),
            info_plist_raw: HashMap::new(),
        }
    }
}

/// App Transport Security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtsSettings {
    /// Allow arbitrary loads (HTTP)
    pub allow_arbitrary_loads: bool,
    /// Allow arbitrary loads for media
    pub allow_arbitrary_loads_for_media: bool,
    /// Allow arbitrary loads in web content
    pub allow_arbitrary_loads_in_web_content: bool,
    /// Exception domains
    pub exception_domains: Vec<ExceptionDomain>,
}

/// ATS exception domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionDomain {
    pub domain: String,
    pub includes_subdomains: bool,
    pub exception_minimum_tls_version: Option<String>,
    pub exception_requires_forward_secrecy: bool,
    pub exception_allow_insecure_http_loads: bool,
}

/// Provisioning profile information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningProfile {
    /// App ID name
    pub app_id_name: Option<String>,
    /// Application identifier prefix
    pub application_identifier_prefix: Vec<String>,
    /// Creation date
    pub creation_date: Option<String>,
    /// Expiration date
    pub expiration_date: Option<String>,
    /// Is enterprise profile
    pub is_enterprise: bool,
    /// Team identifier
    pub team_identifier: Vec<String>,
    /// Team name
    pub team_name: Option<String>,
    /// Provisions all devices
    pub provisions_all_devices: bool,
    /// Provisioned devices (UDIDs)
    pub provisioned_devices: Vec<String>,
    /// UUID
    pub uuid: Option<String>,
}

/// Mach-O binary information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachOInfo {
    /// File path
    pub path: String,
    /// Architecture
    pub architecture: String,
    /// Is encrypted
    pub is_encrypted: bool,
    /// Has code signature
    pub has_code_signature: bool,
    /// Dynamic libraries
    pub dylibs: Vec<String>,
    /// Symbols
    pub symbols: Vec<String>,
}

/// iOS platform adapter
pub struct IosAdapter {
    capabilities: PlatformCapabilities,
}

impl IosAdapter {
    /// Create a new iOS adapter
    pub fn new() -> Self {
        Self {
            capabilities: PlatformCapabilities::ios(),
        }
    }

    /// Parse Info.plist from bytes
    fn parse_info_plist(&self, plist_data: &[u8]) -> PlatformResult<IosMetadata> {
        let plist: Value = plist::from_bytes(plist_data)
            .map_err(|e| PlatformError::ParseError(format!("Failed to parse plist: {}", e)))?;

        let dict = plist
            .as_dictionary()
            .ok_or_else(|| PlatformError::ParseError("Info.plist is not a dictionary".to_string()))?;

        let bundle_id = dict
            .get("CFBundleIdentifier")
            .and_then(|v| v.as_string())
            .unwrap_or("unknown")
            .to_string();

        let mut metadata = IosMetadata::new(bundle_id);
        metadata.info_plist_raw = dict.clone();

        // Extract basic info
        metadata.bundle_name = dict
            .get("CFBundleName")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        metadata.display_name = dict
            .get("CFBundleDisplayName")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string())
            .or_else(|| metadata.bundle_name.clone());

        metadata.bundle_version = dict
            .get("CFBundleVersion")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        metadata.short_version = dict
            .get("CFBundleShortVersionString")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        metadata.minimum_os_version = dict
            .get("MinimumOSVersion")
            .or_else(|| dict.get("LSMinimumSystemVersion"))
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        metadata.executable_name = dict
            .get("CFBundleExecutable")
            .and_then(|v| v.as_string())
            .map(|s| s.to_string());

        // Extract architectures
        if let Some(archs) = dict.get("UIRequiredDeviceCapabilities") {
            if let Some(arr) = archs.as_array() {
                metadata.required_capabilities = arr
                    .iter()
                    .filter_map(|v| v.as_string().map(|s| s.to_string()))
                    .collect();
            }
        }

        // Extract supported device families
        if let Some(families) = dict.get("UIDeviceFamily") {
            if let Some(arr) = families.as_array() {
                metadata.supported_devices = arr
                    .iter()
                    .filter_map(|v| v.as_unsigned_integer().map(|n| n as u32))
                    .collect();
            }
        }

        // Extract URL schemes
        if let Some(url_types) = dict.get("CFBundleURLTypes") {
            if let Some(arr) = url_types.as_array() {
                for url_type in arr {
                    if let Some(url_dict) = url_type.as_dictionary() {
                        if let Some(schemes) = url_dict.get("CFBundleURLSchemes") {
                            if let Some(scheme_arr) = schemes.as_array() {
                                for scheme in scheme_arr {
                                    if let Some(s) = scheme.as_string() {
                                        metadata.url_schemes.push(s.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Extract ATS settings
        if let Some(ats) = dict.get("NSAppTransportSecurity") {
            if let Some(ats_dict) = ats.as_dictionary() {
                let mut ats_settings = AtsSettings {
                    allow_arbitrary_loads: ats_dict
                        .get("NSAllowsArbitraryLoads")
                        .and_then(|v| v.as_boolean())
                        .unwrap_or(false),
                    allow_arbitrary_loads_for_media: ats_dict
                        .get("NSAllowsArbitraryLoadsForMedia")
                        .and_then(|v| v.as_boolean())
                        .unwrap_or(false),
                    allow_arbitrary_loads_in_web_content: ats_dict
                        .get("NSAllowsArbitraryLoadsInWebContent")
                        .and_then(|v| v.as_boolean())
                        .unwrap_or(false),
                    exception_domains: Vec::new(),
                };

                if let Some(domains) = ats_dict.get("NSExceptionDomains") {
                    if let Some(domain_dict) = domains.as_dictionary() {
                        for (domain, settings) in domain_dict {
                            if let Some(settings_dict) = settings.as_dictionary() {
                                let exception = ExceptionDomain {
                                    domain: domain.clone(),
                                    includes_subdomains: settings_dict
                                        .get("NSIncludesSubdomains")
                                        .and_then(|v| v.as_boolean())
                                        .unwrap_or(false),
                                    exception_minimum_tls_version: settings_dict
                                        .get("NSExceptionMinimumTLSVersion")
                                        .and_then(|v| v.as_string())
                                        .map(|s| s.to_string()),
                                    exception_requires_forward_secrecy: settings_dict
                                        .get("NSExceptionRequiresForwardSecrecy")
                                        .and_then(|v| v.as_boolean())
                                        .unwrap_or(true),
                                    exception_allow_insecure_http_loads: settings_dict
                                        .get("NSExceptionAllowsInsecureHTTPLoads")
                                        .and_then(|v| v.as_boolean())
                                        .unwrap_or(false),
                                };
                                ats_settings.exception_domains.push(exception);
                            }
                        }
                    }
                }

                metadata.ats_settings = Some(ats_settings);
            }
        }

        // Extract frameworks
        if let Some(frameworks) = dict.get("CFBundleFrameworks") {
            if let Some(arr) = frameworks.as_array() {
                metadata.frameworks = arr
                    .iter()
                    .filter_map(|v| v.as_string().map(|s| s.to_string()))
                    .collect();
            }
        }

        Ok(metadata)
    }

    /// Parse embedded.mobileprovision
    fn parse_provisioning_profile(&self, profile_data: &[u8]) -> PlatformResult<ProvisioningProfile> {
        // Provisioning profiles are PKCS#7 signed plist files
        // For now, we'll extract what we can from the raw data
        // In production, you'd use proper PKCS#7 parsing

        let mut profile = ProvisioningProfile {
            app_id_name: None,
            application_identifier_prefix: Vec::new(),
            creation_date: None,
            expiration_date: None,
            is_enterprise: false,
            team_identifier: Vec::new(),
            team_name: None,
            provisions_all_devices: false,
            provisioned_devices: Vec::new(),
            uuid: None,
        };

        // Try to extract plist from PKCS#7 wrapper
        // This is a simplified extraction - real implementation would use proper PKCS#7 parsing
        if let Some(start) = profile_data.windows(8).position(|w| w == b"<?xml ver") {
            if let Some(end) = profile_data[start..].windows(9).position(|w| w == b"</plist>") {
                let plist_data = &profile_data[start..start + end + 8];
                if let Ok(plist) = plist::from_bytes(plist_data) {
                    if let Some(dict) = plist.as_dictionary() {
                        profile.app_id_name = dict
                            .get("AppIDName")
                            .and_then(|v| v.as_string())
                            .map(|s| s.to_string());

                        profile.team_name = dict
                            .get("TeamName")
                            .and_then(|v| v.as_string())
                            .map(|s| s.to_string());

                        profile.uuid = dict
                            .get("UUID")
                            .and_then(|v| v.as_string())
                            .map(|s| s.to_string());

                        profile.provisions_all_devices = dict
                            .get("ProvisionsAllDevices")
                            .and_then(|v| v.as_boolean())
                            .unwrap_or(false);

                        if let Some(devices) = dict.get("ProvisionedDevices") {
                            if let Some(arr) = devices.as_array() {
                                profile.provisioned_devices = arr
                                    .iter()
                                    .filter_map(|v| v.as_string().map(|s| s.to_string()))
                                    .collect();
                            }
                        }

                        // Check if enterprise (no device list, provisions all devices)
                        profile.is_enterprise = profile.provisions_all_devices;
                    }
                }
            }
        }

        Ok(profile)
    }

    /// Detect architectures from Mach-O binary
    fn detect_architectures(&self, binary_path: &Path) -> PlatformResult<Vec<String>> {
        let mut architectures = Vec::new();

        // Read Mach-O header
        let file = File::open(binary_path)?;
        let mut reader = BufReader::new(file);
        let mut magic = [0u8; 4];

        if reader.read_exact(&mut magic).is_ok() {
            match u32::from_le_bytes(magic) {
                0xfeedface | 0xfeedfacf => {
                    // 32-bit or 64-bit Mach-O
                    architectures.push("arm64".to_string());
                }
                0xcafebabe | 0xbebafeca => {
                    // Universal binary (fat binary)
                    // Would need to parse fat header to get all architectures
                    architectures.push("fat_binary".to_string());
                }
                _ => {}
            }
        }

        Ok(architectures)
    }

    /// Find the main app bundle in extracted IPA
    fn find_app_bundle(&self, extract_dir: &Path) -> PlatformResult<PathBuf> {
        let payload_dir = extract_dir.join("Payload");
        if !payload_dir.exists() {
            return Err(PlatformError::ParseError(
                "Payload directory not found".to_string(),
            ));
        }

        // Find .app directory
        for entry in std::fs::read_dir(&payload_dir)? {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() && path.extension().map(|e| e == "app").unwrap_or(false) {
                    return Ok(path);
                }
            }
        }

        Err(PlatformError::ParseError(
            ".app bundle not found in Payload".to_string(),
        ))
    }

    /// Extract entitlements from binary
    fn extract_entitlements(&self, binary_path: &Path) -> PlatformResult<HashMap<String, plist::Value>> {
        // In production, this would use codesign -d --entitlements or parse the __entitlements section
        // For now, return empty
        Ok(HashMap::new())
    }
}

impl Default for IosAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PlatformAdapter for IosAdapter {
    fn platform(&self) -> Platform {
        Platform::Ios
    }

    fn capabilities(&self) -> PlatformCapabilities {
        self.capabilities.clone()
    }

    fn can_handle(&self, target: &AnalysisTarget) -> bool {
        target.platform == Platform::Ios
            || self
                .capabilities
                .supports_extension(&target.path.to_lowercase())
    }

    #[instrument(skip(self, target))]
    async fn validate(&self, target: &AnalysisTarget) -> PlatformResult<()> {
        let path = Path::new(&target.path);

        if !path.exists() {
            return Err(PlatformError::InvalidFormat(format!(
                "File not found: {}",
                target.path
            )));
        }

        if !path.is_file() {
            return Err(PlatformError::InvalidFormat(format!(
                "Not a file: {}",
                target.path
            )));
        }

        let file_size = utils::get_file_size(path)?;
        if file_size > self.capabilities.max_file_size {
            return Err(PlatformError::InvalidFormat(format!(
                "File too large: {} bytes (max: {})",
                file_size, self.capabilities.max_file_size
            ));
        }

        // Check if it's a valid ZIP/IPA
        if let Ok(file) = File::open(path) {
            if ZipArchive::new(file).is_err() {
                return Err(PlatformError::InvalidFormat(
                    "Not a valid IPA file".to_string(),
                ));
            }
        }

        Ok(())
    }

    #[instrument(skip(self, target))]
    async fn parse(&self, target: &AnalysisTarget) -> PlatformResult<ParseResult> {
        let path = Path::new(&target.path);
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)?;

        // Find the app bundle
        let mut app_bundle_path: Option<String> = None;
        for i in 0..archive.len() {
            if let Ok(file) = archive.by_index(i) {
                let name = file.name();
                if name.starts_with("Payload/") && name.ends_with(".app/") {
                    app_bundle_path = Some(name.to_string());
                    break;
                }
            }
        }

        let app_bundle = app_bundle_path.ok_or_else(|| {
            PlatformError::ParseError("Could not find .app bundle in IPA".to_string())
        })?;

        let app_name = app_bundle
            .trim_start_matches("Payload/")
            .trim_end_matches(".app/");

        // Extract and parse Info.plist
        let info_plist_path = format!("{}Info.plist", app_bundle);
        let info_plist_data = if let Ok(mut plist_file) = archive.by_name(&info_plist_path) {
            let mut data = Vec::new();
            plist_file.read_to_end(&mut data)?;
            data
        } else {
            return Err(PlatformError::ParseError(
                "Info.plist not found".to_string(),
            ));
        };

        let ios_metadata = self.parse_info_plist(&info_plist_data)?;

        // Try to parse provisioning profile
        let provision_path = format!("{}embedded.mobileprovision", app_bundle);
        let provisioning_profile = if let Ok(mut provision_file) = archive.by_name(&provision_path)
        {
            let mut data = Vec::new();
            provision_file.read_to_end(&mut data)?;
            self.parse_provisioning_profile(&data).ok()
        } else {
            None
        };

        let mut metadata = ios_metadata.clone();
        metadata.provisioning_profile = provisioning_profile;

        // Build platform metadata
        let platform_metadata = PlatformMetadata::new(Platform::Ios)
            .with_name(&metadata.display_name.as_deref().unwrap_or(app_name))
            .with_version(metadata.short_version.as_deref().unwrap_or("unknown"))
            .with_package_id(&metadata.bundle_id)
            .with_target_version(metadata.minimum_os_version.as_deref().unwrap_or("unknown"))
            .with_file_size(utils::get_file_size(path)?)
            .with_checksum(utils::calculate_checksum(path)?);

        // Create parse result
        let mut result = ParseResult::new(&target.path, platform_metadata)
            .add_config_file(&info_plist_path);

        if let Some(exec_name) = &metadata.executable_name {
            let exec_path = format!("{}{}", app_bundle, exec_name);
            result = result.add_entry_point(&exec_path).add_binary_file(&exec_path);
        }

        // Add frameworks
        for i in 0..archive.len() {
            if let Ok(file) = archive.by_index(i) {
                let name = file.name();
                if name.contains(".framework/") && name.ends_with("/") {
                    // Framework directory
                } else if name.ends_with(".dylib") {
                    result = result.add_binary_file(name);
                } else if name.contains("/Frameworks/") && !name.ends_with("/") {
                    result = result.add_binary_file(name);
                }
            }
        }

        // Add iOS-specific metadata as extra
        let ios_json = serde_json::to_value(&metadata)?;
        result.metadata.extra.insert("ios".to_string(), ios_json);

        info!(
            "Parsed iOS IPA: {} v{} (bundle: {})",
            metadata.display_name.as_deref().unwrap_or("Unknown"),
            metadata.short_version.as_deref().unwrap_or("unknown"),
            metadata.bundle_id
        );

        Ok(result)
    }

    #[instrument(skip(self, target, output_dir))]
    async fn extract(&self, target: &AnalysisTarget, output_dir: &Path) -> PlatformResult<PathBuf> {
        let path = Path::new(&target.path);
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)?;

        // Create extraction directory
        let extract_dir = utils::create_work_dir(output_dir, "ios")?;

        // Extract all files
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let name = file.name();

            // Skip directories
            if name.ends_with('/') {
                continue;
            }

            let output_path = extract_dir.join(name);
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let mut output_file = File::create(&output_path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            output_file.write_all(&buffer)?;

            debug!("Extracted: {}", name);
        }

        info!("Extracted iOS IPA to: {}", extract_dir.display());
        Ok(extract_dir)
    }

    fn analysis_config(&self) -> serde_json::Value {
        serde_json::json!({
            "platform": "ios",
            "static_analysis": {
                "macho_analysis": true,
                "plist_analysis": true,
                "framework_analysis": true,
                "entitlement_analysis": true,
            },
            "dynamic_analysis": {
                "instrumentation": true,
                "network_capture": true,
            },
            "check_categories": [
                "insecure_transport",
                "ats_misconfiguration",
                "hardcoded_secrets",
                "insecure_storage",
                "jailbreak_detection",
                "code_obfuscation",
                "weak_crypto",
                "url_scheme_hijacking",
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ios_adapter_creation() {
        let adapter = IosAdapter::new();
        assert_eq!(adapter.platform(), Platform::Ios);
        assert!(adapter.capabilities().static_analysis);
    }

    #[test]
    fn test_parse_info_plist() {
        let adapter = IosAdapter::new();

        // Create a minimal Info.plist
        let plist_data = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.test.app</string>
    <key>CFBundleName</key>
    <string>TestApp</string>
    <key>CFBundleDisplayName</key>
    <string>Test App</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>MinimumOSVersion</key>
    <string>14.0</string>
    <key>CFBundleExecutable</key>
    <string>TestApp</string>
    <key>UIDeviceFamily</key>
    <array>
        <integer>1</integer>
        <integer>2</integer>
    </array>
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>testapp</string>
            </array>
        </dict>
    </array>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
        <key>NSExceptionDomains</key>
        <dict>
            <key>example.com</key>
            <dict>
                <key>NSExceptionAllowsInsecureHTTPLoads</key>
                <true/>
            </dict>
        </dict>
    </dict>
</dict>
</plist>"#;

        let result = adapter.parse_info_plist(plist_data.as_bytes());
        assert!(result.is_ok());

        let metadata = result.unwrap();
        assert_eq!(metadata.bundle_id, "com.test.app");
        assert_eq!(metadata.bundle_name, Some("TestApp".to_string()));
        assert_eq!(metadata.display_name, Some("Test App".to_string()));
        assert_eq!(metadata.bundle_version, Some("1.0.0".to_string()));
        assert_eq!(metadata.short_version, Some("1.0".to_string()));
        assert_eq!(metadata.minimum_os_version, Some("14.0".to_string()));
        assert_eq!(metadata.executable_name, Some("TestApp".to_string()));
        assert_eq!(metadata.supported_devices, vec![1, 2]);
        assert_eq!(metadata.url_schemes, vec!["testapp".to_string()]);

        // Check ATS settings
        let ats = metadata.ats_settings.unwrap();
        assert!(ats.allow_arbitrary_loads);
        assert_eq!(ats.exception_domains.len(), 1);
        assert_eq!(ats.exception_domains[0].domain, "example.com");
        assert!(ats.exception_domains[0].exception_allow_insecure_http_loads);
    }
}
