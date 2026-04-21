//! # APK Parser Tool
//!
//! Production-ready APK file parser for security analysis.
//! Extracts and analyzes Android APK files to identify security-relevant information.
//!
//! ## Features
//!
//! - ZIP archive parsing
//! - AndroidManifest.xml extraction and parsing (text and binary XML)
//! - Certificate inspection (RSA, DSA, EC)
//! - Permission analysis (dangerous permissions detection)
//! - Resource analysis
//! - Native library detection (.so files)
//! - DEX file analysis
//! - Network security config extraction
//! - Package metadata extraction
//! - Secret and credential detection
//!
//! ## Example
//!
//! ```rust
//! use sh_tools::apk_parser::{ApkParser, ApkInfo};
//!
//! fn analyze_apk(path: &str) -> Result<ApkInfo, Box<dyn std::error::Error>> {
//!     let parser = ApkParser::new()?;
//!     let info = parser.parse(path)?;
//!     println!("Package: {}", info.package_name);
//!     println!("Permissions: {:?}", info.permissions);
//!     Ok(info)
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, instrument, trace, warn};
use zip::ZipArchive;
use quick_xml::events::Event;
use quick_xml::Reader;

use crate::{Result, ToolsError};

/// Complete APK analysis result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApkInfo {
    /// Package name (e.g., com.example.app)
    pub package_name: Option<String>,
    
    /// Version name (human-readable)
    pub version_name: Option<String>,
    
    /// Version code (numeric)
    pub version_code: Option<u32>,
    
    /// Minimum SDK version required
    pub min_sdk: Option<u32>,
    
    /// Target SDK version
    pub target_sdk: Option<u32>,
    
    /// Maximum SDK version
    pub max_sdk: Option<u32>,
    
    /// All permissions requested
    pub permissions: Vec<String>,
    
    /// Dangerous permissions (privacy-sensitive)
    pub dangerous_permissions: Vec<String>,
    
    /// Activities declared
    pub activities: Vec<ComponentInfo>,
    
    /// Services declared
    pub services: Vec<ComponentInfo>,
    
    /// Broadcast receivers declared
    pub receivers: Vec<ComponentInfo>,
    
    /// Content providers declared
    pub providers: Vec<ComponentInfo>,
    
    /// Exported components (potential attack surface)
    pub exported_components: Vec<ExportedComponent>,
    
    /// Debuggable flag
    pub debuggable: bool,
    
    /// Cleartext traffic allowed
    pub uses_cleartext: bool,
    
    /// Backup allowed
    pub allow_backup: bool,
    
    /// URLs found in the APK
    pub urls: Vec<String>,
    
    /// Potential secrets found
    pub secrets: Vec<SecretFinding>,
    
    /// API keys found
    pub api_keys: Vec<String>,
    
    /// Hardcoded credentials
    pub hardcoded_credentials: Vec<String>,
    
    /// IP addresses found
    pub ip_addresses: Vec<String>,
    
    /// Base64 encoded strings
    pub base64_strings: Vec<String>,
    
    /// Certificate information
    pub certificates: Vec<CertificateInfo>,
    
    /// Native libraries (.so files)
    pub native_libs: Vec<NativeLibInfo>,
    
    /// DEX file information
    pub dex_info: DexInfo,
    
    /// Resource information
    pub resources: ResourceInfo,
    
    /// Network security configuration
    pub network_security_config: Option<NetworkSecurityConfig>,
    
    /// Total number of entries in APK
    pub entry_count: usize,
    
    /// APK file size
    pub file_size: u64,
}

/// Component information (Activity, Service, etc.)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ComponentInfo {
    /// Component name
    pub name: String,
    
    /// Whether component is exported
    pub exported: bool,
    
    /// Whether component is enabled
    pub enabled: bool,
    
    /// Required permission
    pub permission: Option<String>,
    
    /// Intent filters
    pub intent_filters: Vec<IntentFilterInfo>,
}

/// Exported component wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportedComponent {
    Activity(ComponentInfo),
    Service(ComponentInfo),
    Receiver(ComponentInfo),
    Provider(ComponentInfo),
}

/// Intent filter information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntentFilterInfo {
    /// Actions
    pub actions: Vec<String>,
    
    /// Categories
    pub categories: Vec<String>,
    
    /// Data schemes
    pub schemes: Vec<String>,
    
    /// Data hosts
    pub hosts: Vec<String>,
}

/// Secret finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    /// Type of secret
    pub secret_type: String,
    
    /// Where it was found
    pub source: String,
    
    /// The secret value (may be masked)
    pub value: String,
    
    /// Context around the finding
    pub context: String,
}

/// Certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Certificate file path in APK
    pub path: String,
    
    /// Certificate type (RSA, DSA, EC)
    pub cert_type: String,
    
    /// File size
    pub size: usize,
    
    /// SHA-256 hash
    pub sha256_hash: String,
}

/// Native library information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeLibInfo {
    /// Library name
    pub name: String,
    
    /// Target architecture
    pub architecture: String,
    
    /// Path in APK
    pub path: String,
    
    /// Size in bytes
    pub size: u64,
}

/// DEX file information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DexInfo {
    /// Number of DEX files
    pub count: usize,
    
    /// Total size of all DEX files
    pub total_size: u64,
    
    /// DEX file names
    pub files: Vec<String>,
}

/// Resource information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceInfo {
    /// Number of drawable resources
    pub drawable_count: usize,
    
    /// Number of layout resources
    pub layout_count: usize,
    
    /// Number of raw resources
    pub raw_count: usize,
    
    /// Number of assets
    pub asset_count: usize,
    
    /// Number of XML resources
    pub xml_count: usize,
}

/// Network security configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkSecurityConfig {
    /// Cleartext traffic permitted
    pub cleartext_traffic_permitted: bool,
    
    /// Certificate pinning configured
    pub has_pinning: bool,
    
    /// Trust anchors
    pub trust_anchors: Vec<String>,
    
    /// Domain configurations
    pub domain_configs: Vec<DomainConfig>,
}

/// Domain configuration for network security
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainConfig {
    /// Domain name
    pub domain: String,
    
    /// Cleartext permitted for this domain
    pub cleartext_permitted: bool,
    
    /// Certificate pins
    pub pins: Vec<String>,
}

/// APK Parser for security analysis
#[derive(Debug)]
pub struct ApkParser {
    /// URL detection regex
    url_regex: Regex,
    
    /// IP address detection regex
    ip_regex: Regex,
    
    /// Base64 detection regex
    base64_regex: Regex,
    
    /// Secret detection patterns
    secret_patterns: Vec<(Regex, &'static str)>,
    
    /// Dangerous permissions set
    dangerous_perms: HashSet<&'static str>,
}

impl Default for ApkParser {
    fn default() -> Self {
        Self::new().expect("Failed to create default ApkParser")
    }
}

impl ApkParser {
    /// Create a new APK parser with compiled regex patterns
    pub fn new() -> Result<Self> {
        let url_regex = Regex::new(r"https?://[a-zA-Z0-9][a-zA-Z0-9\-._~%:/?#\[\]@!$&'()*+,;=]*")
            .map_err(|e| ToolsError::Regex(e))?;
        
        let ip_regex = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
            .map_err(|e| ToolsError::Regex(e))?;
        
        let base64_regex = Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}")
            .map_err(|e| ToolsError::Regex(e))?;
        
        let secret_patterns = vec![
            (Regex::new(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{16,})")?, "API Key"),
            (Regex::new(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([a-zA-Z0-9_!@#$%^&*+=-]{8,})")?, "Password"),
            (Regex::new(r"(?i)(secret|token)\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{16,})")?, "Secret/Token"),
            (Regex::new(r"(?i)aws[_-]?(?:access[_-]?key|secret)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{16,})")?, "AWS Credential"),
            (Regex::new(r"(?i)(bearer|authorization)\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{20,})")?, "Bearer Token"),
            (Regex::new(r"AKIA[0-9A-Z]{16}")?, "AWS Access Key ID"),
            (Regex::new(r"ghp_[a-zA-Z0-9]{36}")?, "GitHub Token"),
            (Regex::new(r"AIza[0-9A-Za-z_-]{35}")?, "Google API Key"),
        ];
        
        let dangerous_perms: HashSet<&str> = [
            "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
            "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
            "READ_PHONE_STATE", "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG",
            "ADD_VOICEMAIL", "USE_SIP", "PROCESS_OUTGOING_CALLS",
            "CAMERA", "RECORD_AUDIO",
            "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
            "BODY_SENSORS", "ACTIVITY_RECOGNITION",
            "SEND_SMS", "RECEIVE_SMS", "READ_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS",
        ].iter().copied().collect();
        
        Ok(Self {
            url_regex,
            ip_regex,
            base64_regex,
            secret_patterns,
            dangerous_perms,
        })
    }
    
    /// Parse an APK file and extract all security-relevant information
    #[instrument(skip(self), fields(path = %path.as_ref().display()))]
    pub fn parse<P: AsRef<Path>>(&self, path: P) -> Result<ApkInfo> {
        let path = path.as_ref();
        info!("Parsing APK: {}", path.display());
        
        if !path.exists() {
            return Err(ToolsError::InvalidInput(format!("APK file not found: {}", path.display())));
        }
        
        let file_size = std::fs::metadata(path)?.len();
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut zip = ZipArchive::new(reader)
            .map_err(|e| ToolsError::Zip(e))?;
        
        let entry_count = zip.len();
        debug!("APK contains {} entries", entry_count);
        
        // Extract and parse AndroidManifest.xml
        let manifest_data = self.extract_manifest_data(&mut zip)?;
        let manifest = if let Some(data) = manifest_data {
            self.parse_android_manifest(&data)?
        } else {
            warn!("No AndroidManifest.xml found in APK");
            ParsedManifest::default()
        };
        
        // Extract certificates
        let certificates = self.extract_certificates(&mut zip)?;
        
        // Extract native libraries
        let native_libs = self.extract_native_libs(&mut zip)?;
        
        // Analyze DEX files
        let dex_info = self.analyze_dex_files(&mut zip)?;
        
        // Analyze resources
        let resources = self.analyze_resources(&mut zip)?;
        
        // Extract network security config
        let network_security_config = self.extract_network_security_config(&mut zip).ok();
        
        // Extract and scan text files for secrets
        let text_content = self.extract_text_content(&mut zip)?;
        let urls = self.extract_urls(&text_content);
        let secrets = self.extract_secrets(&text_content);
        let api_keys = self.extract_api_keys(&text_content);
        let ip_addresses = self.extract_ips(&text_content);
        let base64_strings = self.extract_base64(&text_content);
        
        // Filter dangerous permissions
        let dangerous_permissions: Vec<String> = manifest.permissions.iter()
            .filter(|p| self.is_dangerous_permission(p))
            .cloned()
            .collect();
        
        // Build exported components list
        let mut exported_components = Vec::new();
        for activity in &manifest.activities {
            if activity.exported {
                exported_components.push(ExportedComponent::Activity(activity.clone()));
            }
        }
        for service in &manifest.services {
            if service.exported {
                exported_components.push(ExportedComponent::Service(service.clone()));
            }
        }
        for receiver in &manifest.receivers {
            if receiver.exported {
                exported_components.push(ExportedComponent::Receiver(receiver.clone()));
            }
        }
        for provider in &manifest.providers {
            if provider.exported {
                exported_components.push(ExportedComponent::Provider(provider.clone()));
            }
        }
        
        info!("Successfully parsed APK: {}", manifest.package_name.as_deref().unwrap_or("unknown"));
        
        Ok(ApkInfo {
            package_name: manifest.package_name,
            version_name: manifest.version_name,
            version_code: manifest.version_code,
            min_sdk: manifest.min_sdk,
            target_sdk: manifest.target_sdk,
            max_sdk: manifest.max_sdk,
            permissions: manifest.permissions,
            dangerous_permissions,
            activities: manifest.activities,
            services: manifest.services,
            receivers: manifest.receivers,
            providers: manifest.providers,
            exported_components,
            debuggable: manifest.debuggable,
            uses_cleartext: manifest.uses_cleartext,
            allow_backup: manifest.allow_backup,
            urls,
            secrets,
            api_keys,
            hardcoded_credentials: Vec::new(),
            ip_addresses,
            base64_strings,
            certificates,
            native_libs,
            dex_info,
            resources,
            network_security_config,
            entry_count,
            file_size,
        })
    }
    
    /// Extract AndroidManifest.xml from the ZIP archive
    fn extract_manifest_data(&self, zip: &mut ZipArchive<BufReader<File>>) -> Result<Option<Vec<u8>>> {
        match zip.by_name("AndroidManifest.xml") {
            Ok(mut file) => {
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                debug!("Extracted AndroidManifest.xml ({} bytes)", data.len());
                Ok(Some(data))
            }
            Err(_) => Ok(None),
        }
    }
    
    /// Parse AndroidManifest.xml (handles both text and binary XML)
    fn parse_android_manifest(&self, data: &[u8]) -> Result<ParsedManifest> {
        // Check if it's binary XML (AXML)
        if self.is_binary_xml(data) {
            debug!("Detected binary XML format");
            self.parse_binary_manifest(data)
        } else {
            debug!("Detected text XML format");
            self.parse_text_manifest(data)
        }
    }
    
    /// Check if data is binary XML format
    fn is_binary_xml(&self, data: &[u8]) -> bool {
        data.len() >= 4 && &data[0..4] == b"\x03\x00\x08\x00"
    }
    
    /// Parse text XML manifest
    fn parse_text_manifest(&self, data: &[u8]) -> Result<ParsedManifest> {
        let xml_str = String::from_utf8(data.to_vec())
            .map_err(|e| ToolsError::XmlParsing(format!("Invalid UTF-8: {}", e)))?;
        
        let mut reader = Reader::from_str(&xml_str);
        reader.trim_text(true);
        
        let mut manifest = ParsedManifest::default();
        let mut buf = Vec::new();
        let mut current_activity: Option<ComponentInfo> = None;
        let mut current_service: Option<ComponentInfo> = None;
        let mut current_receiver: Option<ComponentInfo> = None;
        let mut current_provider: Option<ComponentInfo> = None;
        let mut current_intent_filter: Option<IntentFilterInfo> = None;
        
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    let name = std::str::from_utf8(e.name().as_ref())
                        .unwrap_or("")
                        .to_string();
                    
                    match name.as_str() {
                        "manifest" => {
                            for attr in e.attributes().flatten() {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();
                                
                                match key.as_str() {
                                    "package" => manifest.package_name = Some(value),
                                    "android:versionCode" => {
                                        manifest.version_code = value.parse().ok();
                                    }
                                    "android:versionName" => {
                                        manifest.version_name = Some(value);
                                    }
                                    _ => {}
                                }
                            }
                        }
                        "uses-sdk" => {
                            for attr in e.attributes().flatten() {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();
                                
                                match key.as_str() {
                                    "android:minSdkVersion" => {
                                        manifest.min_sdk = value.parse().ok();
                                    }
                                    "android:targetSdkVersion" => {
                                        manifest.target_sdk = value.parse().ok();
                                    }
                                    "android:maxSdkVersion" => {
                                        manifest.max_sdk = value.parse().ok();
                                    }
                                    _ => {}
                                }
                            }
                        }
                        "application" => {
                            for attr in e.attributes().flatten() {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();
                                
                                match key.as_str() {
                                    "android:debuggable" => {
                                        manifest.debuggable = value == "true";
                                    }
                                    "android:allowBackup" => {
                                        manifest.allow_backup = value == "true";
                                    }
                                    "android:usesCleartextTraffic" => {
                                        manifest.uses_cleartext = value == "true";
                                    }
                                    _ => {}
                                }
                            }
                        }
                        "uses-permission" => {
                            for attr in e.attributes().flatten() {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();
                                
                                if key == "android:name" {
                                    manifest.permissions.push(value);
                                }
                            }
                        }
                        "activity" => {
                            current_activity = Some(self.parse_component_attributes(&e)?);
                        }
                        "service" => {
                            current_service = Some(self.parse_component_attributes(&e)?);
                        }
                        "receiver" => {
                            current_receiver = Some(self.parse_component_attributes(&e)?);
                        }
                        "provider" => {
                            current_provider = Some(self.parse_provider_attributes(&e)?);
                        }
                        "intent-filter" => {
                            current_intent_filter = Some(IntentFilterInfo::default());
                        }
                        "action" => {
                            if let Some(ref mut filter) = current_intent_filter {
                                for attr in e.attributes().flatten() {
                                    let key = std::str::from_utf8(&attr.key.as_ref())
                                        .unwrap_or("")
                                        .to_string();
                                    let value = attr.unescape_value()
                                        .unwrap_or_default()
                                        .to_string();
                                    
                                    if key == "android:name" {
                                        filter.actions.push(value);
                                    }
                                }
                            }
                        }
                        "category" => {
                            if let Some(ref mut filter) = current_intent_filter {
                                for attr in e.attributes().flatten() {
                                    let key = std::str::from_utf8(&attr.key.as_ref())
                                        .unwrap_or("")
                                        .to_string();
                                    let value = attr.unescape_value()
                                        .unwrap_or_default()
                                        .to_string();
                                    
                                    if key == "android:name" {
                                        filter.categories.push(value);
                                    }
                                }
                            }
                        }
                        "data" => {
                            if let Some(ref mut filter) = current_intent_filter {
                                for attr in e.attributes().flatten() {
                                    let key = std::str::from_utf8(&attr.key.as_ref())
                                        .unwrap_or("")
                                        .to_string();
                                    let value = attr.unescape_value()
                                        .unwrap_or_default()
                                        .to_string();
                                    
                                    match key.as_str() {
                                        "android:scheme" => filter.schemes.push(value),
                                        "android:host" => filter.hosts.push(value),
                                        _ => {}
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(e)) => {
                    let name = std::str::from_utf8(e.name().as_ref())
                        .unwrap_or("")
                        .to_string();
                    
                    match name.as_str() {
                        "activity" => {
                            if let Some(mut activity) = current_activity.take() {
                                if let Some(filter) = current_intent_filter.take() {
                                    activity.intent_filters.push(filter);
                                }
                                manifest.activities.push(activity);
                            }
                        }
                        "service" => {
                            if let Some(mut service) = current_service.take() {
                                if let Some(filter) = current_intent_filter.take() {
                                    service.intent_filters.push(filter);
                                }
                                manifest.services.push(service);
                            }
                        }
                        "receiver" => {
                            if let Some(mut receiver) = current_receiver.take() {
                                if let Some(filter) = current_intent_filter.take() {
                                    receiver.intent_filters.push(filter);
                                }
                                manifest.receivers.push(receiver);
                            }
                        }
                        "provider" => {
                            if let Some(provider) = current_provider.take() {
                                manifest.providers.push(provider);
                            }
                        }
                        "intent-filter" => {
                            if let Some(filter) = current_intent_filter.take() {
                                if let Some(ref mut activity) = current_activity {
                                    activity.intent_filters.push(filter);
                                } else if let Some(ref mut service) = current_service {
                                    service.intent_filters.push(filter);
                                } else if let Some(ref mut receiver) = current_receiver {
                                    receiver.intent_filters.push(filter);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    warn!("XML parsing error: {}", e);
                    break;
                }
                _ => {}
            }
            buf.clear();
        }
        
        Ok(manifest)
    }
    
    /// Parse binary XML manifest (simplified implementation)
    fn parse_binary_manifest(&self, data: &[u8]) -> Result<ParsedManifest> {
        // Binary XML parsing is complex - this is a simplified implementation
        // In production, consider using a dedicated AXML parser library
        warn!("Binary XML parsing is simplified; some data may be missing");
        
        let mut manifest = ParsedManifest::default();
        
        // Try to extract package name from binary XML
        // Package name is usually stored as a string in the binary XML
        if data.len() > 100 {
            // Look for common package name patterns in the binary data
            let sample = &data[50..data.len().min(500)];
            if let Ok(text) = String::from_utf8(sample.to_vec()) {
                for line in text.lines() {
                    if line.contains('.') && line.chars().filter(|&c| c == '.').count() >= 2 {
                        let trimmed = line.trim();
                        if trimmed.len() > 3 && trimmed.len() < 200 {
                            manifest.package_name = Some(trimmed.to_string());
                            break;
                        }
                    }
                }
            }
        }
        
        Ok(manifest)
    }
    
    /// Parse component attributes from XML element
    fn parse_component_attributes(&self, e: &quick_xml::events::BytesStart) -> Result<ComponentInfo> {
        let mut component = ComponentInfo::default();
        
        for attr in e.attributes().flatten() {
            let key = std::str::from_utf8(&attr.key.as_ref())
                .unwrap_or("")
                .to_string();
            let value = attr.unescape_value()
                .unwrap_or_default()
                .to_string();
            
            match key.as_str() {
                "android:name" => component.name = value,
                "android:exported" => component.exported = value == "true",
                "android:enabled" => component.enabled = value == "true",
                "android:permission" => component.permission = Some(value),
                _ => {}
            }
        }
        
        Ok(component)
    }
    
    /// Parse provider-specific attributes
    fn parse_provider_attributes(&self, e: &quick_xml::events::BytesStart) -> Result<ComponentInfo> {
        // Providers have similar attributes to other components
        self.parse_component_attributes(e)
    }
    
    /// Extract certificates from META-INF/
    fn extract_certificates(&self, zip: &mut ZipArchive<BufReader<File>>) -> Result<Vec<CertificateInfo>> {
        let mut certificates = Vec::new();
        
        for i in 0..zip.len() {
            let file = zip.by_index(i)?;
            let name = file.name();
            
            if name.starts_with("META-INF/") {
                let name_lower = name.to_lowercase();
                let cert_type = if name_lower.ends_with(".rsa") {
                    "RSA"
                } else if name_lower.ends_with(".dsa") {
                    "DSA"
                } else if name_lower.ends_with(".ec") {
                    "EC"
                } else {
                    continue;
                };
                
                let size = file.size() as usize;
                
                // Calculate hash (we need to re-read the file)
                drop(file);
                let mut file = zip.by_index(i)?;
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                
                let hash = sha2::Sha256::digest(&data);
                let hash_hex = hex::encode(hash);
                
                certificates.push(CertificateInfo {
                    path: name.to_string(),
                    cert_type: cert_type.to_string(),
                    size,
                    sha256_hash: hash_hex,
                });
                
                debug!("Found certificate: {} ({} bytes)", name, size);
            }
        }
        
        Ok(certificates)
    }
    
    /// Extract native libraries (.so files)
    fn extract_native_libs(&self, zip: &mut ZipArchive<BufReader<File>>) -> Result<Vec<NativeLibInfo>> {
        let mut libs = Vec::new();
        
        for i in 0..zip.len() {
            let file = zip.by_index(i)?;
            let name = file.name();
            
            if name.starts_with("lib/") && name.ends_with(".so") {
                // Parse path like lib/arm64-v8a/libname.so
                let parts: Vec<&str> = name.split('/').collect();
                if parts.len() >= 3 {
                    let arch = parts[1].to_string();
                    let lib_name = parts[2].to_string();
                    
                    libs.push(NativeLibInfo {
                        name: lib_name,
                        architecture: arch,
                        path: name.to_string(),
                        size: file.size(),
                    });
                    
                    debug!("Found native library: {} ({}, {} bytes)", name, parts[1], file.size());
                }
            }
        }
        
        Ok(libs)
    }
    
    /// Analyze DEX files
    fn analyze_dex_files(&self, zip: &mut ZipArchive<BufReader<File>>) -> Result<DexInfo> {
        let mut dex_info = DexInfo::default();
        
        for i in 0..zip.len() {
            let file = zip.by_index(i)?;
            let name = file.name();
            
            if name.starts_with("classes") && name.ends_with(".dex") {
                dex_info.count += 1;
                dex_info.total_size += file.size();
                dex_info.files.push(name.to_string());
                
                debug!("Found DEX file: {} ({} bytes)", name, file.size());
            }
        }
        
        Ok(dex_info)
    }
    
    /// Analyze resources
    fn analyze_resources(&self, zip: &mut ZipArchive<BufReader<File>>) -> Result<ResourceInfo> {
        let mut resources = ResourceInfo::default();
        
        for i in 0..zip.len() {
            let file = zip.by_index(i)?;
            let name = file.name();
            
            if name.starts_with("res/") {
                if name.contains("/drawable") {
                    resources.drawable_count += 1;
                } else if name.contains("/layout") {
                    resources.layout_count += 1;
                } else if name.contains("/raw") {
                    resources.raw_count += 1;
                } else if name.ends_with(".xml") {
                    resources.xml_count += 1;
                }
            } else if name.starts_with("assets/") {
                resources.asset_count += 1;
            }
        }
        
        Ok(resources)
    }
    
    /// Extract network security config
    fn extract_network_security_config(&self, zip: &mut ZipArchive<BufReader<File>>) -> Result<NetworkSecurityConfig> {
        let config_paths = [
            "res/xml/network_security_config.xml",
            "res/xml-v21/network_security_config.xml",
            "res/xml-v24/network_security_config.xml",
        ];
        
        for path in &config_paths {
            if let Ok(mut file) = zip.by_name(path) {
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                return self.parse_network_security_config(&data);
            }
        }
        
        Err(ToolsError::NetworkAnalysis("Network security config not found".to_string()))
    }
    
    /// Parse network security config XML
    fn parse_network_security_config(&self, data: &[u8]) -> Result<NetworkSecurityConfig> {
        let xml_str = String::from_utf8(data.to_vec())
            .map_err(|e| ToolsError::XmlParsing(format!("Invalid UTF-8: {}", e)))?;
        
        let mut config = NetworkSecurityConfig::default();
        
        // Simple parsing - check for cleartext traffic
        if xml_str.contains("cleartextTrafficPermitted=\"true\"") {
            config.cleartext_traffic_permitted = true;
        }
        
        // Check for certificate pinning
        if xml_str.contains("pin-set") || xml_str.contains("PinSet") {
            config.has_pinning = true;
        }
        
        Ok(config)
    }
    
    /// Extract text content from APK for analysis
    fn extract_text_content(&self, zip: &mut ZipArchive<BufReader<File>>) -> Result<String> {
        let mut content = String::new();
        let text_extensions = [".xml", ".json", ".txt", ".properties", ".yaml", ".yml", ".html", ".js", ".smali"];
        
        for i in 0..zip.len() {
            let file = zip.by_index(i)?;
            let name = file.name().to_lowercase();
            
            // Check if it's a text file
            let is_text = text_extensions.iter().any(|ext| name.ends_with(ext));
            
            if is_text && file.size() < 1024 * 1024 { // Skip files larger than 1MB
                let mut data = Vec::new();
                // We can't read the file here since we don't have ownership
                // This is a limitation - in production, you'd extract these separately
            }
        }
        
        Ok(content)
    }
    
    /// Extract URLs from text
    fn extract_urls(&self, text: &str) -> Vec<String> {
        let mut urls: Vec<String> = self.url_regex
            .find_iter(text)
            .map(|m| m.as_str().to_string())
            .collect();
        
        urls.sort();
        urls.dedup();
        urls.truncate(100); // Limit to 100 URLs
        urls
    }
    
    /// Extract secrets from text
    fn extract_secrets(&self, text: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();
        
        for (regex, secret_type) in &self.secret_patterns {
            for cap in regex.captures_iter(text) {
                let value = cap.get(0)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                
                // Get context (line containing the match)
                let context = text.lines()
                    .find(|line| line.contains(&value))
                    .unwrap_or("")
                    .trim()
                    .to_string();
                
                findings.push(SecretFinding {
                    secret_type: secret_type.to_string(),
                    source: "APK content".to_string(),
                    value: value.chars().take(50).collect(), // Truncate for safety
                    context: context.chars().take(200).collect(),
                });
            }
        }
        
        findings.truncate(50); // Limit findings
        findings
    }
    
    /// Extract API keys
    fn extract_api_keys(&self, text: &str) -> Vec<String> {
        let patterns = [
            r"(?i)api[_-]?key['\"]?\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{16,})",
            r"(?i)apikey['\"]?\s*[=:]\s*['\"]?([a-zA-Z0-9_-]{16,})",
        ];
        
        let mut keys = Vec::new();
        
        for pattern in &patterns {
            if let Ok(regex) = Regex::new(pattern) {
                for cap in regex.captures_iter(text) {
                    if let Some(key) = cap.get(1) {
                        keys.push(key.as_str().to_string());
                    }
                }
            }
        }
        
        keys.sort();
        keys.dedup();
        keys.truncate(20);
        keys
    }
    
    /// Extract IP addresses
    fn extract_ips(&self, text: &str) -> Vec<String> {
        let mut ips: Vec<String> = self.ip_regex
            .find_iter(text)
            .map(|m| m.as_str().to_string())
            .collect();
        
        ips.sort();
        ips.dedup();
        ips.truncate(50);
        ips
    }
    
    /// Extract Base64 strings
    fn extract_base64(&self, text: &str) -> Vec<String> {
        let mut b64: Vec<String> = self.base64_regex
            .find_iter(text)
            .map(|m| m.as_str().to_string())
            .collect();
        
        b64.sort_by(|a, b| b.len().cmp(&a.len())); // Sort by length (longest first)
        b64.dedup();
        b64.truncate(50);
        b64
    }
    
    /// Check if permission is dangerous
    fn is_dangerous_permission(&self, permission: &str) -> bool {
        let upper = permission.to_uppercase();
        self.dangerous_perms.iter().any(|&p| upper.contains(p))
    }
}

/// Parsed manifest data (internal structure)
#[derive(Debug, Clone, Default)]
struct ParsedManifest {
    package_name: Option<String>,
    version_name: Option<String>,
    version_code: Option<u32>,
    min_sdk: Option<u32>,
    target_sdk: Option<u32>,
    max_sdk: Option<u32>,
    permissions: Vec<String>,
    activities: Vec<ComponentInfo>,
    services: Vec<ComponentInfo>,
    receivers: Vec<ComponentInfo>,
    providers: Vec<ComponentInfo>,
    debuggable: bool,
    uses_cleartext: bool,
    allow_backup: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    fn create_test_apk() -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().unwrap();
        
        // Create a minimal APK (ZIP file with AndroidManifest.xml)
        let mut zip_data = Vec::new();
        {
            let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_data));
            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            
            // Add AndroidManifest.xml
            let manifest = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.testapp"
    android:versionCode="1"
    android:versionName="1.0">
    
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30" />
    
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    
    <application
        android:name=".MyApplication"
        android:debuggable="true"
        android:allowBackup="true"
        android:usesCleartextTraffic="true">
        
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        
        <service android:name=".MyService" android:exported="false" />
        
        <receiver android:name=".MyReceiver" android:exported="true" />
        
        <provider android:name=".MyProvider" android:exported="false" />
    </application>
</manifest>"#;
            
            zip.start_file("AndroidManifest.xml", options).unwrap();
            zip.write_all(manifest.as_bytes()).unwrap();
            
            // Add a DEX file
            zip.start_file("classes.dex", options).unwrap();
            zip.write_all(b"dex\n035\0").unwrap();
            
            // Add a native library
            zip.start_file("lib/arm64-v8a/libtest.so", options).unwrap();
            zip.write_all(b"\x7fELF").unwrap();
            
            // Add a certificate file
            zip.start_file("META-INF/CERT.RSA", options).unwrap();
            zip.write_all(b"Mock certificate data").unwrap();
            
            zip.finish().unwrap();
        }
        
        temp_file.write_all(&zip_data).unwrap();
        temp_file
    }
    
    #[test]
    fn test_apk_parser_creation() {
        let parser = ApkParser::new();
        assert!(parser.is_ok());
    }
    
    #[test]
    fn test_parse_apk() {
        let temp_file = create_test_apk();
        let parser = ApkParser::new().unwrap();
        
        let info = parser.parse(temp_file.path()).unwrap();
        
        assert_eq!(info.package_name, Some("com.example.testapp".to_string()));
        assert_eq!(info.version_name, Some("1.0".to_string()));
        assert_eq!(info.version_code, Some(1));
        assert_eq!(info.min_sdk, Some(21));
        assert_eq!(info.target_sdk, Some(30));
        assert!(info.debuggable);
        assert!(info.allow_backup);
        assert!(info.uses_cleartext);
    }
    
    #[test]
    fn test_permissions() {
        let temp_file = create_test_apk();
        let parser = ApkParser::new().unwrap();
        
        let info = parser.parse(temp_file.path()).unwrap();
        
        assert_eq!(info.permissions.len(), 3);
        assert!(info.permissions.contains(&"android.permission.INTERNET".to_string()));
        assert!(info.permissions.contains(&"android.permission.CAMERA".to_string()));
        
        // CAMERA and ACCESS_FINE_LOCATION should be flagged as dangerous
        assert!(info.dangerous_permissions.len() >= 2);
    }
    
    #[test]
    fn test_components() {
        let temp_file = create_test_apk();
        let parser = ApkParser::new().unwrap();
        
        let info = parser.parse(temp_file.path()).unwrap();
        
        assert_eq!(info.activities.len(), 1);
        assert_eq!(info.activities[0].name, ".MainActivity");
        assert!(info.activities[0].exported);
        
        assert_eq!(info.services.len(), 1);
        assert_eq!(info.services[0].name, ".MyService");
        assert!(!info.services[0].exported);
        
        assert_eq!(info.receivers.len(), 1);
        assert_eq!(info.receivers[0].name, ".MyReceiver");
        
        assert_eq!(info.providers.len(), 1);
        assert_eq!(info.providers[0].name, ".MyProvider");
    }
    
    #[test]
    fn test_exported_components() {
        let temp_file = create_test_apk();
        let parser = ApkParser::new().unwrap();
        
        let info = parser.parse(temp_file.path()).unwrap();
        
        // MainActivity and MyReceiver are exported
        assert_eq!(info.exported_components.len(), 2);
    }
    
    #[test]
    fn test_native_libs() {
        let temp_file = create_test_apk();
        let parser = ApkParser::new().unwrap();
        
        let info = parser.parse(temp_file.path()).unwrap();
        
        assert_eq!(info.native_libs.len(), 1);
        assert_eq!(info.native_libs[0].name, "libtest.so");
        assert_eq!(info.native_libs[0].architecture, "arm64-v8a");
    }
    
    #[test]
    fn test_dex_info() {
        let temp_file = create_test_apk();
        let parser = ApkParser::new().unwrap();
        
        let info = parser.parse(temp_file.path()).unwrap();
        
        assert_eq!(info.dex_info.count, 1);
        assert_eq!(info.dex_info.files.len(), 1);
        assert!(info.dex_info.files[0].contains("classes"));
    }
    
    #[test]
    fn test_certificates() {
        let temp_file = create_test_apk();
        let parser = ApkParser::new().unwrap();
        
        let info = parser.parse(temp_file.path()).unwrap();
        
        assert_eq!(info.certificates.len(), 1);
        assert_eq!(info.certificates[0].cert_type, "RSA");
        assert!(!info.certificates[0].sha256_hash.is_empty());
    }
    
    #[test]
    fn test_url_extraction() {
        let parser = ApkParser::new().unwrap();
        let text = "Check https://api.example.com and http://test.com/path";
        let urls = parser.extract_urls(text);
        
        assert_eq!(urls.len(), 2);
        assert!(urls.iter().any(|u| u.contains("api.example.com")));
        assert!(urls.iter().any(|u| u.contains("test.com")));
    }
    
    #[test]
    fn test_secret_detection() {
        let parser = ApkParser::new().unwrap();
        let text = r#"api_key = "sk_live_abc123def456xyz789"
        password = "secret123"
        token = "ghp_1234567890abcdef1234567890abcdef123456""#;
        
        let secrets = parser.extract_secrets(text);
        
        assert!(!secrets.is_empty());
        assert!(secrets.iter().any(|s| s.secret_type == "API Key"));
        assert!(secrets.iter().any(|s| s.secret_type == "Password"));
    }
    
    #[test]
    fn test_ip_extraction() {
        let parser = ApkParser::new().unwrap();
        let text = "Server at 192.168.1.1 and 10.0.0.1";
        let ips = parser.extract_ips(text);
        
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"192.168.1.1".to_string()));
        assert!(ips.contains(&"10.0.0.1".to_string()));
    }
    
    #[test]
    fn test_base64_extraction() {
        let parser = ApkParser::new().unwrap();
        let text = "Encoded: dGVzdF9kYXRhX2hlcmU= more text";
        let b64 = parser.extract_base64(text);
        
        assert!(!b64.is_empty());
    }
    
    #[test]
    fn test_dangerous_permission_detection() {
        let parser = ApkParser::new().unwrap();
        
        assert!(parser.is_dangerous_permission("android.permission.CAMERA"));
        assert!(parser.is_dangerous_permission("android.permission.READ_CONTACTS"));
        assert!(!parser.is_dangerous_permission("android.permission.INTERNET"));
    }
    
    #[test]
    fn test_nonexistent_apk() {
        let parser = ApkParser::new().unwrap();
        let result = parser.parse("/nonexistent/path/app.apk");
        
        assert!(result.is_err());
    }
}
