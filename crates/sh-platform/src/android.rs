//! Android Platform Adapter
//!
//! Production-ready adapter for analyzing Android applications (APK, AAB).
//! Extracts and parses AndroidManifest.xml, resources, DEX files, and native libraries.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, Write};
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use quick_xml::events::Event;
use quick_xml::Reader;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, instrument, trace, warn};
use zip::ZipArchive;

use crate::{
    PlatformAdapter, PlatformCapabilities, PlatformError, PlatformMetadata, PlatformResult,
    ParseResult, utils,
};
use sh_types::{AnalysisTarget, Platform};

/// Android-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidMetadata {
    /// Application package name
    pub package_name: String,
    /// Version code (internal version number)
    pub version_code: Option<String>,
    /// Version name (user-visible version)
    pub version_name: Option<String>,
    /// Minimum SDK version required
    pub min_sdk_version: Option<u32>,
    /// Target SDK version
    pub target_sdk_version: Option<u32>,
    /// Maximum SDK version
    pub max_sdk_version: Option<u32>,
    /// Application label/name
    pub application_label: Option<String>,
    /// Main activity name
    pub main_activity: Option<String>,
    /// Permissions declared
    pub permissions: Vec<String>,
    /// Dangerous permissions (runtime permissions)
    pub dangerous_permissions: Vec<String>,
    /// Activities declared
    pub activities: Vec<ActivityInfo>,
    /// Services declared
    pub services: Vec<ServiceInfo>,
    /// Receivers declared
    pub receivers: Vec<ReceiverInfo>,
    /// Providers declared
    pub providers: Vec<ProviderInfo>,
    /// Native libraries (JNI)
    pub native_libraries: Vec<String>,
    /// Supported architectures
    pub architectures: Vec<String>,
    /// Debuggable flag
    pub debuggable: bool,
    /// Allow backup flag
    pub allow_backup: bool,
    /// Uses cleartext traffic
    pub uses_cleartext_traffic: bool,
    /// Network security config
    pub network_security_config: Option<String>,
    /// App components exported
    pub exported_components: Vec<String>,
    /// Deep links/URL schemes
    pub deep_links: Vec<String>,
}

impl AndroidMetadata {
    /// Create new Android metadata
    pub fn new(package_name: impl Into<String>) -> Self {
        Self {
            package_name: package_name.into(),
            version_code: None,
            version_name: None,
            min_sdk_version: None,
            target_sdk_version: None,
            max_sdk_version: None,
            application_label: None,
            main_activity: None,
            permissions: Vec::new(),
            dangerous_permissions: Vec::new(),
            activities: Vec::new(),
            services: Vec::new(),
            receivers: Vec::new(),
            providers: Vec::new(),
            native_libraries: Vec::new(),
            architectures: Vec::new(),
            debuggable: false,
            allow_backup: true,
            uses_cleartext_traffic: false,
            network_security_config: None,
            exported_components: Vec::new(),
            deep_links: Vec::new(),
        }
    }
}

/// Activity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityInfo {
    pub name: String,
    pub exported: bool,
    pub permission: Option<String>,
    pub intent_filters: Vec<IntentFilter>,
}

/// Service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub exported: bool,
    pub permission: Option<String>,
    pub intent_filters: Vec<IntentFilter>,
}

/// Broadcast receiver information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverInfo {
    pub name: String,
    pub exported: bool,
    pub permission: Option<String>,
    pub intent_filters: Vec<IntentFilter>,
}

/// Content provider information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub name: String,
    pub authority: String,
    pub exported: bool,
    pub read_permission: Option<String>,
    pub write_permission: Option<String>,
}

/// Intent filter information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data_schemes: Vec<String>,
    pub data_hosts: Vec<String>,
    pub data_paths: Vec<String>,
}

impl IntentFilter {
    pub fn new() -> Self {
        Self {
            actions: Vec::new(),
            categories: Vec::new(),
            data_schemes: Vec::new(),
            data_hosts: Vec::new(),
            data_paths: Vec::new(),
        }
    }

    pub fn is_launcher(&self) -> bool {
        self.actions.contains("android.intent.action.MAIN")
            && self.categories.contains("android.intent.category.LAUNCHER")
    }

    pub fn has_deep_link(&self) -> bool {
        !self.data_schemes.is_empty() && !self.data_hosts.is_empty()
    }
}

/// Android platform adapter
pub struct AndroidAdapter {
    capabilities: PlatformCapabilities,
}

impl AndroidAdapter {
    /// Create a new Android adapter
    pub fn new() -> Self {
        Self {
            capabilities: PlatformCapabilities::android(),
        }
    }

    /// Parse AndroidManifest.xml from bytes
    fn parse_manifest(&self, manifest_data: &[u8]) -> PlatformResult<AndroidMetadata> {
        let mut reader = Reader::from_reader(manifest_data);
        reader.trim_text(true);

        let mut manifest = AndroidMetadata::new("unknown");
        let mut buf = Vec::new();
        let mut current_component: Option<String> = None;
        let mut current_intent_filter: Option<IntentFilter> = None;
        let mut in_application = false;
        let mut in_activity = false;
        let mut in_service = false;
        let mut in_receiver = false;
        let mut in_provider = false;
        let mut in_intent_filter = false;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref());
                    match name.as_ref() {
                        "manifest" => {
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    let key = String::from_utf8_lossy(attr.key.as_ref());
                                    let value = String::from_utf8_lossy(&attr.value);
                                    match key.as_ref() {
                                        "package" => manifest.package_name = value.to_string(),
                                        "android:versionCode" => {
                                            manifest.version_code = Some(value.to_string())
                                        }
                                        "android:versionName" => {
                                            manifest.version_name = Some(value.to_string())
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        "uses-sdk" => {
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    let key = String::from_utf8_lossy(attr.key.as_ref());
                                    let value = String::from_utf8_lossy(&attr.value);
                                    match key.as_ref() {
                                        "android:minSdkVersion" => {
                                            manifest.min_sdk_version =
                                                value.parse().ok()
                                        }
                                        "android:targetSdkVersion" => {
                                            manifest.target_sdk_version =
                                                value.parse().ok()
                                        }
                                        "android:maxSdkVersion" => {
                                            manifest.max_sdk_version =
                                                value.parse().ok()
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        "uses-permission" => {
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    let key = String::from_utf8_lossy(attr.key.as_ref());
                                    let value = String::from_utf8_lossy(&attr.value);
                                    if key == "android:name" {
                                        manifest.permissions.push(value.to_string());
                                        if Self::is_dangerous_permission(&value) {
                                            manifest.dangerous_permissions.push(value.to_string());
                                        }
                                    }
                                }
                            }
                        }
                        "application" => {
                            in_application = true;
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    let key = String::from_utf8_lossy(attr.key.as_ref());
                                    let value = String::from_utf8_lossy(&attr.value);
                                    match key.as_ref() {
                                        "android:label" => {
                                            manifest.application_label = Some(value.to_string())
                                        }
                                        "android:debuggable" => {
                                            manifest.debuggable = value == "true"
                                        }
                                        "android:allowBackup" => {
                                            manifest.allow_backup = value != "false"
                                        }
                                        "android:usesCleartextTraffic" => {
                                            manifest.uses_cleartext_traffic = value == "true"
                                        }
                                        "android:networkSecurityConfig" => {
                                            manifest.network_security_config = Some(value.to_string())
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        "activity" => {
                            in_activity = true;
                            let mut activity = ActivityInfo {
                                name: String::new(),
                                exported: false,
                                permission: None,
                                intent_filters: Vec::new(),
                            };
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    let key = String::from_utf8_lossy(attr.key.as_ref());
                                    let value = String::from_utf8_lossy(&attr.value);
                                    match key.as_ref() {
                                        "android:name" => activity.name = value.to_string(),
                                        "android:exported" => {
                                            activity.exported = value == "true"
                                        }
                                        "android:permission" => {
                                            activity.permission = Some(value.to_string())
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            current_component = Some(activity.name.clone());
                            if activity.exported {
                                manifest.exported_components.push(format!(
                                    "activity:{}",
                                    activity.name
                                ));
                            }
                            manifest.activities.push(activity);
                        }
                        "service" => {
                            in_service = true;
                            let mut service = ServiceInfo {
                                name: String::new(),
                                exported: false,
                                permission: None,
                                intent_filters: Vec::new(),
                            };
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    let key = String::from_utf8_lossy(attr.key.as_ref());
                                    let value = String::from_utf8_lossy(&attr.value);
                                    match key.as_ref() {
                                        "android:name" => service.name = value.to_string(),
                                        "android:exported" => {
                                            service.exported = value == "true"
                                        }
                                        "android:permission" => {
                                            service.permission = Some(value.to_string())
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            current_component = Some(service.name.clone());
                            if service.exported {
                                manifest.exported_components.push(format!(
                                    "service:{}",
                                    service.name
                                ));
                            }
                            manifest.services.push(service);
                        }
                        "receiver" => {
                            in_receiver = true;
                            let mut receiver = ReceiverInfo {
                                name: String::new(),
                                exported: false,
                                permission: None,
                                intent_filters: Vec::new(),
                            };
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    let key = String::from_utf8_lossy(attr.key.as_ref());
                                    let value = String::from_utf8_lossy(&attr.value);
                                    match key.as_ref() {
                                        "android:name" => receiver.name = value.to_string(),
                                        "android:exported" => {
                                            receiver.exported = value == "true"
                                        }
                                        "android:permission" => {
                                            receiver.permission = Some(value.to_string())
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            current_component = Some(receiver.name.clone());
                            if receiver.exported {
                                manifest.exported_components.push(format!(
                                    "receiver:{}",
                                    receiver.name
                                ));
                            }
                            manifest.receivers.push(receiver);
                        }
                        "provider" => {
                            in_provider = true;
                            let mut provider = ProviderInfo {
                                name: String::new(),
                                authority: String::new(),
                                exported: false,
                                read_permission: None,
                                write_permission: None,
                            };
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    let key = String::from_utf8_lossy(attr.key.as_ref());
                                    let value = String::from_utf8_lossy(&attr.value);
                                    match key.as_ref() {
                                        "android:name" => provider.name = value.to_string(),
                                        "android:authorities" => {
                                            provider.authority = value.to_string()
                                        }
                                        "android:exported" => {
                                            provider.exported = value == "true"
                                        }
                                        "android:readPermission" => {
                                            provider.read_permission = Some(value.to_string())
                                        }
                                        "android:writePermission" => {
                                            provider.write_permission = Some(value.to_string())
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            current_component = Some(provider.name.clone());
                            if provider.exported {
                                manifest.exported_components.push(format!(
                                    "provider:{}",
                                    provider.name
                                ));
                            }
                            manifest.providers.push(provider);
                        }
                        "intent-filter" => {
                            in_intent_filter = true;
                            current_intent_filter = Some(IntentFilter::new());
                        }
                        "action" => {
                            if in_intent_filter {
                                for attr in e.attributes() {
                                    if let Ok(attr) = attr {
                                        let key = String::from_utf8_lossy(attr.key.as_ref());
                                        let value = String::from_utf8_lossy(&attr.value);
                                        if key == "android:name" {
                                            if let Some(ref mut filter) = current_intent_filter {
                                                filter.actions.push(value.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        "category" => {
                            if in_intent_filter {
                                for attr in e.attributes() {
                                    if let Ok(attr) = attr {
                                        let key = String::from_utf8_lossy(attr.key.as_ref());
                                        let value = String::from_utf8_lossy(&attr.value);
                                        if key == "android:name" {
                                            if let Some(ref mut filter) = current_intent_filter {
                                                filter.categories.push(value.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        "data" => {
                            if in_intent_filter {
                                for attr in e.attributes() {
                                    if let Ok(attr) = attr {
                                        let key = String::from_utf8_lossy(attr.key.as_ref());
                                        let value = String::from_utf8_lossy(&attr.value);
                                        if let Some(ref mut filter) = current_intent_filter {
                                            match key.as_ref() {
                                                "android:scheme" => {
                                                    filter.data_schemes.push(value.to_string())
                                                }
                                                "android:host" => {
                                                    filter.data_hosts.push(value.to_string())
                                                }
                                                "android:path" | "android:pathPrefix"
                                                | "android:pathPattern" => {
                                                    filter.data_paths.push(value.to_string())
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::End(e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref());
                    match name.as_ref() {
                        "intent-filter" => {
                            if in_intent_filter {
                                if let Some(filter) = current_intent_filter.take() {
                                    if filter.is_launcher() {
                                        if let Some(ref component) = current_component {
                                            manifest.main_activity = Some(component.clone());
                                        }
                                    }
                                    if filter.has_deep_link() {
                                        for scheme in &filter.data_schemes {
                                            for host in &filter.data_hosts {
                                                manifest.deep_links.push(format!(
                                                    "{}://{}",
                                                    scheme, host
                                                ));
                                            }
                                        }
                                    }
                                    // Add intent filter to current component
                                    if in_activity && !manifest.activities.is_empty() {
                                        let idx = manifest.activities.len() - 1;
                                        manifest.activities[idx].intent_filters.push(filter);
                                    } else if in_service && !manifest.services.is_empty() {
                                        let idx = manifest.services.len() - 1;
                                        manifest.services[idx].intent_filters.push(filter);
                                    } else if in_receiver && !manifest.receivers.is_empty() {
                                        let idx = manifest.receivers.len() - 1;
                                        manifest.receivers[idx].intent_filters.push(filter);
                                    }
                                }
                                in_intent_filter = false;
                            }
                        }
                        "activity" => {
                            in_activity = false;
                            current_component = None;
                        }
                        "service" => {
                            in_service = false;
                            current_component = None;
                        }
                        "receiver" => {
                            in_receiver = false;
                            current_component = None;
                        }
                        "provider" => {
                            in_provider = false;
                            current_component = None;
                        }
                        "application" => {
                            in_application = false;
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    warn!("Error parsing manifest XML: {}", e);
                    break;
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(manifest)
    }

    /// Check if a permission is dangerous (requires runtime permission)
    fn is_dangerous_permission(permission: &str) -> bool {
        let dangerous = [
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.GET_ACCOUNTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.ADD_VOICEMAIL",
            "android.permission.USE_SIP",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.BODY_SENSORS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_WAP_PUSH",
            "android.permission.RECEIVE_MMS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        ];
        dangerous.iter().any(|&p| permission.starts_with(p))
    }

    /// Detect native libraries and architectures
    fn detect_native_libs(&self, archive: &mut ZipArchive<File>) -> Vec<String> {
        let mut architectures = Vec::new();
        let mut native_libs = Vec::new();

        for i in 0..archive.len() {
            if let Ok(file) = archive.by_index(i) {
                let name = file.name();
                if name.starts_with("lib/") {
                    let parts: Vec<&str> = name.split('/').collect();
                    if parts.len() >= 2 {
                        let arch = parts[1];
                        if !architectures.contains(&arch.to_string()) {
                            architectures.push(arch.to_string());
                        }
                    }
                    if name.ends_with(".so") {
                        native_libs.push(name.to_string());
                    }
                }
            }
        }

        native_libs
    }

    /// Extract DEX files from APK
    fn extract_dex_files(
        &self,
        archive: &mut ZipArchive<File>,
        output_dir: &Path,
    ) -> PlatformResult<Vec<PathBuf>> {
        let mut dex_files = Vec::new();

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let name = file.name();

            if name.ends_with(".dex") || name.starts_with("classes") && name.ends_with(".dex") {
                let output_path = output_dir.join(name);
                if let Some(parent) = output_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                let mut output_file = File::create(&output_path)?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                output_file.write_all(&buffer)?;

                dex_files.push(output_path);
                debug!("Extracted DEX file: {}", name);
            }
        }

        Ok(dex_files)
    }

    /// Extract resources from APK
    fn extract_resources(
        &self,
        archive: &mut ZipArchive<File>,
        output_dir: &Path,
    ) -> PlatformResult<Vec<PathBuf>> {
        let mut resources = Vec::new();

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let name = file.name();

            // Extract AndroidManifest.xml and resource files
            if name == "AndroidManifest.xml"
                || name.starts_with("res/")
                || name.starts_with("assets/")
                || name.starts_with("META-INF/")
            {
                let output_path = output_dir.join(name);
                if let Some(parent) = output_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                let mut output_file = File::create(&output_path)?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer)?;
                output_file.write_all(&buffer)?;

                resources.push(output_path);
            }
        }

        Ok(resources)
    }
}

impl Default for AndroidAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PlatformAdapter for AndroidAdapter {
    fn platform(&self) -> Platform {
        Platform::Android
    }

    fn capabilities(&self) -> PlatformCapabilities {
        self.capabilities.clone()
    }

    fn can_handle(&self, target: &AnalysisTarget) -> bool {
        target.platform == Platform::Android
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
            )));
        }

        // Check if it's a valid ZIP/APK
        if let Ok(file) = File::open(path) {
            if ZipArchive::new(file).is_err() {
                return Err(PlatformError::InvalidFormat(
                    "Not a valid APK/AAB file".to_string(),
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

        // Extract and parse AndroidManifest.xml
        let manifest_data = if let Ok(mut manifest_file) = archive.by_name("AndroidManifest.xml")
        {
            let mut data = Vec::new();
            manifest_file.read_to_end(&mut data)?;
            data
        } else {
            return Err(PlatformError::ParseError(
                "AndroidManifest.xml not found".to_string(),
            ));
        };

        // Parse manifest
        let android_metadata = self.parse_manifest(&manifest_data)?;

        // Build platform metadata
        let metadata = PlatformMetadata::new(Platform::Android)
            .with_name(&android_metadata.application_label.as_deref().unwrap_or("Unknown"))
            .with_version(android_metadata.version_name.as_deref().unwrap_or("unknown"))
            .with_package_id(&android_metadata.package_name)
            .with_target_version(
                android_metadata
                    .target_sdk_version
                    .map(|v| v.to_string())
                    .as_deref()
                    .unwrap_or("unknown"),
            )
            .with_min_version(
                android_metadata
                    .min_sdk_version
                    .map(|v| v.to_string())
                    .as_deref()
                    .unwrap_or("unknown"),
            )
            .with_file_size(utils::get_file_size(path)?)
            .with_checksum(utils::calculate_checksum(path)?);

        // Detect native libraries
        let native_libs = self.detect_native_libs(&mut archive);

        // Create parse result
        let mut result = ParseResult::new(&target.path, metadata)
            .add_config_file("AndroidManifest.xml");

        // Add DEX files as entry points
        for i in 0..archive.len() {
            if let Ok(file) = archive.by_index(i) {
                let name = file.name();
                if name.ends_with(".dex") {
                    result = result.add_entry_point(name);
                    result = result.add_binary_file(name);
                } else if name.ends_with(".so") {
                    result = result.add_binary_file(name);
                }
            }
        }

        // Add Android-specific metadata as extra
        let android_json = serde_json::to_value(&android_metadata)?;
        result.metadata.extra.insert("android".to_string(), android_json);

        info!(
            "Parsed Android APK: {} v{} ({} permissions, {} activities)",
            android_metadata.package_name,
            android_metadata.version_name.as_deref().unwrap_or("unknown"),
            android_metadata.permissions.len(),
            android_metadata.activities.len()
        );

        Ok(result)
    }

    #[instrument(skip(self, target, output_dir))]
    async fn extract(&self, target: &AnalysisTarget, output_dir: &Path) -> PlatformResult<PathBuf> {
        let path = Path::new(&target.path);
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)?;

        // Create extraction directory
        let extract_dir = utils::create_work_dir(output_dir, "android")?;

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

        info!("Extracted Android APK to: {}", extract_dir.display());
        Ok(extract_dir)
    }

    fn analysis_config(&self) -> serde_json::Value {
        serde_json::json!({
            "platform": "android",
            "static_analysis": {
                "dex_analysis": true,
                "manifest_analysis": true,
                "resource_analysis": true,
                "native_lib_analysis": true,
            },
            "dynamic_analysis": {
                "instrumentation": true,
                "network_capture": true,
            },
            "check_categories": [
                "insecure_permissions",
                "exported_components",
                "hardcoded_secrets",
                "insecure_storage",
                "network_security",
                "crypto_misuse",
                "webview_vulnerabilities",
            ],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_apk() -> (TempDir, PathBuf) {
        let temp_dir = TempDir::new().unwrap();
        let apk_path = temp_dir.path().join("test.apk");

        // Create a minimal APK (ZIP file with AndroidManifest.xml)
        let file = File::create(&apk_path).unwrap();
        let mut zip = ZipArchive::new(file).unwrap();

        // Note: This is a simplified test. In production, you'd use real APK files
        // or create proper test fixtures with valid AndroidManifest.xml

        (temp_dir, apk_path)
    }

    #[test]
    fn test_android_adapter_creation() {
        let adapter = AndroidAdapter::new();
        assert_eq!(adapter.platform(), Platform::Android);
        assert!(adapter.capabilities().static_analysis);
    }

    #[test]
    fn test_is_dangerous_permission() {
        assert!(AndroidAdapter::is_dangerous_permission(
            "android.permission.CAMERA"
        ));
        assert!(AndroidAdapter::is_dangerous_permission(
            "android.permission.READ_CONTACTS"
        ));
        assert!(!AndroidAdapter::is_dangerous_permission(
            "android.permission.INTERNET"
        ));
    }

    #[test]
    fn test_intent_filter() {
        let mut filter = IntentFilter::new();
        filter.actions.push("android.intent.action.MAIN".to_string());
        filter.categories.push("android.intent.category.LAUNCHER".to_string());
        assert!(filter.is_launcher());
        assert!(!filter.has_deep_link());

        let mut filter2 = IntentFilter::new();
        filter2.data_schemes.push("https".to_string());
        filter2.data_hosts.push("example.com".to_string());
        assert!(!filter2.is_launcher());
        assert!(filter2.has_deep_link());
    }

    #[test]
    fn test_parse_manifest_basic() {
        let adapter = AndroidAdapter::new();

        // Minimal AndroidManifest.xml
        let manifest_xml = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.test.app"
    android:versionCode="1"
    android:versionName="1.0.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="33" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />
    <application android:label="TestApp" android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>"#;

        let result = adapter.parse_manifest(manifest_xml.as_bytes());
        assert!(result.is_ok());

        let metadata = result.unwrap();
        assert_eq!(metadata.package_name, "com.test.app");
        assert_eq!(metadata.version_code, Some("1".to_string()));
        assert_eq!(metadata.version_name, Some("1.0.0".to_string()));
        assert_eq!(metadata.min_sdk_version, Some(21));
        assert_eq!(metadata.target_sdk_version, Some(33));
        assert_eq!(metadata.application_label, Some("TestApp".to_string()));
        assert_eq!(metadata.main_activity, Some(".MainActivity".to_string()));
        assert!(metadata.debuggable);
        assert_eq!(metadata.permissions.len(), 2);
        assert_eq!(metadata.dangerous_permissions.len(), 1); // CAMERA
        assert_eq!(metadata.activities.len(), 1);
        assert_eq!(metadata.exported_components.len(), 1);
    }
}
