//! # AndroidManifest.xml Parser
//!
//! Parses AndroidManifest.xml files from APK archives.
//! Handles both binary XML (AXML) and plain text XML formats.

use crate::{Result, ToolsError};
use quick_xml::events::Event;
use quick_xml::Reader;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, instrument, trace, warn};

/// AndroidManifest.xml structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidManifest {
    /// Package name (e.g., com.example.app)
    pub package_name: String,

    /// Version code
    pub version_code: u32,

    /// Version name
    pub version_name: String,

    /// Minimum SDK version
    pub min_sdk_version: Option<u32>,

    /// Target SDK version
    pub target_sdk_version: Option<u32>,

    /// Maximum SDK version
    pub max_sdk_version: Option<u32>,

    /// Application information
    pub application: ApplicationInfo,

    /// Permissions declared
    pub permissions: Vec<Permission>,

    /// Permissions used
    pub uses_permissions: Vec<UsesPermission>,

    /// Activities
    pub activities: Vec<Activity>,

    /// Services
    pub services: Vec<Service>,

    /// Receivers
    pub receivers: Vec<Receiver>,

    /// Providers
    pub providers: Vec<Provider>,

    /// Intent filters
    pub intent_filters: Vec<IntentFilter>,

    /// Uses-features
    pub uses_features: Vec<UsesFeature>,

    /// Uses-libraries
    pub uses_libraries: Vec<UsesLibrary>,

    /// Debuggable flag
    pub debuggable: bool,

    /// Allow backup flag
    pub allow_backup: bool,

    /// Network security config
    pub network_security_config: Option<String>,

    /// Raw attributes
    pub raw_attributes: HashMap<String, String>,
}

impl Default for AndroidManifest {
    fn default() -> Self {
        Self {
            package_name: String::new(),
            version_code: 0,
            version_name: String::new(),
            min_sdk_version: None,
            target_sdk_version: None,
            max_sdk_version: None,
            application: ApplicationInfo::default(),
            permissions: Vec::new(),
            uses_permissions: Vec::new(),
            activities: Vec::new(),
            services: Vec::new(),
            receivers: Vec::new(),
            providers: Vec::new(),
            intent_filters: Vec::new(),
            uses_features: Vec::new(),
            uses_libraries: Vec::new(),
            debuggable: false,
            allow_backup: false,
            network_security_config: None,
            raw_attributes: HashMap::new(),
        }
    }
}

impl AndroidManifest {
    /// Check if the app is debuggable
    pub fn is_debuggable(&self) -> bool {
        self.debuggable
    }

    /// Check if the app allows backup
    pub fn allows_backup(&self) -> bool {
        self.allow_backup
    }

    /// Get dangerous permissions
    pub fn dangerous_permissions(&self) -> Vec<&UsesPermission> {
        self.uses_permissions
            .iter()
            .filter(|p| p.is_dangerous())
            .collect()
    }

    /// Check if app uses a specific permission
    pub fn uses_permission(&self, permission: &str) -> bool {
        self.uses_permissions.iter().any(|p| p.name == permission)
    }

    /// Get exported components
    pub fn exported_components(&self) -> Vec<ExportedComponent> {
        let mut components = Vec::new();

        for activity in &self.activities {
            if activity.exported {
                components.push(ExportedComponent::Activity(activity.clone()));
            }
        }
        for service in &self.services {
            if service.exported {
                components.push(ExportedComponent::Service(service.clone()));
            }
        }
        for receiver in &self.receivers {
            if receiver.exported {
                components.push(ExportedComponent::Receiver(receiver.clone()));
            }
        }
        for provider in &self.providers {
            if provider.exported {
                components.push(ExportedComponent::Provider(provider.clone()));
            }
        }

        components
    }

    /// Get components with intent filters
    pub fn components_with_intent_filters(&self) -> Vec<(String, Vec<IntentFilter>)> {
        let mut result = Vec::new();

        for activity in &self.activities {
            if !activity.intent_filters.is_empty() {
                result.push((activity.name.clone(), activity.intent_filters.clone()));
            }
        }
        for service in &self.services {
            if !service.intent_filters.is_empty() {
                result.push((service.name.clone(), service.intent_filters.clone()));
            }
        }
        for receiver in &self.receivers {
            if !receiver.intent_filters.is_empty() {
                result.push((receiver.name.clone(), receiver.intent_filters.clone()));
            }
        }

        result
    }
}

/// Application information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationInfo {
    /// Application name
    pub name: Option<String>,

    /// Application label
    pub label: Option<String>,

    /// Application icon
    pub icon: Option<String>,

    /// Theme
    pub theme: Option<String>,

    /// Task affinity
    pub task_affinity: Option<String>,

    /// Process name
    pub process: Option<String>,

    /// Backup agent
    pub backup_agent: Option<String>,

    /// Description
    pub description: Option<String>,

    /// Enabled
    pub enabled: bool,

    /// Persistent
    pub persistent: bool,

    /// Raw attributes
    pub raw_attributes: HashMap<String, String>,
}

impl Default for ApplicationInfo {
    fn default() -> Self {
        Self {
            name: None,
            label: None,
            icon: None,
            theme: None,
            task_affinity: None,
            process: None,
            backup_agent: None,
            description: None,
            enabled: true,
            persistent: false,
            raw_attributes: HashMap::new(),
        }
    }
}

/// Permission declaration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// Permission name
    pub name: String,

    /// Protection level
    pub protection_level: Option<String>,

    /// Permission group
    pub permission_group: Option<String>,

    /// Label
    pub label: Option<String>,

    /// Description
    pub description: Option<String>,
}

/// Permission usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsesPermission {
    /// Permission name
    pub name: String,

    /// Max SDK version
    pub max_sdk_version: Option<u32>,
}

impl UsesPermission {
    /// Check if this is a dangerous permission
    pub fn is_dangerous(&self) -> bool {
        DANGEROUS_PERMISSIONS.iter().any(|p| self.name.contains(p))
    }

    /// Check if this is a signature permission
    pub fn is_signature(&self) -> bool {
        self.name.contains("signature")
    }
}

/// Activity component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Activity {
    /// Activity name
    pub name: String,

    /// Exported flag
    pub exported: bool,

    /// Enabled flag
    pub enabled: bool,

    /// Permission required
    pub permission: Option<String>,

    /// Task affinity
    pub task_affinity: Option<String>,

    /// Launch mode
    pub launch_mode: Option<String>,

    /// Intent filters
    pub intent_filters: Vec<IntentFilter>,

    /// Raw attributes
    pub raw_attributes: HashMap<String, String>,
}

/// Service component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// Service name
    pub name: String,

    /// Exported flag
    pub exported: bool,

    /// Enabled flag
    pub enabled: bool,

    /// Permission required
    pub permission: Option<String>,

    /// Process
    pub process: Option<String>,

    /// Intent filters
    pub intent_filters: Vec<IntentFilter>,

    /// Raw attributes
    pub raw_attributes: HashMap<String, String>,
}

/// Receiver component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receiver {
    /// Receiver name
    pub name: String,

    /// Exported flag
    pub exported: bool,

    /// Enabled flag
    pub enabled: bool,

    /// Permission required
    pub permission: Option<String>,

    /// Process
    pub process: Option<String>,

    /// Intent filters
    pub intent_filters: Vec<IntentFilter>,

    /// Raw attributes
    pub raw_attributes: HashMap<String, String>,
}

/// Provider component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    /// Provider name
    pub name: String,

    /// Authority
    pub authorities: Vec<String>,

    /// Exported flag
    pub exported: bool,

    /// Enabled flag
    pub enabled: bool,

    /// Permission required
    pub permission: Option<String>,

    /// Read permission
    pub read_permission: Option<String>,

    /// Write permission
    pub write_permission: Option<String>,

    /// Grant URI permissions
    pub grant_uri_permissions: bool,

    /// Raw attributes
    pub raw_attributes: HashMap<String, String>,
}

/// Intent filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentFilter {
    /// Actions
    pub actions: Vec<String>,

    /// Categories
    pub categories: Vec<String>,

    /// Data schemes
    pub data_schemes: Vec<String>,

    /// Data hosts
    pub data_hosts: Vec<String>,

    /// Data paths
    pub data_paths: Vec<String>,

    /// Data mime types
    pub data_mime_types: Vec<String>,

    /// Priority
    pub priority: Option<i32>,
}

impl Default for IntentFilter {
    fn default() -> Self {
        Self {
            actions: Vec::new(),
            categories: Vec::new(),
            data_schemes: Vec::new(),
            data_hosts: Vec::new(),
            data_paths: Vec::new(),
            data_mime_types: Vec::new(),
            priority: None,
        }
    }
}

/// Uses-feature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsesFeature {
    /// Feature name
    pub name: String,

    /// Required
    pub required: bool,
}

/// Uses-library
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsesLibrary {
    /// Library name
    pub name: String,

    /// Required
    pub required: bool,
}

/// Uses-sdk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsesSdk {
    /// Minimum SDK version
    pub min_sdk_version: Option<u32>,

    /// Target SDK version
    pub target_sdk_version: Option<u32>,

    /// Maximum SDK version
    pub max_sdk_version: Option<u32>,
}

/// Exported component wrapper
#[derive(Debug, Clone)]
pub enum ExportedComponent {
    Activity(Activity),
    Service(Service),
    Receiver(Receiver),
    Provider(Provider),
}

/// Manifest analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestAnalysis {
    /// Security issues found
    pub issues: Vec<ManifestIssue>,

    /// Security score (0-100)
    pub security_score: u32,

    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Manifest security issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestIssue {
    /// Issue type
    pub issue_type: String,

    /// Severity
    pub severity: String,

    /// Description
    pub description: String,

    /// Component affected
    pub component: Option<String>,

    /// CWE ID
    pub cwe_id: Option<String>,
}

/// Dangerous permissions list
const DANGEROUS_PERMISSIONS: &[&str] = &[
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
];

/// Parse AndroidManifest.xml from bytes
#[instrument(skip(data))]
pub fn parse_manifest(data: &[u8]) -> Result<AndroidManifest> {
    trace!("Parsing AndroidManifest.xml ({} bytes)", data.len());

    // Check if it's binary XML (AXML)
    if is_binary_xml(data) {
        debug!("Detected binary XML format");
        parse_binary_manifest(data)
    } else {
        debug!("Detected text XML format");
        parse_text_manifest(data)
    }
}

/// Check if data is binary XML
fn is_binary_xml(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == b"\x03\x00\x08\x00"
}

/// Parse text XML manifest
#[instrument(skip(data))]
fn parse_text_manifest(data: &[u8]) -> Result<AndroidManifest> {
    let xml_str = String::from_utf8(data.to_vec())
        .map_err(|e| ToolsError::XmlParsing(format!("Invalid UTF-8: {}", e)))?;

    let mut reader = Reader::from_str(&xml_str);
    reader.trim_text(true);

    let mut manifest = AndroidManifest::default();
    let mut buf = Vec::new();
    let mut current_element = String::new();
    let mut current_activity: Option<Activity> = None;
    let mut current_service: Option<Service> = None;
    let mut current_receiver: Option<Receiver> = None;
    let mut current_provider: Option<Provider> = None;
    let mut current_intent_filter: Option<IntentFilter> = None;
    let mut current_permission: Option<Permission> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let name = std::str::from_utf8(e.name().as_ref())
                    .unwrap_or("")
                    .to_string();
                current_element = name.clone();

                match name.as_str() {
                    "manifest" => {
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                match key.as_str() {
                                    "package" => manifest.package_name = value,
                                    "android:versionCode" => {
                                        manifest.version_code = value.parse().unwrap_or(0)
                                    }
                                    "android:versionName" => manifest.version_name = value,
                                    _ => {
                                        manifest.raw_attributes.insert(key, value);
                                    }
                                }
                            }
                        }
                    }
                    "uses-sdk" => {
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                match key.as_str() {
                                    "android:minSdkVersion" => {
                                        manifest.min_sdk_version = value.parse().ok()
                                    }
                                    "android:targetSdkVersion" => {
                                        manifest.target_sdk_version = value.parse().ok()
                                    }
                                    "android:maxSdkVersion" => {
                                        manifest.max_sdk_version = value.parse().ok()
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    "application" => {
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                match key.as_str() {
                                    "android:name" => manifest.application.name = Some(value),
                                    "android:label" => manifest.application.label = Some(value),
                                    "android:icon" => manifest.application.icon = Some(value),
                                    "android:theme" => manifest.application.theme = Some(value),
                                    "android:taskAffinity" => {
                                        manifest.application.task_affinity = Some(value)
                                    }
                                    "android:process" => manifest.application.process = Some(value),
                                    "android:backupAgent" => {
                                        manifest.application.backup_agent = Some(value)
                                    }
                                    "android:description" => {
                                        manifest.application.description = Some(value)
                                    }
                                    "android:enabled" => {
                                        manifest.application.enabled = value == "true"
                                    }
                                    "android:persistent" => {
                                        manifest.application.persistent = value == "true"
                                    }
                                    "android:debuggable" => {
                                        manifest.debuggable = value == "true"
                                    }
                                    "android:allowBackup" => {
                                        manifest.allow_backup = value == "true"
                                    }
                                    "android:networkSecurityConfig" => {
                                        manifest.network_security_config = Some(value)
                                    }
                                    _ => {
                                        manifest.application.raw_attributes.insert(key, value);
                                    }
                                }
                            }
                        }
                    }
                    "uses-permission" => {
                        let mut perm = UsesPermission {
                            name: String::new(),
                            max_sdk_version: None,
                        };
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                match key.as_str() {
                                    "android:name" => perm.name = value,
                                    "android:maxSdkVersion" => {
                                        perm.max_sdk_version = value.parse().ok()
                                    }
                                    _ => {}
                                }
                            }
                        }
                        if !perm.name.is_empty() {
                            manifest.uses_permissions.push(perm);
                        }
                    }
                    "permission" => {
                        current_permission = Some(Permission {
                            name: String::new(),
                            protection_level: None,
                            permission_group: None,
                            label: None,
                            description: None,
                        });
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                if let Some(ref mut perm) = current_permission {
                                    match key.as_str() {
                                        "android:name" => perm.name = value,
                                        "android:protectionLevel" => {
                                            perm.protection_level = Some(value)
                                        }
                                        "android:permissionGroup" => {
                                            perm.permission_group = Some(value)
                                        }
                                        "android:label" => perm.label = Some(value),
                                        "android:description" => perm.description = Some(value),
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                    "activity" => {
                        current_activity = Some(Activity {
                            name: String::new(),
                            exported: false,
                            enabled: true,
                            permission: None,
                            task_affinity: None,
                            launch_mode: None,
                            intent_filters: Vec::new(),
                            raw_attributes: HashMap::new(),
                        });
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                if let Some(ref mut activity) = current_activity {
                                    match key.as_str() {
                                        "android:name" => activity.name = value,
                                        "android:exported" => {
                                            activity.exported = value == "true"
                                        }
                                        "android:enabled" => {
                                            activity.enabled = value == "true"
                                        }
                                        "android:permission" => {
                                            activity.permission = Some(value)
                                        }
                                        "android:taskAffinity" => {
                                            activity.task_affinity = Some(value)
                                        }
                                        "android:launchMode" => {
                                            activity.launch_mode = Some(value)
                                        }
                                        _ => {
                                            activity.raw_attributes.insert(key, value);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "service" => {
                        current_service = Some(Service {
                            name: String::new(),
                            exported: false,
                            enabled: true,
                            permission: None,
                            process: None,
                            intent_filters: Vec::new(),
                            raw_attributes: HashMap::new(),
                        });
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                if let Some(ref mut service) = current_service {
                                    match key.as_str() {
                                        "android:name" => service.name = value,
                                        "android:exported" => {
                                            service.exported = value == "true"
                                        }
                                        "android:enabled" => {
                                            service.enabled = value == "true"
                                        }
                                        "android:permission" => {
                                            service.permission = Some(value)
                                        }
                                        "android:process" => service.process = Some(value),
                                        _ => {
                                            service.raw_attributes.insert(key, value);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "receiver" => {
                        current_receiver = Some(Receiver {
                            name: String::new(),
                            exported: false,
                            enabled: true,
                            permission: None,
                            process: None,
                            intent_filters: Vec::new(),
                            raw_attributes: HashMap::new(),
                        });
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                if let Some(ref mut receiver) = current_receiver {
                                    match key.as_str() {
                                        "android:name" => receiver.name = value,
                                        "android:exported" => {
                                            receiver.exported = value == "true"
                                        }
                                        "android:enabled" => {
                                            receiver.enabled = value == "true"
                                        }
                                        "android:permission" => {
                                            receiver.permission = Some(value)
                                        }
                                        "android:process" => receiver.process = Some(value),
                                        _ => {
                                            receiver.raw_attributes.insert(key, value);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "provider" => {
                        current_provider = Some(Provider {
                            name: String::new(),
                            authorities: Vec::new(),
                            exported: false,
                            enabled: true,
                            permission: None,
                            read_permission: None,
                            write_permission: None,
                            grant_uri_permissions: false,
                            raw_attributes: HashMap::new(),
                        });
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                if let Some(ref mut provider) = current_provider {
                                    match key.as_str() {
                                        "android:name" => provider.name = value,
                                        "android:authorities" => {
                                            provider.authorities =
                                                value.split(';').map(|s| s.to_string()).collect()
                                        }
                                        "android:exported" => {
                                            provider.exported = value == "true"
                                        }
                                        "android:enabled" => {
                                            provider.enabled = value == "true"
                                        }
                                        "android:permission" => {
                                            provider.permission = Some(value)
                                        }
                                        "android:readPermission" => {
                                            provider.read_permission = Some(value)
                                        }
                                        "android:writePermission" => {
                                            provider.write_permission = Some(value)
                                        }
                                        "android:grantUriPermissions" => {
                                            provider.grant_uri_permissions = value == "true"
                                        }
                                        _ => {
                                            provider.raw_attributes.insert(key, value);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "intent-filter" => {
                        current_intent_filter = Some(IntentFilter::default());
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                if let Some(ref mut filter) = current_intent_filter {
                                    if key == "android:priority" {
                                        filter.priority = value.parse().ok();
                                    }
                                }
                            }
                        }
                    }
                    "action" => {
                        if let Some(ref mut filter) = current_intent_filter {
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
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
                    }
                    "category" => {
                        if let Some(ref mut filter) = current_intent_filter {
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
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
                    }
                    "data" => {
                        if let Some(ref mut filter) = current_intent_filter {
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    let key = std::str::from_utf8(&attr.key.as_ref())
                                        .unwrap_or("")
                                        .to_string();
                                    let value = attr.unescape_value()
                                        .unwrap_or_default()
                                        .to_string();

                                    match key.as_str() {
                                        "android:scheme" => filter.data_schemes.push(value),
                                        "android:host" => filter.data_hosts.push(value),
                                        "android:path" | "android:pathPrefix" | "android:pathPattern" => {
                                            filter.data_paths.push(value)
                                        }
                                        "android:mimeType" => filter.data_mime_types.push(value),
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                    "uses-feature" => {
                        let mut feature = UsesFeature {
                            name: String::new(),
                            required: true,
                        };
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                match key.as_str() {
                                    "android:name" => feature.name = value,
                                    "android:required" => feature.required = value == "true",
                                    _ => {}
                                }
                            }
                        }
                        if !feature.name.is_empty() {
                            manifest.uses_features.push(feature);
                        }
                    }
                    "uses-library" => {
                        let mut library = UsesLibrary {
                            name: String::new(),
                            required: true,
                        };
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                match key.as_str() {
                                    "android:name" => library.name = value,
                                    "android:required" => library.required = value == "true",
                                    _ => {}
                                }
                            }
                        }
                        if !library.name.is_empty() {
                            manifest.uses_libraries.push(library);
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
                        if let Some(activity) = current_activity.take() {
                            if !activity.name.is_empty() {
                                manifest.activities.push(activity);
                            }
                        }
                    }
                    "service" => {
                        if let Some(service) = current_service.take() {
                            if !service.name.is_empty() {
                                manifest.services.push(service);
                            }
                        }
                    }
                    "receiver" => {
                        if let Some(receiver) = current_receiver.take() {
                            if !receiver.name.is_empty() {
                                manifest.receivers.push(receiver);
                            }
                        }
                    }
                    "provider" => {
                        if let Some(provider) = current_provider.take() {
                            if !provider.name.is_empty() {
                                manifest.providers.push(provider);
                            }
                        }
                    }
                    "intent-filter" => {
                        if let Some(filter) = current_intent_filter.take() {
                            // Attach to current component
                            if let Some(ref mut activity) = current_activity {
                                activity.intent_filters.push(filter);
                            } else if let Some(ref mut service) = current_service {
                                service.intent_filters.push(filter);
                            } else if let Some(ref mut receiver) = current_receiver {
                                receiver.intent_filters.push(filter);
                            } else {
                                manifest.intent_filters.push(filter);
                            }
                        }
                    }
                    "permission" => {
                        if let Some(perm) = current_permission.take() {
                            if !perm.name.is_empty() {
                                manifest.permissions.push(perm);
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                error!("XML parsing error: {}", e);
                return Err(ToolsError::XmlParsing(format!("XML error: {}", e)));
            }
            _ => {}
        }
        buf.clear();
    }

    debug!("Parsed manifest for package: {}", manifest.package_name);
    Ok(manifest)
}

/// Parse binary XML manifest (AXML)
#[instrument(skip(data))]
fn parse_binary_manifest(data: &[u8]) -> Result<AndroidManifest> {
    // Binary XML parsing is complex and would require a full AXML parser
    // For now, we'll return an error indicating binary XML is not fully supported
    // In a production implementation, you would use a library like android-manifest
    // or implement a proper AXML parser
    warn!("Binary XML parsing not fully implemented");

    // Try to extract basic information from the binary XML
    let mut manifest = AndroidManifest::default();

    // Extract package name from binary XML (usually at a known offset)
    if data.len() > 100 {
        // Look for package name pattern
        if let Ok(text) = String::from_utf8(data[50..150].to_vec()) {
            // Try to find package name
            for line in text.lines() {
                if line.contains('.') && !line.contains(' ') {
                    manifest.package_name = line.trim().to_string();
                    break;
                }
            }
        }
    }

    // If we couldn't extract meaningful data, return an error
    if manifest.package_name.is_empty() {
        return Err(ToolsError::XmlParsing(
            "Binary XML parsing not fully implemented. Please use a tool to convert AXML to text XML.".to_string(),
        ));
    }

    Ok(manifest)
}

/// Analyze manifest for security issues
#[instrument(skip(manifest))]
pub fn analyze_manifest(manifest: &AndroidManifest) -> ManifestAnalysis {
    let mut issues = Vec::new();
    let mut recommendations = Vec::new();
    let mut score = 100u32;

    // Check for debuggable
    if manifest.debuggable {
        issues.push(ManifestIssue {
            issue_type: "debuggable_enabled".to_string(),
            severity: "high".to_string(),
            description: "Application is debuggable. This should be disabled in production builds."
                .to_string(),
            component: None,
            cwe_id: Some("CWE-489".to_string()),
        });
        score = score.saturating_sub(20);
        recommendations.push("Set android:debuggable=\"false\" in production builds".to_string());
    }

    // Check for allowBackup
    if manifest.allow_backup {
        issues.push(ManifestIssue {
            issue_type: "allow_backup_enabled".to_string(),
            severity: "medium".to_string(),
            description: "Application allows backup. Sensitive data may be exposed through backups."
                .to_string(),
            component: None,
            cwe_id: Some("CWE-530".to_string()),
        });
        score = score.saturating_sub(10);
        recommendations.push("Consider setting android:allowBackup=\"false\" if app handles sensitive data".to_string());
    }

    // Check for exported components without permissions
    for activity in &manifest.activities {
        if activity.exported && activity.permission.is_none() {
            issues.push(ManifestIssue {
                issue_type: "exported_component_no_permission".to_string(),
                severity: "medium".to_string(),
                description: format!(
                    "Activity {} is exported without requiring a permission",
                    activity.name
                ),
                component: Some(activity.name.clone()),
                cwe_id: Some("CWE-926".to_string()),
            });
            score = score.saturating_sub(5);
        }
    }

    for service in &manifest.services {
        if service.exported && service.permission.is_none() {
            issues.push(ManifestIssue {
                issue_type: "exported_component_no_permission".to_string(),
                severity: "medium".to_string(),
                description: format!(
                    "Service {} is exported without requiring a permission",
                    service.name
                ),
                component: Some(service.name.clone()),
                cwe_id: Some("CWE-926".to_string()),
            });
            score = score.saturating_sub(5);
        }
    }

    for receiver in &manifest.receivers {
        if receiver.exported && receiver.permission.is_none() {
            issues.push(ManifestIssue {
                issue_type: "exported_component_no_permission".to_string(),
                severity: "medium".to_string(),
                description: format!(
                    "Receiver {} is exported without requiring a permission",
                    receiver.name
                ),
                component: Some(receiver.name.clone()),
                cwe_id: Some("CWE-926".to_string()),
            });
            score = score.saturating_sub(5);
        }
    }

    for provider in &manifest.providers {
        if provider.exported {
            issues.push(ManifestIssue {
                issue_type: "exported_provider".to_string(),
                severity: "high".to_string(),
                description: format!(
                    "ContentProvider {} is exported. Ensure proper access controls are in place.",
                    provider.name
                ),
                component: Some(provider.name.clone()),
                cwe_id: Some("CWE-926".to_string()),
            });
            score = score.saturating_sub(10);
        }
    }

    // Check for dangerous permissions
    let dangerous_perms = manifest.dangerous_permissions();
    if !dangerous_perms.is_empty() {
        recommendations.push(format!(
            "Review {} dangerous permissions for necessity",
            dangerous_perms.len()
        ));
    }

    // Check for network security config
    if manifest.network_security_config.is_none() {
        recommendations.push(
            "Consider implementing a Network Security Config for certificate pinning".to_string(),
        );
    }

    // Check target SDK
    if let Some(target_sdk) = manifest.target_sdk_version {
        if target_sdk < 30 {
            issues.push(ManifestIssue {
                issue_type: "outdated_target_sdk".to_string(),
                severity: "low".to_string(),
                description: format!(
                    "Target SDK version {} is outdated. Consider updating to 30 or higher.",
                    target_sdk
                ),
                component: None,
                cwe_id: None,
            });
            score = score.saturating_sub(5);
        }
    }

    ManifestAnalysis {
        issues,
        security_score: score,
        recommendations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MANIFEST: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.test"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30" />

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.CAMERA" />

    <application
        android:name=".MyApplication"
        android:label="Test App"
        android:debuggable="true"
        android:allowBackup="true">

        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <service android:name=".MyService" android:exported="true" />

    </application>
</manifest>"#;

    #[test]
    fn test_parse_manifest() {
        let manifest = parse_manifest(TEST_MANIFEST.as_bytes()).unwrap();

        assert_eq!(manifest.package_name, "com.example.test");
        assert_eq!(manifest.version_code, 1);
        assert_eq!(manifest.version_name, "1.0");
        assert_eq!(manifest.min_sdk_version, Some(21));
        assert_eq!(manifest.target_sdk_version, Some(30));
        assert!(manifest.debuggable);
        assert!(manifest.allow_backup);
    }

    #[test]
    fn test_parse_permissions() {
        let manifest = parse_manifest(TEST_MANIFEST.as_bytes()).unwrap();

        assert_eq!(manifest.uses_permissions.len(), 2);
        assert!(manifest.uses_permission("android.permission.INTERNET"));
        assert!(manifest.uses_permission("android.permission.CAMERA"));
    }

    #[test]
    fn test_parse_activities() {
        let manifest = parse_manifest(TEST_MANIFEST.as_bytes()).unwrap();

        assert_eq!(manifest.activities.len(), 1);
        assert_eq!(manifest.activities[0].name, ".MainActivity");
        assert!(manifest.activities[0].exported);
    }

    #[test]
    fn test_parse_services() {
        let manifest = parse_manifest(TEST_MANIFEST.as_bytes()).unwrap();

        assert_eq!(manifest.services.len(), 1);
        assert_eq!(manifest.services[0].name, ".MyService");
        assert!(manifest.services[0].exported);
    }

    #[test]
    fn test_dangerous_permissions() {
        let manifest = parse_manifest(TEST_MANIFEST.as_bytes()).unwrap();

        let dangerous = manifest.dangerous_permissions();
        assert_eq!(dangerous.len(), 1);
        assert_eq!(dangerous[0].name, "android.permission.CAMERA");
    }

    #[test]
    fn test_analyze_manifest() {
        let manifest = parse_manifest(TEST_MANIFEST.as_bytes()).unwrap();
        let analysis = analyze_manifest(&manifest);

        assert!(analysis.security_score < 100);
        assert!(!analysis.issues.is_empty());
        assert!(!analysis.recommendations.is_empty());

        // Should find debuggable issue
        assert!(analysis
            .issues
            .iter()
            .any(|i| i.issue_type == "debuggable_enabled"));

        // Should find exported component issues
        assert!(analysis
            .issues
            .iter()
            .any(|i| i.issue_type == "exported_component_no_permission"));
    }
}
