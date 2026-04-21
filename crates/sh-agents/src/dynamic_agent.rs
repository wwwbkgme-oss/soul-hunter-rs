//! # Dynamic Analysis Agent
//!
//! Performs runtime analysis and behavior monitoring of applications.
//! Capabilities include:
//! - Data exfiltration detection
//! - Runtime permission abuse monitoring
//! - Network activity analysis
//! - File system access tracking
//! - Memory analysis
//! - API call tracing
//! - Log analysis
//! - LLM-powered behavior analysis
//! - OpenCodeExecutor pattern for task execution
//!
//! ## Architecture
//!
//! The DynamicAgent implements the SecurityAgent trait and provides:
//! - Real-time runtime monitoring
//! - Event collection and analysis
//! - LLM integration for intelligent analysis
//! - JSON output for findings
//! - Health monitoring and reporting

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{interval, Duration as TokioDuration};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::{
    AgentBase, AgentContext, AgentError, AgentResult, Result, SecurityAgent,
};
use sh_types::{
    AgentCapability, AgentConfig, AgentHealth, AgentId, AgentStatus, AgentType, AnalysisTarget,
    Confidence, Finding, FindingCollection, Location, Platform, Remediation, RemediationEffort,
    Severity,
};

/// Dynamic analysis agent for runtime behavior monitoring
pub struct DynamicAgent {
    base: AgentBase,
    runtime_state: Arc<RwLock<RuntimeState>>,
    event_sender: Option<mpsc::Sender<RuntimeEvent>>,
    monitored_apis: Vec<String>,
    permission_monitor: Arc<RwLock<PermissionMonitor>>,
    network_analyzer: Arc<RwLock<NetworkAnalyzer>>,
    file_system_tracker: Arc<RwLock<FileSystemTracker>>,
    memory_analyzer: Arc<RwLock<MemoryAnalyzer>>,
    api_tracer: Arc<RwLock<ApiTracer>>,
    log_analyzer: Arc<RwLock<LogAnalyzer>>,
    llm_client: Option<Arc<sh_llm::LlmClient>>,
    executor_config: ExecutorConfig,
}

/// Configuration for the OpenCodeExecutor pattern
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    pub max_concurrent_tasks: usize,
    pub task_timeout_secs: u64,
    pub enable_retry: bool,
    pub retry_count: u32,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_tasks: 5,
            task_timeout_secs: 300,
            enable_retry: true,
            retry_count: 3,
        }
    }
}

/// Runtime state for dynamic analysis
#[derive(Debug, Clone)]
struct RuntimeState {
    is_running: bool,
    target_pid: Option<u32>,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    events: Vec<RuntimeEvent>,
    api_calls: HashMap<String, ApiCallStats>,
    file_accesses: Vec<FileAccessEvent>,
    network_connections: Vec<NetworkConnection>,
    memory_allocations: Vec<MemoryAllocation>,
    permission_requests: Vec<PermissionRequest>,
    log_entries: Vec<LogEntry>,
    data_transfers: Vec<DataTransferEvent>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            is_running: false,
            target_pid: None,
            start_time: None,
            end_time: None,
            events: Vec::new(),
            api_calls: HashMap::new(),
            file_accesses: Vec::new(),
            network_connections: Vec::new(),
            memory_allocations: Vec::new(),
            permission_requests: Vec::new(),
            log_entries: Vec::new(),
            data_transfers: Vec::new(),
        }
    }
}

/// API call statistics
#[derive(Debug, Clone, Default)]
struct ApiCallStats {
    count: u32,
    first_seen: Option<DateTime<Utc>>,
    last_seen: Option<DateTime<Utc>>,
    parameters: Vec<String>,
}

/// Runtime event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
enum RuntimeEvent {
    ApiCall(ApiCallEvent),
    FileAccess(FileAccessEvent),
    NetworkActivity(NetworkConnection),
    MemoryAllocation(MemoryAllocation),
    ProcessEvent(ProcessEvent),
    SuspiciousBehavior(SuspiciousBehavior),
    PermissionRequest(PermissionRequest),
    LogEntry(LogEntry),
    DataTransfer(DataTransferEvent),
}

/// API call event
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiCallEvent {
    timestamp: DateTime<Utc>,
    api_name: String,
    parameters: Vec<String>,
    return_value: Option<String>,
    stack_trace: Option<String>,
    thread_id: u32,
    duration_us: u64,
}

/// File access event
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileAccessEvent {
    timestamp: DateTime<Utc>,
    operation: FileOperation,
    path: String,
    size: Option<u64>,
    process_id: u32,
    thread_id: u32,
    is_sensitive: bool,
}

/// File operation types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FileOperation {
    Read,
    Write,
    Delete,
    Execute,
    Create,
    Modify,
}

/// Network connection
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkConnection {
    timestamp: DateTime<Utc>,
    destination: String,
    port: u16,
    protocol: String,
    bytes_sent: u64,
    bytes_received: u64,
    is_encrypted: bool,
    duration_ms: u64,
    connection_type: ConnectionType,
}

/// Connection type
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ConnectionType {
    Outbound,
    Inbound,
    PeerToPeer,
}

/// Memory allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MemoryAllocation {
    timestamp: DateTime<Utc>,
    size: usize,
    address: String,
    operation: MemoryOperation,
    protection: MemoryProtection,
    is_executable: bool,
}

/// Memory operation types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MemoryOperation {
    Allocate,
    Free,
    Read,
    Write,
    Execute,
    Protect,
}

/// Memory protection flags
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MemoryProtection {
    Read,
    Write,
    Execute,
    ReadWrite,
    ReadExecute,
    ReadWriteExecute,
}

/// Process event
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProcessEvent {
    timestamp: DateTime<Utc>,
    event_type: ProcessEventType,
    process_id: u32,
    parent_id: Option<u32>,
    command_line: Option<String>,
    process_name: String,
}

/// Process event types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProcessEventType {
    Start,
    Exit,
    Fork,
    Inject,
    Suspend,
    Resume,
}

/// Suspicious behavior detection
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SuspiciousBehavior {
    timestamp: DateTime<Utc>,
    behavior_type: BehaviorType,
    description: String,
    severity: Severity,
    evidence: Vec<String>,
    confidence: Confidence,
}

/// Behavior types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BehaviorType {
    PrivilegeEscalation,
    CodeInjection,
    DataExfiltration,
    Persistence,
    AntiAnalysis,
    SuspiciousApi,
    NetworkAnomaly,
    PermissionAbuse,
    FileTampering,
    MemoryManipulation,
}

/// Permission request event
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PermissionRequest {
    timestamp: DateTime<Utc>,
    permission: String,
    granted: bool,
    context: String,
    is_dangerous: bool,
    usage_count: u32,
}

/// Log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogEntry {
    timestamp: DateTime<Utc>,
    level: LogLevel,
    tag: String,
    message: String,
    is_sensitive: bool,
}

/// Log level
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LogLevel {
    Verbose,
    Debug,
    Info,
    Warning,
    Error,
    Assert,
}

/// Data transfer event
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataTransferEvent {
    timestamp: DateTime<Utc>,
    direction: DataDirection,
    destination: String,
    data_type: String,
    size_bytes: u64,
    is_encrypted: bool,
    is_compressed: bool,
}

/// Data direction
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DataDirection {
    Upload,
    Download,
    Sync,
}

/// Permission monitor for runtime permission abuse detection
#[derive(Debug)]
struct PermissionMonitor {
    dangerous_permissions: HashSet<String>,
    permission_usage: HashMap<String, PermissionUsageStats>,
    abuse_patterns: Vec<Regex>,
}

/// Permission usage statistics
#[derive(Debug, Clone, Default)]
struct PermissionUsageStats {
    request_count: u32,
    grant_count: u32,
    deny_count: u32,
    last_used: Option<DateTime<Utc>>,
    contexts: Vec<String>,
}

/// Network analyzer for network activity analysis
#[derive(Debug)]
struct NetworkAnalyzer {
    suspicious_ports: HashMap<u16, (String, Severity)>,
    known_bad_hosts: HashSet<String>,
    data_exfiltration_threshold: u64,
    connection_patterns: Vec<Regex>,
}

/// File system tracker for file access monitoring
#[derive(Debug)]
struct FileSystemTracker {
    sensitive_paths: Vec<(String, String, Severity)>,
    file_hashes: HashMap<String, String>,
    access_patterns: Vec<Regex>,
}

/// Memory analyzer for memory analysis
#[derive(Debug)]
struct MemoryAnalyzer {
    executable_regions: Vec<MemoryRegion>,
    injection_patterns: Vec<Regex>,
    heap_spray_threshold: usize,
}

/// Memory region
#[derive(Debug, Clone)]
struct MemoryRegion {
    address: String,
    size: usize,
    protection: MemoryProtection,
    is_executable: bool,
}

/// API tracer for API call tracing
#[derive(Debug)]
struct ApiTracer {
    dangerous_apis: HashMap<String, (String, Severity)>,
    api_sequences: Vec<Vec<String>>,
    call_stack: Vec<String>,
}

/// Log analyzer for log analysis
#[derive(Debug)]
struct LogAnalyzer {
    sensitive_patterns: Vec<Regex>,
    error_threshold: u32,
    warning_threshold: u32,
}

/// LLM analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlmAnalysisResult {
    findings: Vec<LlmFinding>,
    risk_score: f64,
    summary: String,
}

/// LLM finding
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LlmFinding {
    title: String,
    description: String,
    severity: Severity,
    confidence: Confidence,
    category: String,
    evidence: Vec<String>,
}

impl DynamicAgent {
    /// Create a new dynamic analysis agent
    pub fn new(name: impl Into<String>) -> Self {
        let base = AgentBase::new(name, AgentType::Dynamic)
            .with_capabilities(vec![
                AgentCapability::DynamicAnalysis,
                AgentCapability::Fuzzing,
            ])
            .with_platform(Platform::Android);

        let runtime_state = Arc::new(RwLock::new(RuntimeState::default()));

        Self {
            base,
            runtime_state,
            event_sender: None,
            monitored_apis: Self::init_monitored_apis(),
            permission_monitor: Arc::new(RwLock::new(Self::init_permission_monitor())),
            network_analyzer: Arc::new(RwLock::new(Self::init_network_analyzer())),
            file_system_tracker: Arc::new(RwLock::new(Self::init_file_system_tracker())),
            memory_analyzer: Arc::new(RwLock::new(Self::init_memory_analyzer())),
            api_tracer: Arc::new(RwLock::new(Self::init_api_tracer())),
            log_analyzer: Arc::new(RwLock::new(Self::init_log_analyzer())),
            llm_client: None,
            executor_config: ExecutorConfig::default(),
        }
    }

    /// Initialize the list of monitored APIs
    fn init_monitored_apis() -> Vec<String> {
        vec![
            // Android/Java APIs - Data exfiltration
            "android.content.ContentResolver.query".to_string(),
            "android.content.ContentResolver.insert".to_string(),
            "android.content.ContentResolver.update".to_string(),
            "android.content.ContentResolver.delete".to_string(),
            "android.database.Cursor.getString".to_string(),
            "android.database.Cursor.getBlob".to_string(),
            // Android/Java APIs - Network
            "java.net.URL.openConnection".to_string(),
            "java.net.Socket".to_string(),
            "java.net.HttpURLConnection.connect".to_string(),
            "okhttp3.OkHttpClient.newCall".to_string(),
            "retrofit2.Retrofit.create".to_string(),
            // Android/Java APIs - File system
            "java.io.FileInputStream.read".to_string(),
            "java.io.FileOutputStream.write".to_string(),
            "java.io.File.delete".to_string(),
            "android.content.Context.openFileInput".to_string(),
            "android.content.Context.openFileOutput".to_string(),
            // Android/Java APIs - Execution
            "java.lang.Runtime.exec".to_string(),
            "java.lang.ProcessBuilder.start".to_string(),
            "dalvik.system.DexClassLoader".to_string(),
            "java.lang.reflect.Method.invoke".to_string(),
            // Android/Java APIs - SMS/Phone
            "android.telephony.SmsManager.sendTextMessage".to_string(),
            "android.telephony.SmsManager.sendMultipartTextMessage".to_string(),
            "android.telephony.SmsManager.sendDataMessage".to_string(),
            // Android/Java APIs - Location
            "android.location.LocationManager.requestLocationUpdates".to_string(),
            "android.location.LocationManager.getLastKnownLocation".to_string(),
            // Android/Java APIs - Camera/Microphone
            "android.hardware.Camera.open".to_string(),
            "android.media.MediaRecorder.start".to_string(),
            // Android/Java APIs - Crypto
            "javax.crypto.Cipher.getInstance".to_string(),
            "javax.crypto.Cipher.init".to_string(),
            "javax.crypto.Cipher.doFinal".to_string(),
            "java.security.MessageDigest.getInstance".to_string(),
            // Android/Java APIs - Package management
            "android.content.pm.PackageManager.getInstalledPackages".to_string(),
            "android.content.pm.PackageManager.getPackageInfo".to_string(),
            // Android/Java APIs - Account/Contacts
            "android.accounts.AccountManager.getAccounts".to_string(),
            "android.provider.ContactsContract.query".to_string(),
            // Native APIs
            "system".to_string(),
            "popen".to_string(),
            "fork".to_string(),
            "execve".to_string(),
            "ptrace".to_string(),
            "mmap".to_string(),
            "mprotect".to_string(),
            "dlopen".to_string(),
            "dlsym".to_string(),
            "socket".to_string(),
            "connect".to_string(),
            "send".to_string(),
            "recv".to_string(),
            "open".to_string(),
            "read".to_string(),
            "write".to_string(),
            "close".to_string(),
            "unlink".to_string(),
            "chmod".to_string(),
            "chown".to_string(),
        ]
    }

    /// Initialize permission monitor
    fn init_permission_monitor() -> PermissionMonitor {
        let mut dangerous_permissions = HashSet::new();
        dangerous_permissions.insert("android.permission.READ_CONTACTS".to_string());
        dangerous_permissions.insert("android.permission.WRITE_CONTACTS".to_string());
        dangerous_permissions.insert("android.permission.READ_SMS".to_string());
        dangerous_permissions.insert("android.permission.SEND_SMS".to_string());
        dangerous_permissions.insert("android.permission.READ_PHONE_STATE".to_string());
        dangerous_permissions.insert("android.permission.CALL_PHONE".to_string());
        dangerous_permissions.insert("android.permission.ACCESS_FINE_LOCATION".to_string());
        dangerous_permissions.insert("android.permission.ACCESS_COARSE_LOCATION".to_string());
        dangerous_permissions.insert("android.permission.CAMERA".to_string());
        dangerous_permissions.insert("android.permission.RECORD_AUDIO".to_string());
        dangerous_permissions.insert("android.permission.READ_EXTERNAL_STORAGE".to_string());
        dangerous_permissions.insert("android.permission.WRITE_EXTERNAL_STORAGE".to_string());
        dangerous_permissions.insert("android.permission.READ_CALENDAR".to_string());
        dangerous_permissions.insert("android.permission.WRITE_CALENDAR".to_string());
        dangerous_permissions.insert("android.permission.GET_ACCOUNTS".to_string());
        dangerous_permissions.insert("android.permission.READ_CALL_LOG".to_string());
        dangerous_permissions.insert("android.permission.WRITE_CALL_LOG".to_string());
        dangerous_permissions.insert("android.permission.PROCESS_OUTGOING_CALLS".to_string());
        dangerous_permissions.insert("android.permission.BODY_SENSORS".to_string());
        dangerous_permissions.insert("android.permission.ACTIVITY_RECOGNITION".to_string());
        dangerous_permissions.insert("android.permission.ACCESS_BACKGROUND_LOCATION".to_string());

        let abuse_patterns = vec![
            Regex::new(r"(?i)(background|silent|hidden|stealth)").unwrap(),
            Regex::new(r"(?i)(harvest|collect|gather|scrape)").unwrap(),
            Regex::new(r"(?i)(upload|send|transmit|exfil)").unwrap(),
        ];

        PermissionMonitor {
            dangerous_permissions,
            permission_usage: HashMap::new(),
            abuse_patterns,
        }
    }

    /// Initialize network analyzer
    fn init_network_analyzer() -> NetworkAnalyzer {
        let mut suspicious_ports = HashMap::new();
        suspicious_ports.insert(4444, ("Metasploit Default".to_string(), Severity::Critical));
        suspicious_ports.insert(5555, ("ADB Default".to_string(), Severity::High));
        suspicious_ports.insert(6666, ("IRC/Backdoor".to_string(), Severity::High));
        suspicious_ports.insert(6667, ("IRC".to_string(), Severity::Medium));
        suspicious_ports.insert(9999, ("Common Backdoor".to_string(), Severity::High));
        suspicious_ports.insert(31337, ("Backdoor".to_string(), Severity::Critical));
        suspicious_ports.insert(12345, ("NetBus".to_string(), Severity::Critical));
        suspicious_ports.insert(27374, ("SubSeven".to_string(), Severity::Critical));

        let mut known_bad_hosts = HashSet::new();
        known_bad_hosts.insert("malware.example.com".to_string());
        known_bad_hosts.insert("phishing.example.com".to_string());
        known_bad_hosts.insert("botnet.example.com".to_string());
        known_bad_hosts.insert("c2.example.com".to_string());

        let connection_patterns = vec![
            Regex::new(r"(?i)\.(tk|ml|ga|cf|top|xyz|click|link|download)$").unwrap(),
            Regex::new(r"(?i)[a-z0-9]{20,}\.(com|net|org)").unwrap(),
            Regex::new(r"(?i)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap(),
        ];

        NetworkAnalyzer {
            suspicious_ports,
            known_bad_hosts,
            data_exfiltration_threshold: 10_000_000, // 10MB
            connection_patterns,
        }
    }

    /// Initialize file system tracker
    fn init_file_system_tracker() -> FileSystemTracker {
        let sensitive_paths = vec![
            ("/data/data/".to_string(), "Application Data".to_string(), Severity::Medium),
            ("/sdcard/".to_string(), "External Storage".to_string(), Severity::Medium),
            ("/system/".to_string(), "System Directory".to_string(), Severity::High),
            ("/proc/".to_string(), "Process Information".to_string(), Severity::High),
            ("/etc/passwd".to_string(), "Password File".to_string(), Severity::Critical),
            ("/etc/shadow".to_string(), "Shadow Password File".to_string(), Severity::Critical),
            ("/data/system/users/".to_string(), "User Data".to_string(), Severity::Critical),
            ("/data/system/packages.xml".to_string(), "Package Database".to_string(), Severity::High),
        ];

        let access_patterns = vec![
            Regex::new(r"(?i)(password|secret|key|token|credential)").unwrap(),
            Regex::new(r"(?i)(\.db|\.sqlite|\.db3)$").unwrap(),
            Regex::new(r"(?i)(shared_prefs|databases|cache|files)").unwrap(),
        ];

        FileSystemTracker {
            sensitive_paths,
            file_hashes: HashMap::new(),
            access_patterns,
        }
    }

    /// Initialize memory analyzer
    fn init_memory_analyzer() -> MemoryAnalyzer {
        let injection_patterns = vec![
            Regex::new(r"(?i)(inject|hook|patch|modify|overwrite)").unwrap(),
            Regex::new(r"(?i)(ptrace|/proc/\d+/mem|/dev/mem)").unwrap(),
            Regex::new(r"(?i)(mmap.*exec|mprotect.*exec)").unwrap(),
        ];

        MemoryAnalyzer {
            executable_regions: Vec::new(),
            injection_patterns,
            heap_spray_threshold: 100 * 1024 * 1024, // 100MB
        }
    }

    /// Initialize API tracer
    fn init_api_tracer() -> ApiTracer {
        let mut dangerous_apis = HashMap::new();
        dangerous_apis.insert(
            "java.lang.Runtime.exec".to_string(),
            ("Command Execution".to_string(), Severity::High),
        );
        dangerous_apis.insert(
            "java.lang.ProcessBuilder.start".to_string(),
            ("Process Creation".to_string(), Severity::High),
        );
        dangerous_apis.insert(
            "dalvik.system.DexClassLoader".to_string(),
            ("Dynamic Code Loading".to_string(), Severity::High),
        );
        dangerous_apis.insert(
            "java.lang.reflect.Method.invoke".to_string(),
            ("Reflection".to_string(), Severity::Medium),
        );
        dangerous_apis.insert(
            "android.telephony.SmsManager.sendTextMessage".to_string(),
            ("SMS Sending".to_string(), Severity::High),
        );
        dangerous_apis.insert(
            "android.database.sqlite.SQLiteDatabase.rawQuery".to_string(),
            ("Raw SQL".to_string(), Severity::Medium),
        );
        dangerous_apis.insert(
            "android.content.ContentResolver.query".to_string(),
            ("Content Query".to_string(), Severity::Medium),
        );
        dangerous_apis.insert(
            "java.net.URL.openConnection".to_string(),
            ("Network Connection".to_string(), Severity::Medium),
        );
        dangerous_apis.insert(
            "javax.crypto.Cipher.getInstance".to_string(),
            ("Cryptographic Operation".to_string(), Severity::Low),
        );

        ApiTracer {
            dangerous_apis,
            api_sequences: Vec::new(),
            call_stack: Vec::new(),
        }
    }

    /// Initialize log analyzer
    fn init_log_analyzer() -> LogAnalyzer {
        let sensitive_patterns = vec![
            Regex::new(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+").unwrap(),
            Regex::new(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+").unwrap(),
            Regex::new(r"(?i)(secret|token)\s*[=:]\s*\S+").unwrap(),
            Regex::new(r"(?i)(email|phone|ssn|credit.?card)\s*[=:]\s*\S+").unwrap(),
            Regex::new(r"(?i)bearer\s+\S+").unwrap(),
            Regex::new(r"(?i)basic\s+[a-zA-Z0-9+/=]{10,}").unwrap(),
        ];

        LogAnalyzer {
            sensitive_patterns,
            error_threshold: 10,
            warning_threshold: 50,
        }
    }

    /// Initialize LLM client
    async fn init_llm_client(&mut self) -> Result<()> {
        let config = sh_llm::LlmConfig::default()
            .with_provider("ollama")
            .with_model("llama2")
            .with_timeout(60);

        match sh_llm::LlmClient::new(config) {
            Ok(client) => {
                self.llm_client = Some(Arc::new(client));
                info!("LLM client initialized successfully");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to initialize LLM client: {}. Continuing without LLM support.", e);
                Ok(())
            }
        }
    }

    /// Start runtime monitoring
    #[instrument(skip(self, target), fields(agent_id = %self.base.id))]
    async fn start_monitoring(&self, target: &AnalysisTarget) -> Result<()> {
        info!("Starting dynamic analysis for: {}", target.path);

        let path = Path::new(&target.path);
        if !path.exists() {
            return Err(AgentError::InvalidConfig(format!(
                "Target not found: {}",
                target.path
            )));
        }

        // Initialize runtime state
        {
            let mut state = self.runtime_state.write().await;
            state.is_running = true;
            state.start_time = Some(Utc::now());
            state.events.clear();
            state.api_calls.clear();
            state.file_accesses.clear();
            state.network_connections.clear();
            state.memory_allocations.clear();
            state.permission_requests.clear();
            state.log_entries.clear();
            state.data_transfers.clear();
        }

        // Create event channel
        let (tx, mut rx) = mpsc::channel::<RuntimeEvent>(10000);
        let _ = tx.clone();

        // Start event processing task
        let state_clone = self.runtime_state.clone();
        let permission_monitor = self.permission_monitor.clone();
        let network_analyzer = self.network_analyzer.clone();
        let file_system_tracker = self.file_system_tracker.clone();
        let memory_analyzer = self.memory_analyzer.clone();
        let api_tracer = self.api_tracer.clone();
        let log_analyzer = self.log_analyzer.clone();

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let mut state = state_clone.write().await;
                state.events.push(event.clone());

                // Process specific event types
                match &event {
                    RuntimeEvent::ApiCall(api) => {
                        let stats = state
                            .api_calls
                            .entry(api.api_name.clone())
                            .or_insert_with(ApiCallStats::default);
                        stats.count += 1;
                        if stats.first_seen.is_none() {
                            stats.first_seen = Some(api.timestamp);
                        }
                        stats.last_seen = Some(api.timestamp);
                        stats.parameters.extend(api.parameters.clone());
                    }
                    RuntimeEvent::FileAccess(file) => {
                        state.file_accesses.push(file.clone());
                    }
                    RuntimeEvent::NetworkActivity(conn) => {
                        state.network_connections.push(conn.clone());
                    }
                    RuntimeEvent::MemoryAllocation(mem) => {
                        state.memory_allocations.push(mem.clone());
                    }
                    RuntimeEvent::PermissionRequest(perm) => {
                        state.permission_requests.push(perm.clone());
                    }
                    RuntimeEvent::LogEntry(log) => {
                        state.log_entries.push(log.clone());
                    }
                    RuntimeEvent::DataTransfer(transfer) => {
                        state.data_transfers.push(transfer.clone());
                    }
                    _ => {}
                }
            }
        });

        // Start monitoring tasks
        self.start_api_monitoring().await?;
        self.start_file_monitoring().await?;
        self.start_network_monitoring().await?;
        self.start_memory_monitoring().await?;
        self.start_permission_monitoring().await?;
        self.start_log_monitoring().await?;

        info!("Dynamic analysis monitoring started");
        Ok(())
    }

    /// Stop runtime monitoring
    #[instrument(skip(self))]
    async fn stop_monitoring(&self) -> Result<FindingCollection> {
        info!("Stopping dynamic analysis monitoring");

        {
            let mut state = self.runtime_state.write().await;
            state.is_running = false;
            state.end_time = Some(Utc::now());
        }

        // Analyze collected data and generate findings
        let findings = self.analyze_runtime_data().await?;

        // Perform LLM analysis if available
        let llm_findings = self.perform_llm_analysis().await?;

        // Combine findings
        let mut all_findings = findings.findings;
        all_findings.extend(llm_findings.findings);

        info!(
            "Dynamic analysis completed. Found {} findings",
            all_findings.len()
        );

        Ok(FindingCollection::new(all_findings))
    }

    /// Start API call monitoring
    #[instrument(skip(self))]
    async fn start_api_monitoring(&self) -> Result<()> {
        debug!("Starting API monitoring");
        // In a real implementation, this would hook into the runtime
        // For now, we simulate the monitoring setup
        Ok(())
    }

    /// Start file system monitoring
    #[instrument(skip(self))]
    async fn start_file_monitoring(&self) -> Result<()> {
        debug!("Starting file system monitoring");
        // In a real implementation, this would use OS-specific APIs
        Ok(())
    }

    /// Start network monitoring
    #[instrument(skip(self))]
    async fn start_network_monitoring(&self) -> Result<()> {
        debug!("Starting network monitoring");
        // In a real implementation, this would capture network traffic
        Ok(())
    }

    /// Start memory monitoring
    #[instrument(skip(self))]
    async fn start_memory_monitoring(&self) -> Result<()> {
        debug!("Starting memory monitoring");
        // In a real implementation, this would monitor memory allocations
        Ok(())
    }

    /// Start permission monitoring
    #[instrument(skip(self))]
    async fn start_permission_monitoring(&self) -> Result<()> {
        debug!("Starting permission monitoring");
        // In a real implementation, this would monitor permission requests
        Ok(())
    }

    /// Start log monitoring
    #[instrument(skip(self))]
    async fn start_log_monitoring(&self) -> Result<()> {
        debug!("Starting log monitoring");
        // In a real implementation, this would capture log output
        Ok(())
    }

    /// Analyze runtime data and generate findings
    #[instrument(skip(self))]
    async fn analyze_runtime_data(&self) -> Result<FindingCollection> {
        let mut findings = Vec::new();
        let state = self.runtime_state.read().await;

        // Analyze API calls
        findings.extend(self.analyze_api_calls(&state.api_calls).await?);

        // Analyze file accesses
        findings.extend(self.analyze_file_accesses(&state.file_accesses).await?);

        // Analyze network activity
        findings.extend(self.analyze_network_activity(&state.network_connections).await?);

        // Analyze memory patterns
        findings.extend(self.analyze_memory_patterns(&state.memory_allocations).await?);

        // Analyze permission usage
        findings.extend(self.analyze_permission_usage(&state.permission_requests).await?);

        // Analyze log entries
        findings.extend(self.analyze_log_entries(&state.log_entries).await?);

        // Analyze data transfers
        findings.extend(self.analyze_data_transfers(&state.data_transfers).await?);

        // Analyze for suspicious behaviors
        findings.extend(self.analyze_suspicious_behaviors(&state.events).await?);

        Ok(FindingCollection::new(findings))
    }

    /// Analyze API calls for suspicious patterns
    #[instrument(skip(self, api_calls))]
    async fn analyze_api_calls(
        &self,
        api_calls: &HashMap<String, ApiCallStats>,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let tracer = self.api_tracer.read().await;

        // Check for dangerous API usage
        for (api_name, stats) in api_calls {
            if let Some((desc, severity)) = tracer.dangerous_apis.get(api_name) {
                if stats.count > 0 {
                    findings.push(
                        Finding::new(
                            format!("Dangerous API Usage: {}", desc),
                            format!(
                                "The application called {} {} time(s) during execution. This API can be used for malicious purposes.",
                                api_name, stats.count
                            ),
                        )
                        .with_severity(*severity)
                        .with_confidence(Confidence::Confirmed)
                        .with_type("dangerous_api_usage")
                        .with_cwe("CWE-78")
                        .with_owasp("M7: Client Code Quality")
                        .with_location(
                            Location::new()
                                .with_platform(Platform::Android)
                                .with_function(api_name),
                        )
                        .with_remediation(
                            Remediation::new("Review the usage of this API. Ensure input validation is performed and the API is used for legitimate purposes only.")
                                .with_effort(RemediationEffort::Medium)
                                .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x04h-Testing-Code-Quality"),
                        )
                        .with_tool("DynamicAgent", "0.1.0"),
                    );
                }
            }
        }

        // Check for excessive API calls (potential DoS or brute force)
        for (api_name, stats) in api_calls {
            if stats.count > 100 {
                findings.push(
                    Finding::new(
                        format!("Excessive API Calls: {}", api_name),
                        format!(
                            "The application called {} {} times, which may indicate a denial of service attempt or inefficient code.",
                            api_name, stats.count
                        ),
                    )
                    .with_severity(Severity::Medium)
                    .with_confidence(Confidence::Probable)
                    .with_type("excessive_api_calls")
                    .with_cwe("CWE-400")
                    .with_owasp("M7: Client Code Quality")
                    .with_location(Location::new().with_platform(Platform::Android))
                    .with_remediation(
                        Remediation::new("Review the frequency of API calls. Implement rate limiting or caching if appropriate.")
                            .with_effort(RemediationEffort::Low),
                    )
                    .with_tool("DynamicAgent", "0.1.0"),
                );
            }
        }

        // Check for suspicious API sequences
        let api_sequence: Vec<String> = api_calls.keys().cloned().collect();
        if self.detect_suspicious_sequence(&api_sequence).await? {
            findings.push(
                Finding::new(
                    "Suspicious API Sequence",
                    "The application executed a sequence of APIs that may indicate malicious behavior (e.g., data collection followed by network transmission).".to_string(),
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Probable)
                .with_type("suspicious_api_sequence")
                .with_cwe("CWE-78")
                .with_owasp("M7: Client Code Quality")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Review the sequence of API calls. Ensure data collection and transmission are properly authorized and documented.")
                        .with_effort(RemediationEffort::High),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Detect suspicious API sequences
    async fn detect_suspicious_sequence(&self, sequence: &[String]) -> Result<bool> {
        // Check for data collection + network transmission pattern
        let has_data_collection = sequence.iter().any(|api| {
            api.contains("ContentResolver") || api.contains("Cursor") || api.contains("query")
        });

        let has_network_transmission = sequence.iter().any(|api| {
            api.contains("URL") || api.contains("Socket") || api.contains("HttpURLConnection")
        });

        Ok(has_data_collection && has_network_transmission)
    }

    /// Analyze file accesses
    #[instrument(skip(self, file_accesses))]
    async fn analyze_file_accesses(
        &self,
        file_accesses: &[FileAccessEvent],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let tracker = self.file_system_tracker.read().await;

        // Check for sensitive file access
        for access in file_accesses {
            for (pattern, desc, severity) in &tracker.sensitive_paths {
                if access.path.contains(pattern) {
                    findings.push(
                        Finding::new(
                            format!("Sensitive File Access: {}", desc),
                            format!(
                                "The application accessed {} ({}) during execution.",
                                desc, access.path
                            ),
                        )
                        .with_severity(*severity)
                        .with_confidence(Confidence::Confirmed)
                        .with_type("sensitive_file_access")
                        .with_cwe("CWE-276")
                        .with_owasp("M2: Insecure Data Storage")
                        .with_location(
                            Location::new()
                                .with_file(&access.path)
                                .with_platform(Platform::Android),
                        )
                        .with_remediation(
                            Remediation::new("Review the necessity of accessing this location. Ensure proper permissions and validation are in place.")
                                .with_effort(RemediationEffort::Medium),
                        )
                        .with_tool("DynamicAgent", "0.1.0"),
                    );
                }
            }
        }

        // Check for writes to external storage
        let external_writes: Vec<_> = file_accesses
            .iter()
            .filter(|a| matches!(a.operation, FileOperation::Write) && a.path.contains("/sdcard/"))
            .collect();

        if !external_writes.is_empty() {
            findings.push(
                Finding::new(
                    "External Storage Write",
                    format!(
                        "The application wrote {} file(s) to external storage. Data written to external storage is accessible by other applications.",
                        external_writes.len()
                    ),
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Confirmed)
                .with_type("external_storage_write")
                .with_cwe("CWE-276")
                .with_owasp("M2: Insecure Data Storage")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Avoid writing sensitive data to external storage. Use internal storage or encrypted storage mechanisms.")
                        .with_effort(RemediationEffort::Medium)
                        .add_reference("https://developer.android.com/training/data-storage"),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        // Check for database access
        let db_accesses: Vec<_> = file_accesses
            .iter()
            .filter(|a| a.path.ends_with(".db") || a.path.ends_with(".sqlite"))
            .collect();

        if !db_accesses.is_empty() {
            findings.push(
                Finding::new(
                    "Database File Access",
                    format!(
                        "The application accessed {} database file(s). Ensure database files are properly secured.",
                        db_accesses.len()
                    ),
                )
                .with_severity(Severity::Medium)
                .with_confidence(Confidence::Confirmed)
                .with_type("database_access")
                .with_cwe("CWE-276")
                .with_owasp("M2: Insecure Data Storage")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Ensure database files are stored in secure locations and use SQLCipher for encryption if storing sensitive data.")
                        .with_effort(RemediationEffort::Medium),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Analyze network activity
    #[instrument(skip(self, connections))]
    async fn analyze_network_activity(
        &self,
        connections: &[NetworkConnection],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let analyzer = self.network_analyzer.read().await;

        // Check for unencrypted connections
        let unencrypted: Vec<_> = connections.iter().filter(|c| !c.is_encrypted).collect();

        if !unencrypted.is_empty() {
            findings.push(
                Finding::new(
                    "Unencrypted Network Communication",
                    format!(
                        "The application made {} unencrypted network connection(s). Data transmitted over unencrypted channels can be intercepted.",
                        unencrypted.len()
                    ),
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Confirmed)
                .with_type("unencrypted_communication")
                .with_cwe("CWE-319")
                .with_owasp("M3: Insecure Communication")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Use HTTPS/TLS for all network communications. Implement certificate pinning for additional security.")
                        .with_effort(RemediationEffort::Medium)
                        .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x04f-Testing-Network-Communication"),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        // Check for suspicious ports
        for conn in connections {
            if let Some((desc, severity)) = analyzer.suspicious_ports.get(&conn.port) {
                findings.push(
                    Finding::new(
                        format!("Suspicious Network Connection: {}", desc),
                        format!(
                            "The application connected to {}:{} ({}). This port is commonly associated with malicious activity.",
                            conn.destination, conn.port, desc
                        ),
                    )
                    .with_severity(*severity)
                    .with_confidence(Confidence::Probable)
                    .with_type("suspicious_network_connection")
                    .with_cwe("CWE-506")
                    .with_owasp("M7: Client Code Quality")
                    .with_location(Location::new().with_platform(Platform::Android))
                    .with_remediation(
                        Remediation::new("Review the legitimacy of this network connection. Ensure the destination is trusted and necessary.")
                            .with_effort(RemediationEffort::High),
                    )
                    .with_tool("DynamicAgent", "0.1.0"),
                );
            }
        }

        // Check for data exfiltration patterns
        let total_bytes_sent: u64 = connections.iter().map(|c| c.bytes_sent).sum();
        if total_bytes_sent > analyzer.data_exfiltration_threshold {
            findings.push(
                Finding::new(
                    "Potential Data Exfiltration",
                    format!(
                        "The application sent {} bytes of data over the network. This may indicate data exfiltration.",
                        total_bytes_sent
                    ),
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Tentative)
                .with_type("data_exfiltration")
                .with_cwe("CWE-506")
                .with_owasp("M3: Insecure Communication")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Review the amount of data being transmitted. Implement data usage monitoring and alerts.")
                        .with_effort(RemediationEffort::Medium),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        // Check for connections to suspicious domains
        for conn in connections {
            for pattern in &analyzer.connection_patterns {
                if pattern.is_match(&conn.destination) {
                    findings.push(
                        Finding::new(
                            "Suspicious Domain Connection",
                            format!(
                                "The application connected to '{}' which matches a suspicious pattern.",
                                conn.destination
                            ),
                        )
                        .with_severity(Severity::High)
                        .with_confidence(Confidence::Tentative)
                        .with_type("suspicious_domain")
                        .with_cwe("CWE-506")
                        .with_owasp("M7: Client Code Quality")
                        .with_location(Location::new().with_platform(Platform::Android))
                        .with_remediation(
                            Remediation::new("Investigate this domain. Consider implementing domain reputation checking.")
                                .with_effort(RemediationEffort::High),
                        )
                        .with_tool("DynamicAgent", "0.1.0"),
                    );
                    break;
                }
            }
        }

        // Check for beaconing behavior
        if connections.len() >= 5 {
            let mut intervals = Vec::new();
            for i in 1..connections.len() {
                let diff = connections[i]
                    .timestamp
                    .signed_duration_since(connections[i - 1].timestamp)
                    .num_seconds();
                intervals.push(diff.abs());
            }

            if intervals.len() > 3 {
                let avg = intervals.iter().sum::<i64>() / intervals.len() as i64;
                let variance: i64 = intervals
                    .iter()
                    .map(|&x| (x - avg).abs())
                    .sum::<i64>()
                    / intervals.len() as i64;

                if variance < 5 && avg > 0 && avg < 300 {
                    findings.push(
                        Finding::new(
                            "Potential Beaconing Behavior",
                            format!(
                                "Detected {} connections with regular {}-second intervals. This may indicate command and control beaconing.",
                                connections.len(), avg
                            ),
                        )
                        .with_severity(Severity::High)
                        .with_confidence(Confidence::Tentative)
                        .with_type("beaconing")
                        .with_cwe("CWE-506")
                        .with_owasp("M7: Client Code Quality")
                        .with_location(Location::new().with_platform(Platform::Android))
                        .with_remediation(
                            Remediation::new("Investigate the regular network connections. This pattern is commonly used by malware for command and control.")
                                .with_effort(RemediationEffort::High),
                        )
                        .with_tool("DynamicAgent", "0.1.0"),
                    );
                }
            }
        }

        Ok(findings)
    }

    /// Analyze memory patterns
    #[instrument(skip(self, allocations))]
    async fn analyze_memory_patterns(
        &self,
        allocations: &[MemoryAllocation],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let analyzer = self.memory_analyzer.read().await;

        // Check for executable memory allocations (potential code injection)
        let executable_allocs: Vec<_> = allocations
            .iter()
            .filter(|a| a.is_executable)
            .collect();

        if !executable_allocs.is_empty() {
            findings.push(
                Finding::new(
                    "Executable Memory Allocation",
                    format!(
                        "The application allocated {} executable memory region(s). This may indicate code injection or dynamic code execution.",
                        executable_allocs.len()
                    ),
                )
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Probable)
                .with_type("executable_memory")
                .with_cwe("CWE-94")
                .with_owasp("M8: Code Tampering")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Review the necessity of executable memory allocations. This is often used for JIT compilation but can be exploited for code injection.")
                        .with_effort(RemediationEffort::High),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        // Check for large memory allocations
        let large_allocs: Vec<_> = allocations
            .iter()
            .filter(|a| a.size > analyzer.heap_spray_threshold)
            .collect();

        if !large_allocs.is_empty() {
            findings.push(
                Finding::new(
                    "Large Memory Allocation",
                    format!(
                        "The application allocated {} large memory region(s) (>100MB). This may indicate memory exhaustion attacks or inefficient memory usage.",
                        large_allocs.len()
                    ),
                )
                .with_severity(Severity::Medium)
                .with_confidence(Confidence::Tentative)
                .with_type("large_memory_allocation")
                .with_cwe("CWE-400")
                .with_owasp("M7: Client Code Quality")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Review large memory allocations. Implement memory limits and proper cleanup mechanisms.")
                        .with_effort(RemediationEffort::Medium),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        // Check for RWX (Read-Write-Execute) memory regions
        let rwx_allocs: Vec<_> = allocations
            .iter()
            .filter(|a| matches!(a.protection, MemoryProtection::ReadWriteExecute))
            .collect();

        if !rwx_allocs.is_empty() {
            findings.push(
                Finding::new(
                    "RWX Memory Protection",
                    format!(
                        "The application allocated {} memory region(s) with Read-Write-Execute permissions. This is a security risk.",
                        rwx_allocs.len()
                    ),
                )
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Confirmed)
                .with_type("rwx_memory")
                .with_cwe("CWE-94")
                .with_owasp("M8: Code Tampering")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Avoid allocating RWX memory. Use separate regions for code and data with appropriate permissions.")
                        .with_effort(RemediationEffort::High),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Analyze permission usage
    #[instrument(skip(self, permissions))]
    async fn analyze_permission_usage(
        &self,
        permissions: &[PermissionRequest],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let monitor = self.permission_monitor.read().await;

        // Check for dangerous permission usage
        let dangerous_usage: Vec<_> = permissions
            .iter()
            .filter(|p| p.is_dangerous && p.granted)
            .collect();

        for perm in &dangerous_usage {
            findings.push(
                Finding::new(
                    format!("Dangerous Permission Granted: {}", perm.permission),
                    format!(
                        "The application was granted the dangerous permission '{}' in context: {}. Usage count: {}.",
                        perm.permission, perm.context, perm.usage_count
                    ),
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Confirmed)
                .with_type("dangerous_permission_granted")
                .with_cwe("CWE-250")
                .with_owasp("M1: Improper Platform Usage")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Review if this permission is necessary. If not, remove it. If required, ensure proper justification and user consent mechanisms are in place.")
                        .with_effort(RemediationEffort::Low),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        // Check for permission abuse patterns
        for perm in permissions {
            for pattern in &monitor.abuse_patterns {
                if pattern.is_match(&perm.context) {
                    findings.push(
                        Finding::new(
                            "Potential Permission Abuse",
                            format!(
                                "The permission '{}' was used in a suspicious context: {}. This may indicate permission abuse.",
                                perm.permission, perm.context
                            ),
                        )
                        .with_severity(Severity::High)
                        .with_confidence(Confidence::Probable)
                        .with_type("permission_abuse")
                        .with_cwe("CWE-250")
                        .with_owasp("M1: Improper Platform Usage")
                        .with_location(Location::new().with_platform(Platform::Android))
                        .with_remediation(
                            Remediation::new("Review the context in which this permission is used. Ensure it aligns with the stated purpose of the application.")
                                .with_effort(RemediationEffort::Medium),
                        )
                        .with_tool("DynamicAgent", "0.1.0"),
                    );
                    break;
                }
            }
        }

        // Check for excessive permission requests
        let total_requests = permissions.len();
        if total_requests > 20 {
            findings.push(
                Finding::new(
                    "Excessive Permission Requests",
                    format!(
                        "The application requested {} permissions during execution. This may indicate over-privileging.",
                        total_requests
                    ),
                )
                .with_severity(Severity::Medium)
                .with_confidence(Confidence::Tentative)
                .with_type("excessive_permissions")
                .with_cwe("CWE-250")
                .with_owasp("M1: Improper Platform Usage")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Review all requested permissions. Remove any that are not strictly necessary for the application's functionality.")
                        .with_effort(RemediationEffort::Medium),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Analyze log entries
    #[instrument(skip(self, log_entries))]
    async fn analyze_log_entries(
        &self,
        log_entries: &[LogEntry],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let analyzer = self.log_analyzer.read().await;

        // Check for sensitive data in logs
        for log in log_entries {
            for pattern in &analyzer.sensitive_patterns {
                if pattern.is_match(&log.message) {
                    findings.push(
                        Finding::new(
                            "Sensitive Data in Logs",
                            format!(
                                "Potentially sensitive data was found in log output: '{}' (tag: {})",
                                log.message, log.tag
                            ),
                        )
                        .with_severity(Severity::High)
                        .with_confidence(Confidence::Probable)
                        .with_type("sensitive_log_data")
                        .with_cwe("CWE-532")
                        .with_owasp("M2: Insecure Data Storage")
                        .with_location(Location::new().with_platform(Platform::Android))
                        .with_remediation(
                            Remediation::new("Remove sensitive data from log output. Use proper log levels and sanitize log messages.")
                                .with_effort(RemediationEffort::Low)
                                .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x05d-Testing-Data-Storage"),
                        )
                        .with_tool("DynamicAgent", "0.1.0"),
                    );
                    break;
                }
            }
        }

        // Check for excessive errors
        let error_count = log_entries
            .iter()
            .filter(|l| matches!(l.level, LogLevel::Error))
            .count();

        if error_count > analyzer.error_threshold as usize {
            findings.push(
                Finding::new(
                    "Excessive Error Logging",
                    format!(
                        "The application logged {} errors during execution. This may indicate stability issues or error handling problems.",
                        error_count
                    ),
                )
                .with_severity(Severity::Medium)
                .with_confidence(Confidence::Tentative)
                .with_type("excessive_errors")
                .with_cwe("CWE-391")
                .with_owasp("M7: Client Code Quality")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Review error handling. Ensure errors are properly caught and handled without exposing sensitive information.")
                        .with_effort(RemediationEffort::Medium),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        // Check for debug logs in production
        let debug_count = log_entries
            .iter()
            .filter(|l| matches!(l.level, LogLevel::Debug) || matches!(l.level, LogLevel::Verbose))
            .count();

        if debug_count > 100 {
            findings.push(
                Finding::new(
                    "Debug Logging Enabled",
                    format!(
                        "The application logged {} debug/verbose messages. Debug logging should be disabled in production builds.",
                        debug_count
                    ),
                )
                .with_severity(Severity::Low)
                .with_confidence(Confidence::Tentative)
                .with_type("debug_logging")
                .with_cwe("CWE-532")
                .with_owasp("M7: Client Code Quality")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Disable debug logging in production builds. Use ProGuard or R8 to remove log statements.")
                        .with_effort(RemediationEffort::Low),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Analyze data transfers
    #[instrument(skip(self, transfers))]
    async fn analyze_data_transfers(
        &self,
        transfers: &[DataTransferEvent],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for large data uploads
        let total_upload: u64 = transfers
            .iter()
            .filter(|t| matches!(t.direction, DataDirection::Upload))
            .map(|t| t.size_bytes)
            .sum();

        if total_upload > 10_000_000 {
            // 10MB
            findings.push(
                Finding::new(
                    "Large Data Upload",
                    format!(
                        "The application uploaded {} bytes of data. This may indicate data exfiltration.",
                        total_upload
                    ),
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Tentative)
                .with_type("large_data_upload")
                .with_cwe("CWE-506")
                .with_owasp("M3: Insecure Communication")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Review data upload patterns. Implement data usage monitoring and user consent for large transfers.")
                        .with_effort(RemediationEffort::Medium),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        // Check for unencrypted data transfers
        let unencrypted_transfers: Vec<_> = transfers
            .iter()
            .filter(|t| !t.is_encrypted)
            .collect();

        if !unencrypted_transfers.is_empty() {
            findings.push(
                Finding::new(
                    "Unencrypted Data Transfer",
                    format!(
                        "The application performed {} unencrypted data transfer(s). Sensitive data should always be encrypted in transit.",
                        unencrypted_transfers.len()
                    ),
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Confirmed)
                .with_type("unencrypted_transfer")
                .with_cwe("CWE-319")
                .with_owasp("M3: Insecure Communication")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Encrypt all data transfers using TLS. Never transmit sensitive data in plaintext.")
                        .with_effort(RemediationEffort::Medium),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        // Check for frequent sync operations
        let sync_count = transfers
            .iter()
            .filter(|t| matches!(t.direction, DataDirection::Sync))
            .count();

        if sync_count > 50 {
            findings.push(
                Finding::new(
                    "Frequent Sync Operations",
                    format!(
                        "The application performed {} sync operations. This may impact battery life and user experience.",
                        sync_count
                    ),
                )
                .with_severity(Severity::Low)
                .with_confidence(Confidence::Tentative)
                .with_type("frequent_sync")
                .with_cwe("CWE-400")
                .with_owasp("M7: Client Code Quality")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Optimize sync operations. Use batching and implement proper sync intervals.")
                        .with_effort(RemediationEffort::Low),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Analyze for suspicious behaviors
    #[instrument(skip(self, events))]
    async fn analyze_suspicious_behaviors(
        &self,
        events: &[RuntimeEvent],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for process injection events
        let injection_events: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RuntimeEvent::ProcessEvent(pe)
                    if matches!(pe.event_type, ProcessEventType::Inject) =>
                {
                    Some(pe)
                }
                _ => None,
            })
            .collect();

        if !injection_events.is_empty() {
            findings.push(
                Finding::new(
                    "Process Injection Detected",
                    format!(
                        "{} process injection event(s) were detected during execution. This is a common technique used by malware.",
                        injection_events.len()
                    ),
                )
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Confirmed)
                .with_type("process_injection")
                .with_cwe("CWE-94")
                .with_owasp("M8: Code Tampering")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Process injection is highly suspicious. Investigate the source and purpose of this behavior immediately.")
                        .with_effort(RemediationEffort::Critical),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        // Check for anti-analysis behaviors
        let anti_analysis: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RuntimeEvent::SuspiciousBehavior(sb)
                    if matches!(sb.behavior_type, BehaviorType::AntiAnalysis) =>
                {
                    Some(sb)
                }
                _ => None,
            })
            .collect();

        if !anti_analysis.is_empty() {
            findings.push(
                Finding::new(
                    "Anti-Analysis Behavior Detected",
                    "The application exhibited behaviors consistent with anti-analysis techniques (e.g., debugger detection, emulator detection).".to_string(),
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Probable)
                .with_type("anti_analysis")
                .with_cwe("CWE-507")
                .with_owasp("M8: Code Tampering")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Anti-analysis behaviors are commonly used by malware. Review the purpose of these checks.")
                        .with_effort(RemediationEffort::High),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        // Check for privilege escalation
        let priv_esc: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                RuntimeEvent::SuspiciousBehavior(sb)
                    if matches!(sb.behavior_type, BehaviorType::PrivilegeEscalation) =>
                {
                    Some(sb)
                }
                _ => None,
            })
            .collect();

        if !priv_esc.is_empty() {
            findings.push(
                Finding::new(
                    "Privilege Escalation Attempt",
                    "The application attempted to escalate privileges. This is a serious security concern.".to_string(),
                )
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Confirmed)
                .with_type("privilege_escalation")
                .with_cwe("CWE-250")
                .with_owasp("M1: Improper Platform Usage")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Review privilege escalation attempts. Applications should not attempt to gain elevated privileges.")
                        .with_effort(RemediationEffort::Critical),
                )
                .with_tool("DynamicAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Perform LLM analysis
    #[instrument(skip(self))]
    async fn perform_llm_analysis(&self) -> Result<FindingCollection> {
        let mut findings = Vec::new();

        if let Some(ref llm_client) = self.llm_client {
            let state = self.runtime_state.read().await;

            // Prepare analysis context
            let context = self.prepare_llm_context(&state).await?;

            // Send to LLM for analysis
            let messages = vec![
                sh_llm::Message::system(
                    "You are a security analysis expert. Analyze the following runtime behavior data and identify potential security issues. Respond with a JSON object containing findings.",
                ),
                sh_llm::Message::user(context),
            ];

            match llm_client.chat(messages).await {
                Ok(response) => {
                    // Parse LLM response
                    if let Ok(llm_result) =
                        serde_json::from_str::<LlmAnalysisResult>(&response.content)
                    {
                        for llm_finding in llm_result.findings {
                            findings.push(
                                Finding::new(llm_finding.title, llm_finding.description)
                                    .with_severity(llm_finding.severity)
                                    .with_confidence(llm_finding.confidence)
                                    .with_type(&llm_finding.category)
                                    .with_location(Location::new().with_platform(Platform::Android))
                                    .with_tool("DynamicAgent-LLM", "0.1.0"),
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!("LLM analysis failed: {}", e);
                }
            }
        }

        Ok(FindingCollection::new(findings))
    }

    /// Prepare context for LLM analysis
    async fn prepare_llm_context(&self, state: &RuntimeState) -> Result<String> {
        let api_summary: Vec<String> = state
            .api_calls
            .iter()
            .map(|(api, stats)| {
                format!(
                    "{}: {} calls",
                    api, stats.count
                )
            })
            .collect();

        let network_summary = format!(
            "Network connections: {}, Total bytes sent: {}",
            state.network_connections.len(),
            state.network_connections.iter().map(|c| c.bytes_sent).sum::<u64>()
        );

        let file_summary = format!(
            "File accesses: {} reads, {} writes",
            state.file_accesses.iter().filter(|f| matches!(f.operation, FileOperation::Read)).count(),
            state.file_accesses.iter().filter(|f| matches!(f.operation, FileOperation::Write)).count()
        );

        let context = format!(
            "Runtime Analysis Summary:\n\nAPI Calls:\n{}\n\n{}\n\n{}\n\nPermissions requested: {}\n\nLog entries: {}\n\nData transfers: {}",
            api_summary.join("\n"),
            network_summary,
            file_summary,
            state.permission_requests.len(),
            state.log_entries.len(),
            state.data_transfers.len()
        );

        Ok(context)
    }

    /// Execute with OpenCodeExecutor pattern
    #[instrument(skip(self, context))]
    async fn execute_with_executor(&self, context: &AgentContext) -> Result<AgentResult> {
        let start_time = std::time::Instant::now();

        // Create execution task
        let task = async {
            self.start_monitoring(&context.target).await?;
            
            // Run for the specified duration
            let duration = TokioDuration::from_secs(context.timeout_secs.min(60));
            tokio::time::sleep(duration).await;
            
            // Stop monitoring and get findings
            self.stop_monitoring().await
        };

        // Execute with timeout
        let result = tokio::time::timeout(
            TokioDuration::from_secs(self.executor_config.task_timeout_secs),
            task,
        )
        .await;

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(findings)) => {
                self.base.increment_completed();
                self.base.set_status(AgentStatus::Idle);

                info!(
                    "DynamicAgent completed task: {} with {} findings in {}ms",
                    context.task_id,
                    findings.total_count,
                    execution_time_ms
                );

                Ok(AgentResult::success(
                    context.task_id,
                    self.base.id,
                    findings,
                    execution_time_ms,
                ))
            }
            Ok(Err(e)) => {
                self.base.increment_failed();
                self.base.set_status(AgentStatus::Error);

                error!("DynamicAgent failed task: {} with error: {}", context.task_id, e);

                Ok(AgentResult::failed(context.task_id, self.base.id, e.to_string()))
            }
            Err(_) => {
                self.base.increment_failed();
                self.base.set_status(AgentStatus::Error);

                error!("DynamicAgent task: {} timed out", context.task_id);

                Ok(AgentResult::failed(
                    context.task_id,
                    self.base.id,
                    format!("Task timed out after {} seconds", self.executor_config.task_timeout_secs),
                ))
            }
        }
    }
}

#[async_trait]
impl SecurityAgent for DynamicAgent {
    fn id(&self) -> AgentId {
        self.base.id
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn agent_type(&self) -> AgentType {
        AgentType::Dynamic
    }

    fn capabilities(&self) -> Vec<AgentCapability> {
        self.base.capabilities.clone()
    }

    fn status(&self) -> AgentStatus {
        self.base.get_status()
    }

    fn config(&self) -> &AgentConfig {
        // This is a workaround - in practice, avoid this pattern
        unsafe { &*(self.base.config.read().unwrap() as *const AgentConfig) }
    }

    async fn initialize(&mut self, config: AgentConfig) -> Result<()> {
        info!("Initializing DynamicAgent: {}", self.base.name);

        if let Ok(mut guard) = self.base.config.write() {
            *guard = config;
        }

        // Initialize LLM client
        self.init_llm_client().await?;

        self.base.set_status(AgentStatus::Idle);
        self.base.update_heartbeat();

        info!("DynamicAgent initialized successfully");
        Ok(())
    }

    #[instrument(skip(self, context), fields(agent_id = %self.base.id, task_id = %context.task_id))]
    async fn execute(&self, context: AgentContext) -> Result<AgentResult> {
        let start_time = std::time::Instant::now();

        info!(
            "DynamicAgent executing task: {} on target: {}",
            context.task_id, context.target.path
        );

        self.base.set_status(AgentStatus::Busy);
        self.base.update_heartbeat();

        // Validate target
        if !Path::new(&context.target.path).exists() {
            self.base.increment_failed();
            self.base.set_status(AgentStatus::Idle);
            return Ok(AgentResult::failed(
                context.task_id,
                self.base.id,
                format!("Target not found: {}", context.target.path),
            ));
        }

        // Execute using OpenCodeExecutor pattern
        let result = self.execute_with_executor(&context).await;

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        match result {
            Ok(agent_result) => Ok(agent_result),
            Err(e) => {
                self.base.increment_failed();
                self.base.set_status(AgentStatus::Error);

                error!(
                    "DynamicAgent failed task: {} with error: {}",
                    context.task_id, e
                );

                Ok(AgentResult::failed(context.task_id, self.base.id, e.to_string()))
            }
        }
    }

    async fn health(&self) -> AgentHealth {
        self.base.get_health()
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down DynamicAgent: {}", self.base.name);

        // Stop any ongoing monitoring
        {
            let mut state = self.runtime_state.write().await;
            state.is_running = false;
        }

        self.base.set_status(AgentStatus::Offline);
        Ok(())
    }

    fn update_heartbeat(&self) {
        self.base.update_heartbeat();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_dynamic_agent_creation() {
        let agent = DynamicAgent::new("Test Dynamic Agent");

        assert_eq!(agent.name(), "Test Dynamic Agent");
        assert_eq!(agent.agent_type(), AgentType::Dynamic);
        assert!(agent.has_capability(&AgentCapability::DynamicAnalysis));
        assert!(agent.has_capability(&AgentCapability::Fuzzing));
    }

    #[test]
    fn test_monitored_apis_initialized() {
        let agent = DynamicAgent::new("Test Agent");
        assert!(!agent.monitored_apis.is_empty());
        assert!(agent.monitored_apis.contains(&"java.lang.Runtime.exec".to_string()));
        assert!(agent.monitored_apis.contains(&"android.telephony.SmsManager.sendTextMessage".to_string()));
    }

    #[test]
    fn test_executor_config_default() {
        let config = ExecutorConfig::default();
        assert_eq!(config.max_concurrent_tasks, 5);
        assert_eq!(config.task_timeout_secs, 300);
        assert!(config.enable_retry);
        assert_eq!(config.retry_count, 3);
    }

    #[tokio::test]
    async fn test_dynamic_agent_initialization() {
        let mut agent = DynamicAgent::new("Test Agent");
        let config = AgentConfig::default().with_timeout(600);

        assert!(agent.initialize(config).await.is_ok());
        assert_eq!(agent.status(), AgentStatus::Idle);
    }

    #[tokio::test]
    async fn test_dynamic_agent_health() {
        let agent = DynamicAgent::new("Test Agent");
        let health = agent.health().await;

        assert_eq!(health.agent_id, agent.id());
        assert_eq!(health.status, AgentStatus::Idle);
    }

    #[tokio::test]
    async fn test_runtime_state_default() {
        let state = RuntimeState::default();
        assert!(!state.is_running);
        assert!(state.target_pid.is_none());
        assert!(state.events.is_empty());
        assert!(state.api_calls.is_empty());
    }

    #[test]
    fn test_file_operation_variants() {
        let ops = vec![
            FileOperation::Read,
            FileOperation::Write,
            FileOperation::Delete,
            FileOperation::Execute,
            FileOperation::Create,
            FileOperation::Modify,
        ];
        assert_eq!(ops.len(), 6);
    }

    #[test]
    fn test_memory_protection_variants() {
        let protections = vec![
            MemoryProtection::Read,
            MemoryProtection::Write,
            MemoryProtection::Execute,
            MemoryProtection::ReadWrite,
            MemoryProtection::ReadExecute,
            MemoryProtection::ReadWriteExecute,
        ];
        assert_eq!(protections.len(), 6);
    }

    #[test]
    fn test_behavior_type_variants() {
        let behaviors = vec![
            BehaviorType::PrivilegeEscalation,
            BehaviorType::CodeInjection,
            BehaviorType::DataExfiltration,
            BehaviorType::Persistence,
            BehaviorType::AntiAnalysis,
            BehaviorType::SuspiciousApi,
            BehaviorType::NetworkAnomaly,
            BehaviorType::PermissionAbuse,
            BehaviorType::FileTampering,
            BehaviorType::MemoryManipulation,
        ];
        assert_eq!(behaviors.len(), 10);
    }

    #[test]
    fn test_data_direction_variants() {
        let directions = vec![
            DataDirection::Upload,
            DataDirection::Download,
            DataDirection::Sync,
        ];
        assert_eq!(directions.len(), 3);
    }

    #[test]
    fn test_log_level_variants() {
        let levels = vec![
            LogLevel::Verbose,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warning,
            LogLevel::Error,
            LogLevel::Assert,
        ];
        assert_eq!(levels.len(), 6);
    }

    #[test]
    fn test_process_event_type_variants() {
        let types = vec![
            ProcessEventType::Start,
            ProcessEventType::Exit,
            ProcessEventType::Fork,
            ProcessEventType::Inject,
            ProcessEventType::Suspend,
            ProcessEventType::Resume,
        ];
        assert_eq!(types.len(), 6);
    }

    #[test]
    fn test_memory_operation_variants() {
        let ops = vec![
            MemoryOperation::Allocate,
            MemoryOperation::Free,
            MemoryOperation::Read,
            MemoryOperation::Write,
            MemoryOperation::Execute,
            MemoryOperation::Protect,
        ];
        assert_eq!(ops.len(), 6);
    }

    #[test]
    fn test_connection_type_variants() {
        let types = vec![
            ConnectionType::Outbound,
            ConnectionType::Inbound,
            ConnectionType::PeerToPeer,
        ];
        assert_eq!(types.len(), 3);
    }

    #[tokio::test]
    async fn test_permission_monitor_initialization() {
        let monitor = DynamicAgent::init_permission_monitor();
        assert!(!monitor.dangerous_permissions.is_empty());
        assert!(monitor.dangerous_permissions.contains("android.permission.READ_CONTACTS"));
        assert!(!monitor.abuse_patterns.is_empty());
    }

    #[tokio::test]
    async fn test_network_analyzer_initialization() {
        let analyzer = DynamicAgent::init_network_analyzer();
        assert!(!analyzer.suspicious_ports.is_empty());
        assert!(analyzer.suspicious_ports.contains_key(&4444));
        assert!(!analyzer.known_bad_hosts.is_empty());
        assert!(!analyzer.connection_patterns.is_empty());
    }

    #[tokio::test]
    async fn test_file_system_tracker_initialization() {
        let tracker = DynamicAgent::init_file_system_tracker();
        assert!(!tracker.sensitive_paths.is_empty());
        assert!(tracker.file_hashes.is_empty());
        assert!(!tracker.access_patterns.is_empty());
    }

    #[tokio::test]
    async fn test_memory_analyzer_initialization() {
        let analyzer = DynamicAgent::init_memory_analyzer();
        assert!(analyzer.executable_regions.is_empty());
        assert!(!analyzer.injection_patterns.is_empty());
        assert_eq!(analyzer.heap_spray_threshold, 100 * 1024 * 1024);
    }

    #[tokio::test]
    async fn test_api_tracer_initialization() {
        let tracer = DynamicAgent::init_api_tracer();
        assert!(!tracer.dangerous_apis.is_empty());
        assert!(tracer.api_sequences.is_empty());
        assert!(tracer.call_stack.is_empty());
    }

    #[tokio::test]
    async fn test_log_analyzer_initialization() {
        let analyzer = DynamicAgent::init_log_analyzer();
        assert!(!analyzer.sensitive_patterns.is_empty());
        assert_eq!(analyzer.error_threshold, 10);
        assert_eq!(analyzer.warning_threshold, 50);
    }

    #[tokio::test]
    async fn test_detect_suspicious_sequence() {
        let agent = DynamicAgent::new("Test Agent");
        
        // Test with data collection + network pattern
        let suspicious_seq = vec![
            "android.content.ContentResolver.query".to_string(),
            "java.net.URL.openConnection".to_string(),
        ];
        assert!(agent.detect_suspicious_sequence(&suspicious_seq).await.unwrap());

        // Test without suspicious pattern
        let normal_seq = vec![
            "java.lang.StringBuilder".to_string(),
            "java.lang.System.currentTimeMillis".to_string(),
        ];
        assert!(!agent.detect_suspicious_sequence(&normal_seq).await.unwrap());
    }

    #[tokio::test]
    async fn test_analyze_api_calls_empty() {
        let agent = DynamicAgent::new("Test Agent");
        let api_calls = HashMap::new();
        let findings = agent.analyze_api_calls(&api_calls).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_file_accesses_empty() {
        let agent = DynamicAgent::new("Test Agent");
        let file_accesses = Vec::new();
        let findings = agent.analyze_file_accesses(&file_accesses).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_network_activity_empty() {
        let agent = DynamicAgent::new("Test Agent");
        let connections = Vec::new();
        let findings = agent.analyze_network_activity(&connections).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_memory_patterns_empty() {
        let agent = DynamicAgent::new("Test Agent");
        let allocations = Vec::new();
        let findings = agent.analyze_memory_patterns(&allocations).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_permission_usage_empty() {
        let agent = DynamicAgent::new("Test Agent");
        let permissions = Vec::new();
        let findings = agent.analyze_permission_usage(&permissions).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_log_entries_empty() {
        let agent = DynamicAgent::new("Test Agent");
        let log_entries = Vec::new();
        let findings = agent.analyze_log_entries(&log_entries).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_data_transfers_empty() {
        let agent = DynamicAgent::new("Test Agent");
        let transfers = Vec::new();
        let findings = agent.analyze_data_transfers(&transfers).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_suspicious_behaviors_empty() {
        let agent = DynamicAgent::new("Test Agent");
        let events = Vec::new();
        let findings = agent.analyze_suspicious_behaviors(&events).await.unwrap();
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_prepare_llm_context() {
        let agent = DynamicAgent::new("Test Agent");
        let state = RuntimeState::default();
        
        let context = agent.prepare_llm_context(&state).await.unwrap();
        assert!(context.contains("Runtime Analysis Summary"));
        assert!(context.contains("API Calls"));
        assert!(context.contains("Network connections"));
    }

    #[test]
    fn test_api_call_stats_default() {
        let stats = ApiCallStats::default();
        assert_eq!(stats.count, 0);
        assert!(stats.first_seen.is_none());
        assert!(stats.last_seen.is_none());
        assert!(stats.parameters.is_empty());
    }

    #[test]
    fn test_permission_usage_stats_default() {
        let stats = PermissionUsageStats::default();
        assert_eq!(stats.request_count, 0);
        assert_eq!(stats.grant_count, 0);
        assert_eq!(stats.deny_count, 0);
        assert!(stats.last_used.is_none());
        assert!(stats.contexts.is_empty());
    }

    #[test]
    fn test_serialize_runtime_event() {
        let event = RuntimeEvent::ApiCall(ApiCallEvent {
            timestamp: Utc::now(),
            api_name: "test.api".to_string(),
            parameters: vec!["param1".to_string()],
            return_value: None,
            stack_trace: None,
            thread_id: 1,
            duration_us: 100,
        });

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("api_call"));
        assert!(json.contains("test.api"));
    }

    #[test]
    fn test_serialize_file_access_event() {
        let event = FileAccessEvent {
            timestamp: Utc::now(),
            operation: FileOperation::Read,
            path: "/test/path".to_string(),
            size: Some(1024),
            process_id: 1234,
            thread_id: 1,
            is_sensitive: false,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("read"));
        assert!(json.contains("/test/path"));
    }

    #[test]
    fn test_serialize_network_connection() {
        let conn = NetworkConnection {
            timestamp: Utc::now(),
            destination: "example.com".to_string(),
            port: 443,
            protocol: "HTTPS".to_string(),
            bytes_sent: 1024,
            bytes_received: 2048,
            is_encrypted: true,
            duration_ms: 100,
            connection_type: ConnectionType::Outbound,
        };

        let json = serde_json::to_string(&conn).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("443"));
        assert!(json.contains("outbound"));
    }

    #[test]
    fn test_serialize_memory_allocation() {
        let alloc = MemoryAllocation {
            timestamp: Utc::now(),
            size: 1024,
            address: "0x7fff0000".to_string(),
            operation: MemoryOperation::Allocate,
            protection: MemoryProtection::ReadWrite,
            is_executable: false,
        };

        let json = serde_json::to_string(&alloc).unwrap();
        assert!(json.contains("allocate"));
        assert!(json.contains("read_write"));
    }

    #[test]
    fn test_serialize_permission_request() {
        let perm = PermissionRequest {
            timestamp: Utc::now(),
            permission: "android.permission.CAMERA".to_string(),
            granted: true,
            context: "Photo capture".to_string(),
            is_dangerous: true,
            usage_count: 5,
        };

        let json = serde_json::to_string(&perm).unwrap();
        assert!(json.contains("CAMERA"));
        assert!(json.contains("Photo capture"));
    }

    #[test]
    fn test_serialize_log_entry() {
        let log = LogEntry {
            timestamp: Utc::now(),
            level: LogLevel::Error,
            tag: "TestTag".to_string(),
            message: "Test error message".to_string(),
            is_sensitive: false,
        };

        let json = serde_json::to_string(&log).unwrap();
        assert!(json.contains("error"));
        assert!(json.contains("TestTag"));
    }

    #[test]
    fn test_serialize_data_transfer() {
        let transfer = DataTransferEvent {
            timestamp: Utc::now(),
            direction: DataDirection::Upload,
            destination: "api.example.com".to_string(),
            data_type: "JSON".to_string(),
            size_bytes: 1024,
            is_encrypted: true,
            is_compressed: false,
        };

        let json = serde_json::to_string(&transfer).unwrap();
        assert!(json.contains("upload"));
        assert!(json.contains("api.example.com"));
    }

    #[test]
    fn test_serialize_suspicious_behavior() {
        let behavior = SuspiciousBehavior {
            timestamp: Utc::now(),
            behavior_type: BehaviorType::DataExfiltration,
            description: "Large data upload detected".to_string(),
            severity: Severity::High,
            evidence: vec!["10MB uploaded".to_string()],
            confidence: Confidence::Probable,
        };

        let json = serde_json::to_string(&behavior).unwrap();
        assert!(json.contains("data_exfiltration"));
        assert!(json.contains("Large data upload"));
    }

    #[test]
    fn test_serialize_process_event() {
        let event = ProcessEvent {
            timestamp: Utc::now(),
            event_type: ProcessEventType::Start,
            process_id: 1234,
            parent_id: Some(1),
            command_line: Some("/bin/test".to_string()),
            process_name: "test".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("start"));
        assert!(json.contains("test"));
    }

    #[test]
    fn test_llm_analysis_result_serialization() {
        let result = LlmAnalysisResult {
            findings: vec![LlmFinding {
                title: "Test Finding".to_string(),
                description: "Test description".to_string(),
                severity: Severity::High,
                confidence: Confidence::Confirmed,
                category: "test".to_string(),
                evidence: vec!["evidence1".to_string()],
            }],
            risk_score: 7.5,
            summary: "Test summary".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("Test Finding"));
        assert!(json.contains("7.5"));
    }
}
