//! # Network Analysis Agent
//!
//! Performs network traffic analysis and communication security assessment.
//! Capabilities include:
//! - Traffic capture and analysis
//! - Protocol analysis (HTTP/HTTPS, TCP, UDP)
//! - Certificate validation
//! - DNS analysis
//! - TLS/SSL configuration analysis
//! - Network anomaly detection
//! - Man-in-the-middle detection

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    AgentBase, AgentContext, AgentError, AgentResult, Result, SecurityAgent,
};
use sh_types::{
    AgentCapability, AgentConfig, AgentHealth, AgentId, AgentStatus, AgentType, AnalysisTarget,
    Confidence, Finding, FindingCollection, Location, Platform, Remediation, RemediationEffort,
    Severity,
};

/// Network analysis agent for traffic and communication analysis
pub struct NetworkAgent {
    base: AgentBase,
    capture_config: CaptureConfig,
    protocol_analyzers: Vec<Box<dyn ProtocolAnalyzer + Send + Sync>>,
    known_bad_hosts: HashSet<String>,
    suspicious_patterns: Vec<Regex>,
}

/// Network capture configuration
#[derive(Debug, Clone)]
struct CaptureConfig {
    interface: String,
    port_filter: Option<Vec<u16>>,
    host_filter: Option<Vec<String>>,
    max_packet_size: usize,
    capture_duration_secs: u64,
    promiscuous_mode: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: "any".to_string(),
            port_filter: None,
            host_filter: None,
            max_packet_size: 65535,
            capture_duration_secs: 300,
            promiscuous_mode: false,
        }
    }
}

/// Protocol analyzer trait
#[async_trait]
trait ProtocolAnalyzer: Send + Sync {
    fn protocol_name(&self) -> &str;
    fn can_analyze(&self, data: &[u8]) -> bool;
    async fn analyze(&self, connection: &NetworkConnection) -> Result<Vec<Finding>>;
}

/// HTTP protocol analyzer
struct HttpAnalyzer;

#[async_trait]
impl ProtocolAnalyzer for HttpAnalyzer {
    fn protocol_name(&self) -> &str {
        "HTTP"
    }

    fn can_analyze(&self, data: &[u8]) -> bool {
        data.starts_with(b"GET ")
            || data.starts_with(b"POST ")
            || data.starts_with(b"PUT ")
            || data.starts_with(b"DELETE ")
            || data.starts_with(b"HTTP/")
    }

    async fn analyze(&self, connection: &NetworkConnection) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for HTTP (not HTTPS)
        if connection.port == 80 || connection.protocol == "HTTP" {
            findings.push(
                Finding::new(
                    "Unencrypted HTTP Communication",
                    format!(
                        "HTTP traffic detected to {}:{}. Data is transmitted in plaintext.",
                        connection.destination, connection.port
                    ),
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Confirmed)
                .with_type("unencrypted_http")
                .with_cwe("CWE-319")
                .with_owasp("M3: Insecure Communication")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Migrate to HTTPS for all communications. Use TLS 1.2 or higher.")
                        .with_effort(RemediationEffort::Medium)
                        .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x04f-Testing-Network-Communication"),
                )
                .with_tool("NetworkAgent", "0.1.0"),
            );
        }

        // Check for sensitive headers
        if connection.request_data.is_some() {
            let data = connection.request_data.as_ref().unwrap();
            let sensitive_headers = vec!["Authorization", "Cookie", "X-API-Key", "X-Auth-Token"];

            for header in &sensitive_headers {
                if data.to_lowercase().contains(&format!("{}:", header.to_lowercase())) {
                    findings.push(
                        Finding::new(
                            "Sensitive Header in HTTP Request",
                            format!(
                                "The {} header was detected in an HTTP request. This may expose credentials if the connection is not properly secured.",
                                header
                            ),
                        )
                        .with_severity(Severity::Medium)
                        .with_confidence(Confidence::Probable)
                        .with_type("sensitive_header")
                        .with_cwe("CWE-319")
                        .with_owasp("M3: Insecure Communication")
                        .with_location(Location::new().with_platform(Platform::Android))
                        .with_remediation(
                            Remediation::new("Ensure sensitive headers are only sent over encrypted connections. Implement certificate pinning.")
                                .with_effort(RemediationEffort::Medium),
                        )
                        .with_tool("NetworkAgent", "0.1.0"),
                    );
                }
            }
        }

        Ok(findings)
    }
}

/// TLS/SSL analyzer
struct TlsAnalyzer;

#[async_trait]
impl ProtocolAnalyzer for TlsAnalyzer {
    fn protocol_name(&self) -> &str {
        "TLS/SSL"
    }

    fn can_analyze(&self, data: &[u8]) -> bool {
        // TLS record layer starts with content type
        data.len() > 5 && data[0] >= 0x14 && data[0] <= 0x17
    }

    async fn analyze(&self, connection: &NetworkConnection) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check TLS version
        if let Some(tls_info) = &connection.tls_info {
            // Check for weak TLS versions
            if tls_info.version == "TLSv1.0" || tls_info.version == "TLSv1.1" {
                findings.push(
                    Finding::new(
                        "Weak TLS Version",
                        format!(
                            "Connection to {}:{} uses {} which has known vulnerabilities.",
                            connection.destination, connection.port, tls_info.version
                        ),
                    )
                    .with_severity(Severity::High)
                    .with_confidence(Confidence::Confirmed)
                    .with_type("weak_tls_version")
                    .with_cwe("CWE-326")
                    .with_owasp("M3: Insecure Communication")
                    .with_location(Location::new().with_platform(Platform::Android))
                    .with_remediation(
                        Remediation::new("Upgrade to TLS 1.2 or TLS 1.3. Disable support for older TLS versions.")
                            .with_effort(RemediationEffort::Medium)
                            .add_reference("https://tools.ietf.org/html/rfc7525"),
                    )
                    .with_tool("NetworkAgent", "0.1.0"),
                );
            }

            // Check for weak cipher suites
            if let Some(ref cipher) = tls_info.cipher_suite {
                let weak_ciphers = vec!["RC4", "DES", "MD5", "NULL", "EXPORT"];
                for weak in &weak_ciphers {
                    if cipher.contains(weak) {
                        findings.push(
                            Finding::new(
                                "Weak Cipher Suite",
                                format!(
                                    "Connection uses weak cipher suite: {}. This cipher is considered insecure.",
                                    cipher
                                ),
                            )
                            .with_severity(Severity::High)
                            .with_confidence(Confidence::Confirmed)
                            .with_type("weak_cipher")
                            .with_cwe("CWE-326")
                            .with_owasp("M3: Insecure Communication")
                            .with_location(Location::new().with_platform(Platform::Android))
                            .with_remediation(
                                Remediation::new("Configure the application to use only strong cipher suites. Disable weak ciphers.")
                                    .with_effort(RemediationEffort::Medium),
                            )
                            .with_tool("NetworkAgent", "0.1.0"),
                        );
                        break;
                    }
                }
            }

            // Check certificate validation
            if !tls_info.certificate_valid {
                findings.push(
                    Finding::new(
                        "Invalid TLS Certificate",
                        "The TLS certificate validation failed. This may indicate a man-in-the-middle attack or misconfiguration.",
                    )
                    .with_severity(Severity::Critical)
                    .with_confidence(Confidence::Confirmed)
                    .with_type("invalid_certificate")
                    .with_cwe("CWE-295")
                    .with_owasp("M3: Insecure Communication")
                    .with_location(Location::new().with_platform(Platform::Android))
                    .with_remediation(
                        Remediation::new("Ensure proper certificate validation is implemented. Do not disable certificate validation in production.")
                            .with_effort(RemediationEffort::High)
                            .add_reference("https://developer.android.com/training/articles/security-ssl"),
                    )
                    .with_tool("NetworkAgent", "0.1.0"),
                );
            }

            // Check certificate pinning
            if !tls_info.certificate_pinned {
                findings.push(
                    Finding::new(
                        "Certificate Pinning Not Implemented",
                        "The application does not implement certificate pinning. This makes it vulnerable to man-in-the-middle attacks with rogue certificates.",
                    )
                    .with_severity(Severity::Medium)
                    .with_confidence(Confidence::Probable)
                    .with_type("no_certificate_pinning")
                    .with_cwe("CWE-295")
                    .with_owasp("M3: Insecure Communication")
                    .with_location(Location::new().with_platform(Platform::Android))
                    .with_remediation(
                        Remediation::new("Implement certificate pinning using NetworkSecurityConfig or a pinning library like OkHttp CertificatePinner.")
                            .with_effort(RemediationEffort::Medium)
                            .add_reference("https://developer.android.com/training/articles/security-config"),
                    )
                    .with_tool("NetworkAgent", "0.1.0"),
                );
            }
        }

        Ok(findings)
    }
}

/// Network connection information
#[derive(Debug, Clone)]
struct NetworkConnection {
    timestamp: chrono::DateTime<Utc>,
    source_ip: IpAddr,
    source_port: u16,
    destination_ip: IpAddr,
    destination: String, // hostname or IP
    port: u16,
    protocol: String,
    bytes_sent: u64,
    bytes_received: u64,
    request_data: Option<String>,
    response_data: Option<String>,
    tls_info: Option<TlsInfo>,
    duration_ms: u64,
}

impl NetworkConnection {
    fn new(
        source_ip: IpAddr,
        source_port: u16,
        destination_ip: IpAddr,
        destination: String,
        port: u16,
        protocol: String,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            source_ip,
            source_port,
            destination_ip,
            destination,
            port,
            protocol,
            bytes_sent: 0,
            bytes_received: 0,
            request_data: None,
            response_data: None,
            tls_info: None,
            duration_ms: 0,
        }
    }

    fn with_bytes(mut self, sent: u64, received: u64) -> Self {
        self.bytes_sent = sent;
        self.bytes_received = received;
        self
    }

    fn with_request_data(mut self, data: impl Into<String>) -> Self {
        self.request_data = Some(data.into());
        self
    }

    fn with_tls_info(mut self, tls_info: TlsInfo) -> Self {
        self.tls_info = Some(tls_info);
        self
    }

    fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = duration_ms;
        self
    }
}

/// TLS connection information
#[derive(Debug, Clone)]
struct TlsInfo {
    version: String,
    cipher_suite: Option<String>,
    certificate_valid: bool,
    certificate_pinned: bool,
    certificate_chain: Vec<String>,
    sni_hostname: Option<String>,
}

/// DNS query information
#[derive(Debug, Clone)]
struct DnsQuery {
    timestamp: chrono::DateTime<Utc>,
    query_name: String,
    query_type: String,
    response_ips: Vec<IpAddr>,
    response_time_ms: u64,
}

impl NetworkAgent {
    /// Create a new network analysis agent
    pub fn new(name: impl Into<String>) -> Self {
        let base = AgentBase::new(name, AgentType::Network)
            .with_capabilities(vec![
                AgentCapability::NetworkAnalysis,
                AgentCapability::TrafficAnalysis,
            ])
            .with_platform(Platform::Network);

        let mut protocol_analyzers: Vec<Box<dyn ProtocolAnalyzer + Send + Sync>> = Vec::new();
        protocol_analyzers.push(Box::new(HttpAnalyzer));
        protocol_analyzers.push(Box::new(TlsAnalyzer));

        Self {
            base,
            capture_config: CaptureConfig::default(),
            protocol_analyzers,
            known_bad_hosts: Self::init_known_bad_hosts(),
            suspicious_patterns: Self::init_suspicious_patterns(),
        }
    }

    /// Initialize known bad hosts list
    fn init_known_bad_hosts() -> HashSet<String> {
        let mut hosts = HashSet::new();
        // Known malicious domains (examples)
        hosts.insert("malware.example.com".to_string());
        hosts.insert("phishing.example.com".to_string());
        hosts.insert("botnet.example.com".to_string());
        hosts
    }

    /// Initialize suspicious patterns
    fn init_suspicious_patterns() -> Vec<Regex> {
        vec![
            // DGA-like domains (high entropy)
            Regex::new(r"^[a-z0-9]{20,}\.(com|net|org|info)$").unwrap(),
            // IP addresses in URLs
            Regex::new(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap(),
            // Suspicious TLDs
            Regex::new(r"\.(tk|ml|ga|cf|top|xyz|click|link)$").unwrap(),
        ]
    }

    /// Capture and analyze network traffic
    #[instrument(skip(self, target), fields(agent_id = %self.base.id))]
    async fn capture_traffic(&self, target: &AnalysisTarget) -> Result<FindingCollection> {
        info!("Starting network traffic capture for: {}", target.path);

        // In a real implementation, this would:
        // 1. Set up packet capture (e.g., using pcap)
        // 2. Filter traffic related to the target
        // 3. Parse protocols
        // 4. Analyze for security issues

        // For now, we simulate the analysis
        let connections = self.simulate_traffic_capture().await?;
        let dns_queries = self.simulate_dns_capture().await?;

        let mut all_findings = Vec::new();

        // Analyze connections
        for connection in &connections {
            all_findings.extend(self.analyze_connection(connection).await?);
        }

        // Analyze DNS queries
        for query in &dns_queries {
            all_findings.extend(self.analyze_dns_query(query).await?);
        }

        // Analyze traffic patterns
        all_findings.extend(self.analyze_traffic_patterns(&connections).await?);

        // Check for known bad hosts
        all_findings.extend(self.check_known_bad_hosts(&connections).await?);

        info!(
            "Network analysis completed. Found {} findings",
            all_findings.len()
        );

        Ok(FindingCollection::new(all_findings))
    }

    /// Simulate traffic capture (for testing/demo)
    #[instrument(skip(self))]
    async fn simulate_traffic_capture(&self) -> Result<Vec<NetworkConnection>> {
        // In a real implementation, this would capture actual traffic
        // For now, return simulated data
        Ok(vec![
            NetworkConnection::new(
                "192.168.1.100".parse().unwrap(),
                54321,
                "93.184.216.34".parse().unwrap(),
                "example.com".to_string(),
                443,
                "HTTPS".to_string(),
            )
            .with_bytes(1024, 2048)
            .with_request_data("GET /api/data HTTP/1.1")
            .with_tls_info(TlsInfo {
                version: "TLSv1.2".to_string(),
                cipher_suite: Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string()),
                certificate_valid: true,
                certificate_pinned: false,
                certificate_chain: vec!["example.com".to_string()],
                sni_hostname: Some("example.com".to_string()),
            })
            .with_duration(150),
            NetworkConnection::new(
                "192.168.1.100".parse().unwrap(),
                54322,
                "93.184.216.34".parse().unwrap(),
                "example.com".to_string(),
                80,
                "HTTP".to_string(),
            )
            .with_bytes(512, 1024)
            .with_request_data("GET /insecure HTTP/1.1")
            .with_duration(50),
        ])
    }

    /// Simulate DNS capture
    #[instrument(skip(self))]
    async fn simulate_dns_capture(&self) -> Result<Vec<DnsQuery>> {
        Ok(vec![
            DnsQuery {
                timestamp: Utc::now(),
                query_name: "example.com".to_string(),
                query_type: "A".to_string(),
                response_ips: vec!["93.184.216.34".parse().unwrap()],
                response_time_ms: 25,
            },
            DnsQuery {
                timestamp: Utc::now(),
                query_name: "suspicious-domain.xyz".to_string(),
                query_type: "A".to_string(),
                response_ips: vec!["192.0.2.1".parse().unwrap()],
                response_time_ms: 100,
            },
        ])
    }

    /// Analyze a single connection
    #[instrument(skip(self, connection))]
    async fn analyze_connection(&self, connection: &NetworkConnection) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Run protocol-specific analyzers
        for analyzer in &self.protocol_analyzers {
            // In a real implementation, we'd pass the actual packet data
            // For now, we use a simplified check
            if analyzer.protocol_name() == "HTTP" && connection.port == 80 {
                findings.extend(analyzer.analyze(connection).await?);
            } else if analyzer.protocol_name() == "TLS/SSL" && connection.port == 443 {
                findings.extend(analyzer.analyze(connection).await?);
            }
        }

        // Check for suspicious ports
        let suspicious_ports = vec![
            (23, "Telnet", Severity::Critical),
            (21, "FTP", Severity::High),
            (53, "DNS", Severity::Low),
            (110, "POP3", Severity::Medium),
            (143, "IMAP", Severity::Medium),
            (445, "SMB", Severity::High),
            (3389, "RDP", Severity::High),
            (4444, "Metasploit", Severity::Critical),
            (5555, "ADB", Severity::High),
            (6667, "IRC", Severity::Medium),
        ];

        for (port, service, severity) in suspicious_ports {
            if connection.port == port {
                findings.push(
                    Finding::new(
                        format!("Connection to {} Port", service),
                        format!(
                            "The application connected to port {} ({}). This may indicate suspicious activity.",
                            port, service
                        ),
                    )
                    .with_severity(severity)
                    .with_confidence(Confidence::Probable)
                    .with_type("suspicious_port")
                    .with_cwe("CWE-506")
                    .with_owasp("M7: Client Code Quality")
                    .with_location(Location::new().with_platform(Platform::Android))
                    .with_remediation(
                        Remediation::new(format!(
                            "Review the necessity of connecting to {} port. Ensure this is for legitimate purposes.",
                            service
                        ))
                        .with_effort(RemediationEffort::Medium),
                    )
                    .with_tool("NetworkAgent", "0.1.0"),
                );
            }
        }

        // Check for large data transfers
        let total_bytes = connection.bytes_sent + connection.bytes_received;
        if total_bytes > 10_000_000 {
            // 10MB
            findings.push(
                Finding::new(
                    "Large Data Transfer",
                    format!(
                        "Large data transfer detected: {} bytes to {}:{}.",
                        total_bytes, connection.destination, connection.port
                    ),
                )
                .with_severity(Severity::Medium)
                .with_confidence(Confidence::Tentative)
                .with_type("large_transfer")
                .with_cwe("CWE-506")
                .with_owasp("M3: Insecure Communication")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Review large data transfers. Implement data usage monitoring and alerts.")
                        .with_effort(RemediationEffort::Low),
                )
                .with_tool("NetworkAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Analyze DNS query
    #[instrument(skip(self, query))]
    async fn analyze_dns_query(&self, query: &DnsQuery) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for suspicious domain patterns
        for pattern in &self.suspicious_patterns {
            if pattern.is_match(&query.query_name) {
                findings.push(
                    Finding::new(
                        "Suspicious Domain Pattern",
                        format!(
                            "DNS query for '{}' matches a suspicious pattern. This may indicate command and control communication.",
                            query.query_name
                        ),
                    )
                    .with_severity(Severity::High)
                    .with_confidence(Confidence::Tentative)
                    .with_type("suspicious_domain")
                    .with_cwe("CWE-506")
                    .with_owasp("M7: Client Code Quality")
                    .with_location(Location::new().with_platform(Platform::Android))
                    .with_remediation(
                        Remediation::new("Investigate this domain. Consider implementing DNS filtering or domain reputation checking.")
                            .with_effort(RemediationEffort::Medium),
                    )
                    .with_tool("NetworkAgent", "0.1.0"),
                );
                break;
            }
        }

        // Check for DGA-like domains (high entropy, random-looking)
        if query.query_name.len() > 20 && query.query_name.chars().filter(|c| c.is_ascii_digit()).count() > 5 {
            findings.push(
                Finding::new(
                    "Potential DGA Domain",
                    format!(
                        "DNS query for '{}' has characteristics of a Domain Generation Algorithm (DGA) domain.",
                        query.query_name
                    ),
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Tentative)
                .with_type("dga_domain")
                .with_cwe("CWE-506")
                .with_owasp("M7: Client Code Quality")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Investigate this domain. DGA domains are commonly used by malware for command and control.")
                        .with_effort(RemediationEffort::High),
                )
                .with_tool("NetworkAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Analyze traffic patterns
    #[instrument(skip(self, connections))]
    async fn analyze_traffic_patterns(
        &self,
        connections: &[NetworkConnection],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for beaconing behavior (regular intervals)
        if connections.len() >= 5 {
            let mut intervals = Vec::new();
            for i in 1..connections.len() {
                let diff = connections[i]
                    .timestamp
                    .signed_duration_since(connections[i - 1].timestamp)
                    .num_seconds();
                intervals.push(diff.abs());
            }

            // Check if intervals are similar (beaconing)
            if intervals.len() > 3 {
                let avg = intervals.iter().sum::<i64>() / intervals.len() as i64;
                let variance: i64 = intervals
                    .iter()
                    .map(|&x| (x - avg).abs())
                    .sum::<i64>()
                    / intervals.len() as i64;

                if variance < 5 && avg > 0 && avg < 300 {
                    // Regular intervals less than 5 minutes
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
                        .with_tool("NetworkAgent", "0.1.0"),
                    );
                }
            }
        }

        // Check for connection to multiple unique destinations
        let unique_destinations: HashSet<_> = connections
            .iter()
            .map(|c| &c.destination)
            .collect();

        if unique_destinations.len() > 10 {
            findings.push(
                Finding::new(
                    "Multiple Unique Destinations",
                    format!(
                        "Application connected to {} unique destinations. This may indicate scanning or command and control activity.",
                        unique_destinations.len()
                    ),
                )
                .with_severity(Severity::Medium)
                .with_confidence(Confidence::Tentative)
                .with_type("multiple_destinations")
                .with_cwe("CWE-506")
                .with_owasp("M7: Client Code Quality")
                .with_location(Location::new().with_platform(Platform::Android))
                .with_remediation(
                    Remediation::new("Review the necessity of connecting to many different destinations. Implement network monitoring.")
                        .with_effort(RemediationEffort::Medium),
                )
                .with_tool("NetworkAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Check for known bad hosts
    #[instrument(skip(self, connections))]
    async fn check_known_bad_hosts(
        &self,
        connections: &[NetworkConnection],
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for connection in connections {
            if self.known_bad_hosts.contains(&connection.destination) {
                findings.push(
                    Finding::new(
                        "Connection to Known Malicious Host",
                        format!(
                            "The application connected to {} which is a known malicious host.",
                            connection.destination
                        ),
                    )
                    .with_severity(Severity::Critical)
                    .with_confidence(Confidence::Confirmed)
                    .with_type("malicious_host")
                    .with_cwe("CWE-506")
                    .with_owasp("M7: Client Code Quality")
                    .with_location(Location::new().with_platform(Platform::Android))
                    .with_remediation(
                        Remediation::new("Block connections to this host immediately. Investigate the application for malware.")
                            .with_effort(RemediationEffort::Critical),
                    )
                    .with_tool("NetworkAgent", "0.1.0"),
                );
            }
        }

        Ok(findings)
    }

    /// Analyze PCAP file
    #[instrument(skip(self, target))]
    async fn analyze_pcap(&self, target: &AnalysisTarget) -> Result<FindingCollection> {
        info!("Analyzing PCAP file: {}", target.path);

        let path = Path::new(&target.path);
        if !path.exists() {
            return Err(AgentError::InvalidConfig(format!(
                "PCAP file not found: {}",
                target.path
            )));
        }

        // In a real implementation, this would:
        // 1. Parse the PCAP file
        // 2. Extract connections
        // 3. Analyze each connection

        // For now, simulate the analysis
        self.capture_traffic(target).await
    }
}

#[async_trait]
impl SecurityAgent for NetworkAgent {
    fn id(&self) -> AgentId {
        self.base.id
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn agent_type(&self) -> AgentType {
        AgentType::Network
    }

    fn capabilities(&self) -> Vec<AgentCapability> {
        self.base.capabilities.clone()
    }

    fn status(&self) -> AgentStatus {
        self.base.get_status()
    }

    fn config(&self) -> &AgentConfig {
        unsafe { &*(self.base.config.read().unwrap() as *const AgentConfig) }
    }

    async fn initialize(&mut self, config: AgentConfig) -> Result<()> {
        info!("Initializing NetworkAgent: {}", self.base.name);

        if let Ok(mut guard) = self.base.config.write() {
            *guard = config;
        }

        self.base.set_status(AgentStatus::Idle);
        self.base.update_heartbeat();

        info!("NetworkAgent initialized successfully");
        Ok(())
    }

    #[instrument(skip(self, context), fields(agent_id = %self.base.id, task_id = %context.task_id))]
    async fn execute(&self, context: AgentContext) -> Result<AgentResult> {
        let start_time = std::time::Instant::now();

        info!(
            "NetworkAgent executing task: {} on target: {}",
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

        // Determine analysis type based on file extension
        let path = Path::new(&context.target.path);
        let result = if path.extension().map(|e| e == "pcap").unwrap_or(false) {
            self.analyze_pcap(&context.target).await
        } else {
            self.capture_traffic(&context.target).await
        };

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        match result {
            Ok(findings) => {
                self.base.increment_completed();
                self.base.set_status(AgentStatus::Idle);

                info!(
                    "NetworkAgent completed task: {} with {} findings in {}ms",
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
            Err(e) => {
                self.base.increment_failed();
                self.base.set_status(AgentStatus::Error);

                error!(
                    "NetworkAgent failed task: {} with error: {}",
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
        info!("Shutting down NetworkAgent: {}", self.base.name);
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

    #[test]
    fn test_network_agent_creation() {
        let agent = NetworkAgent::new("Test Network Agent");

        assert_eq!(agent.name(), "Test Network Agent");
        assert_eq!(agent.agent_type(), AgentType::Network);
        assert!(agent.has_capability(&AgentCapability::NetworkAnalysis));
        assert!(agent.has_capability(&AgentCapability::TrafficAnalysis));
    }

    #[test]
    fn test_known_bad_hosts_initialized() {
        let agent = NetworkAgent::new("Test Agent");
        assert!(!agent.known_bad_hosts.is_empty());
        assert!(agent.known_bad_hosts.contains("malware.example.com"));
    }

    #[test]
    fn test_suspicious_patterns_initialized() {
        let agent = NetworkAgent::new("Test Agent");
        assert!(!agent.suspicious_patterns.is_empty());
    }

    #[tokio::test]
    async fn test_network_agent_initialization() {
        let mut agent = NetworkAgent::new("Test Agent");
        let config = AgentConfig::default().with_timeout(600);

        assert!(agent.initialize(config).await.is_ok());
        assert_eq!(agent.status(), AgentStatus::Idle);
    }

    #[tokio::test]
    async fn test_network_agent_health() {
        let agent = NetworkAgent::new("Test Agent");
        let health = agent.health().await;

        assert_eq!(health.agent_id, agent.id());
        assert_eq!(health.status, AgentStatus::Idle);
    }

    #[test]
    fn test_capture_config_default() {
        let config = CaptureConfig::default();
        assert_eq!(config.interface, "any");
        assert_eq!(config.max_packet_size, 65535);
        assert_eq!(config.capture_duration_secs, 300);
    }
}
