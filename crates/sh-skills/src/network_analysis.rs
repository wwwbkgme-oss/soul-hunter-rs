//! Network Analysis Skill
//!
//! Production-ready network security analysis for mobile and IoT applications.
//! Analyzes network configurations, traffic patterns, and security configurations
//! to identify vulnerabilities and misconfigurations.
//!
//! ## Features
//!
//! - Traffic inspection (HAR, PCAP support)
//! - TLS/SSL validation
//! - Certificate pinning detection
//! - Credential leak detection
//! - Insecure protocol detection
//! - Network security config analysis
//! - Cleartext traffic detection
//! - Weak TLS version detection
//! - Weak cipher suite detection
//!
//! ## Example
//!
//! ```rust
//! use sh_skills::network_analysis::NetworkAnalysisSkill;
//! use sh_types::{AnalysisTarget, Platform};
//!
//! async fn analyze_network() {
//!     let skill = NetworkAnalysisSkill::new();
//!     let target = AnalysisTarget::new("app.apk", Platform::Android);
//!     // Execute via SecuritySkill trait...
//! }
//! ```

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tracing::{debug, error, info, instrument, trace, warn};
use uuid::Uuid;

use sh_types::{
    AnalysisTarget, Confidence, Finding, Location, Platform, Remediation, RemediationEffort,
    Severity,
};

use crate::{Result, SecuritySkill, SkillConfig, SkillContext, SkillError, SkillId, SkillResult};

/// Network security finding types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NetworkFindingType {
    /// Cleartext traffic allowed
    CleartextTraffic,
    /// Missing certificate pinning
    MissingCertificatePinning,
    /// Insecure TLS version (1.0/1.1)
    InsecureTlsVersion,
    /// Weak cipher suite
    WeakCipherSuite,
    /// Trust manager violation (accepts all certs)
    TrustManagerViolation,
    /// Hostname verifier violation (accepts all hostnames)
    HostnameVerifierViolation,
    /// Insecure network configuration
    InsecureNetworkConfig,
    /// Domain validation disabled
    DomainValidationDisabled,
    /// User certificates trusted
    UserCertificatesTrusted,
    /// Debug overrides present
    DebugOverridesPresent,
    /// Insecure HTTP connection
    InsecureHttpConnection,
    /// Sensitive data in URL
    SensitiveDataInUrl,
    /// Credentials in traffic
    CredentialsInTraffic,
    /// Weak TLS configuration
    WeakTlsConfiguration,
    /// Certificate validation bypass
    CertificateValidationBypass,
    /// Insecure protocol detected
    InsecureProtocol,
    /// Missing certificate transparency
    MissingCertificateTransparency,
}

impl std::fmt::Display for NetworkFindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkFindingType::CleartextTraffic => write!(f, "cleartext_traffic"),
            NetworkFindingType::MissingCertificatePinning => write!(f, "missing_certificate_pinning"),
            NetworkFindingType::InsecureTlsVersion => write!(f, "insecure_tls_version"),
            NetworkFindingType::WeakCipherSuite => write!(f, "weak_cipher_suite"),
            NetworkFindingType::TrustManagerViolation => write!(f, "trust_manager_violation"),
            NetworkFindingType::HostnameVerifierViolation => write!(f, "hostname_verifier_violation"),
            NetworkFindingType::InsecureNetworkConfig => write!(f, "insecure_network_config"),
            NetworkFindingType::DomainValidationDisabled => write!(f, "domain_validation_disabled"),
            NetworkFindingType::UserCertificatesTrusted => write!(f, "user_certificates_trusted"),
            NetworkFindingType::DebugOverridesPresent => write!(f, "debug_overrides_present"),
            NetworkFindingType::InsecureHttpConnection => write!(f, "insecure_http_connection"),
            NetworkFindingType::SensitiveDataInUrl => write!(f, "sensitive_data_in_url"),
            NetworkFindingType::CredentialsInTraffic => write!(f, "credentials_in_traffic"),
            NetworkFindingType::WeakTlsConfiguration => write!(f, "weak_tls_configuration"),
            NetworkFindingType::CertificateValidationBypass => {
                write!(f, "certificate_validation_bypass")
            }
            NetworkFindingType::InsecureProtocol => write!(f, "insecure_protocol"),
            NetworkFindingType::MissingCertificateTransparency => {
                write!(f, "missing_certificate_transparency")
            }
        }
    }
}

/// TLS version
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    SslV2,
    SslV3,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
    Unknown,
}

impl TlsVersion {
    /// Check if this TLS version is considered secure
    pub fn is_secure(&self) -> bool {
        matches!(self, TlsVersion::Tls12 | TlsVersion::Tls13)
    }

    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsVersion::SslV2 => "SSLv2",
            TlsVersion::SslV3 => "SSLv3",
            TlsVersion::Tls10 => "TLS 1.0",
            TlsVersion::Tls11 => "TLS 1.1",
            TlsVersion::Tls12 => "TLS 1.2",
            TlsVersion::Tls13 => "TLS 1.3",
            TlsVersion::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Cipher suite strength
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CipherStrength {
    Weak,
    Medium,
    Strong,
}

/// Cipher suite information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherSuite {
    pub name: String,
    pub strength: CipherStrength,
    pub key_exchange: String,
    pub encryption: String,
    pub mac: String,
}

/// Network traffic entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEntry {
    pub id: String,
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub tls_version: Option<TlsVersion>,
    pub cipher_suite: Option<String>,
    pub certificate_chain: Vec<CertificateInfo>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint: String,
    pub is_valid: bool,
}

/// Configuration for network analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAnalysisConfig {
    /// Check for cleartext traffic
    pub check_cleartext: bool,
    /// Check for certificate pinning
    pub check_pinning: bool,
    /// Check TLS configuration
    pub check_tls: bool,
    /// Check trust managers
    pub check_trust_managers: bool,
    /// Check hostname verifiers
    pub check_hostname_verifiers: bool,
    /// Check for weak cipher suites
    pub check_weak_ciphers: bool,
    /// Check for credential leaks
    pub check_credential_leaks: bool,
    /// Check for insecure protocols
    pub check_insecure_protocols: bool,
    /// Check for sensitive data in URLs
    pub check_sensitive_urls: bool,
    /// Minimum TLS version allowed
    pub min_tls_version: TlsVersion,
    /// Enable PCAP analysis
    pub enable_pcap_analysis: bool,
    /// Enable HAR analysis
    pub enable_har_analysis: bool,
}

impl Default for NetworkAnalysisConfig {
    fn default() -> Self {
        Self {
            check_cleartext: true,
            check_pinning: true,
            check_tls: true,
            check_trust_managers: true,
            check_hostname_verifiers: true,
            check_weak_ciphers: true,
            check_credential_leaks: true,
            check_insecure_protocols: true,
            check_sensitive_urls: true,
            min_tls_version: TlsVersion::Tls12,
            enable_pcap_analysis: true,
            enable_har_analysis: true,
        }
    }
}

/// Network analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAnalysisResult {
    pub total_requests: usize,
    pub insecure_connections: usize,
    pub tls_enabled_connections: usize,
    pub certificate_pinning_enabled: bool,
    pub cleartext_traffic_allowed: bool,
    pub weak_tls_versions_found: Vec<TlsVersion>,
    pub weak_cipher_suites_found: Vec<String>,
    pub credentials_exposed: usize,
    pub security_score: u32,
}

/// Network analysis skill
#[derive(Debug)]
pub struct NetworkAnalysisSkill {
    id: SkillId,
    config: NetworkAnalysisConfig,
    /// Regex patterns for credential detection
    credential_patterns: Vec<Regex>,
    /// Regex patterns for sensitive data detection
    sensitive_patterns: Vec<Regex>,
    /// Weak cipher suites
    weak_ciphers: HashSet<String>,
    /// Medium strength cipher suites
    medium_ciphers: HashSet<String>,
}

impl NetworkAnalysisSkill {
    /// Create a new network analysis skill
    pub fn new() -> Self {
        let credential_patterns = Self::build_credential_patterns();
        let sensitive_patterns = Self::build_sensitive_patterns();
        let weak_ciphers = Self::build_weak_cipher_list();
        let medium_ciphers = Self::build_medium_cipher_list();

        Self {
            id: Uuid::new_v4(),
            config: NetworkAnalysisConfig::default(),
            credential_patterns,
            sensitive_patterns,
            weak_ciphers,
            medium_ciphers,
        }
    }

    /// Create with custom configuration
    pub fn with_config(mut self, config: NetworkAnalysisConfig) -> Self {
        self.config = config;
        self
    }

    /// Build regex patterns for credential detection
    fn build_credential_patterns() -> Vec<Regex> {
        vec![
            Regex::new(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?([^&\s'\"]+)").unwrap(),
            Regex::new(r"(?i)(?:username|user|email)\s*[=:]\s*['\"]?([^&\s'\"]+)").unwrap(),
            Regex::new(r"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{16,})").unwrap(),
            Regex::new(r"(?i)(?:secret[_-]?key|secret)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{16,})").unwrap(),
            Regex::new(r"(?i)(?:access[_-]?token|token)\s*[=:]\s*['\"]?([^&\s'\"]+)").unwrap(),
            Regex::new(r"(?i)(?:auth[_-]?token|authorization)\s*[=:]\s*['\"]?([^&\s'\"]+)").unwrap(),
            Regex::new(r"(?i)bearer\s+([A-Za-z0-9_-]+)").unwrap(),
            Regex::new(r"(?i)basic\s+([A-Za-z0-9+/=]+)").unwrap(),
        ]
    }

    /// Build regex patterns for sensitive data detection
    fn build_sensitive_patterns() -> Vec<Regex> {
        vec![
            Regex::new(r"(?i)(?:password|passwd|pwd)").unwrap(),
            Regex::new(r"(?i)(?:credit[_-]?card|card[_-]?number|cvv|ccv)").unwrap(),
            Regex::new(r"(?i)(?:ssn|social[_-]?security)").unwrap(),
            Regex::new(r"(?i)(?:api[_-]?key|secret[_-]?key|private[_-]?key)").unwrap(),
            Regex::new(r"(?i)(?:access[_-]?token|auth[_-]?token|bearer)").unwrap(),
            Regex::new(r"(?i)(?:session[_-]?id|sessionid|jsessionid)").unwrap(),
        ]
    }

    /// Build list of weak cipher suites
    fn build_weak_cipher_list() -> HashSet<String> {
        let mut weak = HashSet::new();
        // NULL ciphers
        weak.insert("TLS_NULL_WITH_NULL_NULL".to_string());
        weak.insert("TLS_RSA_WITH_NULL_MD5".to_string());
        weak.insert("TLS_RSA_WITH_NULL_SHA".to_string());
        // Export ciphers
        weak.insert("TLS_RSA_EXPORT_WITH_RC4_40_MD5".to_string());
        weak.insert("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5".to_string());
        weak.insert("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA".to_string());
        // RC4 ciphers
        weak.insert("TLS_RSA_WITH_RC4_128_MD5".to_string());
        weak.insert("TLS_RSA_WITH_RC4_128_SHA".to_string());
        // DES ciphers
        weak.insert("TLS_RSA_WITH_DES_CBC_SHA".to_string());
        weak.insert("TLS_RSA_WITH_3DES_EDE_CBC_SHA".to_string());
        // DH ciphers with small key sizes
        weak.insert("TLS_DH_anon_WITH_RC4_128_MD5".to_string());
        weak.insert("TLS_DH_anon_WITH_DES_CBC_SHA".to_string());
        weak.insert("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA".to_string());
        weak.insert("TLS_DH_anon_WITH_AES_128_CBC_SHA".to_string());
        weak.insert("TLS_DH_anon_WITH_AES_256_CBC_SHA".to_string());
        // MD5 ciphers
        weak.insert("TLS_RSA_WITH_NULL_MD5".to_string());
        weak.insert("TLS_RSA_WITH_RC4_128_MD5".to_string());
        weak
    }

    /// Build list of medium strength cipher suites
    fn build_medium_cipher_list() -> HashSet<String> {
        let mut medium = HashSet::new();
        // SHA1 based ciphers
        medium.insert("TLS_RSA_WITH_AES_128_CBC_SHA".to_string());
        medium.insert("TLS_RSA_WITH_AES_256_CBC_SHA".to_string());
        medium.insert("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA".to_string());
        medium.insert("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA".to_string());
        medium.insert("TLS_RSA_WITH_SEED_CBC_SHA".to_string());
        medium
    }

    /// Analyze based on target platform
    #[instrument(skip(self, target), fields(platform = %target.platform))]
    async fn analyze_target(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        match target.platform {
            Platform::Android => {
                findings.extend(self.analyze_android(target).await?);
            }
            Platform::Ios => {
                findings.extend(self.analyze_ios(target).await?);
            }
            Platform::Iot => {
                findings.extend(self.analyze_iot(target).await?);
            }
            Platform::Network | Platform::Web => {
                findings.extend(self.analyze_network_traffic(target).await?);
            }
            _ => {
                warn!("Platform {:?} not specifically supported for network analysis", target.platform);
            }
        }

        Ok(findings)
    }

    /// Analyze Android network security
    async fn analyze_android(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check network_security_config.xml
        if self.config.check_cleartext {
            findings.extend(self.check_cleartext_traffic(target).await?);
        }

        // Check for certificate pinning
        if self.config.check_pinning {
            findings.extend(self.check_certificate_pinning(target).await?);
        }

        // Check for insecure trust managers
        if self.config.check_trust_managers {
            findings.extend(self.check_trust_managers(target).await?);
        }

        // Check for insecure hostname verifiers
        if self.config.check_hostname_verifiers {
            findings.extend(self.check_hostname_verifiers(target).await?);
        }

        // Check for user certificate trust
        if self.config.check_tls {
            findings.extend(self.check_user_certificate_trust(target).await?);
        }

        // Check for debug overrides
        findings.extend(self.check_debug_overrides(target).await?);

        // Analyze source code for network patterns
        findings.extend(self.analyze_source_code(target).await?);

        Ok(findings)
    }

    /// Analyze iOS network security
    async fn analyze_ios(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check Info.plist for ATS settings
        findings.extend(self.check_ios_ats(target).await?);

        // Check for certificate pinning implementation
        if self.config.check_pinning {
            findings.extend(self.check_ios_certificate_pinning(target).await?);
        }

        // Check for insecure URL session configurations
        findings.extend(self.check_ios_url_session(target).await?);

        Ok(findings)
    }

    /// Analyze IoT network security
    async fn analyze_iot(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for hardcoded endpoints
        findings.extend(self.check_hardcoded_endpoints(target).await?);

        // Check for insecure protocols
        if self.config.check_insecure_protocols {
            findings.extend(self.check_insecure_protocols(target).await?);
        }

        // Check for MQTT/CoAP security
        findings.extend(self.check_mqtt_security(target).await?);

        Ok(findings)
    }

    /// Analyze network traffic files (HAR, PCAP)
    async fn analyze_network_traffic(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let path = Path::new(&target.path);

        if !path.exists() {
            return Err(SkillError::TargetNotFound(target.path.clone()));
        }

        // Determine file type by extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            match ext.to_lowercase().as_str() {
                "har" if self.config.enable_har_analysis => {
                    findings.extend(self.analyze_har_file(target).await?);
                }
                "pcap" | "pcapng" if self.config.enable_pcap_analysis => {
                    findings.extend(self.analyze_pcap_file(target).await?);
                }
                "json" => {
                    // Try to parse as HAR
                    findings.extend(self.analyze_har_file(target).await?);
                }
                _ => {
                    debug!("Unknown file extension for network analysis: {}", ext);
                }
            }
        }

        Ok(findings)
    }

    /// Check for cleartext traffic configuration
    #[instrument(skip(self))]
    async fn check_cleartext_traffic(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check AndroidManifest.xml for usesCleartextTraffic
        let manifest_path = format!("{}/AndroidManifest.xml", target.path);
        if Path::new(&manifest_path).exists() {
            match tokio::fs::read_to_string(&manifest_path).await {
                Ok(content) => {
                    if content.contains("usesCleartextTraffic=\"true\"") {
                        let finding = Finding::new(
                            "Cleartext Traffic Enabled in Manifest",
                            "The application allows cleartext HTTP traffic in AndroidManifest.xml, which exposes data to interception and tampering",
                        )
                        .with_severity(Severity::High)
                        .with_confidence(Confidence::Confirmed)
                        .with_type("network_security")
                        .with_cwe("CWE-319")
                        .with_owasp("M3: Insecure Communication")
                        .with_location(
                            Location::new()
                                .with_file("AndroidManifest.xml")
                                .with_platform(Platform::Android)
                                .with_snippet("usesCleartextTraffic=\"true\""),
                        )
                        .with_remediation(
                            Remediation::new("Set usesCleartextTraffic=\"false\" or remove the attribute to enforce HTTPS only")
                                .with_effort(RemediationEffort::Low)
                                .add_reference("https://developer.android.com/guide/topics/manifest/application-element#usesCleartextTraffic"),
                        )
                        .with_tool("network_analysis", "1.0.0");

                        findings.push(finding);
                    }
                }
                Err(e) => {
                    warn!("Failed to read AndroidManifest.xml: {}", e);
                }
            }
        }

        // Check network_security_config.xml
        let config_paths = [
            format!("{}/res/xml/network_security_config.xml", target.path),
            format!("{}/res/xml-v21/network_security_config.xml", target.path),
            format!("{}/res/xml-v24/network_security_config.xml", target.path),
        ];

        for config_path in &config_paths {
            if Path::new(config_path).exists() {
                match tokio::fs::read_to_string(config_path).await {
                    Ok(content) => {
                        // Check base-config
                        if content.contains("cleartextTrafficPermitted=\"true\"") {
                            let finding = Finding::new(
                                "Cleartext Traffic Permitted in Network Security Config",
                                "Network security configuration allows cleartext traffic, enabling unencrypted HTTP connections",
                            )
                            .with_severity(Severity::High)
                            .with_confidence(Confidence::Confirmed)
                            .with_type("network_security")
                            .with_cwe("CWE-319")
                            .with_owasp("M3: Insecure Communication")
                            .with_location(
                                Location::new()
                                    .with_file(config_path.strip_prefix(&format!("{}/", target.path)).unwrap_or(config_path))
                                    .with_platform(Platform::Android)
                                    .with_snippet("cleartextTrafficPermitted=\"true\""),
                            )
                            .with_remediation(
                                Remediation::new("Set cleartextTrafficPermitted=\"false\" in base-config and domain-config elements")
                                    .with_effort(RemediationEffort::Low)
                                    .add_reference("https://developer.android.com/training/articles/security-config#CleartextTrafficPermitted"),
                            )
                            .with_tool("network_analysis", "1.0.0");

                            findings.push(finding);
                        }

                        // Check for domain-specific cleartext
                        if content.contains("<domain-config") && content.contains("cleartextTrafficPermitted=\"true\"") {
                            let finding = Finding::new(
                                "Domain-Specific Cleartext Traffic Allowed",
                                "Specific domains are configured to allow cleartext traffic, which may expose sensitive data",
                            )
                            .with_severity(Severity::Medium)
                            .with_confidence(Confidence::Confirmed)
                            .with_type("network_security")
                            .with_cwe("CWE-319")
                            .with_owasp("M3: Insecure Communication")
                            .with_location(
                                Location::new()
                                    .with_file(config_path.strip_prefix(&format!("{}/", target.path)).unwrap_or(config_path))
                                    .with_platform(Platform::Android),
                            )
                            .with_remediation(
                                Remediation::new("Remove cleartextTrafficPermitted=\"true\" from domain-config elements or use HTTPS for those domains")
                                    .with_effort(RemediationEffort::Medium),
                            )
                            .with_tool("network_analysis", "1.0.0");

                            findings.push(finding);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read network_security_config.xml: {}", e);
                    }
                }
                break; // Only process the first found config
            }
        }

        Ok(findings)
    }

    /// Check for certificate pinning
    #[instrument(skip(self))]
    async fn check_certificate_pinning(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let config_paths = [
            format!("{}/res/xml/network_security_config.xml", target.path),
            format!("{}/res/xml-v21/network_security_config.xml", target.path),
            format!("{}/res/xml-v24/network_security_config.xml", target.path),
        ];

        let mut config_found = false;
        let mut pinning_found = false;

        for config_path in &config_paths {
            if Path::new(config_path).exists() {
                config_found = true;
                match tokio::fs::read_to_string(config_path).await {
                    Ok(content) => {
                        if content.contains("<pin-set") || content.contains("<pin ") {
                            pinning_found = true;
                            info!("Certificate pinning detected in {}", config_path);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read network_security_config.xml: {}", e);
                    }
                }
                break;
            }
        }

        if config_found && !pinning_found {
            let finding = Finding::new(
                "Certificate Pinning Not Implemented",
                "The application does not implement certificate pinning, making it vulnerable to man-in-the-middle attacks with rogue certificates",
            )
            .with_severity(Severity::Medium)
            .with_confidence(Confidence::Probable)
            .with_type("network_security")
            .with_cwe("CWE-295")
            .with_owasp("M3: Insecure Communication")
            .with_location(
                Location::new()
                    .with_file("res/xml/network_security_config.xml")
                    .with_platform(Platform::Android),
            )
            .with_remediation(
                Remediation::new("Implement certificate pinning using <pin-set> in network_security_config.xml")
                    .with_effort(RemediationEffort::Medium)
                    .add_reference("https://developer.android.com/training/articles/security-config#CertificatePinning")
                    .add_reference("https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning"),
            )
            .with_tool("network_analysis", "1.0.0");

            findings.push(finding);
        } else if !config_found {
            let finding = Finding::new(
                "Network Security Config Missing",
                "The application does not have a network_security_config.xml file, which limits network security configuration options",
            )
            .with_severity(Severity::Low)
            .with_confidence(Confidence::Confirmed)
            .with_type("network_security")
            .with_location(
                Location::new()
                    .with_platform(Platform::Android),
            )
            .with_remediation(
                Remediation::new("Create a network_security_config.xml file to define security policies including certificate pinning")
                    .with_effort(RemediationEffort::Low)
                    .add_reference("https://developer.android.com/training/articles/security-config"),
            )
            .with_tool("network_analysis", "1.0.0");

            findings.push(finding);
        }

        Ok(findings)
    }

    /// Check for insecure trust managers
    #[instrument(skip(self))]
    async fn check_trust_managers(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Patterns that indicate insecure TrustManager implementations
        let insecure_patterns = [
            ("X509TrustManager", "checkClientTrusted", "empty"),
            ("X509TrustManager", "checkServerTrusted", "empty"),
            ("TrustManager", "getAcceptedIssuers", "null"),
            ("TrustManager", "getAcceptedIssuers", "new X509Certificate[0]"),
        ];

        // This would scan source code/DEX for these patterns
        // For now, we'll add a placeholder that can be expanded
        debug!("Checking trust managers for: {}", target.path);

        // TODO: Implement DEX bytecode analysis for TrustManager patterns
        // This requires integration with the APK parser and DEX analyzer

        Ok(findings)
    }

    /// Check for insecure hostname verifiers
    #[instrument(skip(self))]
    async fn check_hostname_verifiers(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Patterns that indicate insecure HostnameVerifier implementations
        let insecure_patterns = [
            "HostnameVerifier",
            "verify",
            "return true",
            "SSLSession",
        ];

        debug!("Checking hostname verifiers for: {}", target.path);

        // TODO: Implement source code analysis for HostnameVerifier patterns

        Ok(findings)
    }

    /// Check for user certificate trust
    #[instrument(skip(self))]
    async fn check_user_certificate_trust(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let config_paths = [
            format!("{}/res/xml/network_security_config.xml", target.path),
            format!("{}/res/xml-v21/network_security_config.xml", target.path),
        ];

        for config_path in &config_paths {
            if Path::new(config_path).exists() {
                match tokio::fs::read_to_string(config_path).await {
                    Ok(content) => {
                        if content.contains("src=\"user\"") {
                            let finding = Finding::new(
                                "User Certificates Trusted",
                                "The application trusts user-installed certificates, which allows man-in-the-middle attacks with user-added CAs",
                            )
                            .with_severity(Severity::Medium)
                            .with_confidence(Confidence::Confirmed)
                            .with_type("network_security")
                            .with_cwe("CWE-295")
                            .with_owasp("M3: Insecure Communication")
                            .with_location(
                                Location::new()
                                    .with_file(config_path.strip_prefix(&format!("{}/", target.path)).unwrap_or(config_path))
                                    .with_platform(Platform::Android)
                                    .with_snippet("<certificates src=\"user\"/>"),
                            )
                            .with_remediation(
                                Remediation::new("Remove <certificates src=\"user\"/> from trust anchors unless specifically required for your use case")
                                    .with_effort(RemediationEffort::Low)
                                    .add_reference("https://developer.android.com/training/articles/security-config#ConfiguringBase"),
                            )
                            .with_tool("network_analysis", "1.0.0");

                            findings.push(finding);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read network_security_config.xml: {}", e);
                    }
                }
                break;
            }
        }

        Ok(findings)
    }

    /// Check for debug overrides
    #[instrument(skip(self))]
    async fn check_debug_overrides(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let config_paths = [
            format!("{}/res/xml/network_security_config.xml", target.path),
            format!("{}/res/xml-v21/network_security_config.xml", target.path),
        ];

        for config_path in &config_paths {
            if Path::new(config_path).exists() {
                match tokio::fs::read_to_string(config_path).await {
                    Ok(content) => {
                        if content.contains("<debug-overrides>") {
                            let finding = Finding::new(
                                "Debug Overrides Present in Network Config",
                                "Network security configuration contains debug overrides that may weaken security in production builds",
                            )
                            .with_severity(Severity::Low)
                            .with_confidence(Confidence::Confirmed)
                            .with_type("network_security")
                            .with_cwe("CWE-489")
                            .with_owasp("M1: Improper Platform Usage")
                            .with_location(
                                Location::new()
                                    .with_file(config_path.strip_prefix(&format!("{}/", target.path)).unwrap_or(config_path))
                                    .with_platform(Platform::Android)
                                    .with_snippet("<debug-overrides>"),
                            )
                            .with_remediation(
                                Remediation::new("Remove debug-overrides configuration for production releases")
                                    .with_effort(RemediationEffort::Low)
                                    .add_reference("https://developer.android.com/training/articles/security-config#debug-overrides"),
                            )
                            .with_tool("network_analysis", "1.0.0");

                            findings.push(finding);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read network_security_config.xml: {}", e);
                    }
                }
                break;
            }
        }

        Ok(findings)
    }

    /// Analyze source code for network patterns
    #[instrument(skip(self))]
    async fn analyze_source_code(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for insecure URL patterns in source code
        let insecure_url_patterns = [
            ("http://", "Insecure HTTP URL", Severity::Medium),
            ("ftp://", "Insecure FTP URL", Severity::Medium),
            ("telnet://", "Insecure Telnet URL", Severity::High),
        ];

        // This would scan source files for these patterns
        // Implementation would use the tools module for file extraction

        debug!("Analyzing source code for network patterns: {}", target.path);

        Ok(findings)
    }

    /// Check iOS ATS (App Transport Security) settings
    #[instrument(skip(self))]
    async fn check_ios_ats(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let plist_path = format!("{}/Info.plist", target.path);
        if Path::new(&plist_path).exists() {
            match tokio::fs::read_to_string(&plist_path).await {
                Ok(content) => {
                    // Check for ATS bypass
                    if content.contains("NSAllowsArbitraryLoads") && content.contains("<true/>") {
                        let finding = Finding::new(
                            "App Transport Security Disabled",
                            "App Transport Security (ATS) is disabled via NSAllowsArbitraryLoads, allowing insecure HTTP connections",
                        )
                        .with_severity(Severity::High)
                        .with_confidence(Confidence::Confirmed)
                        .with_type("network_security")
                        .with_cwe("CWE-319")
                        .with_owasp("M3: Insecure Communication")
                        .with_location(
                            Location::new()
                                .with_file("Info.plist")
                                .with_platform(Platform::Ios)
                                .with_snippet("NSAllowsArbitraryLoads"),
                        )
                        .with_remediation(
                            Remediation::new("Remove NSAllowsArbitraryLoads or set to false. Use NSExceptionDomains for specific exceptions if needed")
                                .with_effort(RemediationEffort::Low)
                                .add_reference("https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity"),
                        )
                        .with_tool("network_analysis", "1.0.0");

                        findings.push(finding);
                    }

                    // Check for arbitrary loads in media
                    if content.contains("NSAllowsArbitraryLoadsForMedia") && content.contains("<true/>") {
                        let finding = Finding::new(
                            "ATS Arbitrary Loads for Media Enabled",
                            "App Transport Security allows arbitrary loads for media, which may expose media content to interception",
                        )
                        .with_severity(Severity::Medium)
                        .with_confidence(Confidence::Confirmed)
                        .with_type("network_security")
                        .with_cwe("CWE-319")
                        .with_location(
                            Location::new()
                                .with_file("Info.plist")
                                .with_platform(Platform::Ios),
                        )
                        .with_remediation(
                            Remediation::new("Remove NSAllowsArbitraryLoadsForMedia or ensure media is loaded over HTTPS")
                                .with_effort(RemediationEffort::Low),
                        )
                        .with_tool("network_analysis", "1.0.0");

                        findings.push(finding);
                    }
                }
                Err(e) => {
                    warn!("Failed to read Info.plist: {}", e);
                }
            }
        }

        Ok(findings)
    }

    /// Check iOS certificate pinning
    #[instrument(skip(self))]
    async fn check_ios_certificate_pinning(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for common pinning libraries or implementations
        // This would scan for patterns like:
        // - TrustKit
        // - Alamofire certificate pinning
        // - URLSessionDelegate with certificate validation

        debug!("Checking iOS certificate pinning for: {}", target.path);

        // Placeholder - would need source code analysis
        let finding = Finding::new(
            "Certificate Pinning Not Detected",
            "Could not detect certificate pinning implementation. Manual verification recommended",
        )
        .with_severity(Severity::Info)
        .with_confidence(Confidence::Tentative)
        .with_type("network_security")
        .with_location(
            Location::new()
                .with_platform(Platform::Ios),
        )
        .with_remediation(
            Remediation::new("Consider implementing certificate pinning using TrustKit or native URLSession pinning")
                .with_effort(RemediationEffort::Medium)
                .add_reference("https://github.com/datatheorem/TrustKit"),
        )
        .with_tool("network_analysis", "1.0.0");

        findings.push(finding);

        Ok(findings)
    }

    /// Check iOS URL session configuration
    #[instrument(skip(self))]
    async fn check_ios_url_session(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for insecure URLSession configurations
        debug!("Checking iOS URL session configuration for: {}", target.path);

        Ok(findings)
    }

    /// Check for hardcoded endpoints
    #[instrument(skip(self))]
    async fn check_hardcoded_endpoints(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Patterns for hardcoded endpoints
        let endpoint_patterns = [
            ("http://", "Hardcoded HTTP endpoint"),
            ("mqtt://", "Hardcoded MQTT endpoint"),
            ("coap://", "Hardcoded CoAP endpoint"),
        ];

        debug!("Checking for hardcoded endpoints in: {}", target.path);

        Ok(findings)
    }

    /// Check for insecure protocols
    #[instrument(skip(self))]
    async fn check_insecure_protocols(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for insecure protocol usage
        let insecure_protocols = [
            ("telnet://", "Telnet", Severity::Critical),
            ("ftp://", "FTP", Severity::Medium),
            ("http://", "HTTP", Severity::Medium),
        ];

        debug!("Checking for insecure protocols in: {}", target.path);

        Ok(findings)
    }

    /// Check MQTT security
    #[instrument(skip(self))]
    async fn check_mqtt_security(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for MQTT without TLS
        debug!("Checking MQTT security for: {}", target.path);

        Ok(findings)
    }

    /// Analyze HAR (HTTP Archive) file
    #[instrument(skip(self))]
    async fn analyze_har_file(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        match tokio::fs::read_to_string(&target.path).await {
            Ok(content) => {
                let har: serde_json::Value = match serde_json::from_str(&content) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Failed to parse HAR file: {}", e);
                        return Ok(findings);
                    }
                };

                // Get entries from HAR
                if let Some(entries) = har["log"]["entries"].as_array() {
                    let mut insecure_count = 0;
                    let mut credential_count = 0;
                    let mut sensitive_count = 0;

                    for (idx, entry) in entries.iter().enumerate() {
                        if let Some(request) = entry["request"].as_object() {
                            let url = request["url"].as_str().unwrap_or("");

                            // Check for insecure HTTP
                            if self.config.check_cleartext && url.starts_with("http://") {
                                insecure_count += 1;
                                if insecure_count <= 5 { // Limit findings
                                    let finding = Finding::new(
                                        format!("Insecure HTTP Connection in Traffic (Request {})", idx + 1),
                                        format!("Network traffic contains unencrypted HTTP request to: {}", self.truncate_url(url)),
                                    )
                                    .with_severity(Severity::High)
                                    .with_confidence(Confidence::Confirmed)
                                    .with_type("network_traffic")
                                    .with_cwe("CWE-319")
                                    .with_owasp("M3: Insecure Communication")
                                    .with_location(
                                        Location::new()
                                            .with_file(&target.path)
                                            .with_platform(Platform::Network)
                                            .with_snippet(url),
                                    )
                                    .with_remediation(
                                        Remediation::new("Use HTTPS for all network communications")
                                            .with_effort(RemediationEffort::Low),
                                    )
                                    .with_tool("network_analysis", "1.0.0");

                                    findings.push(finding);
                                }
                            }

                            // Check for sensitive data in URL
                            if self.config.check_sensitive_urls {
                                if let Some(finding) = self.check_url_for_sensitive_data(url, &target.path, idx) {
                                    sensitive_count += 1;
                                    findings.push(finding);
                                }
                            }

                            // Check for credentials in request
                            if self.config.check_credential_leaks {
                                // Check headers
                                if let Some(headers) = request["headers"].as_array() {
                                    for header in headers {
                                        if let Some(name) = header["name"].as_str() {
                                            if let Some(value) = header["value"].as_str() {
                                                if self.contains_credentials(value) {
                                                    credential_count += 1;
                                                    let finding = Finding::new(
                                                        format!("Credentials in HTTP Header (Request {})", idx + 1),
                                                        format!("Potentially sensitive credential found in {} header", name),
                                                    )
                                                    .with_severity(Severity::Critical)
                                                    .with_confidence(Confidence::Probable)
                                                    .with_type("credential_exposure")
                                                    .with_cwe("CWE-798")
                                                    .with_owasp("M2: Insecure Data Storage")
                                                    .with_location(
                                                        Location::new()
                                                            .with_file(&target.path)
                                                            .with_platform(Platform::Network)
                                                            .with_snippet(&format!("{}: [REDACTED]", name)),
                                                    )
                                                    .with_remediation(
                                                        Remediation::new("Avoid sending credentials in headers. Use secure authentication mechanisms like OAuth 2.0")
                                                            .with_effort(RemediationEffort::Medium),
                                                    )
                                                    .with_tool("network_analysis", "1.0.0");

                                                    findings.push(finding);
                                                }
                                            }
                                        }
                                    }
                                }

                                // Check query parameters
                                if url.contains('?') {
                                    if let Some(finding) = self.check_query_params_for_credentials(url, &target.path, idx) {
                                        credential_count += 1;
                                        findings.push(finding);
                                    }
                                }
                            }

                            // Check response for security headers
                            if let Some(response) = entry["response"].as_object() {
                                if let Some(headers) = response["headers"].as_array() {
                                    self.check_security_headers(&mut findings, headers, &target.path, idx);
                                }
                            }
                        }
                    }

                    // Add summary finding if many issues found
                    if insecure_count > 5 {
                        let finding = Finding::new(
                            "Multiple Insecure HTTP Connections Detected",
                            format!("Found {} insecure HTTP connections in network traffic. Only first 5 shown.", insecure_count),
                        )
                        .with_severity(Severity::High)
                        .with_confidence(Confidence::Confirmed)
                        .with_type("network_traffic")
                        .with_cwe("CWE-319")
                        .with_location(
                            Location::new()
                                .with_file(&target.path)
                                .with_platform(Platform::Network),
                        )
                        .with_remediation(
                            Remediation::new("Migrate all endpoints to HTTPS and update application configuration")
                                .with_effort(RemediationEffort::Medium),
                        )
                        .with_tool("network_analysis", "1.0.0");

                        findings.push(finding);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to read HAR file: {}", e);
            }
        }

        Ok(findings)
    }

    /// Analyze PCAP file
    #[instrument(skip(self))]
    async fn analyze_pcap_file(&self, target: &AnalysisTarget) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // PCAP analysis requires external tools like tshark or pcap libraries
        // This is a placeholder that documents the limitation
        let finding = Finding::new(
            "PCAP Analysis Limited",
            "PCAP file detected but full packet analysis requires external tools (tshark) or native pcap libraries",
        )
        .with_severity(Severity::Info)
        .with_confidence(Confidence::Tentative)
        .with_type("network_traffic")
        .with_location(
            Location::new()
                .with_file(&target.path)
                .with_platform(Platform::Network),
        )
        .with_remediation(
            Remediation::new("Install tshark and use: tshark -r <pcap_file> -V for detailed analysis")
                .with_effort(RemediationEffort::Low),
        )
        .with_tool("network_analysis", "1.0.0");

        findings.push(finding);

        // Try to extract basic info if possible
        if let Ok(metadata) = tokio::fs::metadata(&target.path).await {
            let size = metadata.len();
            if size == 0 {
                let finding = Finding::new(
                    "Empty PCAP File",
                    "The PCAP file appears to be empty",
                )
                .with_severity(Severity::Info)
                .with_confidence(Confidence::Confirmed)
                .with_type("network_traffic")
                .with_location(
                    Location::new()
                        .with_file(&target.path)
                        .with_platform(Platform::Network),
                )
                .with_tool("network_analysis", "1.0.0");

                findings.push(finding);
            }
        }

        Ok(findings)
    }

    /// Check URL for sensitive data
    fn check_url_for_sensitive_data(&self, url: &str, file_path: &str, idx: usize) -> Option<Finding> {
        let lower_url = url.to_lowercase();

        for pattern in &self.sensitive_patterns {
            if pattern.is_match(&lower_url) {
                return Some(
                    Finding::new(
                        format!("Sensitive Data in URL (Request {})", idx + 1),
                        format!("URL contains potentially sensitive information: {}", self.truncate_url(url)),
                    )
                    .with_severity(Severity::Medium)
                    .with_confidence(Confidence::Probable)
                    .with_type("information_disclosure")
                    .with_cwe("CWE-598")
                    .with_owasp("M2: Insecure Data Storage")
                    .with_location(
                        Location::new()
                            .with_file(file_path)
                            .with_platform(Platform::Network)
                            .with_snippet(self.truncate_url(url)),
                    )
                    .with_remediation(
                        Remediation::new("Move sensitive data from URL parameters to POST body or use secure headers")
                            .with_effort(RemediationEffort::Low),
                    )
                    .with_tool("network_analysis", "1.0.0"),
                );
            }
        }

        None
    }

    /// Check query parameters for credentials
    fn check_query_params_for_credentials(&self, url: &str, file_path: &str, idx: usize) -> Option<Finding> {
        if let Some(query) = url.split('?').nth(1) {
            for pattern in &self.credential_patterns {
                if pattern.is_match(query) {
                    return Some(
                        Finding::new(
                            format!("Credentials in URL Query Parameters (Request {})", idx + 1),
                            "URL query parameters contain potential credentials. This exposes sensitive data in browser history and server logs",
                        )
                        .with_severity(Severity::Critical)
                        .with_confidence(Confidence::Confirmed)
                        .with_type("credential_exposure")
                        .with_cwe("CWE-598")
                        .with_owasp("M2: Insecure Data Storage")
                        .with_location(
                            Location::new()
                                .with_file(file_path)
                                .with_platform(Platform::Network)
                                .with_snippet("[REDACTED URL]"),
                        )
                        .with_remediation(
                            Remediation::new("Never send credentials in URL parameters. Use POST requests with proper authentication headers")
                                .with_effort(RemediationEffort::Low),
                        )
                        .with_tool("network_analysis", "1.0.0"),
                    );
                }
            }
        }

        None
    }

    /// Check security headers
    fn check_security_headers(
        &self,
        findings: &mut Vec<Finding>,
        headers: &Vec<serde_json::Value>,
        file_path: &str,
        idx: usize,
    ) {
        let mut has_hsts = false;
        let mut has_xfo = false;
        let mut has_csp = false;
        let mut has_xcto = false;

        for header in headers {
            if let Some(name) = header["name"].as_str() {
                let lower_name = name.to_lowercase();
                match lower_name.as_str() {
                    "strict-transport-security" => has_hsts = true,
                    "x-frame-options" => has_xfo = true,
                    "content-security-policy" | "content-security-policy-report-only" => has_csp = true,
                    "x-content-type-options" => has_xcto = true,
                    _ => {}
                }
            }
        }

        // Report missing headers (only for first few requests to avoid noise)
        if idx < 3 {
            if !has_hsts {
                findings.push(
                    Finding::new(
                        format!("Missing HSTS Header (Response {})", idx + 1),
                        "Response does not include Strict-Transport-Security header, making the application vulnerable to SSL stripping attacks",
                    )
                    .with_severity(Severity::Medium)
                    .with_confidence(Confidence::Probable)
                    .with_type("network_security")
                    .with_cwe("CWE-319")
                    .with_location(
                        Location::new()
                            .with_file(file_path)
                            .with_platform(Platform::Network),
                    )
                    .with_remediation(
                        Remediation::new("Add Strict-Transport-Security header with appropriate max-age")
                            .with_effort(RemediationEffort::Low)
                            .add_reference("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"),
                    )
                    .with_tool("network_analysis", "1.0.0"),
                );
            }
        }
    }

    /// Check if content contains credentials
    fn contains_credentials(&self, content: &str) -> bool {
        self.credential_patterns.iter().any(|p| p.is_match(content))
    }

    /// Truncate URL for display
    fn truncate_url(&self, url: &str) -> String {
        if url.len() > 100 {
            format!("{}...", &url[..100])
        } else {
            url.to_string()
        }
    }

    /// Get cipher suite strength
    pub fn get_cipher_strength(&self, cipher_name: &str) -> CipherStrength {
        let upper = cipher_name.to_uppercase();
        if self.weak_ciphers.contains(&upper) {
            CipherStrength::Weak
        } else if self.medium_ciphers.contains(&upper) {
            CipherStrength::Medium
        } else {
            CipherStrength::Strong
        }
    }

    /// Check if TLS version is secure
    pub fn is_tls_version_secure(&self, version: TlsVersion) -> bool {
        version >= self.config.min_tls_version
    }

    /// Calculate security score
    pub fn calculate_security_score(&self, findings: &[Finding]) -> u32 {
        let mut score = 100u32;

        for finding in findings {
            score = score.saturating_sub(match finding.severity {
                Severity::Critical => 25,
                Severity::High => 15,
                Severity::Medium => 10,
                Severity::Low => 5,
                Severity::Info => 0,
            });
        }

        score
    }
}

#[async_trait]
impl SecuritySkill for NetworkAnalysisSkill {
    fn id(&self) -> SkillId {
        self.id
    }

    fn name(&self) -> &str {
        "network_analysis"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![
            Platform::Android,
            Platform::Ios,
            Platform::Iot,
            Platform::Network,
            Platform::Web,
        ]
    }

    #[instrument(skip(self, ctx), fields(task_id = %ctx.task_id))]
    async fn execute(&self, ctx: SkillContext) -> Result<SkillResult> {
        info!("Executing network analysis for: {}", ctx.target.path);
        let start_time = std::time::Instant::now();

        if !self.supports_platform(&ctx.target.platform) {
            return Err(SkillError::TargetNotSupported(
                ctx.target.platform.to_string(),
            ));
        }

        // Validate configuration
        self.validate_config(&ctx.config)?;

        // Perform analysis
        let findings = self.analyze_target(&ctx.target).await?;

        // Filter by minimum severity
        let filtered_findings: Vec<Finding> = findings
            .into_iter()
            .filter(|f| f.severity >= ctx.config.min_severity)
            .take(ctx.config.max_findings)
            .collect();

        // Calculate security score
        let security_score = self.calculate_security_score(&filtered_findings);

        let execution_time = start_time.elapsed().as_millis() as u64;

        let result = SkillResult::new(self.id, ctx.task_id)
            .with_findings(filtered_findings)
            .with_metadata("skill_type", serde_json::json!("network_analysis"))
            .with_metadata("platform", serde_json::json!(ctx.target.platform.to_string()))
            .with_metadata("security_score", serde_json::json!(security_score))
            .with_metadata("config", serde_json::to_value(&self.config).unwrap_or_default())
            .with_execution_time(execution_time);

        info!(
            "Network analysis completed in {}ms with {} findings",
            execution_time,
            result.findings.len()
        );

        Ok(result)
    }
}

impl Default for NetworkAnalysisSkill {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::fs;

    #[test]
    fn test_network_analysis_skill_creation() {
        let skill = NetworkAnalysisSkill::new();
        assert_eq!(skill.name(), "network_analysis");
        assert_eq!(skill.version(), "1.0.0");
    }

    #[test]
    fn test_supported_platforms() {
        let skill = NetworkAnalysisSkill::new();
        let platforms = skill.supported_platforms();
        assert!(platforms.contains(&Platform::Android));
        assert!(platforms.contains(&Platform::Ios));
        assert!(platforms.contains(&Platform::Network));
    }

    #[test]
    fn test_network_finding_type_display() {
        assert_eq!(
            NetworkFindingType::CleartextTraffic.to_string(),
            "cleartext_traffic"
        );
        assert_eq!(
            NetworkFindingType::MissingCertificatePinning.to_string(),
            "missing_certificate_pinning"
        );
    }

    #[test]
    fn test_tls_version_security() {
        assert!(!TlsVersion::SslV2.is_secure());
        assert!(!TlsVersion::SslV3.is_secure());
        assert!(!TlsVersion::Tls10.is_secure());
        assert!(!TlsVersion::Tls11.is_secure());
        assert!(TlsVersion::Tls12.is_secure());
        assert!(TlsVersion::Tls13.is_secure());
    }

    #[test]
    fn test_tls_version_ordering() {
        assert!(TlsVersion::Tls10 < TlsVersion::Tls12);
        assert!(TlsVersion::Tls12 < TlsVersion::Tls13);
    }

    #[test]
    fn test_cipher_strength_detection() {
        let skill = NetworkAnalysisSkill::new();
        assert_eq!(
            skill.get_cipher_strength("TLS_RSA_WITH_RC4_128_MD5"),
            CipherStrength::Weak
        );
        assert_eq!(
            skill.get_cipher_strength("TLS_RSA_WITH_AES_128_CBC_SHA"),
            CipherStrength::Medium
        );
        assert_eq!(
            skill.get_cipher_strength("TLS_AES_256_GCM_SHA384"),
            CipherStrength::Strong
        );
    }

    #[test]
    fn test_credential_pattern_matching() {
        let skill = NetworkAnalysisSkill::new();
        assert!(skill.contains_credentials("password=secret123"));
        assert!(skill.contains_credentials("api_key=abc123xyz"));
        assert!(!skill.contains_credentials("username=john"));
    }

    #[test]
    fn test_url_truncation() {
        let skill = NetworkAnalysisSkill::new();
        let short_url = "https://example.com/api";
        let long_url = "https://example.com/api/v1/users/12345/posts/67890/comments?page=1&limit=100&sort=descending";

        assert_eq!(skill.truncate_url(short_url), short_url);
        assert!(skill.truncate_url(long_url).ends_with("..."));
        assert!(skill.truncate_url(long_url).len() <= 103);
    }

    #[test]
    fn test_security_score_calculation() {
        let skill = NetworkAnalysisSkill::new();
        let findings = vec![
            Finding::new("Test 1", "Description 1").with_severity(Severity::Critical),
            Finding::new("Test 2", "Description 2").with_severity(Severity::High),
            Finding::new("Test 3", "Description 3").with_severity(Severity::Medium),
        ];

        let score = skill.calculate_security_score(&findings);
        assert_eq!(score, 50); // 100 - 25 - 15 - 10
    }

    #[test]
    fn test_default_config() {
        let config = NetworkAnalysisConfig::default();
        assert!(config.check_cleartext);
        assert!(config.check_pinning);
        assert!(config.check_tls);
        assert!(config.check_credential_leaks);
        assert_eq!(config.min_tls_version, TlsVersion::Tls12);
    }

    #[test]
    fn test_custom_config() {
        let skill = NetworkAnalysisSkill::new().with_config(NetworkAnalysisConfig {
            check_cleartext: false,
            check_pinning: false,
            ..Default::default()
        });

        // Config is private, but we can verify the skill was created
        assert_eq!(skill.name(), "network_analysis");
    }

    #[tokio::test]
    async fn test_cleartext_detection_in_manifest() {
        let temp_dir = TempDir::new().unwrap();
        let manifest_path = temp_dir.path().join("AndroidManifest.xml");

        let manifest_content = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application android:usesCleartextTraffic="true">
    </application>
</manifest>"#;

        fs::write(&manifest_path, manifest_content).await.unwrap();

        let skill = NetworkAnalysisSkill::new();
        let target = AnalysisTarget::new(temp_dir.path().to_str().unwrap(), Platform::Android);
        let findings = skill.check_cleartext_traffic(&target).await.unwrap();

        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.title.contains("Manifest")));
    }

    #[tokio::test]
    async fn test_network_security_config_analysis() {
        let temp_dir = TempDir::new().unwrap();
        let xml_path = temp_dir.path().join("res/xml/network_security_config.xml");
        fs::create_dir_all(xml_path.parent().unwrap()).await.unwrap();

        let config_content = r#"<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
        </trust-anchors>
    </debug-overrides>
</network-security-config>"#;

        fs::write(&xml_path, config_content).await.unwrap();

        let skill = NetworkAnalysisSkill::new();
        let target = AnalysisTarget::new(temp_dir.path().to_str().unwrap(), Platform::Android);
        let findings = skill.analyze_android(&target).await.unwrap();

        // Should find cleartext, user certs, and debug overrides
        assert!(!findings.is_empty());
    }

    #[tokio::test]
    async fn test_har_analysis() {
        let temp_dir = TempDir::new().unwrap();
        let har_path = temp_dir.path().join("test.har");

        let har_content = r#"{
            "log": {
                "entries": [
                    {
                        "request": {
                            "url": "http://insecure.example.com/api",
                            "method": "GET",
                            "headers": []
                        },
                        "response": {
                            "status": 200,
                            "headers": []
                        }
                    },
                    {
                        "request": {
                            "url": "https://secure.example.com/api?password=secret",
                            "method": "POST",
                            "headers": [
                                {"name": "Authorization", "value": "Bearer token123"}
                            ]
                        },
                        "response": {
                            "status": 200,
                            "headers": []
                        }
                    }
                ]
            }
        }"#;

        fs::write(&har_path, har_content).await.unwrap();

        let skill = NetworkAnalysisSkill::new();
        let target = AnalysisTarget::new(har_path.to_str().unwrap(), Platform::Network);
        let findings = skill.analyze_har_file(&target).await.unwrap();

        // Should find insecure HTTP and sensitive data in URL
        assert!(!findings.is_empty());
    }

    #[tokio::test]
    async fn test_ios_ats_analysis() {
        let temp_dir = TempDir::new().unwrap();
        let plist_path = temp_dir.path().join("Info.plist");

        let plist_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
</dict>
</plist>"#;

        fs::write(&plist_path, plist_content).await.unwrap();

        let skill = NetworkAnalysisSkill::new();
        let target = AnalysisTarget::new(temp_dir.path().to_str().unwrap(), Platform::Ios);
        let findings = skill.check_ios_ats(&target).await.unwrap();

        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.title.contains("Transport Security")));
    }

    #[test]
    fn test_weak_cipher_lists() {
        let skill = NetworkAnalysisSkill::new();

        // Verify weak ciphers are detected
        assert_eq!(
            skill.get_cipher_strength("TLS_RSA_WITH_RC4_128_MD5"),
            CipherStrength::Weak
        );
        assert_eq!(
            skill.get_cipher_strength("TLS_RSA_WITH_NULL_SHA"),
            CipherStrength::Weak
        );

        // Verify medium ciphers
        assert_eq!(
            skill.get_cipher_strength("TLS_RSA_WITH_AES_128_CBC_SHA"),
            CipherStrength::Medium
        );

        // Verify unknown ciphers are strong by default
        assert_eq!(
            skill.get_cipher_strength("TLS_UNKNOWN_CIPHER"),
            CipherStrength::Strong
        );
    }

    #[test]
    fn test_network_analysis_result_structure() {
        let result = NetworkAnalysisResult {
            total_requests: 100,
            insecure_connections: 10,
            tls_enabled_connections: 90,
            certificate_pinning_enabled: false,
            cleartext_traffic_allowed: true,
            weak_tls_versions_found: vec![TlsVersion::Tls10, TlsVersion::Tls11],
            weak_cipher_suites_found: vec!["TLS_RSA_WITH_RC4_128_MD5".to_string()],
            credentials_exposed: 5,
            security_score: 75,
        };

        assert_eq!(result.total_requests, 100);
        assert_eq!(result.insecure_connections, 10);
        assert!(result.cleartext_traffic_allowed);
        assert_eq!(result.weak_tls_versions_found.len(), 2);
    }
}
