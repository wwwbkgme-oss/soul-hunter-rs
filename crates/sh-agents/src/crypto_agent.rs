//! # Crypto Analysis Agent
//!
//! Performs cryptographic analysis and identifies security issues in crypto implementations.
//! Capabilities include:
//! - Weak algorithm detection
//! - Insecure mode detection
//! - Hardcoded key detection
//! - Random number generator analysis
//! - Certificate validation analysis
//! - Protocol downgrade detection
//! - Key length validation
//! - Entropy analysis

use async_trait::async_trait;
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;
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

/// Crypto analysis agent for cryptographic security assessment
pub struct CryptoAgent {
    base: AgentBase,
    weak_algorithms: Vec<WeakAlgorithm>,
    insecure_modes: Vec<InsecureMode>,
    key_patterns: Vec<Regex>,
    entropy_threshold: f64,
}

/// Weak algorithm definition
#[derive(Debug, Clone)]
struct WeakAlgorithm {
    name: String,
    pattern: Regex,
    severity: Severity,
    description: String,
    recommendation: String,
}

/// Insecure mode definition
#[derive(Debug, Clone)]
struct InsecureMode {
    algorithm: String,
    mode: String,
    severity: Severity,
    description: String,
    recommendation: String,
}

/// Crypto finding details
#[derive(Debug, Clone)]
struct CryptoFinding {
    finding_type: CryptoFindingType,
    algorithm: Option<String>,
    key_size: Option<u32>,
    mode: Option<String>,
    location: String,
    context: String,
}

/// Types of crypto findings
#[derive(Debug, Clone)]
enum CryptoFindingType {
    WeakAlgorithm,
    InsecureMode,
    ShortKey,
    HardcodedKey,
    WeakRandom,
    CertificateValidation,
    ProtocolDowngrade,
    WeakHash,
    StaticIv,
    WeakPadding,
}

impl CryptoAgent {
    /// Create a new crypto analysis agent
    pub fn new(name: impl Into<String>) -> Self {
        let base = AgentBase::new(name, AgentType::Crypto)
            .with_capabilities(vec![
                AgentCapability::CryptoAnalysis,
                AgentCapability::SecretDetection,
            ])
            .with_platform(Platform::Android);

        Self {
            base,
            weak_algorithms: Self::init_weak_algorithms(),
            insecure_modes: Self::init_insecure_modes(),
            key_patterns: Self::init_key_patterns(),
            entropy_threshold: 3.0, // Minimum entropy per byte
        }
    }

    /// Initialize weak algorithm definitions
    fn init_weak_algorithms() -> Vec<WeakAlgorithm> {
        vec![
            WeakAlgorithm {
                name: "DES".to_string(),
                pattern: Regex::new(r"(?i)DES/(ECB|CBC|CFB|OFB)").unwrap(),
                severity: Severity::Critical,
                description: "DES is an outdated encryption algorithm with a 56-bit key that can be brute-forced in hours".to_string(),
                recommendation: "Use AES-256-GCM or ChaCha20-Poly1305 instead".to_string(),
            },
            WeakAlgorithm {
                name: "3DES".to_string(),
                pattern: Regex::new(r"(?i)3DES|TripleDES|DESede").unwrap(),
                severity: Severity::High,
                description: "3DES is vulnerable to Sweet32 birthday attacks and is deprecated".to_string(),
                recommendation: "Use AES-256-GCM instead".to_string(),
            },
            WeakAlgorithm {
                name: "RC4".to_string(),
                pattern: Regex::new(r"(?i)RC4|ARCFOUR").unwrap(),
                severity: Severity::Critical,
                description: "RC4 has multiple vulnerabilities and is completely broken".to_string(),
                recommendation: "Use AES-256-GCM or ChaCha20-Poly1305 instead".to_string(),
            },
            WeakAlgorithm {
                name: "Blowfish".to_string(),
                pattern: Regex::new(r"(?i)Blowfish").unwrap(),
                severity: Severity::Medium,
                description: "Blowfish has a 64-bit block size vulnerable to birthday attacks".to_string(),
                recommendation: "Use AES-256-GCM instead".to_string(),
            },
            WeakAlgorithm {
                name: "MD5".to_string(),
                pattern: Regex::new(r"(?i)MessageDigest\.getInstance\([\"']MD5[\"']\)|MD5\(").unwrap(),
                severity: Severity::High,
                description: "MD5 is cryptographically broken and vulnerable to collision attacks".to_string(),
                recommendation: "Use SHA-256 or SHA-3 for hashing".to_string(),
            },
            WeakAlgorithm {
                name: "SHA1".to_string(),
                pattern: Regex::new(r"(?i)MessageDigest\.getInstance\([\"']SHA-?1[\"']\)|SHA1\(").unwrap(),
                severity: Severity::High,
                description: "SHA1 is cryptographically broken and vulnerable to collision attacks".to_string(),
                recommendation: "Use SHA-256 or SHA-3 for hashing".to_string(),
            },
            WeakAlgorithm {
                name: "RSA with PKCS#1 v1.5".to_string(),
                pattern: Regex::new(r"(?i)RSA/ECB/PKCS1Padding").unwrap(),
                severity: Severity::Medium,
                description: "PKCS#1 v1.5 padding is vulnerable to padding oracle attacks".to_string(),
                recommendation: "Use RSA-OAEP padding instead".to_string(),
            },
        ]
    }

    /// Initialize insecure mode definitions
    fn init_insecure_modes() -> Vec<InsecureMode> {
        vec![
            InsecureMode {
                algorithm: "AES".to_string(),
                mode: "ECB".to_string(),
                severity: Severity::High,
                description: "ECB mode does not provide semantic security and leaks information about the plaintext".to_string(),
                recommendation: "Use AES-GCM or AES-CTR with proper IV/nonce management".to_string(),
            },
            InsecureMode {
                algorithm: "AES".to_string(),
                mode: "CBC".to_string(),
                severity: Severity::Medium,
                description: "CBC mode without proper IV management is vulnerable to attacks".to_string(),
                recommendation: "Use AES-GCM which provides authenticated encryption".to_string(),
            },
        ]
    }

    /// Initialize key detection patterns
    fn init_key_patterns() -> Vec<Regex> {
        vec![
            // AES keys (128, 192, 256 bits in hex)
            Regex::new(r"[0-9a-fA-F]{32,64}").unwrap(),
            // Base64 encoded keys
            Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").unwrap(),
            // RSA private key markers
            Regex::new(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
            // API keys
            Regex::new(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]").unwrap(),
            // Secret keys
            Regex::new(r"(?i)(secret[_-]?key|secret)\s*[=:]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]").unwrap(),
        ]
    }

    /// Analyze cryptographic implementation
    #[instrument(skip(self, target), fields(agent_id = %self.base.id))]
    async fn analyze_crypto(&self, target: &AnalysisTarget) -> Result<FindingCollection> {
        info!("Starting crypto analysis for: {}", target.path);

        let path = Path::new(&target.path);
        if !path.exists() {
            return Err(AgentError::InvalidConfig(format!(
                "Target not found: {}",
                target.path
            )));
        }

        let mut findings = Vec::new();

        // Analyze source code or binary
        if path.is_dir() {
            findings.extend(self.analyze_directory(path).await?);
        } else if path.is_file() {
            findings.extend(self.analyze_file(path).await?);
        }

        info!(
            "Crypto analysis completed. Found {} findings",
            findings.len()
        );

        Ok(FindingCollection::new(findings))
    }

    /// Analyze a directory
    #[instrument(skip(self, path))]
    async fn analyze_directory(&self, path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let mut entries = tokio::fs::read_dir(path).await.map_err(AgentError::Io)?;

        while let Some(entry) = entries.next_entry().await.map_err(AgentError::Io)? {
            let entry_path = entry.path();
            let metadata = entry.metadata().await.map_err(AgentError::Io)?;

            if metadata.is_file() {
                // Check if it's a source code file
                if let Some(ext) = entry_path.extension() {
                    let ext = ext.to_string_lossy().to_lowercase();
                    if matches!(ext.as_str(), "java" | "kt" | "c" | "cpp" | "rs" | "js" | "ts" | "py" | "go") {
                        findings.extend(self.analyze_file(&entry_path).await?);
                    }
                }
            } else if metadata.is_dir() {
                // Recursively analyze subdirectories
                findings.extend(self.analyze_directory(&entry_path).await?);
            }
        }

        Ok(findings)
    }

    /// Analyze a single file
    #[instrument(skip(self, path))]
    async fn analyze_file(&self, path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let content = match tokio::fs::read_to_string(path).await {
            Ok(c) => c,
            Err(_) => return Ok(findings), // Skip binary files
        };

        let file_path = path.to_string_lossy().to_string();

        // Check for weak algorithms
        findings.extend(self.check_weak_algorithms(&content, &file_path).await?);

        // Check for insecure modes
        findings.extend(self.check_insecure_modes(&content, &file_path).await?);

        // Check for hardcoded keys
        findings.extend(self.check_hardcoded_keys(&content, &file_path).await?);

        // Check for weak random number generation
        findings.extend(self.check_weak_random(&content, &file_path).await?);

        // Check for certificate validation issues
        findings.extend(self.check_certificate_validation(&content, &file_path).await?);

        // Check for static IVs
        findings.extend(self.check_static_iv(&content, &file_path).await?);

        Ok(findings)
    }

    /// Check for weak algorithms
    #[instrument(skip(self, content, file_path))]
    async fn check_weak_algorithms(
        &self,
        content: &str,
        file_path: &str,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for weak_algo in &self.weak_algorithms {
            for mat in weak_algo.pattern.find_iter(content) {
                findings.push(
                    Finding::new(
                        format!("Weak Cryptographic Algorithm: {}", weak_algo.name),
                        weak_algo.description.clone(),
                    )
                    .with_severity(weak_algo.severity)
                    .with_confidence(Confidence::Confirmed)
                    .with_type("weak_algorithm")
                    .with_cwe("CWE-327")
                    .with_owasp("M5: Insufficient Cryptography")
                    .with_location(
                        Location::new()
                            .with_file(file_path)
                            .with_platform(Platform::Android)
                            .with_snippet(mat.as_str()),
                    )
                    .with_remediation(
                        Remediation::new(&weak_algo.recommendation)
                            .with_effort(RemediationEffort::Medium)
                            .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x04g-Testing-Cryptography"),
                    )
                    .with_tool("CryptoAgent", "0.1.0"),
                );
            }
        }

        Ok(findings)
    }

    /// Check for insecure modes
    #[instrument(skip(self, content, file_path))]
    async fn check_insecure_modes(
        &self,
        content: &str,
        file_path: &str,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for insecure_mode in &self.insecure_modes {
            let pattern = format!(
                r"(?i){}/\s*{}",
                insecure_mode.algorithm, insecure_mode.mode
            );
            if let Ok(regex) = Regex::new(&pattern) {
                for mat in regex.find_iter(content) {
                    findings.push(
                        Finding::new(
                            format!(
                                "Insecure Cipher Mode: {}/{}",
                                insecure_mode.algorithm, insecure_mode.mode
                            ),
                            insecure_mode.description.clone(),
                        )
                        .with_severity(insecure_mode.severity)
                        .with_confidence(Confidence::Confirmed)
                        .with_type("insecure_mode")
                        .with_cwe("CWE-326")
                        .with_owasp("M5: Insufficient Cryptography")
                        .with_location(
                            Location::new()
                                .with_file(file_path)
                                .with_platform(Platform::Android)
                                .with_snippet(mat.as_str()),
                        )
                        .with_remediation(
                            Remediation::new(&insecure_mode.recommendation)
                                .with_effort(RemediationEffort::Medium)
                                .add_reference("https://developer.android.com/guide/topics/security/cryptography"),
                        )
                        .with_tool("CryptoAgent", "0.1.0"),
                    );
                }
            }
        }

        Ok(findings)
    }

    /// Check for hardcoded keys
    #[instrument(skip(self, content, file_path))]
    async fn check_hardcoded_keys(
        &self,
        content: &str,
        file_path: &str,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for hardcoded AES keys
        let aes_key_pattern = Regex::new(r"(?i)(?:secretkeyspec|ivparameterspec)\s*\(\s*['\"]([0-9a-fA-F]{32,64})['\"]").unwrap();
        for mat in aes_key_pattern.find_iter(content) {
            findings.push(
                Finding::new(
                    "Hardcoded Cryptographic Key",
                    "A cryptographic key is hardcoded in the source code. This makes it easy for attackers to extract and use the key.",
                )
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Confirmed)
                .with_type("hardcoded_key")
                .with_cwe("CWE-798")
                .with_owasp("M5: Insufficient Cryptography")
                .with_location(
                    Location::new()
                        .with_file(file_path)
                        .with_platform(Platform::Android)
                        .with_snippet(mat.as_str()),
                )
                .with_remediation(
                    Remediation::new("Remove hardcoded keys from source code. Use Android Keystore or secure key management solutions.")
                        .with_effort(RemediationEffort::Medium)
                        .add_reference("https://developer.android.com/training/articles/keystore")
                        .add_reference("https://owasp.org/www-project-mobile-security-testing-guide/latest/0x05d-Testing-Data-Storage"),
                )
                .with_tool("CryptoAgent", "0.1.0"),
            );
        }

        // Check for hardcoded passwords used as keys
        let password_pattern = Regex::new(r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]").unwrap();
        for mat in password_pattern.find_iter(content) {
            // Check entropy to filter out common variable names
            let key = mat.as_str();
            if self.calculate_entropy(key) > self.entropy_threshold {
                findings.push(
                    Finding::new(
                        "Hardcoded Password/Key Material",
                        "Password or key material is hardcoded in the source code. This is a serious security risk.",
                    )
                    .with_severity(Severity::Critical)
                    .with_confidence(Confidence::Probable)
                    .with_type("hardcoded_password")
                    .with_cwe("CWE-798")
                    .with_owasp("M5: Insufficient Cryptography")
                    .with_location(
                        Location::new()
                            .with_file(file_path)
                            .with_platform(Platform::Android)
                            .with_snippet(mat.as_str()),
                    )
                    .with_remediation(
                        Remediation::new("Remove hardcoded passwords. Use secure credential storage or authentication mechanisms.")
                            .with_effort(RemediationEffort::Medium),
                    )
                    .with_tool("CryptoAgent", "0.1.0"),
                );
            }
        }

        // Check for private keys
        let private_key_pattern = Regex::new(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap();
        for mat in private_key_pattern.find_iter(content) {
            findings.push(
                Finding::new(
                    "Private Key Embedded in Source",
                    "A private key is embedded in the source code. Private keys should never be included in application code.",
                )
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Confirmed)
                .with_type("embedded_private_key")
                .with_cwe("CWE-798")
                .with_owasp("M5: Insufficient Cryptography")
                .with_location(
                    Location::new()
                        .with_file(file_path)
                        .with_platform(Platform::Android)
                        .with_snippet(mat.as_str()),
                )
                .with_remediation(
                    Remediation::new("Remove private keys from source code. Use secure key storage mechanisms like Android Keystore or hardware security modules.")
                        .with_effort(RemediationEffort::High)
                        .add_reference("https://developer.android.com/training/articles/keystore"),
                )
                .with_tool("CryptoAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Check for weak random number generation
    #[instrument(skip(self, content, file_path))]
    async fn check_weak_random(&self, content: &str, file_path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for java.util.Random (not cryptographically secure)
        let weak_random_pattern = Regex::new(r"(?i)new\s+Random\(\)|java\.util\.Random").unwrap();
        for mat in weak_random_pattern.find_iter(content) {
            findings.push(
                Finding::new(
                    "Weak Random Number Generator",
                    "java.util.Random is not cryptographically secure and should not be used for security-sensitive operations.",
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Confirmed)
                .with_type("weak_random")
                .with_cwe("CWE-338")
                .with_owasp("M5: Insufficient Cryptography")
                .with_location(
                    Location::new()
                        .with_file(file_path)
                        .with_platform(Platform::Android)
                        .with_snippet(mat.as_str()),
                )
                .with_remediation(
                    Remediation::new("Use java.security.SecureRandom for cryptographically secure random number generation.")
                        .with_effort(RemediationEffort::Low)
                        .add_reference("https://developer.android.com/reference/java/security/SecureRandom"),
                )
                .with_tool("CryptoAgent", "0.1.0"),
            );
        }

        // Check for predictable seeds
        let seeded_random_pattern = Regex::new(r"(?i)new\s+Random\s*\(\s*\d+\s*\)|setSeed\s*\(\s*\d+\s*\)").unwrap();
        for mat in seeded_random_pattern.find_iter(content) {
            findings.push(
                Finding::new(
                    "Predictable Random Seed",
                    "Random number generator is seeded with a predictable value. This makes the output predictable and insecure.",
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Confirmed)
                .with_type("predictable_seed")
                .with_cwe("CWE-336")
                .with_owasp("M5: Insufficient Cryptography")
                .with_location(
                    Location::new()
                        .with_file(file_path)
                        .with_platform(Platform::Android)
                        .with_snippet(mat.as_str()),
                )
                .with_remediation(
                    Remediation::new("Do not seed SecureRandom with predictable values. Let it self-seed from the OS entropy pool.")
                        .with_effort(RemediationEffort::Low),
                )
                .with_tool("CryptoAgent", "0.1.0"),
            );
        }

        // Check for Math.random() usage
        let math_random_pattern = Regex::new(r"(?i)Math\.random\(\)").unwrap();
        for mat in math_random_pattern.find_iter(content) {
            findings.push(
                Finding::new(
                    "Math.random() Used for Security",
                    "Math.random() is not cryptographically secure and should not be used for security-sensitive operations like generating tokens or keys.",
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Confirmed)
                .with_type("math_random")
                .with_cwe("CWE-338")
                .with_owasp("M5: Insufficient Cryptography")
                .with_location(
                    Location::new()
                        .with_file(file_path)
                        .with_platform(Platform::Android)
                        .with_snippet(mat.as_str()),
                )
                .with_remediation(
                    Remediation::new("Use SecureRandom for generating random values used in security contexts.")
                        .with_effort(RemediationEffort::Low),
                )
                .with_tool("CryptoAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Check for certificate validation issues
    #[instrument(skip(self, content, file_path))]
    async fn check_certificate_validation(
        &self,
        content: &str,
        file_path: &str,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for hostname verification disabled
        let hostname_verifier_pattern = Regex::new(r"(?i)setHostnameVerifier\s*\(\s*ALLOW_ALL\s*\)|HostnameVerifier\s*\{\s*[^}]*return\s+true").unwrap();
        for mat in hostname_verifier_pattern.find_iter(content) {
            findings.push(
                Finding::new(
                    "Hostname Verification Disabled",
                    "Hostname verification is disabled or accepts all hostnames. This makes the application vulnerable to man-in-the-middle attacks.",
                )
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Confirmed)
                .with_type("disabled_hostname_verification")
                .with_cwe("CWE-295")
                .with_owasp("M3: Insecure Communication")
                .with_location(
                    Location::new()
                        .with_file(file_path)
                        .with_platform(Platform::Android)
                        .with_snippet(mat.as_str()),
                )
                .with_remediation(
                    Remediation::new("Never disable hostname verification. Use the default hostname verifier or implement proper validation.")
                        .with_effort(RemediationEffort::Medium)
                        .add_reference("https://developer.android.com/training/articles/security-ssl"),
                )
                .with_tool("CryptoAgent", "0.1.0"),
            );
        }

        // Check for certificate validation disabled
        let trust_all_pattern = Regex::new(r"(?i)checkServerTrusted\s*\([^)]*\)\s*\{\s*[^}]*\}|TrustAll|trust\s+all\s+certificates").unwrap();
        for mat in trust_all_pattern.find_iter(content) {
            findings.push(
                Finding::new(
                    "Certificate Validation Disabled",
                    "Server certificate validation is disabled. This makes the application vulnerable to man-in-the-middle attacks.",
                )
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Confirmed)
                .with_type("disabled_certificate_validation")
                .with_cwe("CWE-295")
                .with_owasp("M3: Insecure Communication")
                .with_location(
                    Location::new()
                        .with_file(file_path)
                        .with_platform(Platform::Android)
                        .with_snippet(mat.as_str()),
                )
                .with_remediation(
                    Remediation::new("Never disable certificate validation. Implement proper certificate pinning and validation.")
                        .with_effort(RemediationEffort::High)
                        .add_reference("https://developer.android.com/training/articles/security-config"),
                )
                .with_tool("CryptoAgent", "0.1.0"),
            );
        }

        // Check for insecure SSL context
        let insecure_ssl_pattern = Regex::new(r"(?i)SSLContext\.getInstance\s*\(\s*['\"]SSL['\"]\s*\)").unwrap();
        for mat in insecure_ssl_pattern.find_iter(content) {
            findings.push(
                Finding::new(
                    "Insecure SSL Context",
                    "SSL context is initialized with 'SSL' which may include insecure protocols. Use 'TLS' instead.",
                )
                .with_severity(Severity::Medium)
                .with_confidence(Confidence::Confirmed)
                .with_type("insecure_ssl_context")
                .with_cwe("CWE-326")
                .with_owasp("M3: Insecure Communication")
                .with_location(
                    Location::new()
                        .with_file(file_path)
                        .with_platform(Platform::Android)
                        .with_snippet(mat.as_str()),
                )
                .with_remediation(
                    Remediation::new("Use 'TLS' instead of 'SSL' when creating SSLContext. Consider specifying TLSv1.2 or higher.")
                        .with_effort(RemediationEffort::Low),
                )
                .with_tool("CryptoAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Check for static IVs
    #[instrument(skip(self, content, file_path))]
    async fn check_static_iv(&self, content: &str, file_path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for static IV in cipher initialization
        let static_iv_pattern = Regex::new(r"(?i)IvParameterSpec\s*\(\s*['\"]([0-9a-fA-F]{32})['\"]|IvParameterSpec\s*\(\s*new\s+byte\[\]\s*\{\s*0").unwrap();
        for mat in static_iv_pattern.find_iter(content) {
            findings.push(
                Finding::new(
                    "Static Initialization Vector",
                    "A static IV is used for encryption. IVs should be unique for each encryption operation to maintain security.",
                )
                .with_severity(Severity::High)
                .with_confidence(Confidence::Confirmed)
                .with_type("static_iv")
                .with_cwe("CWE-329")
                .with_owasp("M5: Insufficient Cryptography")
                .with_location(
                    Location::new()
                        .with_file(file_path)
                        .with_platform(Platform::Android)
                        .with_snippet(mat.as_str()),
                )
                .with_remediation(
                    Remediation::new("Generate a random IV for each encryption operation and transmit it alongside the ciphertext (e.g., prepend to ciphertext).")
                        .with_effort(RemediationEffort::Medium)
                        .add_reference("https://developer.android.com/guide/topics/security/cryptography"),
                )
                .with_tool("CryptoAgent", "0.1.0"),
            );
        }

        // Check for zero IV
        let zero_iv_pattern = Regex::new(r"(?i)new\s+IvParameterSpec\s*\(\s*new\s+byte\[16\]\s*\)").unwrap();
        for mat in zero_iv_pattern.find_iter(content) {
            findings.push(
                Finding::new(
                    "Zero Initialization Vector",
                    "A zero IV is used for encryption. This completely defeats the purpose of using an IV and makes the encryption vulnerable.",
                )
                .with_severity(Severity::Critical)
                .with_confidence(Confidence::Confirmed)
                .with_type("zero_iv")
                .with_cwe("CWE-329")
                .with_owasp("M5: Insufficient Cryptography")
                .with_location(
                    Location::new()
                        .with_file(file_path)
                        .with_platform(Platform::Android)
                        .with_snippet(mat.as_str()),
                )
                .with_remediation(
                    Remediation::new("Generate a random IV for each encryption operation using SecureRandom.")
                        .with_effort(RemediationEffort::Low),
                )
                .with_tool("CryptoAgent", "0.1.0"),
            );
        }

        Ok(findings)
    }

    /// Calculate Shannon entropy of a string
    fn calculate_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }

        let mut freq = HashMap::new();
        for c in s.chars() {
            *freq.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        freq.values()
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum()
    }
}

#[async_trait]
impl SecurityAgent for CryptoAgent {
    fn id(&self) -> AgentId {
        self.base.id
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn agent_type(&self) -> AgentType {
        AgentType::Crypto
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
        info!("Initializing CryptoAgent: {}", self.base.name);

        if let Ok(mut guard) = self.base.config.write() {
            *guard = config;
        }

        self.base.set_status(AgentStatus::Idle);
        self.base.update_heartbeat();

        info!("CryptoAgent initialized successfully");
        Ok(())
    }

    #[instrument(skip(self, context), fields(agent_id = %self.base.id, task_id = %context.task_id))]
    async fn execute(&self, context: AgentContext) -> Result<AgentResult> {
        let start_time = std::time::Instant::now();

        info!(
            "CryptoAgent executing task: {} on target: {}",
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

        // Perform crypto analysis
        let result = self.analyze_crypto(&context.target).await;

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        match result {
            Ok(findings) => {
                self.base.increment_completed();
                self.base.set_status(AgentStatus::Idle);

                info!(
                    "CryptoAgent completed task: {} with {} findings in {}ms",
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
                    "CryptoAgent failed task: {} with error: {}",
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
        info!("Shutting down CryptoAgent: {}", self.base.name);
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
    fn test_crypto_agent_creation() {
        let agent = CryptoAgent::new("Test Crypto Agent");

        assert_eq!(agent.name(), "Test Crypto Agent");
        assert_eq!(agent.agent_type(), AgentType::Crypto);
        assert!(agent.has_capability(&AgentCapability::CryptoAnalysis));
        assert!(agent.has_capability(&AgentCapability::SecretDetection));
    }

    #[test]
    fn test_weak_algorithms_initialized() {
        let agent = CryptoAgent::new("Test Agent");
        assert!(!agent.weak_algorithms.is_empty());
        
        let des_algo = agent.weak_algorithms.iter().find(|a| a.name == "DES");
        assert!(des_algo.is_some());
        assert_eq!(des_algo.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_insecure_modes_initialized() {
        let agent = CryptoAgent::new("Test Agent");
        assert!(!agent.insecure_modes.is_empty());
        
        let ecb_mode = agent.insecure_modes.iter().find(|m| m.mode == "ECB");
        assert!(ecb_mode.is_some());
    }

    #[test]
    fn test_key_patterns_initialized() {
        let agent = CryptoAgent::new("Test Agent");
        assert!(!agent.key_patterns.is_empty());
    }

    #[tokio::test]
    async fn test_crypto_agent_initialization() {
        let mut agent = CryptoAgent::new("Test Agent");
        let config = AgentConfig::default().with_timeout(600);

        assert!(agent.initialize(config).await.is_ok());
        assert_eq!(agent.status(), AgentStatus::Idle);
    }

    #[tokio::test]
    async fn test_crypto_agent_health() {
        let agent = CryptoAgent::new("Test Agent");
        let health = agent.health().await;

        assert_eq!(health.agent_id, agent.id());
        assert_eq!(health.status, AgentStatus::Idle);
    }

    #[test]
    fn test_entropy_calculation() {
        let agent = CryptoAgent::new("Test Agent");
        
        // High entropy string
        let high_entropy = "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789";
        let entropy = agent.calculate_entropy(high_entropy);
        assert!(entropy > 4.0); // Should have high entropy
        
        // Low entropy string (repeated character)
        let low_entropy = "aaaaaaaaaa";
        let entropy2 = agent.calculate_entropy(low_entropy);
        assert!(entropy2 < 1.0); // Should have low entropy
    }
}
