//! # Secret Detection Module
//!
//! Detects hardcoded secrets, API keys, passwords, and other sensitive data
//! in APK files and source code.
//!
//! ## Supported Secret Types
//!
//! - API Keys (various formats)
//! - OAuth tokens
//! - Database connection strings
//! - Private keys
//! - Passwords
//! - AWS credentials
//! - Google API keys
//! - Firebase tokens
//! - JWT tokens
//! - And more...
//!
//! ## Example
//!
//! ```rust
//! use sh_tools::secrets::SecretScanner;
//!
//! async fn scan_for_secrets() {
//!     let scanner = SecretScanner::new();
//!     let findings = scanner.scan_text("const API_KEY = 'sk-abc123'").await;
//!     println!("Found {} secrets", findings.len());
//! }
//! ```

use crate::{Result, ToolsError};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info, instrument, trace, warn};

/// Types of secrets that can be detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    /// Generic API key
    ApiKey,

    /// AWS Access Key ID
    AwsAccessKeyId,

    /// AWS Secret Access Key
    AwsSecretKey,

    /// Google API Key
    GoogleApiKey,

    /// Firebase token
    FirebaseToken,

    /// Private key (various formats)
    PrivateKey,

    /// Password
    Password,

    /// Database connection string
    DatabaseConnection,

    /// OAuth token
    OAuthToken,

    /// JWT token
    JwtToken,

    /// GitHub token
    GithubToken,

    /// Slack token
    SlackToken,

    /// Stripe key
    StripeKey,

    /// Twilio key
    TwilioKey,

    /// SendGrid key
    SendGridKey,

    /// Generic secret
    GenericSecret,

    /// Hardcoded IP address
    HardcodedIp,

    /// Hardcoded URL
    HardcodedUrl,

    /// Certificate
    Certificate,

    /// Encryption key
    EncryptionKey,
}

impl SecretType {
    /// Get the display name for this secret type
    pub fn display_name(&self) -> &'static str {
        match self {
            SecretType::ApiKey => "API Key",
            SecretType::AwsAccessKeyId => "AWS Access Key ID",
            SecretType::AwsSecretKey => "AWS Secret Key",
            SecretType::GoogleApiKey => "Google API Key",
            SecretType::FirebaseToken => "Firebase Token",
            SecretType::PrivateKey => "Private Key",
            SecretType::Password => "Password",
            SecretType::DatabaseConnection => "Database Connection String",
            SecretType::OAuthToken => "OAuth Token",
            SecretType::JwtToken => "JWT Token",
            SecretType::GithubToken => "GitHub Token",
            SecretType::SlackToken => "Slack Token",
            SecretType::StripeKey => "Stripe Key",
            SecretType::TwilioKey => "Twilio Key",
            SecretType::SendGridKey => "SendGrid Key",
            SecretType::GenericSecret => "Generic Secret",
            SecretType::HardcodedIp => "Hardcoded IP Address",
            SecretType::HardcodedUrl => "Hardcoded URL",
            SecretType::Certificate => "Certificate",
            SecretType::EncryptionKey => "Encryption Key",
        }
    }

    /// Get the severity level for this secret type
    pub fn severity(&self) -> &'static str {
        match self {
            SecretType::PrivateKey | SecretType::AwsSecretKey | SecretType::Password => "critical",
            SecretType::ApiKey
            | SecretType::AwsAccessKeyId
            | SecretType::GoogleApiKey
            | SecretType::FirebaseToken
            | SecretType::DatabaseConnection
            | SecretType::OAuthToken
            | SecretType::JwtToken
            | SecretType::GithubToken
            | SecretType::StripeKey
            | SecretType::EncryptionKey => "high",
            SecretType::SlackToken | SecretType::TwilioKey | SecretType::SendGridKey => "high",
            SecretType::GenericSecret | SecretType::Certificate => "medium",
            SecretType::HardcodedIp | SecretType::HardcodedUrl => "low",
        }
    }

    /// Get CWE ID for this secret type
    pub fn cwe_id(&self) -> Option<&'static str> {
        match self {
            SecretType::Password | SecretType::ApiKey | SecretType::PrivateKey => Some("CWE-798"),
            SecretType::AwsSecretKey
            | SecretType::AwsAccessKeyId
            | SecretType::GoogleApiKey
            | SecretType::FirebaseToken => Some("CWE-798"),
            SecretType::DatabaseConnection => Some("CWE-798"),
            SecretType::GenericSecret => Some("CWE-798"),
            _ => None,
        }
    }
}

/// A detected secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretFinding {
    /// Type of secret
    pub secret_type: SecretType,

    /// Secret value (may be masked)
    pub value: String,

    /// Masked value for display
    pub masked_value: String,

    /// File path where found
    pub file_path: Option<String>,

    /// Line number
    pub line_number: Option<u32>,

    /// Column number
    pub column_number: Option<u32>,

    /// Context around the secret
    pub context: String,

    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,

    /// Pattern that matched
    pub pattern_name: String,
}

impl SecretFinding {
    /// Create a new secret finding
    pub fn new(secret_type: SecretType, value: impl Into<String>) -> Self {
        let value = value.into();
        let masked_value = mask_secret(&value);

        Self {
            secret_type,
            value,
            masked_value,
            file_path: None,
            line_number: None,
            column_number: None,
            context: String::new(),
            confidence: 0.5,
            pattern_name: String::new(),
        }
    }

    /// Set file location
    pub fn with_location(
        mut self,
        file_path: impl Into<String>,
        line: u32,
        column: u32,
    ) -> Self {
        self.file_path = Some(file_path.into());
        self.line_number = Some(line);
        self.column_number = Some(column);
        self
    }

    /// Set context
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = context.into();
        self
    }

    /// Set confidence
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Set pattern name
    pub fn with_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.pattern_name = pattern.into();
        self
    }

    /// Get severity
    pub fn severity(&self) -> &'static str {
        self.secret_type.severity()
    }

    /// Get CWE ID
    pub fn cwe_id(&self) -> Option<&'static str> {
        self.secret_type.cwe_id()
    }
}

/// Secret scanner for detecting hardcoded secrets
#[derive(Debug)]
pub struct SecretScanner {
    /// Compiled regex patterns
    patterns: Vec<SecretPattern>,

    /// Whether to mask secret values in output
    mask_secrets: bool,

    /// Minimum confidence threshold
    min_confidence: f32,
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretScanner {
    /// Create a new secret scanner with default patterns
    pub fn new() -> Self {
        let mut scanner = Self {
            patterns: Vec::new(),
            mask_secrets: true,
            min_confidence: 0.5,
        };

        scanner.load_default_patterns();
        scanner
    }

    /// Create a scanner with custom settings
    pub fn with_options(mask_secrets: bool, min_confidence: f32) -> Self {
        let mut scanner = Self {
            patterns: Vec::new(),
            mask_secrets,
            min_confidence,
        };

        scanner.load_default_patterns();
        scanner
    }

    /// Load default detection patterns
    fn load_default_patterns(&mut self) {
        // API Keys
        self.add_pattern(
            SecretType::ApiKey,
            "api_key_generic",
            r#"(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?"#,
            0.7,
        );

        // AWS Access Key ID
        self.add_pattern(
            SecretType::AwsAccessKeyId,
            "aws_access_key_id",
            r#"AKIA[0-9A-Z]{16}"#,
            0.95,
        );

        // AWS Secret Key
        self.add_pattern(
            SecretType::AwsSecretKey,
            "aws_secret_key",
            r#"(?i)aws[_-]?(?:secret|access)[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?"#,
            0.9,
        );

        // Google API Key
        self.add_pattern(
            SecretType::GoogleApiKey,
            "google_api_key",
            r#"AIza[0-9A-Za-z_-]{35}"#,
            0.95,
        );

        // Firebase
        self.add_pattern(
            SecretType::FirebaseToken,
            "firebase_token",
            r#"(?i)firebase[_-]?(?:token|key|secret)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?"#,
            0.8,
        );

        // Private Keys
        self.add_pattern(
            SecretType::PrivateKey,
            "private_key_pem",
            r#"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"#,
            0.99,
        );

        // Passwords
        self.add_pattern(
            SecretType::Password,
            "password_hardcoded",
            r#"(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^"\'\s]{4,})["\']?"#,
            0.8,
        );

        // Database connections
        self.add_pattern(
            SecretType::DatabaseConnection,
            "db_connection_string",
            r#"(?i)(mongodb|mysql|postgresql|postgres|jdbc)://[^\s\"']+"#,
            0.85,
        );

        // OAuth tokens
        self.add_pattern(
            SecretType::OAuthToken,
            "oauth_token",
            r#"(?i)oauth[_-]?token\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?"#,
            0.8,
        );

        // JWT tokens
        self.add_pattern(
            SecretType::JwtToken,
            "jwt_token",
            r#"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"#,
            0.9,
        );

        // GitHub tokens
        self.add_pattern(
            SecretType::GithubToken,
            "github_token",
            r#"gh[pousr]_[A-Za-z0-9_]{36,}"#,
            0.95,
        );

        // Slack tokens
        self.add_pattern(
            SecretType::SlackToken,
            "slack_token",
            r#"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}(-[a-zA-Z0-9]{24})?"#,
            0.95,
        );

        // Stripe keys
        self.add_pattern(
            SecretType::StripeKey,
            "stripe_key",
            r#"sk_live_[0-9a-zA-Z]{24,}"#,
            0.95,
        );

        // Twilio
        self.add_pattern(
            SecretType::TwilioKey,
            "twilio_key",
            r#"SK[0-9a-fA-F]{32}"#,
            0.9,
        );

        // SendGrid
        self.add_pattern(
            SecretType::SendGridKey,
            "sendgrid_key",
            r#"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"#,
            0.95,
        );

        // Generic secrets
        self.add_pattern(
            SecretType::GenericSecret,
            "secret_generic",
            r#"(?i)(secret|token|key)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{16,})["\']?"#,
            0.6,
        );

        // Hardcoded IPs
        self.add_pattern(
            SecretType::HardcodedIp,
            "hardcoded_ip",
            r#"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"#,
            0.5,
        );

        // URLs with credentials
        self.add_pattern(
            SecretType::HardcodedUrl,
            "url_with_creds",
            r#"https?://[^:]+:[^@]+@[^/]+"#,
            0.85,
        );

        // Certificates
        self.add_pattern(
            SecretType::Certificate,
            "certificate_pem",
            r#"-----BEGIN CERTIFICATE-----"#,
            0.9,
        );

        // Encryption keys
        self.add_pattern(
            SecretType::EncryptionKey,
            "encryption_key",
            r#"(?i)(encryption[_-]?key|aes[_-]?key|des[_-]?key)\s*[=:]\s*["\']?([a-fA-F0-9]{16,})["\']?"#,
            0.85,
        );
    }

    /// Add a custom pattern
    pub fn add_pattern(
        &mut self,
        secret_type: SecretType,
        name: &str,
        pattern: &str,
        confidence: f32,
    ) {
        match Regex::new(pattern) {
            Ok(regex) => {
                self.patterns.push(SecretPattern {
                    secret_type,
                    name: name.to_string(),
                    regex,
                    confidence,
                });
            }
            Err(e) => {
                warn!("Failed to compile pattern '{}': {}", name, e);
            }
        }
    }

    /// Scan text for secrets
    #[instrument(skip(self, text), fields(text_len = text.len()))]
    pub async fn scan_text(&self, text: &str) -> Vec<SecretFinding> {
        trace!("Scanning text for secrets ({} bytes)", text.len());
        let mut findings = Vec::new();

        for pattern in &self.patterns {
            for mat in pattern.regex.find_iter(text) {
                let value = mat.as_str().to_string();

                // Skip if value is too short or looks like a variable name
                if value.len() < 8 || is_likely_false_positive(&value) {
                    continue;
                }

                let finding = SecretFinding::new(pattern.secret_type, value.clone())
                    .with_pattern(pattern.name.clone())
                    .with_confidence(pattern.confidence)
                    .with_context(extract_context(text, mat.start(), mat.end()));

                if finding.confidence >= self.min_confidence {
                    findings.push(finding);
                }
            }
        }

        // Remove duplicates
        findings.sort_by(|a, b| a.value.cmp(&b.value));
        findings.dedup_by(|a, b| a.value == b.value);

        debug!("Found {} secrets in text", findings.len());
        findings
    }

    /// Scan a file for secrets
    #[instrument(skip(self), fields(path = %path))]
    pub async fn scan_file(&self, path: &str, content: &str) -> Vec<SecretFinding> {
        trace!("Scanning file for secrets: {}", path);
        let mut findings = self.scan_text(content).await;

        // Add file location info
        for finding in &mut findings {
            finding.file_path = Some(path.to_string());

            // Find line and column numbers
            if let Some((line, col)) = find_position(content, &finding.value) {
                finding.line_number = Some(line);
                finding.column_number = Some(col);
            }
        }

        findings
    }

    /// Scan multiple files
    #[instrument(skip(self, files))]
    pub async fn scan_files(&self, files: &[(String, String)]) -> Vec<SecretFinding> {
        trace!("Scanning {} files for secrets", files.len());
        let mut all_findings = Vec::new();

        for (path, content) in files {
            let findings = self.scan_file(path, content).await;
            all_findings.extend(findings);
        }

        info!("Found {} total secrets in {} files", all_findings.len(), files.len());
        all_findings
    }

    /// Scan an APK file
    #[instrument(skip(self), fields(path = %path))]
    pub async fn scan_apk(&self, path: &str) -> Result<Vec<SecretFinding>> {
        use crate::apk::ApkParser;

        info!("Scanning APK for secrets: {}", path);

        let parser = ApkParser::new();
        let text_files = parser.extract_text_files(path).await?;

        let mut all_findings = Vec::new();

        for (file_path, content) in text_files {
            let findings = self.scan_file(&file_path, &content).await;
            all_findings.extend(findings);
        }

        info!(
            "Found {} secrets in APK: {}",
            all_findings.len(),
            path
        );
        Ok(all_findings)
    }

    /// Set whether to mask secrets
    pub fn set_mask_secrets(&mut self, mask: bool) {
        self.mask_secrets = mask;
    }

    /// Set minimum confidence threshold
    pub fn set_min_confidence(&mut self, confidence: f32) {
        self.min_confidence = confidence.clamp(0.0, 1.0);
    }

    /// Get loaded patterns
    pub fn patterns(&self) -> &[SecretPattern] {
        &self.patterns
    }

    /// Get statistics about findings
    pub fn statistics(findings: &[SecretFinding]) -> HashMap<SecretType, usize> {
        let mut stats: HashMap<SecretType, usize> = HashMap::new();
        for finding in findings {
            *stats.entry(finding.secret_type).or_insert(0) += 1;
        }
        stats
    }
}

/// Internal pattern structure
#[derive(Debug)]
pub struct SecretPattern {
    /// Secret type
    pub secret_type: SecretType,

    /// Pattern name
    pub name: String,

    /// Compiled regex
    pub regex: Regex,

    /// Default confidence
    pub confidence: f32,
}

/// Mask a secret value for display
fn mask_secret(value: &str) -> String {
    if value.len() <= 8 {
        return "***".to_string();
    }

    let visible_chars = 4;
    let masked_len = value.len() - (visible_chars * 2);

    if masked_len <= 0 {
        return "***".to_string();
    }

    format!(
        "{}...{}",
        &value[..visible_chars],
        &value[value.len() - visible_chars..]
    )
}

/// Check if a value is likely a false positive
fn is_likely_false_positive(value: &str) -> bool {
    let false_positives = [
        "example",
        "sample",
        "test",
        "dummy",
        "placeholder",
        "your_",
        "insert_",
        "change_",
        "replace_",
        "TODO",
        "FIXME",
        "null",
        "undefined",
        "true",
        "false",
        "function",
        "return",
        "var",
        "let",
        "const",
    ];

    let lower = value.to_lowercase();
    false_positives.iter().any(|fp| lower.contains(fp))
}

/// Extract context around a match
fn extract_context(text: &str, start: usize, end: usize) -> String {
    let context_size = 50;

    let context_start = start.saturating_sub(context_size);
    let context_end = (end + context_size).min(text.len());

    let mut context = String::new();

    if context_start > 0 {
        context.push_str("...");
    }

    context.push_str(&text[context_start..context_end]);

    if context_end < text.len() {
        context.push_str("...");
    }

    context.replace('\n', " ")
}

/// Find line and column number for a value
fn find_position(text: &str, value: &str) -> Option<(u32, u32)> {
    if let Some(pos) = text.find(value) {
        let before = &text[..pos];
        let line = before.lines().count() as u32;
        let last_newline = before.rfind('\n').map(|n| n + 1).unwrap_or(0);
        let col = (pos - last_newline + 1) as u32;
        Some((line, col))
    } else {
        None
    }
}

/// Convert secret findings to sh_types::Finding
pub fn to_security_findings(findings: &[SecretFinding]) -> Vec<sh_types::Finding> {
    findings
        .iter()
        .map(|f| {
            let severity = match f.severity() {
                "critical" => sh_types::Severity::Critical,
                "high" => sh_types::Severity::High,
                "medium" => sh_types::Severity::Medium,
                "low" => sh_types::Severity::Low,
                _ => sh_types::Severity::Info,
            };

            let mut finding = sh_types::Finding::new(
                format!("{}: {}", f.secret_type.display_name(), f.pattern_name),
                format!(
                    "Hardcoded {} detected. Value: {}\n\nContext: {}",
                    f.secret_type.display_name(),
                    f.masked_value,
                    f.context
                ),
            )
            .with_severity(severity)
            .with_confidence(sh_types::Confidence::Confirmed)
            .with_type("hardcoded_secret")
            .with_tool("sh-tools-secrets", env!("CARGO_PKG_VERSION"));

            if let Some(cwe) = f.cwe_id() {
                finding = finding.with_cwe(cwe);
            }

            if let Some(ref path) = f.file_path {
                let location = sh_types::Location::new()
                    .with_file(path)
                    .with_platform(sh_types::Platform::Android);
                finding = finding.with_location(location);
            }

            finding
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_secret() {
        assert_eq!(mask_secret("short"), "***");
        assert_eq!(mask_secret("this-is-a-long-secret"), "this...cret");
        assert_eq!(mask_secret("1234567890abcdef"), "1234...cdef");
    }

    #[test]
    fn test_is_likely_false_positive() {
        assert!(is_likely_false_positive("example_key"));
        assert!(is_likely_false_positive("test_token"));
        assert!(is_likely_false_positive("your_api_key_here"));
        assert!(!is_likely_false_positive("sk_live_abc123"));
    }

    #[tokio::test]
    async fn test_scan_text_api_key() {
        let scanner = SecretScanner::new();
        let text = r#"
            const API_KEY = "sk_live_abc123xyz789";
            const config = {
                apiKey: "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"
            };
        "#;

        let findings = scanner.scan_text(text).await;
        assert!(!findings.is_empty());

        // Should find Google API key
        assert!(findings.iter().any(|f| matches!(f.secret_type, SecretType::GoogleApiKey)));
    }

    #[tokio::test]
    async fn test_scan_text_aws_key() {
        let scanner = SecretScanner::new();
        let text = r#"
            aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
            aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        "#;

        let findings = scanner.scan_text(text).await;
        assert!(!findings.is_empty());

        // Should find AWS Access Key ID
        assert!(findings.iter().any(|f| matches!(f.secret_type, SecretType::AwsAccessKeyId)));
    }

    #[tokio::test]
    async fn test_scan_text_password() {
        let scanner = SecretScanner::new();
        let text = r#"
            password = "SuperSecret123!"
            const pwd = "another_password";
        "#;

        let findings = scanner.scan_text(text).await;
        assert!(!findings.is_empty());

        // Should find password
        assert!(findings.iter().any(|f| matches!(f.secret_type, SecretType::Password)));
    }

    #[tokio::test]
    async fn test_scan_text_private_key() {
        let scanner = SecretScanner::new();
        let text = r#"
            -----BEGIN RSA PRIVATE KEY-----
            MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgwKVPSmwaFkYLv
            ...
            -----END RSA PRIVATE KEY-----
        "#;

        let findings = scanner.scan_text(text).await;
        assert!(!findings.is_empty());

        // Should find private key
        assert!(findings.iter().any(|f| matches!(f.secret_type, SecretType::PrivateKey)));
    }

    #[tokio::test]
    async fn test_scan_text_jwt() {
        let scanner = SecretScanner::new();
        let text = r#"
            const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        "#;

        let findings = scanner.scan_text(text).await;
        assert!(!findings.is_empty());

        // Should find JWT token
        assert!(findings.iter().any(|f| matches!(f.secret_type, SecretType::JwtToken)));
    }

    #[tokio::test]
    async fn test_scan_text_database_url() {
        let scanner = SecretScanner::new();
        let text = r#"
            DATABASE_URL=mysql://user:password@localhost:3306/mydb
            mongodb://admin:secret123@mongodb.example.com:27017/production
        "#;

        let findings = scanner.scan_text(text).await;
        assert!(!findings.is_empty());

        // Should find database connection strings
        assert!(findings.iter().any(|f| matches!(f.secret_type, SecretType::DatabaseConnection)));
    }

    #[test]
    fn test_secret_type_display_name() {
        assert_eq!(SecretType::ApiKey.display_name(), "API Key");
        assert_eq!(SecretType::AwsAccessKeyId.display_name(), "AWS Access Key ID");
        assert_eq!(SecretType::Password.display_name(), "Password");
    }

    #[test]
    fn test_secret_type_severity() {
        assert_eq!(SecretType::PrivateKey.severity(), "critical");
        assert_eq!(SecretType::AwsSecretKey.severity(), "critical");
        assert_eq!(SecretType::ApiKey.severity(), "high");
        assert_eq!(SecretType::HardcodedIp.severity(), "low");
    }

    #[test]
    fn test_statistics() {
        let findings = vec![
            SecretFinding::new(SecretType::ApiKey, "key1"),
            SecretFinding::new(SecretType::ApiKey, "key2"),
            SecretFinding::new(SecretType::Password, "pass1"),
        ];

        let stats = SecretScanner::statistics(&findings);
        assert_eq!(stats.get(&SecretType::ApiKey), Some(&2));
        assert_eq!(stats.get(&SecretType::Password), Some(&1));
    }
}
