//! # Network Security Analysis Module
//!
//! Analyzes network security configurations in Android applications including:
//! - Network Security Config XML parsing
//! - Certificate pinning analysis
//! - Cleartext traffic configuration
//! - Trust anchor configuration
//! - Domain-specific configurations
//!
//! ## Example
//!
//! ```rust
//! use sh_tools::network::NetworkAnalyzer;
//!
//! async fn analyze_network() {
//!     let analyzer = NetworkAnalyzer::new();
//!     let config = analyzer.analyze_apk("app.apk").await.unwrap();
//!     println!("Cleartext allowed: {}", config.cleartext_traffic_permitted);
//! }
//! ```

use crate::{Result, ToolsError};
use quick_xml::events::Event;
use quick_xml::Reader;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, error, info, instrument, trace, warn};

/// Network security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityConfig {
    /// Base configuration - cleartext traffic permitted
    pub cleartext_traffic_permitted: bool,

    /// Trust anchors
    pub trust_anchors: Vec<TrustAnchor>,

    /// Domain configurations
    pub domain_configs: Vec<DomainConfig>,

    /// Certificate pinning configuration
    pub pinning: Option<PinningConfig>,

    /// Debug configuration
    pub debug_overrides: Option<DebugOverrides>,

    /// Raw configuration
    pub raw_config: String,
}

impl Default for NetworkSecurityConfig {
    fn default() -> Self {
        Self {
            cleartext_traffic_permitted: false,
            trust_anchors: Vec::new(),
            domain_configs: Vec::new(),
            pinning: None,
            debug_overrides: None,
            raw_config: String::new(),
        }
    }
}

impl NetworkSecurityConfig {
    /// Check if cleartext traffic is allowed for a specific domain
    pub fn is_cleartext_allowed(&self, domain: &str) -> bool {
        // Check domain-specific configs first
        for config in &self.domain_configs {
            if config.matches_domain(domain) {
                return config.cleartext_traffic_permitted;
            }
        }

        // Fall back to base config
        self.cleartext_traffic_permitted
    }

    /// Check if certificate pinning is configured
    pub fn has_pinning(&self) -> bool {
        self.pinning.as_ref().map_or(false, |p| !p.pins.is_empty())
    }

    /// Get all pinned domains
    pub fn pinned_domains(&self) -> Vec<&str> {
        if let Some(ref pinning) = self.pinning {
            pinning.pins.keys().map(|s| s.as_str()).collect()
        } else {
            Vec::new()
        }
    }

    /// Check if user certificates are trusted
    pub fn trusts_user_certs(&self) -> bool {
        self.trust_anchors.iter().any(|a| a.src == "user")
    }

    /// Check if system certificates are trusted
    pub fn trusts_system_certs(&self) -> bool {
        self.trust_anchors.iter().any(|a| a.src == "system")
    }

    /// Get security issues
    pub fn get_issues(&self) -> Vec<NetworkSecurityIssue> {
        let mut issues = Vec::new();

        // Check for cleartext traffic
        if self.cleartext_traffic_permitted {
            issues.push(NetworkSecurityIssue {
                issue_type: "cleartext_traffic_enabled".to_string(),
                severity: "medium".to_string(),
                description: "Cleartext traffic is permitted. This allows HTTP connections which are not encrypted.".to_string(),
                recommendation: "Set cleartextTrafficPermitted=\"false\" or remove the attribute to use HTTPS only.".to_string(),
                cwe_id: Some("CWE-319".to_string()),
            });
        }

        // Check for missing certificate pinning
        if !self.has_pinning() {
            issues.push(NetworkSecurityIssue {
                issue_type: "certificate_pinning_missing".to_string(),
                severity: "low".to_string(),
                description: "Certificate pinning is not configured. This makes the app vulnerable to MITM attacks with rogue certificates.".to_string(),
                recommendation: "Consider implementing certificate pinning for critical domains.".to_string(),
                cwe_id: Some("CWE-295".to_string()),
            });
        }

        // Check for user certificate trust
        if self.trusts_user_certs() {
            issues.push(NetworkSecurityIssue {
                issue_type: "user_certificates_trusted".to_string(),
                severity: "medium".to_string(),
                description: "User-installed certificates are trusted. This allows MITM attacks with user-installed root CAs.".to_string(),
                recommendation: "Remove <certificates src=\"user\"/> from trust anchors unless specifically required.".to_string(),
                cwe_id: Some("CWE-295".to_string()),
            });
        }

        // Check for debug overrides
        if self.debug_overrides.is_some() {
            issues.push(NetworkSecurityIssue {
                issue_type: "debug_overrides_present".to_string(),
                severity: "low".to_string(),
                description: "Debug overrides are configured. Ensure these are not present in production builds.".to_string(),
                recommendation: "Remove debug-overrides configuration for production releases.".to_string(),
                cwe_id: Some("CWE-489".to_string()),
            });
        }

        // Check domain-specific issues
        for config in &self.domain_configs {
            if config.cleartext_traffic_permitted {
                issues.push(NetworkSecurityIssue {
                    issue_type: "domain_cleartext_enabled".to_string(),
                    severity: "medium".to_string(),
                    description: format!("Cleartext traffic is permitted for domain: {}", config.domain),
                    recommendation: "Use HTTPS for all domain communications.".to_string(),
                    cwe_id: Some("CWE-319".to_string()),
                });
            }
        }

        issues
    }

    /// Get security score (0-100)
    pub fn security_score(&self) -> u32 {
        let mut score = 100u32;

        if self.cleartext_traffic_permitted {
            score = score.saturating_sub(20);
        }

        if !self.has_pinning() {
            score = score.saturating_sub(10);
        }

        if self.trusts_user_certs() {
            score = score.saturating_sub(15);
        }

        if self.debug_overrides.is_some() {
            score = score.saturating_sub(5);
        }

        // Deduct for domains with cleartext
        let cleartext_domains = self.domain_configs.iter().filter(|d| d.cleartext_traffic_permitted).count();
        score = score.saturating_sub(cleartext_domains as u32 * 5);

        score
    }
}

/// Trust anchor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchor {
    /// Source (system, user, or raw resource)
    pub src: String,

    /// Override pins flag
    pub override_pins: bool,
}

/// Domain-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    /// Domain pattern
    pub domain: String,

    /// Include subdomains
    pub include_subdomains: bool,

    /// Cleartext traffic permitted
    pub cleartext_traffic_permitted: bool,

    /// Trust anchors for this domain
    pub trust_anchors: Vec<TrustAnchor>,

    /// Pin set reference
    pub pin_set: Option<String>,
}

impl DomainConfig {
    /// Check if a domain matches this configuration
    pub fn matches_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        let config_domain = self.domain.to_lowercase();

        if self.include_subdomains {
            domain_lower == config_domain
                || domain_lower.ends_with(&format!(".{}", config_domain))
        } else {
            domain_lower == config_domain
        }
    }
}

/// Certificate pinning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinningConfig {
    /// Expiration date
    pub expiration: Option<String>,

    /// Pins by domain
    pub pins: HashMap<String, Vec<Pin>>,
}

/// Certificate pin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pin {
    /// Pin digest algorithm
    pub digest: String,

    /// Pin value (base64 encoded hash)
    pub value: String,
}

/// Debug overrides configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugOverrides {
    /// Trust anchors for debug builds
    pub trust_anchors: Vec<TrustAnchor>,
}

/// Network security issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityIssue {
    /// Issue type
    pub issue_type: String,

    /// Severity
    pub severity: String,

    /// Description
    pub description: String,

    /// Recommendation
    pub recommendation: String,

    /// CWE ID
    pub cwe_id: Option<String>,
}

/// Network analyzer for APK files
#[derive(Debug, Clone)]
pub struct NetworkAnalyzer;

impl Default for NetworkAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkAnalyzer {
    /// Create a new network analyzer
    pub fn new() -> Self {
        Self
    }

    /// Analyze network security from an APK file
    #[instrument(skip(self), fields(path = %path.as_ref()))]
    pub async fn analyze_apk<P: AsRef<std::path::Path>>(&self, path: P) -> Result<NetworkSecurityConfig> {
        let path = path.as_ref();
        info!("Analyzing network security for APK: {}", path.display());

        // Try to extract network_security_config.xml
        let parser = crate::apk::ApkParser::new();

        let config_paths = [
            "res/xml/network_security_config.xml",
            "res/xml-v21/network_security_config.xml",
            "res/xml-v24/network_security_config.xml",
        ];

        for config_path in &config_paths {
            if let Ok(data) = parser.extract_file(path, config_path).await {
                let config = parse_network_security_config(&data)?;
                info!("Found network security config at: {}", config_path);
                return Ok(config);
            }
        }

        // Check AndroidManifest.xml for networkSecurityConfig reference
        if let Ok(manifest_data) = parser.extract_file(path, "AndroidManifest.xml").await {
            let manifest_str = String::from_utf8_lossy(&manifest_data);
            if manifest_str.contains("networkSecurityConfig") {
                debug!("Network security config referenced but file not found");
            }
        }

        // Return default config if not found
        warn!("No network security config found in APK");
        Ok(NetworkSecurityConfig::default())
    }

    /// Parse network security config from XML data
    pub fn parse_config(&self, xml_data: &[u8]) -> Result<NetworkSecurityConfig> {
        parse_network_security_config(xml_data)
    }

    /// Analyze URLs in the APK for security issues
    #[instrument(skip(self), fields(path = %path.as_ref()))]
    pub async fn analyze_urls<P: AsRef<std::path::Path>>(&self, path: P) -> Result<UrlAnalysis> {
        let path = path.as_ref();
        info!("Analyzing URLs in APK: {}", path.display());

        let parser = crate::apk::ApkParser::new();
        let text_files = parser.extract_text_files(path).await?;

        let mut http_urls = Vec::new();
        let mut https_urls = Vec::new();
        let mut ip_addresses = Vec::new();

        let url_regex = Regex::new(r#"https?://[^\s<>"'\)\]\}]+"#).unwrap();
        let ip_regex = Regex::new(r#"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"#).unwrap();

        for (file_path, content) in text_files {
            // Find URLs
            for mat in url_regex.find_iter(&content) {
                let url = mat.as_str().to_string();
                if url.starts_with("https://") {
                    https_urls.push((url, file_path.clone()));
                } else if url.starts_with("http://") {
                    http_urls.push((url, file_path.clone()));
                }
            }

            // Find IP addresses
            for mat in ip_regex.find_iter(&content) {
                let ip = mat.as_str().to_string();
                // Filter out common false positives
                if !ip.starts_with("0.") && !ip.starts_with("127.") {
                    ip_addresses.push((ip, file_path.clone()));
                }
            }
        }

        // Remove duplicates
        http_urls.sort_by(|a, b| a.0.cmp(&b.0));
        http_urls.dedup_by(|a, b| a.0 == b.0);
        https_urls.sort_by(|a, b| a.0.cmp(&b.0));
        https_urls.dedup_by(|a, b| a.0 == b.0);
        ip_addresses.sort_by(|a, b| a.0.cmp(&b.0));
        ip_addresses.dedup_by(|a, b| a.0 == b.0);

        info!(
            "Found {} HTTP URLs, {} HTTPS URLs, {} IP addresses",
            http_urls.len(),
            https_urls.len(),
            ip_addresses.len()
        );

        Ok(UrlAnalysis {
            http_urls,
            https_urls,
            ip_addresses,
        })
    }

    /// Check for insecure network configurations
    pub fn check_insecure_config(&self, config: &NetworkSecurityConfig) -> Vec<NetworkSecurityIssue> {
        config.get_issues()
    }
}

/// URL analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlAnalysis {
    /// HTTP URLs found
    pub http_urls: Vec<(String, String)>,

    /// HTTPS URLs found
    pub https_urls: Vec<(String, String)>,

    /// IP addresses found
    pub ip_addresses: Vec<(String, String)>,
}

impl UrlAnalysis {
    /// Get insecure URLs (HTTP)
    pub fn insecure_urls(&self) -> &[(String, String)] {
        &self.http_urls
    }

    /// Get secure URLs (HTTPS)
    pub fn secure_urls(&self) -> &[(String, String)] {
        &self.https_urls
    }

    /// Check if there are any insecure URLs
    pub fn has_insecure_urls(&self) -> bool {
        !self.http_urls.is_empty()
    }

    /// Get unique domains
    pub fn unique_domains(&self) -> Vec<String> {
        let mut domains: std::collections::HashSet<String> = std::collections::HashSet::new();

        for (url, _) in &self.http_urls {
            if let Some(domain) = extract_domain(url) {
                domains.insert(domain);
            }
        }

        for (url, _) in &self.https_urls {
            if let Some(domain) = extract_domain(url) {
                domains.insert(domain);
            }
        }

        domains.into_iter().collect()
    }
}

/// Parse network security config XML
#[instrument(skip(xml_data))]
pub fn parse_network_security_config(xml_data: &[u8]) -> Result<NetworkSecurityConfig> {
    let xml_str = String::from_utf8(xml_data.to_vec())
        .map_err(|e| ToolsError::XmlParsing(format!("Invalid UTF-8: {}", e)))?;

    trace!("Parsing network security config ({} bytes)", xml_data.len());

    let mut reader = Reader::from_str(&xml_str);
    reader.trim_text(true);

    let mut config = NetworkSecurityConfig {
        raw_config: xml_str.clone(),
        ..Default::default()
    };

    let mut buf = Vec::new();
    let mut current_domain_config: Option<DomainConfig> = None;
    let mut current_pin_set: Option<(String, Vec<Pin>)> = None;
    let mut in_pin_set = false;
    let mut in_debug_overrides = false;
    let mut in_trust_anchors = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let name = std::str::from_utf8(e.name().as_ref())
                    .unwrap_or("")
                    .to_string();

                match name.as_str() {
                    "network-security-config" => {
                        // Root element - check for base cleartext setting
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                if key == "cleartextTrafficPermitted" {
                                    config.cleartext_traffic_permitted = value == "true";
                                }
                            }
                        }
                    }
                    "base-config" => {
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                if key == "cleartextTrafficPermitted" {
                                    config.cleartext_traffic_permitted = value == "true";
                                }
                            }
                        }
                    }
                    "domain-config" => {
                        let mut domain_config = DomainConfig {
                            domain: String::new(),
                            include_subdomains: false,
                            cleartext_traffic_permitted: config.cleartext_traffic_permitted,
                            trust_anchors: Vec::new(),
                            pin_set: None,
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
                                    "cleartextTrafficPermitted" => {
                                        domain_config.cleartext_traffic_permitted = value == "true";
                                    }
                                    _ => {}
                                }
                            }
                        }

                        current_domain_config = Some(domain_config);
                    }
                    "domain" => {
                        if let Some(ref mut domain_config) = current_domain_config {
                            for attr in e.attributes() {
                                if let Ok(attr) = attr {
                                    let key = std::str::from_utf8(&attr.key.as_ref())
                                        .unwrap_or("")
                                        .to_string();
                                    let value = attr.unescape_value()
                                        .unwrap_or_default()
                                        .to_string();

                                    match key.as_str() {
                                        "includeSubdomains" => {
                                            domain_config.include_subdomains = value == "true";
                                        }
                                        _ => {
                                            // Assume it's the domain text
                                            if value.contains(".") {
                                                domain_config.domain = value;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    "trust-anchors" => {
                        in_trust_anchors = true;
                    }
                    "certificates" => {
                        let mut anchor = TrustAnchor {
                            src: String::new(),
                            override_pins: false,
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
                                    "src" => anchor.src = value,
                                    "overridePins" => anchor.override_pins = value == "true",
                                    _ => {}
                                }
                            }
                        }

                        if in_debug_overrides {
                            if let Some(ref mut debug) = config.debug_overrides {
                                debug.trust_anchors.push(anchor);
                            }
                        } else if let Some(ref mut domain_config) = current_domain_config {
                            domain_config.trust_anchors.push(anchor);
                        } else {
                            config.trust_anchors.push(anchor);
                        }
                    }
                    "pin-set" => {
                        in_pin_set = true;
                        let mut expiration = None;

                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                let key = std::str::from_utf8(&attr.key.as_ref())
                                    .unwrap_or("")
                                    .to_string();
                                let value = attr.unescape_value()
                                    .unwrap_or_default()
                                    .to_string();

                                if key == "expiration" {
                                    expiration = Some(value);
                                }
                            }
                        }

                        if config.pinning.is_none() {
                            config.pinning = Some(PinningConfig {
                                expiration,
                                pins: HashMap::new(),
                            });
                        } else if let Some(ref mut pinning) = config.pinning {
                            pinning.expiration = expiration;
                        }

                        // Create a pin set for the current domain
                        if let Some(ref domain_config) = current_domain_config {
                            current_pin_set = Some((domain_config.domain.clone(), Vec::new()));
                        }
                    }
                    "pin" => {
                        if in_pin_set {
                            let mut pin = Pin {
                                digest: String::new(),
                                value: String::new(),
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
                                        "digest" => pin.digest = value,
                                        _ => {
                                            // The pin value is usually the text content or another attribute
                                            if value.len() > 20 {
                                                pin.value = value;
                                            }
                                        }
                                    }
                                }
                            }

                            if let Some((ref domain, ref mut pins)) = current_pin_set {
                                pins.push(pin);
                            }
                        }
                    }
                    "debug-overrides" => {
                        in_debug_overrides = true;
                        config.debug_overrides = Some(DebugOverrides {
                            trust_anchors: Vec::new(),
                        });
                    }
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name = std::str::from_utf8(e.name().as_ref())
                    .unwrap_or("")
                    .to_string();

                match name.as_str() {
                    "domain-config" => {
                        if let Some(domain_config) = current_domain_config.take() {
                            config.domain_configs.push(domain_config);
                        }
                    }
                    "pin-set" => {
                        in_pin_set = false;
                        if let Some((domain, pins)) = current_pin_set.take() {
                            if let Some(ref mut pinning) = config.pinning {
                                pinning.pins.insert(domain, pins);
                            }
                        }
                    }
                    "trust-anchors" => {
                        in_trust_anchors = false;
                    }
                    "debug-overrides" => {
                        in_debug_overrides = false;
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

    debug!("Parsed network security config with {} domain configs", config.domain_configs.len());
    Ok(config)
}

/// Extract domain from URL
fn extract_domain(url: &str) -> Option<String> {
    url.split("//").nth(1)?
        .split('/')
        .next()?
        .split(':')
        .next()
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_NETWORK_CONFIG: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </base-config>

    <domain-config>
        <domain includeSubdomains="true">example.com</domain>
        <pin-set expiration="2025-01-01">
            <pin digest="SHA-256">sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
        </pin-set>
    </domain-config>

    <domain-config cleartextTrafficPermitted="true">
        <domain>insecure.example.com</domain>
    </domain-config>

    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
        </trust-anchors>
    </debug-overrides>
</network-security-config>"#;

    #[test]
    fn test_parse_network_security_config() {
        let config = parse_network_security_config(TEST_NETWORK_CONFIG.as_bytes()).unwrap();

        assert!(!config.cleartext_traffic_permitted);
        assert_eq!(config.trust_anchors.len(), 1);
        assert_eq!(config.trust_anchors[0].src, "system");
        assert_eq!(config.domain_configs.len(), 2);
    }

    #[test]
    fn test_domain_matching() {
        let config = DomainConfig {
            domain: "example.com".to_string(),
            include_subdomains: true,
            cleartext_traffic_permitted: false,
            trust_anchors: Vec::new(),
            pin_set: None,
        };

        assert!(config.matches_domain("example.com"));
        assert!(config.matches_domain("www.example.com"));
        assert!(config.matches_domain("api.sub.example.com"));
        assert!(!config.matches_domain("other.com"));
        assert!(!config.matches_domain("notexample.com"));
    }

    #[test]
    fn test_security_score() {
        let config = parse_network_security_config(TEST_NETWORK_CONFIG.as_bytes()).unwrap();
        let score = config.security_score();

        // Should have deductions for missing pinning and debug overrides
        assert!(score < 100);
        assert!(score > 50);
    }

    #[test]
    fn test_get_issues() {
        let config = parse_network_security_config(TEST_NETWORK_CONFIG.as_bytes()).unwrap();
        let issues = config.get_issues();

        // Should find issues for missing pinning and debug overrides
        assert!(!issues.is_empty());
        assert!(issues.iter().any(|i| i.issue_type == "certificate_pinning_missing"));
        assert!(issues.iter().any(|i| i.issue_type == "debug_overrides_present"));
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("https://api.example.com/v1/users"),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            extract_domain("http://example.com"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_domain("https://example.com:8080/path"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_trusts_user_certs() {
        let mut config = NetworkSecurityConfig::default();
        assert!(!config.trusts_user_certs());

        config.trust_anchors.push(TrustAnchor {
            src: "user".to_string(),
            override_pins: false,
        });
        assert!(config.trusts_user_certs());
    }

    #[test]
    fn test_is_cleartext_allowed() {
        let mut config = NetworkSecurityConfig::default();
        config.cleartext_traffic_permitted = false;

        // Add domain-specific config
        config.domain_configs.push(DomainConfig {
            domain: "insecure.example.com".to_string(),
            include_subdomains: false,
            cleartext_traffic_permitted: true,
            trust_anchors: Vec::new(),
            pin_set: None,
        });

        assert!(!config.is_cleartext_allowed("example.com"));
        assert!(config.is_cleartext_allowed("insecure.example.com"));
    }
}
