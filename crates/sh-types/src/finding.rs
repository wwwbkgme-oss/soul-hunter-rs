//! Finding types for security analysis results

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Confidence, Platform, Severity};

/// Unique identifier for findings
pub type FindingId = Uuid;

/// A security finding/vulnerability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub finding_type: String,
    
    // Classification
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
    pub cvss_score: Option<f64>,
    
    // Location
    pub location: Location,
    
    // Remediation
    pub remediation: Option<Remediation>,
    
    // Metadata
    pub tool_name: String,
    pub tool_version: String,
    pub timestamp: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
    
    // Evidence chain
    pub evidence: Vec<Evidence>,
    
    // Correlation
    pub correlated_ids: Vec<FindingId>,
    pub duplicate_of: Option<FindingId>,
}

impl Finding {
    pub fn new(title: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            title: title.into(),
            description: description.into(),
            severity: Severity::Info,
            confidence: Confidence::Tentative,
            finding_type: "unknown".to_string(),
            cwe_id: None,
            owasp_category: None,
            cvss_score: None,
            location: Location::default(),
            remediation: None,
            tool_name: "unknown".to_string(),
            tool_version: "0.0.0".to_string(),
            timestamp: Utc::now(),
            metadata: None,
            evidence: Vec::new(),
            correlated_ids: Vec::new(),
            duplicate_of: None,
        }
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_type(mut self, finding_type: impl Into<String>) -> Self {
        self.finding_type = finding_type.into();
        self
    }

    pub fn with_cwe(mut self, cwe_id: impl Into<String>) -> Self {
        self.cwe_id = Some(cwe_id.into());
        self
    }

    pub fn with_owasp(mut self, category: impl Into<String>) -> Self {
        self.owasp_category = Some(category.into());
        self
    }

    pub fn with_cvss(mut self, score: f64) -> Self {
        self.cvss_score = Some(score);
        self
    }

    pub fn with_location(mut self, location: Location) -> Self {
        self.location = location;
        self
    }

    pub fn with_remediation(mut self, remediation: Remediation) -> Self {
        self.remediation = Some(remediation);
        self
    }

    pub fn with_tool(mut self, name: impl Into<String>, version: impl Into<String>) -> Self {
        self.tool_name = name.into();
        self.tool_version = version.into();
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub fn add_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    pub fn correlate_with(mut self, finding_id: FindingId) -> Self {
        self.correlated_ids.push(finding_id);
        self
    }

    pub fn mark_duplicate(mut self, original_id: FindingId) -> Self {
        self.duplicate_of = Some(original_id);
        self
    }
}

/// Location information for a finding
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Location {
    pub file_path: Option<String>,
    pub line_number: Option<u32>,
    pub column_number: Option<u32>,
    pub function_name: Option<String>,
    pub class_name: Option<String>,
    pub package_name: Option<String>,
    pub platform: Platform,
    pub snippet: Option<String>,
}

impl Location {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_file(mut self, path: impl Into<String>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    pub fn with_line(mut self, line: u32) -> Self {
        self.line_number = Some(line);
        self
    }

    pub fn with_column(mut self, column: u32) -> Self {
        self.column_number = Some(column);
        self
    }

    pub fn with_function(mut self, name: impl Into<String>) -> Self {
        self.function_name = Some(name.into());
        self
    }

    pub fn with_class(mut self, name: impl Into<String>) -> Self {
        self.class_name = Some(name.into());
        self
    }

    pub fn with_package(mut self, name: impl Into<String>) -> Self {
        self.package_name = Some(name.into());
        self
    }

    pub fn with_platform(mut self, platform: Platform) -> Self {
        self.platform = platform;
        self
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }
}

/// Remediation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    pub description: String,
    pub effort: RemediationEffort,
    pub code_example: Option<String>,
    pub references: Vec<String>,
}

impl Remediation {
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            effort: RemediationEffort::Medium,
            code_example: None,
            references: Vec::new(),
        }
    }

    pub fn with_effort(mut self, effort: RemediationEffort) -> Self {
        self.effort = effort;
        self
    }

    pub fn with_code_example(mut self, code: impl Into<String>) -> Self {
        self.code_example = Some(code.into());
        self
    }

    pub fn add_reference(mut self, reference: impl Into<String>) -> Self {
        self.references.push(reference.into());
        self
    }
}

/// Remediation effort levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationEffort {
    Trivial,
    Low,
    Medium,
    High,
    Complex,
}

impl Default for RemediationEffort {
    fn default() -> Self {
        RemediationEffort::Medium
    }
}

/// Evidence for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Uuid,
    pub evidence_type: String,
    pub data: String,
    pub hash: Option<String>,
    pub timestamp: DateTime<Utc>,
}

impl Evidence {
    pub fn new(evidence_type: impl Into<String>, data: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            evidence_type: evidence_type.into(),
            data: data.into(),
            hash: None,
            timestamp: Utc::now(),
        }
    }

    pub fn with_hash(mut self, hash: impl Into<String>) -> Self {
        self.hash = Some(hash.into());
        self
    }
}

/// Collection of findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCollection {
    pub findings: Vec<Finding>,
    pub total_count: usize,
    pub by_severity: std::collections::HashMap<Severity, usize>,
}

impl FindingCollection {
    pub fn new(findings: Vec<Finding>) -> Self {
        let total_count = findings.len();
        let mut by_severity: std::collections::HashMap<Severity, usize> = std::collections::HashMap::new();
        
        for finding in &findings {
            *by_severity.entry(finding.severity).or_insert(0) += 1;
        }
        
        Self {
            findings,
            total_count,
            by_severity,
        }
    }

    pub fn critical(&self) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.severity == Severity::Critical).collect()
    }

    pub fn high(&self) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.severity == Severity::High).collect()
    }

    pub fn by_severity(&self, severity: Severity) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.severity == severity).collect()
    }

    pub fn add(&mut self, finding: Finding) {
        self.findings.push(finding);
        self.total_count += 1;
    }
}

impl Default for FindingCollection {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_builder() {
        let finding = Finding::new("Test Finding", "Test description")
            .with_severity(Severity::High)
            .with_cwe("CWE-798")
            .with_cvss(7.5);

        assert_eq!(finding.title, "Test Finding");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.cwe_id, Some("CWE-798".to_string()));
        assert_eq!(finding.cvss_score, Some(7.5));
    }

    #[test]
    fn test_location_builder() {
        let location = Location::new()
            .with_file("AndroidManifest.xml")
            .with_line(42)
            .with_platform(crate::Platform::Android);

        assert_eq!(location.file_path, Some("AndroidManifest.xml".to_string()));
        assert_eq!(location.line_number, Some(42));
    }

    #[test]
    fn test_finding_collection() {
        let findings = vec![
            Finding::new("F1", "D1").with_severity(Severity::Critical),
            Finding::new("F2", "D2").with_severity(Severity::High),
            Finding::new("F3", "D3").with_severity(Severity::Critical),
        ];

        let collection = FindingCollection::new(findings);
        assert_eq!(collection.total_count, 3);
        assert_eq!(collection.critical().len(), 2);
        assert_eq!(collection.high().len(), 1);
    }
}
