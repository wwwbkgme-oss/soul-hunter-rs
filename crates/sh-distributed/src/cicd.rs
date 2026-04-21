//! CI/CD Integration Module
//!
//! Provides integration with popular CI/CD platforms for security analysis reporting.
//! Supports GitHub Actions, GitLab CI, Jenkins, Azure DevOps, and CircleCI.
//!
//! ## Features
//!
//! - **Auto-detection**: Automatically detects CI/CD platform from environment variables
//! - **Risk Mapping**: Maps security findings to CI/CD conclusions (success, failure, neutral)
//! - **Markdown Reports**: Generates formatted security reports for PR/MR comments
//! - **Inline Annotations**: Adds code annotations directly in the CI/CD interface
//! - **Build Status Updates**: Updates build status based on security findings
//!
//! ## Example Usage
//!
//! ```rust
//! use sh_distributed::cicd::{CICDIntegration, CICDConfig, RiskThreshold};
//! use sh_types::FindingCollection;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Auto-detect CI/CD platform
//!     let config = CICDConfig::auto_detect()?;
//!     let integration = CICDIntegration::new(config);
//!
//!     // Generate and post report
//!     let findings = FindingCollection::new(vec![]); // Your findings here
//!     integration.post_security_report(&findings).await?;
//!
//!     Ok(())
//! }
//! ```

use std::collections::HashMap;
use std::env;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::error::{DistributedError, Result};
use sh_types::{Finding, FindingCollection, Severity};

/// CI/CD Platform types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CICDPlatform {
    /// GitHub Actions
    GitHubActions,
    /// GitLab CI
    GitLabCI,
    /// Jenkins
    Jenkins,
    /// Azure DevOps
    AzureDevOps,
    /// CircleCI
    CircleCI,
    /// Unknown/Local
    Unknown,
}

impl fmt::Display for CICDPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CICDPlatform::GitHubActions => write!(f, "github_actions"),
            CICDPlatform::GitLabCI => write!(f, "gitlab_ci"),
            CICDPlatform::Jenkins => write!(f, "jenkins"),
            CICDPlatform::AzureDevOps => write!(f, "azure_devops"),
            CICDPlatform::CircleCI => write!(f, "circleci"),
            CICDPlatform::Unknown => write!(f, "unknown"),
        }
    }
}

impl CICDPlatform {
    /// Auto-detect CI/CD platform from environment variables
    pub fn auto_detect() -> Self {
        if env::var("GITHUB_ACTIONS").is_ok() {
            CICDPlatform::GitHubActions
        } else if env::var("GITLAB_CI").is_ok() {
            CICDPlatform::GitLabCI
        } else if env::var("JENKINS_URL").is_ok() {
            CICDPlatform::Jenkins
        } else if env::var("TF_BUILD").is_ok() || env::var("AZURE_DEVOPS").is_ok() {
            CICDPlatform::AzureDevOps
        } else if env::var("CIRCLECI").is_ok() {
            CICDPlatform::CircleCI
        } else {
            CICDPlatform::Unknown
        }
    }

    /// Check if running in CI/CD environment
    pub fn is_ci() -> bool {
        env::var("CI").is_ok()
            || env::var("GITHUB_ACTIONS").is_ok()
            || env::var("GITLAB_CI").is_ok()
            || env::var("JENKINS_URL").is_ok()
            || env::var("TF_BUILD").is_ok()
            || env::var("CIRCLECI").is_ok()
    }
}

/// Risk threshold for determining CI/CD conclusion
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskThreshold {
    /// Block on any finding (Info+)
    Strict,
    /// Block on Low+
    Low,
    /// Block on Medium+
    Medium,
    /// Block on High+
    High,
    /// Block on Critical only
    Critical,
    /// Never block (informational only)
    Never,
}

impl RiskThreshold {
    /// Check if a finding severity exceeds the threshold
    pub fn should_block(&self, severity: Severity) -> bool {
        match self {
            RiskThreshold::Strict => true,
            RiskThreshold::Low => severity >= Severity::Low,
            RiskThreshold::Medium => severity >= Severity::Medium,
            RiskThreshold::High => severity >= Severity::High,
            RiskThreshold::Critical => severity >= Severity::Critical,
            RiskThreshold::Never => false,
        }
    }

    /// Get the minimum severity that triggers a block
    pub fn min_severity(&self) -> Option<Severity> {
        match self {
            RiskThreshold::Strict => Some(Severity::Info),
            RiskThreshold::Low => Some(Severity::Low),
            RiskThreshold::Medium => Some(Severity::Medium),
            RiskThreshold::High => Some(Severity::High),
            RiskThreshold::Critical => Some(Severity::Critical),
            RiskThreshold::Never => None,
        }
    }
}

impl Default for RiskThreshold {
    fn default() -> Self {
        RiskThreshold::High
    }
}

/// CI/CD conclusion status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CICDConclusion {
    /// Success - no blocking issues
    Success,
    /// Failure - blocking issues found
    Failure,
    /// Neutral - informational only
    Neutral,
    /// Skipped - analysis skipped
    Skipped,
    /// Cancelled - analysis cancelled
    Cancelled,
}

impl fmt::Display for CICDConclusion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CICDConclusion::Success => write!(f, "success"),
            CICDConclusion::Failure => write!(f, "failure"),
            CICDConclusion::Neutral => write!(f, "neutral"),
            CICDConclusion::Skipped => write!(f, "skipped"),
            CICDConclusion::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// CI/CD configuration
#[derive(Debug, Clone)]
pub struct CICDConfig {
    /// CI/CD platform
    pub platform: CICDPlatform,
    /// Risk threshold for blocking builds
    pub risk_threshold: RiskThreshold,
    /// API token for platform integration
    pub api_token: Option<String>,
    /// API base URL (for self-hosted instances)
    pub api_url: Option<String>,
    /// Repository owner/organization
    pub repository_owner: Option<String>,
    /// Repository name
    pub repository_name: Option<String>,
    /// Commit SHA
    pub commit_sha: Option<String>,
    /// Pull/Merge request number
    pub pr_number: Option<u64>,
    /// Build ID
    pub build_id: Option<String>,
    /// Build URL
    pub build_url: Option<String>,
    /// Branch name
    pub branch: Option<String>,
    /// Enable inline annotations
    pub enable_annotations: bool,
    /// Enable PR/MR comments
    pub enable_comments: bool,
    /// Enable status updates
    pub enable_status_updates: bool,
    /// Custom report template
    pub report_template: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl CICDConfig {
    /// Create new configuration with auto-detected platform
    pub fn new() -> Self {
        Self {
            platform: CICDPlatform::auto_detect(),
            risk_threshold: RiskThreshold::default(),
            api_token: None,
            api_url: None,
            repository_owner: None,
            repository_name: None,
            commit_sha: None,
            pr_number: None,
            build_id: None,
            build_url: None,
            branch: None,
            enable_annotations: true,
            enable_comments: true,
            enable_status_updates: true,
            report_template: None,
            metadata: HashMap::new(),
        }
    }

    /// Auto-detect configuration from environment
    pub fn auto_detect() -> Result<Self> {
        let platform = CICDPlatform::auto_detect();
        let mut config = Self::new();
        config.platform = platform;

        match platform {
            CICDPlatform::GitHubActions => config.detect_github_actions(),
            CICDPlatform::GitLabCI => config.detect_gitlab_ci(),
            CICDPlatform::Jenkins => config.detect_jenkins(),
            CICDPlatform::AzureDevOps => config.detect_azure_devops(),
            CICDPlatform::CircleCI => config.detect_circleci(),
            CICDPlatform::Unknown => {
                warn!("No CI/CD platform detected");
            }
        }

        Ok(config)
    }

    /// Detect GitHub Actions environment
    fn detect_github_actions(&mut self) {
        self.api_token = env::var("GITHUB_TOKEN").ok();
        self.api_url = env::var("GITHUB_API_URL").ok().or_else(|| {
            env::var("GITHUB_SERVER_URL").map(|url| format!("{}/api/v3", url)).ok()
        });
        self.repository_owner = env::var("GITHUB_REPOSITORY_OWNER").ok();
        self.repository_name = env::var("GITHUB_REPOSITORY")
            .ok()
            .and_then(|r| r.split('/').nth(1).map(String::from));
        self.commit_sha = env::var("GITHUB_SHA").ok();
        self.branch = env::var("GITHUB_REF_NAME").ok();
        self.build_id = env::var("GITHUB_RUN_ID").ok();
        self.build_url = env::var("GITHUB_SERVER_URL")
            .ok()
            .zip(env::var("GITHUB_REPOSITORY").ok())
            .zip(env::var("GITHUB_RUN_ID").ok())
            .map(|((server, repo), run_id)| format!("{}/{}/actions/runs/{}", server, repo, run_id));

        // Detect PR number from GITHUB_REF
        if let Ok(github_ref) = env::var("GITHUB_REF") {
            if let Some(pr_num) = github_ref.strip_prefix("refs/pull/") {
                if let Some(num_str) = pr_num.strip_suffix("/merge") {
                    self.pr_number = num_str.parse().ok();
                }
            }
        }

        info!("Detected GitHub Actions environment");
    }

    /// Detect GitLab CI environment
    fn detect_gitlab_ci(&mut self) {
        self.api_token = env::var("GITLAB_TOKEN").or_else(|_| env::var("CI_JOB_TOKEN")).ok();
        self.api_url = env::var("CI_API_V4_URL").ok();
        self.repository_owner = env::var("CI_PROJECT_NAMESPACE").ok();
        self.repository_name = env::var("CI_PROJECT_NAME").ok();
        self.commit_sha = env::var("CI_COMMIT_SHA").ok();
        self.branch = env::var("CI_COMMIT_REF_NAME").ok();
        self.build_id = env::var("CI_PIPELINE_ID").ok();
        self.build_url = env::var("CI_PIPELINE_URL").ok();

        if let Ok(mr_iid) = env::var("CI_MERGE_REQUEST_IID") {
            self.pr_number = mr_iid.parse().ok();
        }

        info!("Detected GitLab CI environment");
    }

    /// Detect Jenkins environment
    fn detect_jenkins(&mut self) {
        self.api_token = env::var("JENKINS_API_TOKEN").ok();
        self.api_url = env::var("JENKINS_URL").ok();
        self.repository_name = env::var("JOB_NAME").ok();
        self.commit_sha = env::var("GIT_COMMIT").ok();
        self.branch = env::var("GIT_BRANCH").ok();
        self.build_id = env::var("BUILD_ID").ok();
        self.build_url = env::var("BUILD_URL").ok();

        info!("Detected Jenkins environment");
    }

    /// Detect Azure DevOps environment
    fn detect_azure_devops(&mut self) {
        self.api_token = env::var("SYSTEM_ACCESSTOKEN").ok();
        self.repository_owner = env::var("SYSTEM_TEAMPROJECT").ok();
        self.repository_name = env::var("BUILD_REPOSITORY_NAME").ok();
        self.commit_sha = env::var("BUILD_SOURCEVERSION").ok();
        self.branch = env::var("BUILD_SOURCEBRANCHNAME").ok();
        self.build_id = env::var("BUILD_BUILDID").ok();
        self.build_url = env::var("SYSTEM_TEAMFOUNDATIONSERVER_URI")
            .ok()
            .zip(env::var("SYSTEM_TEAMPROJECT").ok())
            .zip(env::var("BUILD_BUILDID").ok())
            .map(|((server, project), build_id)| {
                format!("{}/{}/_build/results?buildId={}", server, project, build_id)
            });

        if let Ok(pr_id) = env::var("SYSTEM_PULLREQUEST_PULLREQUESTID") {
            self.pr_number = pr_id.parse().ok();
        }

        info!("Detected Azure DevOps environment");
    }

    /// Detect CircleCI environment
    fn detect_circleci(&mut self) {
        self.api_token = env::var("CIRCLE_TOKEN").ok();
        self.repository_owner = env::var("CIRCLE_PROJECT_USERNAME").ok();
        self.repository_name = env::var("CIRCLE_PROJECT_REPONAME").ok();
        self.commit_sha = env::var("CIRCLE_SHA1").ok();
        self.branch = env::var("CIRCLE_BRANCH").ok();
        self.build_id = env::var("CIRCLE_BUILD_NUM").ok();
        self.build_url = env::var("CIRCLE_BUILD_URL").ok();

        if let Ok(pr_num) = env::var("CIRCLE_PR_NUMBER") {
            self.pr_number = pr_num.parse().ok();
        }

        info!("Detected CircleCI environment");
    }

    /// Set risk threshold
    pub fn with_risk_threshold(mut self, threshold: RiskThreshold) -> Self {
        self.risk_threshold = threshold;
        self
    }

    /// Set API token
    pub fn with_api_token(mut self, token: impl Into<String>) -> Self {
        self.api_token = Some(token.into());
        self
    }

    /// Set API URL
    pub fn with_api_url(mut self, url: impl Into<String>) -> Self {
        self.api_url = Some(url.into());
        self
    }

    /// Disable annotations
    pub fn without_annotations(mut self) -> Self {
        self.enable_annotations = false;
        self
    }

    /// Disable comments
    pub fn without_comments(mut self) -> Self {
        self.enable_comments = false;
        self
    }

    /// Disable status updates
    pub fn without_status_updates(mut self) -> Self {
        self.enable_status_updates = false;
        self
    }
}

impl Default for CICDConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Code annotation for inline comments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeAnnotation {
    /// File path
    pub file_path: String,
    /// Line number (1-based)
    pub line: u32,
    /// Column number (optional)
    pub column: Option<u32>,
    /// Annotation message
    pub message: String,
    /// Severity level
    pub severity: AnnotationLevel,
    /// Title/summary
    pub title: Option<String>,
    /// Raw details
    pub raw_details: Option<String>,
}

/// Annotation severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationLevel {
    /// Notice/informational
    Notice,
    /// Warning
    Warning,
    /// Error
    Error,
}

impl From<Severity> for AnnotationLevel {
    fn from(severity: Severity) -> Self {
        match severity {
            Severity::Info => AnnotationLevel::Notice,
            Severity::Low => AnnotationLevel::Notice,
            Severity::Medium => AnnotationLevel::Warning,
            Severity::High => AnnotationLevel::Error,
            Severity::Critical => AnnotationLevel::Error,
        }
    }
}

/// Security report summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    /// Report title
    pub title: String,
    /// Report timestamp
    pub timestamp: DateTime<Utc>,
    /// Total findings count
    pub total_findings: usize,
    /// Findings by severity
    pub findings_by_severity: HashMap<String, usize>,
    /// Critical findings
    pub critical_findings: Vec<FindingSummary>,
    /// High findings
    pub high_findings: Vec<FindingSummary>,
    /// Medium findings
    pub medium_findings: Vec<FindingSummary>,
    /// Low findings
    pub low_findings: Vec<FindingSummary>,
    /// Info findings
    pub info_findings: Vec<FindingSummary>,
    /// Risk score (0-10)
    pub risk_score: Option<f64>,
    /// Conclusion
    pub conclusion: CICDConclusion,
    /// Build URL
    pub build_url: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Finding summary for reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    /// Finding ID
    pub id: String,
    /// Title
    pub title: String,
    /// Severity
    pub severity: Severity,
    /// File path
    pub file_path: Option<String>,
    /// Line number
    pub line: Option<u32>,
    /// Description
    pub description: String,
    /// CWE ID
    pub cwe_id: Option<String>,
    /// Tool name
    pub tool_name: String,
}

impl From<&Finding> for FindingSummary {
    fn from(finding: &Finding) -> Self {
        Self {
            id: finding.id.to_string(),
            title: finding.title.clone(),
            severity: finding.severity,
            file_path: finding.location.file_path.clone(),
            line: finding.location.line_number,
            description: finding.description.clone(),
            cwe_id: finding.cwe_id.clone(),
            tool_name: finding.tool_name.clone(),
        }
    }
}

/// CI/CD Integration handler
#[derive(Debug, Clone)]
pub struct CICDIntegration {
    /// Configuration
    pub config: CICDConfig,
}

impl CICDIntegration {
    /// Create new CI/CD integration
    pub fn new(config: CICDConfig) -> Self {
        Self { config }
    }

    /// Create with auto-detected configuration
    pub fn auto_detect() -> Result<Self> {
        let config = CICDConfig::auto_detect()?;
        Ok(Self::new(config))
    }

    /// Post security report to CI/CD platform
    pub async fn post_security_report(&self, findings: &FindingCollection) -> Result<()> {
        if self.config.platform == CICDPlatform::Unknown {
            warn!("Unknown CI/CD platform, skipping report");
            return Ok(());
        }

        let report = self.generate_report(findings);

        // Post PR/MR comment if enabled
        if self.config.enable_comments {
            self.post_comment(&report).await?;
        }

        // Post inline annotations if enabled
        if self.config.enable_annotations {
            self.post_annotations(findings).await?;
        }

        // Update build status if enabled
        if self.config.enable_status_updates {
            self.update_build_status(&report).await?;
        }

        Ok(())
    }

    /// Generate security report
    pub fn generate_report(&self, findings: &FindingCollection) -> SecurityReport {
        let conclusion = self.determine_conclusion(findings);
        let mut findings_by_severity: HashMap<String, usize> = HashMap::new();

        // Count findings by severity
        for (severity, count) in &findings.by_severity {
            findings_by_severity.insert(severity.to_string(), *count);
        }

        // Categorize findings
        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();
        let mut info = Vec::new();

        for finding in &findings.findings {
            let summary: FindingSummary = finding.into();
            match finding.severity {
                Severity::Critical => critical.push(summary),
                Severity::High => high.push(summary),
                Severity::Medium => medium.push(summary),
                Severity::Low => low.push(summary),
                Severity::Info => info.push(summary),
            }
        }

        // Sort by severity and line number
        for list in [&mut critical, &mut high, &mut medium, &mut low, &mut info].iter_mut() {
            list.sort_by(|a, b| {
                b.severity
                    .cmp(&a.severity)
                    .then_with(|| a.file_path.cmp(&b.file_path))
                    .then_with(|| a.line.cmp(&b.line))
            });
        }

        SecurityReport {
            title: "Security Analysis Report".to_string(),
            timestamp: Utc::now(),
            total_findings: findings.total_count,
            findings_by_severity,
            critical_findings: critical,
            high_findings: high,
            medium_findings: medium,
            low_findings: low,
            info_findings: info,
            risk_score: None,
            conclusion,
            build_url: self.config.build_url.clone(),
            metadata: self.config.metadata.clone(),
        }
    }

    /// Determine CI/CD conclusion based on findings and threshold
    pub fn determine_conclusion(&self, findings: &FindingCollection) -> CICDConclusion {
        let blocking_count = findings
            .findings
            .iter()
            .filter(|f| self.config.risk_threshold.should_block(f.severity))
            .count();

        if blocking_count > 0 {
            CICDConclusion::Failure
        } else if findings.total_count > 0 {
            CICDConclusion::Neutral
        } else {
            CICDConclusion::Success
        }
    }

    /// Generate markdown report
    pub fn generate_markdown(&self, report: &SecurityReport) -> String {
        let mut md = String::new();

        // Header
        md.push_str(&format!("# {}\n\n", report.title));
        md.push_str(&format!("**Generated:** {}\n\n", report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")));

        // Summary
        md.push_str("## Summary\n\n");
        md.push_str(&format!("- **Total Findings:** {}\n", report.total_findings));
        md.push_str(&format!("- **Conclusion:** {}\n", report.conclusion));
        
        if let Some(url) = &report.build_url {
            md.push_str(&format!("- **Build:** [View Details]({})\n", url));
        }
        md.push('\n');

        // Severity breakdown
        md.push_str("## Findings by Severity\n\n");
        md.push_str("| Severity | Count |\n");
        md.push_str("|----------|-------|\n");
        
        let severities = ["Critical", "High", "Medium", "Low", "Info"];
        for severity in &severities {
            let count = report.findings_by_severity.get(*severity).copied().unwrap_or(0);
            let emoji = match *severity {
                "Critical" => "🔴",
                "High" => "🟠",
                "Medium" => "🟡",
                "Low" => "🔵",
                "Info" => "⚪",
                _ => "",
            };
            md.push_str(&format!("| {} {} | {} |\n", emoji, severity, count));
        }
        md.push('\n');

        // Critical findings
        if !report.critical_findings.is_empty() {
            md.push_str("## 🔴 Critical Findings\n\n");
            for finding in &report.critical_findings {
                md.push_str(&self.format_finding_markdown(finding));
            }
        }

        // High findings
        if !report.high_findings.is_empty() {
            md.push_str("## 🟠 High Findings\n\n");
            for finding in &report.high_findings {
                md.push_str(&self.format_finding_markdown(finding));
            }
        }

        // Medium findings
        if !report.medium_findings.is_empty() {
            md.push_str("## 🟡 Medium Findings\n\n");
            for finding in &report.medium_findings {
                md.push_str(&self.format_finding_markdown(finding));
            }
        }

        // Low findings (collapsed)
        if !report.low_findings.is_empty() {
            md.push_str("<details>\n");
            md.push_str("<summary><strong>🔵 Low Findings (");
            md.push_str(&report.low_findings.len().to_string());
            md.push_str(")</strong></summary>\n\n");
            for finding in &report.low_findings {
                md.push_str(&self.format_finding_markdown(finding));
            }
            md.push_str("</details>\n\n");
        }

        // Info findings (collapsed)
        if !report.info_findings.is_empty() {
            md.push_str("<details>\n");
            md.push_str("<summary><strong>⚪ Info Findings (");
            md.push_str(&report.info_findings.len().to_string());
            md.push_str(")</strong></summary>\n\n");
            for finding in &report.info_findings {
                md.push_str(&self.format_finding_markdown(finding));
            }
            md.push_str("</details>\n\n");
        }

        // Footer
        md.push_str("---\n\n");
        md.push_str("*Generated by Soul Hunter Security Analysis*\n");

        md
    }

    /// Format a single finding as markdown
    fn format_finding_markdown(&self, finding: &FindingSummary) -> String {
        let mut md = String::new();
        
        md.push_str(&format!("### {}\n\n", finding.title));
        md.push_str(&format!("**ID:** `{}`\n\n", finding.id));
        
        if let Some(ref path) = finding.file_path {
            md.push_str(&format!("**Location:** `{}`", path));
            if let Some(line) = finding.line {
                md.push_str(&format!":{}\n\n", line));
            } else {
                md.push_str("\n\n");
            }
        }

        if let Some(ref cwe) = finding.cwe_id {
            md.push_str(&format!("**CWE:** {}\n\n", cwe));
        }

        md.push_str(&format!("**Tool:** {}\n\n", finding.tool_name));
        md.push_str(&format!("**Description:** {}\n\n", finding.description));
        md.push('\n');

        md
    }

    /// Post comment to CI/CD platform
    async fn post_comment(&self, report: &SecurityReport) -> Result<()> {
        let markdown = self.generate_markdown(report);

        match self.config.platform {
            CICDPlatform::GitHubActions => {
                self.post_github_comment(&markdown).await?;
            }
            CICDPlatform::GitLabCI => {
                self.post_gitlab_comment(&markdown).await?;
            }
            CICDPlatform::AzureDevOps => {
                self.post_azure_devops_comment(&markdown).await?;
            }
            _ => {
                debug!("PR/MR comments not implemented for {:?}", self.config.platform);
            }
        }

        Ok(())
    }

    /// Post GitHub comment
    async fn post_github_comment(&self, markdown: &str) -> Result<()> {
        use std::process::Command;

        // Use GitHub CLI if available
        if let Some(pr_number) = self.config.pr_number {
            if Command::new("gh").arg("--version").output().is_ok() {
                let output = Command::new("gh")
                    .args([
                        "pr",
                        "comment",
                        &pr_number.to_string(),
                        "--body",
                        markdown,
                    ])
                    .output();

                match output {
                    Ok(result) if result.status.success() => {
                        info!("Posted GitHub PR comment");
                        return Ok(());
                    }
                    Ok(result) => {
                        let stderr = String::from_utf8_lossy(&result.stderr);
                        warn!("Failed to post GitHub comment: {}", stderr);
                    }
                    Err(e) => {
                        warn!("Failed to execute gh command: {}", e);
                    }
                }
            }
        }

        // Fallback: Write to file for GitHub Actions
        if let Ok(github_step_summary) = env::var("GITHUB_STEP_SUMMARY") {
            if let Err(e) = tokio::fs::write(&github_step_summary, markdown).await {
                warn!("Failed to write to GITHUB_STEP_SUMMARY: {}", e);
            } else {
                info!("Wrote report to GITHUB_STEP_SUMMARY");
            }
        }

        Ok(())
    }

    /// Post GitLab comment
    async fn post_gitlab_comment(&self, markdown: &str) -> Result<()> {
        // GitLab comments would require API calls
        // For now, write to a file that can be used by CI
        info!("GitLab MR comment would be posted here");
        debug!("Comment content: {} bytes", markdown.len());
        Ok(())
    }

    /// Post Azure DevOps comment
    async fn post_azure_devops_comment(&self, markdown: &str) -> Result<()> {
        // Azure DevOps comments would require API calls
        info!("Azure DevOps PR comment would be posted here");
        debug!("Comment content: {} bytes", markdown.len());
        Ok(())
    }

    /// Post inline annotations
    async fn post_annotations(&self, findings: &FindingCollection) -> Result<()> {
        let annotations: Vec<CodeAnnotation> = findings
            .findings
            .iter()
            .filter_map(|f| self.finding_to_annotation(f))
            .collect();

        if annotations.is_empty() {
            return Ok(());
        }

        match self.config.platform {
            CICDPlatform::GitHubActions => {
                self.post_github_annotations(&annotations).await?;
            }
            CICDPlatform::GitLabCI => {
                self.post_gitlab_annotations(&annotations).await?;
            }
            CICDPlatform::AzureDevOps => {
                self.post_azure_devops_annotations(&annotations).await?;
            }
            _ => {
                debug!("Annotations not implemented for {:?}", self.config.platform);
            }
        }

        Ok(())
    }

    /// Convert finding to code annotation
    fn finding_to_annotation(&self, finding: &Finding) -> Option<CodeAnnotation> {
        let file_path = finding.location.file_path.clone()?;
        let line = finding.location.line_number?;

        Some(CodeAnnotation {
            file_path,
            line,
            column: finding.location.column_number,
            message: format!("[{}] {}", finding.severity, finding.title),
            severity: finding.severity.into(),
            title: Some(finding.title.clone()),
            raw_details: Some(finding.description.clone()),
        })
    }

    /// Post GitHub annotations
    async fn post_github_annotations(&self, annotations: &[CodeAnnotation]) -> Result<()> {
        // GitHub Actions uses special syntax for annotations
        for annotation in annotations {
            let level = match annotation.severity {
                AnnotationLevel::Notice => "notice",
                AnnotationLevel::Warning => "warning",
                AnnotationLevel::Error => "error",
            };

            let message = if let Some(ref title) = annotation.title {
                format!("{}: {}", title, annotation.message)
            } else {
                annotation.message.clone()
            };

            // GitHub Actions annotation syntax
            println!("::{} file={},line={}::{}\n", level, annotation.file_path, annotation.line, message);
        }

        info!("Posted {} GitHub annotations", annotations.len());
        Ok(())
    }

    /// Post GitLab annotations (code quality report)
    async fn post_gitlab_annotations(&self, annotations: &[CodeAnnotation]) -> Result<()> {
        // GitLab uses code quality reports in JSON format
        let code_quality: Vec<GitLabCodeQualityEntry> = annotations
            .iter()
            .map(|a| GitLabCodeQualityEntry {
                description: a.message.clone(),
                check_name: a.title.clone().unwrap_or_default(),
                fingerprint: format!("{}:{}", a.file_path, a.line),
                severity: match a.severity {
                    AnnotationLevel::Error => "blocker",
                    AnnotationLevel::Warning => "major",
                    AnnotationLevel::Notice => "minor",
                }.to_string(),
                location: GitLabLocation {
                    path: a.file_path.clone(),
                    lines: GitLabLines {
                        begin: a.line,
                        end: a.line,
                    },
                },
            })
            .collect();

        // Write code quality report
        let report_path = "gl-code-quality-report.json";
        let json = serde_json::to_string_pretty(&code_quality)
            .map_err(|e| DistributedError::Serialization(e))?;
        
        tokio::fs::write(report_path, json).await
            .map_err(|e| DistributedError::Other(format!("Failed to write code quality report: {}", e)))?;

        info!("Wrote GitLab code quality report to {}", report_path);
        Ok(())
    }

    /// Post Azure DevOps annotations
    async fn post_azure_devops_annotations(&self, annotations: &[CodeAnnotation]) -> Result<()> {
        // Azure DevOps uses logging commands
        for annotation in annotations {
            let level = match annotation.severity {
                AnnotationLevel::Notice => "debug",
                AnnotationLevel::Warning => "warning",
                AnnotationLevel::Error => "error",
            };

            println!("##vso[task.logissue type={};sourcepath={};linenumber={};columnnumber={};]{}\n",
                level,
                annotation.file_path,
                annotation.line,
                annotation.column.unwrap_or(1),
                annotation.message
            );
        }

        info!("Posted {} Azure DevOps annotations", annotations.len());
        Ok(())
    }

    /// Update build status
    async fn update_build_status(&self, report: &SecurityReport) -> Result<()> {
        match self.config.platform {
            CICDPlatform::GitHubActions => {
                // GitHub Actions uses exit codes
                self.set_github_exit_code(report.conclusion)?;
            }
            CICDPlatform::GitLabCI => {
                // GitLab uses pipeline status
                self.set_gitlab_exit_code(report.conclusion)?;
            }
            CICDPlatform::Jenkins => {
                // Jenkins uses build status
                self.set_jenkins_exit_code(report.conclusion)?;
            }
            CICDPlatform::AzureDevOps => {
                // Azure DevOps uses task results
                self.set_azure_devops_result(report.conclusion)?;
            }
            CICDPlatform::CircleCI => {
                // CircleCI uses exit codes
                self.set_circleci_exit_code(report.conclusion)?;
            }
            _ => {}
        }

        Ok(())
    }

    /// Set GitHub Actions exit code
    fn set_github_exit_code(&self, conclusion: CICDConclusion) -> Result<()> {
        match conclusion {
            CICDConclusion::Failure => {
                eprintln!("::error::Security analysis found blocking issues");
                std::process::exit(1);
            }
            CICDConclusion::Success | CICDConclusion::Neutral => {
                // Exit with 0 for success/neutral
            }
            _ => {}
        }
        Ok(())
    }

    /// Set GitLab CI exit code
    fn set_gitlab_exit_code(&self, conclusion: CICDConclusion) -> Result<()> {
        match conclusion {
            CICDConclusion::Failure => {
                std::process::exit(1);
            }
            _ => {}
        }
        Ok(())
    }

    /// Set Jenkins exit code
    fn set_jenkins_exit_code(&self, conclusion: CICDConclusion) -> Result<()> {
        match conclusion {
            CICDConclusion::Failure => {
                std::process::exit(1);
            }
            _ => {}
        }
        Ok(())
    }

    /// Set Azure DevOps task result
    fn set_azure_devops_result(&self, conclusion: CICDConclusion) -> Result<()> {
        let result = match conclusion {
            CICDConclusion::Success => "Succeeded",
            CICDConclusion::Failure => "Failed",
            CICDConclusion::Neutral => "SucceededWithIssues",
            CICDConclusion::Skipped => "Skipped",
            CICDConclusion::Cancelled => "Cancelled",
        };

        println!("##vso[task.complete result={};]Security analysis complete", result);
        Ok(())
    }

    /// Set CircleCI exit code
    fn set_circleci_exit_code(&self, conclusion: CICDConclusion) -> Result<()> {
        match conclusion {
            CICDConclusion::Failure => {
                std::process::exit(1);
            }
            _ => {}
        }
        Ok(())
    }

    /// Get blocking findings
    pub fn get_blocking_findings(&self, findings: &FindingCollection) -> Vec<&Finding> {
        findings
            .findings
            .iter()
            .filter(|f| self.config.risk_threshold.should_block(f.severity))
            .collect()
    }

    /// Check if findings should block the build
    pub fn should_block(&self, findings: &FindingCollection) -> bool {
        findings
            .findings
            .iter()
            .any(|f| self.config.risk_threshold.should_block(f.severity))
    }

    /// Generate SARIF output path
    pub fn get_sarif_output_path(&self) -> Option<String> {
        match self.config.platform {
            CICDPlatform::GitHubActions => {
                env::var("GITHUB_WORKSPACE")
                    .ok()
                    .map(|ws| format!("{}/soul-hunter-results.sarif", ws))
            }
            _ => Some("soul-hunter-results.sarif".to_string()),
        }
    }
}

impl Default for CICDIntegration {
    fn default() -> Self {
        Self::new(CICDConfig::default())
    }
}

/// GitLab Code Quality report entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GitLabCodeQualityEntry {
    description: String,
    check_name: String,
    fingerprint: String,
    severity: String,
    location: GitLabLocation,
}

/// GitLab location
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GitLabLocation {
    path: String,
    lines: GitLabLines,
}

/// GitLab lines
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GitLabLines {
    begin: u32,
    end: u32,
}

/// CI/CD report formatter
pub struct CICDReportFormatter;

impl CICDReportFormatter {
    /// Format findings for console output
    pub fn format_console(findings: &FindingCollection) -> String {
        let mut output = String::new();
        
        output.push_str("╔══════════════════════════════════════════════════════════════╗\n");
        output.push_str("║           Soul Hunter Security Analysis Report              ║\n");
        output.push_str("╚══════════════════════════════════════════════════════════════╝\n\n");
        
        output.push_str(&format!("Total Findings: {}\n\n", findings.total_count));
        
        // Severity breakdown
        output.push_str("Findings by Severity:\n");
        output.push_str("─────────────────────\n");
        
        let severities = [
            (Severity::Critical, "🔴 Critical"),
            (Severity::High, "🟠 High"),
            (Severity::Medium, "🟡 Medium"),
            (Severity::Low, "🔵 Low"),
            (Severity::Info, "⚪ Info"),
        ];
        
        for (severity, label) in &severities {
            let count = findings.by_severity.get(severity).copied().unwrap_or(0);
            output.push_str(&format!("  {}: {}\n", label, count));
        }
        
        output.push('\n');
        
        // List critical and high findings
        let critical_high: Vec<_> = findings
            .findings
            .iter()
            .filter(|f| f.severity >= Severity::High)
            .collect();
        
        if !critical_high.is_empty() {
            output.push_str("Critical & High Priority Findings:\n");
            output.push_str("──────────────────────────────────\n");
            
            for finding in critical_high {
                let icon = match finding.severity {
                    Severity::Critical => "🔴",
                    Severity::High => "🟠",
                    _ => "",
                };
                
                output.push_str(&format!("\n{} {}\n", icon, finding.title));
                
                if let Some(ref path) = finding.location.file_path {
                    output.push_str(&format!("   Location: {}", path));
                    if let Some(line) = finding.location.line_number {
                        output.push_str(&format!":{}", line));
                    }
                    output.push('\n');
                }
                
                if let Some(ref cwe) = finding.cwe_id {
                    output.push_str(&format!("   CWE: {}\n", cwe));
                }
                
                output.push_str(&format!("   Tool: {}\n", finding.tool_name));
            }
        }
        
        output
    }

    /// Format summary only
    pub fn format_summary(findings: &FindingCollection) -> String {
        format!(
            "Security Analysis: {} findings (🔴 {} Critical, 🟠 {} High, 🟡 {} Medium, 🔵 {} Low, ⚪ {} Info)",
            findings.total_count,
            findings.by_severity.get(&Severity::Critical).copied().unwrap_or(0),
            findings.by_severity.get(&Severity::High).copied().unwrap_or(0),
            findings.by_severity.get(&Severity::Medium).copied().unwrap_or(0),
            findings.by_severity.get(&Severity::Low).copied().unwrap_or(0),
            findings.by_severity.get(&Severity::Info).copied().unwrap_or(0),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{Confidence, Finding, Location, Platform, Severity};

    fn create_test_finding(title: &str, severity: Severity) -> Finding {
        Finding::new(title, "Test description")
            .with_severity(severity)
            .with_type("test")
            .with_tool("test-tool", "1.0.0")
            .with_location(
                Location::new()
                    .with_file("test/file.rs")
                    .with_line(42)
                    .with_platform(Platform::Android)
            )
    }

    #[test]
    fn test_cicd_platform_display() {
        assert_eq!(CICDPlatform::GitHubActions.to_string(), "github_actions");
        assert_eq!(CICDPlatform::GitLabCI.to_string(), "gitlab_ci");
        assert_eq!(CICDPlatform::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_risk_threshold_should_block() {
        let strict = RiskThreshold::Strict;
        assert!(strict.should_block(Severity::Info));
        assert!(strict.should_block(Severity::Critical));

        let high = RiskThreshold::High;
        assert!(!high.should_block(Severity::Medium));
        assert!(high.should_block(Severity::High));
        assert!(high.should_block(Severity::Critical));

        let never = RiskThreshold::Never;
        assert!(!never.should_block(Severity::Critical));
    }

    #[test]
    fn test_cicd_conclusion_display() {
        assert_eq!(CICDConclusion::Success.to_string(), "success");
        assert_eq!(CICDConclusion::Failure.to_string(), "failure");
    }

    #[test]
    fn test_determine_conclusion() {
        let config = CICDConfig::new().with_risk_threshold(RiskThreshold::High);
        let integration = CICDIntegration::new(config);

        // No findings
        let empty = FindingCollection::new(vec![]);
        assert_eq!(integration.determine_conclusion(&empty), CICDConclusion::Success);

        // Only info findings
        let info_only = FindingCollection::new(vec![
            create_test_finding("Info finding", Severity::Info),
        ]);
        assert_eq!(integration.determine_conclusion(&info_only), CICDConclusion::Neutral);

        // High severity finding
        let with_high = FindingCollection::new(vec![
            create_test_finding("High finding", Severity::High),
        ]);
        assert_eq!(integration.determine_conclusion(&with_high), CICDConclusion::Failure);
    }

    #[test]
    fn test_generate_markdown() {
        let config = CICDConfig::new();
        let integration = CICDIntegration::new(config);

        let findings = FindingCollection::new(vec![
            create_test_finding("Critical Issue", Severity::Critical),
            create_test_finding("High Issue", Severity::High),
            create_test_finding("Medium Issue", Severity::Medium),
        ]);

        let report = integration.generate_report(&findings);
        let markdown = integration.generate_markdown(&report);

        assert!(markdown.contains("Security Analysis Report"));
        assert!(markdown.contains("Critical Issue"));
        assert!(markdown.contains("High Issue"));
        assert!(markdown.contains("🔴"));
        assert!(markdown.contains("🟠"));
    }

    #[test]
    fn test_finding_to_annotation() {
        let config = CICDConfig::new();
        let integration = CICDIntegration::new(config);

        let finding = create_test_finding("Test", Severity::High);
        let annotation = integration.finding_to_annotation(&finding);

        assert!(annotation.is_some());
        let ann = annotation.unwrap();
        assert_eq!(ann.file_path, "test/file.rs");
        assert_eq!(ann.line, 42);
        assert_eq!(ann.severity, AnnotationLevel::Error);
    }

    #[test]
    fn test_annotation_level_from_severity() {
        assert_eq!(AnnotationLevel::from(Severity::Info), AnnotationLevel::Notice);
        assert_eq!(AnnotationLevel::from(Severity::Low), AnnotationLevel::Notice);
        assert_eq!(AnnotationLevel::from(Severity::Medium), AnnotationLevel::Warning);
        assert_eq!(AnnotationLevel::from(Severity::High), AnnotationLevel::Error);
        assert_eq!(AnnotationLevel::from(Severity::Critical), AnnotationLevel::Error);
    }

    #[test]
    fn test_should_block() {
        let config = CICDConfig::new().with_risk_threshold(RiskThreshold::Medium);
        let integration = CICDIntegration::new(config);

        let findings = FindingCollection::new(vec![
            create_test_finding("Low", Severity::Low),
            create_test_finding("Medium", Severity::Medium),
        ]);

        assert!(integration.should_block(&findings));
        assert_eq!(integration.get_blocking_findings(&findings).len(), 1);
    }

    #[test]
    fn test_report_formatter() {
        let findings = FindingCollection::new(vec![
            create_test_finding("Critical", Severity::Critical),
            create_test_finding("High", Severity::High),
        ]);

        let console = CICDReportFormatter::format_console(&findings);
        assert!(console.contains("Soul Hunter Security Analysis Report"));
        assert!(console.contains("Critical"));

        let summary = CICDReportFormatter::format_summary(&findings);
        assert!(summary.contains("2 findings"));
        assert!(summary.contains("🔴 1 Critical"));
    }

    #[test]
    fn test_finding_summary_from_finding() {
        let finding = create_test_finding("Test Title", Severity::High)
            .with_cwe("CWE-79");
        
        let summary: FindingSummary = (&finding).into();
        
        assert_eq!(summary.title, "Test Title");
        assert_eq!(summary.severity, Severity::High);
        assert_eq!(summary.cwe_id, Some("CWE-79".to_string()));
        assert_eq!(summary.file_path, Some("test/file.rs".to_string()));
        assert_eq!(summary.line, Some(42));
    }

    #[test]
    fn test_cicd_config_builder() {
        let config = CICDConfig::new()
            .with_risk_threshold(RiskThreshold::Critical)
            .with_api_token("test-token")
            .without_annotations()
            .without_comments();

        assert_eq!(config.risk_threshold, RiskThreshold::Critical);
        assert_eq!(config.api_token, Some("test-token".to_string()));
        assert!(!config.enable_annotations);
        assert!(!config.enable_comments);
    }
}
