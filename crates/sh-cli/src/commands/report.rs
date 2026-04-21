//! Report command - Production Ready

use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing::{info, error};

use crate::{ReportArgs, ReportFormat};

pub async fn execute(args: ReportArgs) -> Result<()> {
    info!("Generating report from {:?}", args.input);

    // Validate input exists
    if !args.input.exists() {
        anyhow::bail!("Input file not found: {:?}", args.input);
    }

    // Read input file
    let input_content = tokio::fs::read_to_string(&args.input).await
        .context("Failed to read input file")?;

    // Parse findings
    let findings: sh_types::FindingCollection = serde_json::from_str(&input_content)
        .context("Failed to parse findings JSON")?;

    // Generate report based on format
    let report = match args.format {
        ReportFormat::Json => {
            serde_json::to_string_pretty(&findings)?
        }
        ReportFormat::Html => {
            generate_html_report(&findings, args.template.as_ref())?
        }
        ReportFormat::Markdown => {
            generate_markdown_report(&findings)?
        }
        ReportFormat::Sarif => {
            generate_sarif_report(&findings)?
        }
    };

    // Write report
    tokio::fs::write(&args.output, report).await
        .context("Failed to write report file")?;

    info!("Report generated: {:?}", args.output);
    info!("  Format: {:?}", args.format);
    info!("  Findings: {}", findings.total_count);

    Ok(())
}

fn generate_html_report(findings: &sh_types::FindingCollection, template: Option<&PathBuf>) -> Result<String> {
    let mut html = String::new();
    
    html.push_str("<!DOCTYPE html>\n");
    html.push_str("<html>\n<head>\n");
    html.push_str("<title>Soul Hunter Security Report</title>\n");
    html.push_str("<style>\n");
    html.push_str(include_str!("../templates/report.css"));
    html.push_str("</style>\n");
    html.push_str("</head>\n<body>\n");
    
    // Header
    html.push_str("<h1>Security Analysis Report</h1>\n");
    html.push_str(&format!("<p>Generated: {}</p>\n", chrono::Utc::now()));
    html.push_str(&format!("<p>Total Findings: {}</p>\n", findings.total_count));
    
    // Summary
    html.push_str("<h2>Summary</h2>\n");
    html.push_str("<table>\n");
    html.push_str("<tr><th>Severity</th><th>Count</th></tr>\n");
    for (severity, count) in &findings.by_severity {
        let class = format!("{:?}", severity).to_lowercase();
        html.push_str(&format!(
            "<tr class=\"{}\"><td>{:?}</td><td>{}</td></tr>\n",
            class, severity, count
        ));
    }
    html.push_str("</table>\n");
    
    // Findings
    html.push_str("<h2>Findings</h2>\n");
    for finding in &findings.findings {
        html.push_str("<div class=\"finding\">\n");
        html.push_str(&format!("<h3>{}</h3>\n", finding.title));
        html.push_str(&format!("<p><strong>Severity:</strong> {:?}</p>\n", finding.severity));
        html.push_str(&format!("<p><strong>Confidence:</strong> {:?}</p>\n", finding.confidence));
        html.push_str(&format!("<p><strong>Type:</strong> {}</p>\n", finding.finding_type));
        if let Some(ref cwe) = finding.cwe_id {
            html.push_str(&format!("<p><strong>CWE:</strong> {}</p>\n", cwe));
        }
        if let Some(ref owasp) = finding.owasp_category {
            html.push_str(&format!("<p><strong>OWASP:</strong> {}</p>\n", owasp));
        }
        html.push_str(&format!("<p>{}</p>\n", finding.description));
        if let Some(ref remediation) = finding.remediation {
            html.push_str(&format!("<p><strong>Remediation:</strong> {}</p>\n", remediation.description));
        }
        html.push_str("</div>\n");
    }
    
    html.push_str("</body>\n</html>");
    
    Ok(html)
}

fn generate_markdown_report(findings: &sh_types::FindingCollection) -> Result<String> {
    let mut md = String::new();
    
    md.push_str("# Security Analysis Report\n\n");
    md.push_str(&format!("**Generated:** {}\n\n", chrono::Utc::now()));
    md.push_str(&format!("**Total Findings:** {}\n\n", findings.total_count));
    
    // Summary
    md.push_str("## Summary\n\n");
    md.push_str("| Severity | Count |\n");
    md.push_str("|----------|-------|\n");
    for (severity, count) in &findings.by_severity {
        md.push_str(&format!("| {:?} | {} |\n", severity, count));
    }
    md.push('\n');
    
    // Findings
    md.push_str("## Findings\n\n");
    for (i, finding) in findings.findings.iter().enumerate() {
        md.push_str(&format!("### {}. {}\n\n", i + 1, finding.title));
        md.push_str(&format!("- **Severity:** {:?}\n", finding.severity));
        md.push_str(&format!("- **Confidence:** {:?}\n", finding.confidence));
        md.push_str(&format!("- **Type:** {}\n", finding.finding_type));
        if let Some(ref cwe) = finding.cwe_id {
            md.push_str(&format!("- **CWE:** {}\n", cwe));
        }
        if let Some(ref owasp) = finding.owasp_category {
            md.push_str(&format!("- **OWASP:** {}\n", owasp));
        }
        md.push('\n');
        md.push_str(&format!("{}\n\n", finding.description));
        if let Some(ref remediation) = finding.remediation {
            md.push_str(&format!("**Remediation:** {}\n\n", remediation.description));
        }
    }
    
    Ok(md)
}

fn generate_sarif_report(findings: &sh_types::FindingCollection) -> Result<String> {
    // SARIF v2.1.0 format
    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Soul Hunter",
                    "version": "0.1.0"
                }
            },
            "results": findings.findings.iter().map(|f| {
                serde_json::json!({
                    "ruleId": f.finding_type,
                    "level": match f.severity {
                        sh_types::Severity::Critical | sh_types::Severity::High => "error",
                        sh_types::Severity::Medium => "warning",
                        _ => "note",
                    },
                    "message": {
                        "text": f.description
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.location.file_path.as_ref().unwrap_or(&"unknown".to_string())
                            },
                            "region": {
                                "startLine": f.location.line_number.unwrap_or(1)
                            }
                        }
                    }]
                })
            }).collect::<Vec<_>>()
        }]
    });
    
    Ok(serde_json::to_string_pretty(&sarif)?)
}
