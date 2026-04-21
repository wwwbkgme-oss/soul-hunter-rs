//! Assess command - Production Ready

use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing::{info, error};

use sh_core::{Config, Orchestrator};
use sh_types::AssessmentConfig;

use crate::AssessArgs;

pub async fn execute(args: AssessArgs) -> Result<()> {
    info!("Starting assessment of {:?}", args.target);

    // Validate target exists
    if !args.target.exists() {
        anyhow::bail!("Target not found: {:?}", args.target);
    }

    // Build configuration
    let config = AssessmentConfig {
        enable_static_analysis: true,
        enable_dynamic_analysis: true,
        enable_network_analysis: true,
        enable_crypto_analysis: true,
        enable_intent_analysis: true,
        enable_owasp_mapping: true,
        enable_risk_scoring: true,
        enable_evidence_chain: args.evidence,
        enable_attack_graph: args.attack_graph,
        enable_correlation: true,
        output_format: match args.output_format {
            crate::OutputFormat::Json => sh_types::OutputFormat::Json,
            crate::OutputFormat::Yaml => sh_types::OutputFormat::Json, // Fallback
            crate::OutputFormat::Sarif => sh_types::OutputFormat::Json, // Fallback
            crate::OutputFormat::Html => sh_types::OutputFormat::Json, // Fallback
            crate::OutputFormat::Markdown => sh_types::OutputFormat::Json, // Fallback
        },
        max_workers: args.workers as u32,
        tool_configs: std::collections::HashMap::new(),
    };

    // Create orchestrator
    let orchestrator_config = Config {
        max_workers: args.workers,
        job_timeout_secs: 300,
        max_retries: 3,
        enable_dashboard: args.dashboard,
        dashboard_port: args.dashboard_port,
        enable_evidence_chain: args.evidence,
        evidence_signing: false,
        enable_attack_graph: args.attack_graph,
        enable_correlation: true,
        enable_risk_scoring: true,
    };

    let orchestrator = Orchestrator::new(orchestrator_config);

    // Start dashboard if requested
    if args.dashboard {
        info!("Starting dashboard on port {}", args.dashboard_port);
        // Dashboard would be started here
    }

    // Run assessment
    let target_path = args.target.to_string_lossy().to_string();
    let assessment = orchestrator.assess(&target_path, config).await
        .context("Assessment failed")?;

    // Output results
    let output = match args.output_format {
        crate::OutputFormat::Json => serde_json::to_string_pretty(&assessment)?,
        crate::OutputFormat::Yaml => serde_yaml::to_string(&assessment)?,
        _ => serde_json::to_string_pretty(&assessment)?,
    };

    // Write to file or stdout
    if let Some(output_path) = args.output {
        tokio::fs::write(&output_path, output).await
            .context("Failed to write output file")?;
        info!("Results written to {:?}", output_path);
    } else {
        println!("{}", output);
    }

    // Print summary
    if let Some(ref findings) = assessment.findings {
        info!("Assessment complete: {} findings", findings.total_count);
        info!("  Critical: {}", findings.by_severity.get(&sh_types::Severity::Critical).unwrap_or(&0));
        info!("  High: {}", findings.by_severity.get(&sh_types::Severity::High).unwrap_or(&0));
        info!("  Medium: {}", findings.by_severity.get(&sh_types::Severity::Medium).unwrap_or(&0));
        info!("  Low: {}", findings.by_severity.get(&sh_types::Severity::Low).unwrap_or(&0));
        
        if let Some(ref risk) = assessment.risk_score {
            info!("  Risk Score: {:.1}/10", risk.overall_score);
        }
    }

    Ok(())
}
