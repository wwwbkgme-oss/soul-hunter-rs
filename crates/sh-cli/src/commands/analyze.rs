//! Analyze command - Production Ready

use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing::{info, error};

use sh_core::{Config, Orchestrator};
use sh_types::{AssessmentConfig, Platform};

use crate::{AnalyzeArgs, OutputFormat};

pub async fn execute(args: AnalyzeArgs) -> Result<()> {
    info!("Starting analysis of {:?}", args.target);

    // Validate target exists
    if !args.target.exists() {
        anyhow::bail!("Target not found: {:?}", args.target);
    }

    // Build configuration
    let mut config = AssessmentConfig::default();
    
    if args.all {
        config.enable_static_analysis = true;
        config.enable_dynamic_analysis = true;
        config.enable_network_analysis = true;
        config.enable_crypto_analysis = true;
        config.enable_intent_analysis = true;
    } else {
        config.enable_static_analysis = args.static_analysis;
        config.enable_dynamic_analysis = args.dynamic_analysis;
        config.enable_network_analysis = args.network_analysis;
        config.enable_crypto_analysis = args.crypto_analysis;
        config.enable_intent_analysis = args.intent_analysis;
    }

    // If no specific analysis enabled, enable static by default
    if !config.enable_static_analysis && !config.enable_dynamic_analysis 
        && !config.enable_network_analysis && !config.enable_crypto_analysis 
        && !config.enable_intent_analysis {
        config.enable_static_analysis = true;
    }

    config.max_workers = args.workers as u32;

    // Create orchestrator
    let orchestrator_config = Config {
        max_workers: args.workers,
        job_timeout_secs: 300,
        max_retries: 3,
        enable_dashboard: false,
        dashboard_port: 0,
        enable_evidence_chain: false,
        evidence_signing: false,
        enable_attack_graph: false,
        enable_correlation: true,
        enable_risk_scoring: true,
    };

    let orchestrator = Orchestrator::new(orchestrator_config);

    // Run assessment
    let target_path = args.target.to_string_lossy().to_string();
    let assessment = orchestrator.assess(&target_path, config).await
        .context("Assessment failed")?;

    // Output results
    let output_format = args.output_format.unwrap_or(crate::OutputFormat::Json);
    let output = match output_format {
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
        info!("Analysis complete: {} findings", findings.total_count);
        info!("  Critical: {}", findings.by_severity.get(&sh_types::Severity::Critical).unwrap_or(&0));
        info!("  High: {}", findings.by_severity.get(&sh_types::Severity::High).unwrap_or(&0));
        info!("  Medium: {}", findings.by_severity.get(&sh_types::Severity::Medium).unwrap_or(&0));
        info!("  Low: {}", findings.by_severity.get(&sh_types::Severity::Low).unwrap_or(&0));
    }

    Ok(())
}
