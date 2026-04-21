//! Risk Calculator - Production Ready
//! 
//! Calculates risk scores with CVSS and business context
//! Based on tracker-brain-rs and zero-hero-rs implementations

use tracing::{debug, info, warn};

use sh_types::prelude::*;
use sh_types::{Finding, RiskScore, Severity};

/// Risk calculator with business context
#[derive(Debug, Clone)]
pub struct RiskCalculator {
    factors: RiskFactors,
}

impl RiskCalculator {
    pub fn new() -> Self {
        Self {
            factors: RiskFactors::default(),
        }
    }

    pub fn with_factors(mut self, factors: RiskFactors) -> Self {
        self.factors = factors;
        self
    }

    /// Calculate risk score for a single finding
    pub fn calculate(&self, finding: &Finding, context: &BusinessContext) -> RiskScore {
        let cvss_component = finding.cvss_score.unwrap_or(5.0) * self.factors.cvss_weight;
        
        let criticality_component = (context.asset_criticality as i32 as f64 / 4.0) 
            * 10.0 * self.factors.asset_criticality_weight;
        
        let exploitability_component = context.exploitability * 10.0 * self.factors.exploitability_weight;
        
        let exposure_component = context.exposure_level() * 10.0 * self.factors.exposure_weight;
        
        let sensitivity_component = (context.data_sensitivity as i32 as f64 / 3.0) 
            * 10.0 * self.factors.data_sensitivity_weight;
        
        let compliance_component = if context.compliance_frameworks.is_empty() { 
            0.0 
        } else { 
            5.0 * self.factors.compliance_weight 
        };
        
        let confidence_component = self.confidence_score(finding) * 10.0 * self.factors.confidence_weight;

        let total = cvss_component + criticality_component + exploitability_component 
            + exposure_component + sensitivity_component + compliance_component + confidence_component;

        let overall_score = total.clamp(0.0, 10.0);
        
        RiskScore::new(overall_score)
            .with_business_impact(criticality_component)
            .with_threat_level(exploitability_component + exposure_component)
    }

    /// Calculate risk scores for batch of findings
    pub fn calculate_batch(&self, findings: &[Finding], contexts: &[BusinessContext]) -> Vec<RiskScore> {
        let default_context = BusinessContext::default();
        findings.iter().enumerate().map(|(i, finding)| {
            let context = contexts.get(i).unwrap_or(&default_context);
            self.calculate(finding, context)
        }).collect()
    }

    /// Calculate overall risk for assessment
    pub fn calculate_overall(&self, findings: &[Finding], contexts: &[BusinessContext]) -> RiskScore {
        if findings.is_empty() {
            return RiskScore::new(0.0);
        }

        let scores: Vec<RiskScore> = self.calculate_batch(findings, contexts);
        
        let avg_score = scores.iter().map(|s| s.overall_score).sum::<f64>() / scores.len() as f64;
        let max_score = scores.iter().map(|s| s.overall_score).fold(0.0, f64::max);
        
        // Weight average and max
        let overall = (avg_score * 0.6) + (max_score * 0.4);
        
        RiskScore::new(overall.clamp(0.0, 10.0))
    }

    /// Calculate confidence score for finding
    fn confidence_score(&self, finding: &Finding) -> f64 {
        match finding.confidence {
            sh_types::Confidence::Confirmed => 1.0,
            sh_types::Confidence::Probable => 0.7,
            sh_types::Confidence::Tentative => 0.4,
        }
    }
}

impl Default for RiskCalculator {
    fn default() -> Self {
        Self::new()
    }
}

/// Risk calculation factors
#[derive(Debug, Clone)]
pub struct RiskFactors {
    pub cvss_weight: f64,
    pub asset_criticality_weight: f64,
    pub exploitability_weight: f64,
    pub exposure_weight: f64,
    pub data_sensitivity_weight: f64,
    pub compliance_weight: f64,
    pub confidence_weight: f64,
}

impl Default for RiskFactors {
    fn default() -> Self {
        Self {
            cvss_weight: 0.25,
            asset_criticality_weight: 0.20,
            exploitability_weight: 0.20,
            exposure_weight: 0.15,
            data_sensitivity_weight: 0.10,
            compliance_weight: 0.05,
            confidence_weight: 0.05,
        }
    }
}

/// Business context for risk calculation
#[derive(Debug, Clone)]
pub struct BusinessContext {
    pub asset_id: String,
    pub exposure: ExposureLevel,
    pub data_sensitivity: DataSensitivity,
    pub regulated_data: bool,
    pub compliance_frameworks: Vec<String>,
    pub exploitability: f64,
    pub asset_criticality: AssetCriticality,
}

impl BusinessContext {
    pub fn new(asset_id: impl Into<String>) -> Self {
        Self {
            asset_id: asset_id.into(),
            exposure: ExposureLevel::Internal,
            data_sensitivity: DataSensitivity::Medium,
            regulated_data: false,
            compliance_frameworks: Vec::new(),
            exploitability: 0.5,
            asset_criticality: AssetCriticality::Medium,
        }
    }

    pub fn with_exposure(mut self, exposure: ExposureLevel) -> Self {
        self.exposure = exposure;
        self
    }

    pub fn with_data_sensitivity(mut self, sensitivity: DataSensitivity) -> Self {
        self.data_sensitivity = sensitivity;
        self
    }

    pub fn with_regulated_data(mut self, regulated: bool) -> Self {
        self.regulated_data = regulated;
        self
    }

    pub fn add_compliance(mut self, framework: impl Into<String>) -> Self {
        self.compliance_frameworks.push(framework.into());
        self
    }

    pub fn with_exploitability(mut self, exploitability: f64) -> Self {
        self.exploitability = exploitability.clamp(0.0, 1.0);
        self
    }

    pub fn with_asset_criticality(mut self, criticality: AssetCriticality) -> Self {
        self.asset_criticality = criticality;
        self
    }

    /// Get exposure level as numeric value
    pub fn exposure_level(&self) -> f64 {
        match self.exposure {
            ExposureLevel::PublicInternet => 1.0,
            ExposureLevel::CorporateNetwork => 0.7,
            ExposureLevel::Internal => 0.4,
            ExposureLevel::Isolated => 0.1,
        }
    }
}

impl Default for BusinessContext {
    fn default() -> Self {
        Self::new("unknown")
    }
}

/// Exposure levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExposureLevel {
    PublicInternet,
    CorporateNetwork,
    Internal,
    Isolated,
}

impl Default for ExposureLevel {
    fn default() -> Self {
        ExposureLevel::Internal
    }
}

/// Data sensitivity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSensitivity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl Default for DataSensitivity {
    fn default() -> Self {
        DataSensitivity::Medium
    }
}

/// Asset criticality levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetCriticality {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Default for AssetCriticality {
    fn default() -> Self {
        AssetCriticality::Medium
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_finding(cvss: Option<f64>) -> Finding {
        let mut finding = Finding::new("Test", "Description")
            .with_severity(Severity::High);
        
        if let Some(score) = cvss {
            finding = finding.with_cvss(score);
        }
        
        finding
    }

    #[test]
    fn test_risk_calculation() {
        let calculator = RiskCalculator::new();
        let finding = create_test_finding(Some(7.5));
        let context = BusinessContext::new("test-asset")
            .with_exposure(ExposureLevel::PublicInternet)
            .with_data_sensitivity(DataSensitivity::High);

        let score = calculator.calculate(&finding, &context);
        
        assert!(score.overall_score > 0.0);
        assert!(score.overall_score <= 10.0);
    }

    #[test]
    fn test_risk_factors() {
        let factors = RiskFactors::default();
        let sum = factors.cvss_weight + factors.asset_criticality_weight 
            + factors.exploitability_weight + factors.exposure_weight 
            + factors.data_sensitivity_weight + factors.compliance_weight 
            + factors.confidence_weight;
        
        // Weights should sum to approximately 1.0
        assert!((sum - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_business_context() {
        let context = BusinessContext::new("asset-1")
            .with_exposure(ExposureLevel::PublicInternet)
            .with_data_sensitivity(DataSensitivity::Critical)
            .add_compliance("PCI-DSS");

        assert_eq!(context.asset_id, "asset-1");
        assert_eq!(context.exposure, ExposureLevel::PublicInternet);
        assert_eq!(context.data_sensitivity, DataSensitivity::Critical);
        assert_eq!(context.compliance_frameworks.len(), 1);
    }

    #[test]
    fn test_exposure_level() {
        let public = BusinessContext::new("test").with_exposure(ExposureLevel::PublicInternet);
        assert_eq!(public.exposure_level(), 1.0);

        let isolated = BusinessContext::new("test").with_exposure(ExposureLevel::Isolated);
        assert_eq!(isolated.exposure_level(), 0.1);
    }
}
