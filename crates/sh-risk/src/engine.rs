//! Risk Scoring Engine - Production Ready
//!
//! Core risk calculation engine that combines CVSS scores with business context
//! to produce overall risk scores. Merges implementations from tracker-brain-rs
//! and zero-hero-rs.

use std::collections::HashMap;

use tracing::{debug, info, trace, warn};

use sh_types::risk::{
    AssetCriticality, ComplianceFramework, CvssScore, DataSensitivity as TypesDataSensitivity,
    RiskCalculation, RiskFactors as TypesRiskFactors,
};
use sh_types::{Confidence, Finding, FindingCollection, Severity};

use crate::cvss::CvssCalculator;
use crate::ml_scoring::{MlFeatures, MlRiskScorer};
use crate::{Result, RiskError, RiskScore, RiskStatistics};

/// Risk scoring engine
#[derive(Debug, Clone)]
pub struct RiskEngine {
    factors: RiskFactors,
    ml_scorer: Option<MlRiskScorer>,
    use_ml: bool,
}

impl RiskEngine {
    /// Create a new risk engine with default factors
    pub fn new() -> Self {
        Self {
            factors: RiskFactors::default(),
            ml_scorer: None,
            use_ml: false,
        }
    }

    /// Create with custom risk factors
    pub fn with_factors(mut self, factors: RiskFactors) -> Result<Self> {
        factors.validate()?;
        self.factors = factors;
        Ok(self)
    }

    /// Enable ML-based scoring
    pub fn with_ml(mut self, enabled: bool) -> Self {
        self.use_ml = enabled;
        if enabled && self.ml_scorer.is_none() {
            self.ml_scorer = Some(MlRiskScorer::default());
        }
        self
    }

    /// Set custom ML scorer
    pub fn with_ml_scorer(mut self, scorer: MlRiskScorer) -> Self {
        self.ml_scorer = Some(scorer);
        self.use_ml = true;
        self
    }

    /// Calculate risk score for a single finding
    pub fn calculate(&self, finding: &Finding, context: &BusinessContext) -> RiskScore {
        trace!("Calculating risk for finding: {}", finding.id);

        // Get CVSS score
        let cvss_score = finding.cvss_score.unwrap_or(5.0);
        let cvss_component = cvss_score * self.factors.cvss_weight;

        // Calculate business impact
        let criticality_component =
            (context.asset_criticality as i32 as f64 / 4.0) * 10.0 * self.factors.asset_criticality_weight;

        // Calculate threat level
        let exploitability_component = context.exploitability * 10.0 * self.factors.exploitability_weight;
        let exposure_component = context.exposure_level() * 10.0 * self.factors.exposure_weight;

        // Data sensitivity
        let sensitivity_component =
            (context.data_sensitivity as i32 as f64 / 3.0) * 10.0 * self.factors.data_sensitivity_weight;

        // Compliance
        let compliance_component = if context.compliance_frameworks.is_empty() {
            0.0
        } else {
            5.0 * self.factors.compliance_weight
        };

        // Confidence
        let confidence_component = self.confidence_score(finding) * 10.0 * self.factors.confidence_weight;

        // ML component (if enabled)
        let (ml_component, ml_confidence) = if self.use_ml {
            self.calculate_ml_component(finding, context)
        } else {
            (0.0, None)
        };

        // Calculate total
        let total = cvss_component
            + criticality_component
            + exploitability_component
            + exposure_component
            + sensitivity_component
            + compliance_component
            + confidence_component
            + ml_component;

        let overall = total.clamp(0.0, 10.0);

        let business_impact = criticality_component + sensitivity_component + compliance_component;
        let threat_level = exploitability_component + exposure_component;

        debug!(
            "Risk calculated: overall={}, cvss={}, business={}, threat={}",
            overall, cvss_component, business_impact, threat_level
        );

        RiskScore::new(overall)
            .with_cvss(cvss_component)
            .with_business_impact(business_impact)
            .with_threat_level(threat_level)
            .with_ml_confidence(ml_confidence.unwrap_or(1.0))
    }

    /// Calculate risk scores for batch of findings
    pub fn calculate_batch(
        &self,
        findings: &[Finding],
        contexts: &[BusinessContext],
    ) -> Vec<RiskScore> {
        findings
            .iter()
            .enumerate()
            .map(|(i, finding)| {
                let context = contexts.get(i).unwrap_or(&BusinessContext::default());
                self.calculate(finding, context)
            })
            .collect()
    }

    /// Calculate overall risk for assessment
    pub fn calculate_overall(
        &self,
        findings: &[Finding],
        contexts: &[BusinessContext],
    ) -> RiskScore {
        if findings.is_empty() {
            return RiskScore::new(0.0);
        }

        let scores: Vec<RiskScore> = self.calculate_batch(findings, contexts);

        // Calculate weighted average
        let avg_score = scores.iter().map(|s| s.overall).sum::<f64>() / scores.len() as f64;
        let max_score = scores.iter().map(|s| s.overall).fold(0.0, f64::max);

        // Weight average and max (60% avg, 40% max)
        let overall = (avg_score * 0.6) + (max_score * 0.4);

        let avg_cvss = scores.iter().map(|s| s.cvss_component).sum::<f64>() / scores.len() as f64;
        let avg_business = scores.iter().map(|s| s.business_impact).sum::<f64>() / scores.len() as f64;
        let avg_threat = scores.iter().map(|s| s.threat_level).sum::<f64>() / scores.len() as f64;

        RiskScore::new(overall.clamp(0.0, 10.0))
            .with_cvss(avg_cvss)
            .with_business_impact(avg_business)
            .with_threat_level(avg_threat)
    }

    /// Calculate risk for a finding collection
    pub fn calculate_collection(&self, collection: &FindingCollection) -> RiskStatistics {
        let scores: Vec<RiskScore> = collection
            .findings
            .iter()
            .map(|f| self.calculate(f, &BusinessContext::default()))
            .collect();

        RiskStatistics::from_scores(&scores)
    }

    /// Calculate risk using sh-types RiskCalculation
    pub fn calculate_with_types(&self, calculation: &RiskCalculation) -> f64 {
        calculation.calculate()
    }

    /// Calculate confidence score for finding
    fn confidence_score(&self, finding: &Finding) -> f64 {
        match finding.confidence {
            Confidence::Confirmed => 1.0,
            Confidence::Probable => 0.7,
            Confidence::Tentative => 0.4,
        }
    }

    /// Calculate ML component
    fn calculate_ml_component(&self, finding: &Finding, context: &BusinessContext) -> (f64, Option<f64>) {
        if let Some(ref scorer) = self.ml_scorer {
            let features = MlFeatures::from_finding(finding, context);
            match scorer.predict(&features) {
                Ok((score, confidence)) => {
                    let component = score * self.factors.ml_weight;
                    (component, Some(confidence))
                }
                Err(e) => {
                    warn!("ML prediction failed: {}", e);
                    (0.0, None)
                }
            }
        } else {
            (0.0, None)
        }
    }

    /// Get current risk factors
    pub fn factors(&self) -> &RiskFactors {
        &self.factors
    }

    /// Update risk factors
    pub fn set_factors(&mut self, factors: RiskFactors) -> Result<()> {
        factors.validate()?;
        self.factors = factors;
        Ok(())
    }
}

impl Default for RiskEngine {
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
    pub ml_weight: f64,
}

impl RiskFactors {
    /// Validate that weights sum to approximately 1.0
    pub fn validate(&self) -> Result<()> {
        let sum = self.cvss_weight
            + self.asset_criticality_weight
            + self.exploitability_weight
            + self.exposure_weight
            + self.data_sensitivity_weight
            + self.compliance_weight
            + self.confidence_weight
            + self.ml_weight;

        if (sum - 1.0).abs() > 0.01 {
            return Err(RiskError::InvalidRiskFactors(sum));
        }

        Ok(())
    }

    /// Create builder with CVSS weight
    pub fn with_cvss(mut self, weight: f64) -> Self {
        self.cvss_weight = weight.clamp(0.0, 1.0);
        self
    }

    /// Create builder with asset criticality weight
    pub fn with_asset_criticality(mut self, weight: f64) -> Self {
        self.asset_criticality_weight = weight.clamp(0.0, 1.0);
        self
    }

    /// Create builder with exploitability weight
    pub fn with_exploitability(mut self, weight: f64) -> Self {
        self.exploitability_weight = weight.clamp(0.0, 1.0);
        self
    }

    /// Create builder with exposure weight
    pub fn with_exposure(mut self, weight: f64) -> Self {
        self.exposure_weight = weight.clamp(0.0, 1.0);
        self
    }

    /// Create builder with data sensitivity weight
    pub fn with_data_sensitivity(mut self, weight: f64) -> Self {
        self.data_sensitivity_weight = weight.clamp(0.0, 1.0);
        self
    }

    /// Create builder with compliance weight
    pub fn with_compliance(mut self, weight: f64) -> Self {
        self.compliance_weight = weight.clamp(0.0, 1.0);
        self
    }

    /// Create builder with confidence weight
    pub fn with_confidence(mut self, weight: f64) -> Self {
        self.confidence_weight = weight.clamp(0.0, 1.0);
        self
    }

    /// Create builder with ML weight
    pub fn with_ml(mut self, weight: f64) -> Self {
        self.ml_weight = weight.clamp(0.0, 1.0);
        self
    }
}

impl Default for RiskFactors {
    fn default() -> Self {
        Self {
            cvss_weight: 0.25,
            asset_criticality_weight: 0.20,
            exploitability_weight: 0.15,
            exposure_weight: 0.15,
            data_sensitivity_weight: 0.10,
            compliance_weight: 0.05,
            confidence_weight: 0.05,
            ml_weight: 0.05,
        }
    }
}

/// Business context for risk calculation
#[derive(Debug, Clone)]
pub struct BusinessContext {
    pub asset_id: String,
    pub asset_name: Option<String>,
    pub exposure: ExposureLevel,
    pub data_sensitivity: DataSensitivity,
    pub regulated_data: bool,
    pub compliance_frameworks: Vec<ComplianceFramework>,
    pub exploitability: f64,
    pub asset_criticality: AssetCriticality,
    pub custom_weights: HashMap<String, f64>,
}

impl BusinessContext {
    /// Create new business context
    pub fn new(asset_id: impl Into<String>) -> Self {
        Self {
            asset_id: asset_id.into(),
            asset_name: None,
            exposure: ExposureLevel::Internal,
            data_sensitivity: DataSensitivity::Medium,
            regulated_data: false,
            compliance_frameworks: Vec::new(),
            exploitability: 0.5,
            asset_criticality: AssetCriticality::Medium,
            custom_weights: HashMap::new(),
        }
    }

    /// Set asset name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.asset_name = Some(name.into());
        self
    }

    /// Set exposure level
    pub fn with_exposure(mut self, exposure: ExposureLevel) -> Self {
        self.exposure = exposure;
        self
    }

    /// Set data sensitivity
    pub fn with_data_sensitivity(mut self, sensitivity: DataSensitivity) -> Self {
        self.data_sensitivity = sensitivity;
        self
    }

    /// Set regulated data flag
    pub fn with_regulated_data(mut self, regulated: bool) -> Self {
        self.regulated_data = regulated;
        self
    }

    /// Add compliance framework
    pub fn add_compliance(mut self, framework: ComplianceFramework) -> Self {
        self.compliance_frameworks.push(framework);
        self
    }

    /// Set exploitability
    pub fn with_exploitability(mut self, exploitability: f64) -> Self {
        self.exploitability = exploitability.clamp(0.0, 1.0);
        self
    }

    /// Set asset criticality
    pub fn with_asset_criticality(mut self, criticality: AssetCriticality) -> Self {
        self.asset_criticality = criticality;
        self
    }

    /// Add custom weight
    pub fn add_custom_weight(mut self, key: impl Into<String>, weight: f64) -> Self {
        self.custom_weights.insert(key.into(), weight.clamp(0.0, 1.0));
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

    /// Convert to sh-types RiskCalculation
    pub fn to_risk_calculation(&self, cvss_score: f64) -> RiskCalculation {
        let mut calc = RiskCalculation::new(cvss_score)
            .with_asset_criticality(self.asset_criticality)
            .with_exploitability(self.exploitability)
            .with_exposure(self.exposure_level())
            .with_data_sensitivity(TypesDataSensitivity::from(self.data_sensitivity));

        for framework in &self.compliance_frameworks {
            calc = calc.add_compliance(*framework);
        }

        calc
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

impl From<DataSensitivity> for TypesDataSensitivity {
    fn from(s: DataSensitivity) -> Self {
        match s {
            DataSensitivity::Low => TypesDataSensitivity::Public,
            DataSensitivity::Medium => TypesDataSensitivity::Internal,
            DataSensitivity::High => TypesDataSensitivity::Confidential,
            DataSensitivity::Critical => TypesDataSensitivity::Restricted,
        }
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
        let mut finding = Finding::new("Test Finding", "Test description").with_severity(Severity::High);

        if let Some(score) = cvss {
            finding = finding.with_cvss(score);
        }

        finding
    }

    #[test]
    fn test_risk_engine_creation() {
        let engine = RiskEngine::new();
        assert_eq!(engine.factors().cvss_weight, 0.25);
    }

    #[test]
    fn test_risk_calculation() {
        let engine = RiskEngine::new();
        let finding = create_test_finding(Some(7.5));
        let context = BusinessContext::new("test-asset")
            .with_exposure(ExposureLevel::PublicInternet)
            .with_data_sensitivity(DataSensitivity::High);

        let score = engine.calculate(&finding, &context);

        assert!(score.overall > 0.0);
        assert!(score.overall <= 10.0);
    }

    #[test]
    fn test_risk_factors_validation() {
        let valid_factors = RiskFactors::default();
        assert!(valid_factors.validate().is_ok());

        let invalid_factors = RiskFactors {
            cvss_weight: 0.5,
            asset_criticality_weight: 0.5,
            exploitability_weight: 0.5,
            exposure_weight: 0.5,
            data_sensitivity_weight: 0.5,
            compliance_weight: 0.5,
            confidence_weight: 0.5,
            ml_weight: 0.5,
        };
        assert!(invalid_factors.validate().is_err());
    }

    #[test]
    fn test_business_context() {
        let context = BusinessContext::new("asset-1")
            .with_name("Test Asset")
            .with_exposure(ExposureLevel::PublicInternet)
            .with_data_sensitivity(DataSensitivity::Critical)
            .with_regulated_data(true)
            .add_compliance(ComplianceFramework::PciDss)
            .with_exploitability(0.8);

        assert_eq!(context.asset_id, "asset-1");
        assert_eq!(context.asset_name, Some("Test Asset".to_string()));
        assert_eq!(context.exposure, ExposureLevel::PublicInternet);
        assert_eq!(context.exposure_level(), 1.0);
        assert_eq!(context.compliance_frameworks.len(), 1);
    }

    #[test]
    fn test_overall_risk_calculation() {
        let engine = RiskEngine::new();
        let findings = vec![
            create_test_finding(Some(7.5)),
            create_test_finding(Some(5.0)),
            create_test_finding(Some(9.0)),
        ];
        let contexts = vec![
            BusinessContext::new("asset-1").with_exposure(ExposureLevel::PublicInternet),
            BusinessContext::new("asset-2").with_exposure(ExposureLevel::Internal),
            BusinessContext::new("asset-3").with_exposure(ExposureLevel::CorporateNetwork),
        ];

        let overall = engine.calculate_overall(&findings, &contexts);
        assert!(overall.overall > 0.0);
        assert!(overall.overall <= 10.0);
    }

    #[test]
    fn test_collection_risk() {
        let engine = RiskEngine::new();
        let findings = vec![
            create_test_finding(Some(9.0)).with_severity(Severity::Critical),
            create_test_finding(Some(7.5)).with_severity(Severity::High),
            create_test_finding(Some(5.0)).with_severity(Severity::Medium),
        ];
        let collection = FindingCollection::new(findings);

        let stats = engine.calculate_collection(&collection);
        assert!(stats.average > 0.0);
        assert_eq!(stats.total_count(), 3);
    }

    #[test]
    fn test_empty_findings() {
        let engine = RiskEngine::new();
        let overall = engine.calculate_overall(&[], &[]);
        assert_eq!(overall.overall, 0.0);
    }
}
