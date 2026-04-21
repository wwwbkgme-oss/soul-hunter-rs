//! Risk scoring types

use serde::{Deserialize, Serialize};

/// CVSS v3.1 score components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssScore {
    pub base_score: f64,
    pub temporal_score: Option<f64>,
    pub environmental_score: Option<f64>,
    
    // Base metrics
    pub attack_vector: AttackVector,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
    pub scope: Scope,
    pub confidentiality_impact: Impact,
    pub integrity_impact: Impact,
    pub availability_impact: Impact,
    
    // Temporal metrics
    pub exploit_code_maturity: Option<ExploitCodeMaturity>,
    pub remediation_level: Option<RemediationLevel>,
    pub report_confidence: Option<ReportConfidence>,
}

impl CvssScore {
    pub fn new(base_score: f64) -> Self {
        Self {
            base_score,
            temporal_score: None,
            environmental_score: None,
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::None,
            integrity_impact: Impact::None,
            availability_impact: Impact::None,
            exploit_code_maturity: None,
            remediation_level: None,
            report_confidence: None,
        }
    }

    pub fn with_temporal(mut self, score: f64) -> Self {
        self.temporal_score = Some(score);
        self
    }

    pub fn with_environmental(mut self, score: f64) -> Self {
        self.environmental_score = Some(score);
        self
    }

    pub fn calculate_severity(&self) -> crate::Severity {
        match self.base_score {
            s if s >= 9.0 => crate::Severity::Critical,
            s if s >= 7.0 => crate::Severity::High,
            s if s >= 4.0 => crate::Severity::Medium,
            s if s >= 0.1 => crate::Severity::Low,
            _ => crate::Severity::Info,
        }
    }
}

/// Attack vector
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

/// Attack complexity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackComplexity {
    Low,
    High,
}

/// Privileges required
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

/// User interaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserInteraction {
    None,
    Required,
}

/// Scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Unchanged,
    Changed,
}

/// Impact level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    None,
    Low,
    High,
}

/// Exploit code maturity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExploitCodeMaturity {
    NotDefined,
    High,
    Functional,
    ProofOfConcept,
    Unproven,
}

/// Remediation level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationLevel {
    NotDefined,
    Unavailable,
    Workaround,
    TemporaryFix,
    OfficialFix,
}

/// Report confidence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportConfidence {
    NotDefined,
    Confirmed,
    Reasonable,
    Unknown,
}

/// Risk calculation factors
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Asset criticality levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

/// Data sensitivity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSensitivity {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Restricted = 3,
}

impl Default for DataSensitivity {
    fn default() -> Self {
        DataSensitivity::Internal
    }
}

/// Compliance frameworks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    PciDss,
    Hipaa,
    Gdpr,
    Soc2,
    Iso27001,
    Nist,
    Owasp,
}

/// Risk score calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskCalculation {
    pub cvss_score: f64,
    pub asset_criticality: AssetCriticality,
    pub exploitability: f64,
    pub exposure: f64,
    pub data_sensitivity: DataSensitivity,
    pub compliance: Vec<ComplianceFramework>,
    pub confidence: f64,
    pub factors: RiskFactors,
}

impl RiskCalculation {
    pub fn new(cvss_score: f64) -> Self {
        Self {
            cvss_score,
            asset_criticality: AssetCriticality::Medium,
            exploitability: 0.5,
            exposure: 0.5,
            data_sensitivity: DataSensitivity::Internal,
            compliance: Vec::new(),
            confidence: 1.0,
            factors: RiskFactors::default(),
        }
    }

    pub fn with_asset_criticality(mut self, criticality: AssetCriticality) -> Self {
        self.asset_criticality = criticality;
        self
    }

    pub fn with_exploitability(mut self, exploitability: f64) -> Self {
        self.exploitability = exploitability.clamp(0.0, 1.0);
        self
    }

    pub fn with_exposure(mut self, exposure: f64) -> Self {
        self.exposure = exposure.clamp(0.0, 1.0);
        self
    }

    pub fn with_data_sensitivity(mut self, sensitivity: DataSensitivity) -> Self {
        self.data_sensitivity = sensitivity;
        self
    }

    pub fn add_compliance(mut self, framework: ComplianceFramework) -> Self {
        self.compliance.push(framework);
        self
    }

    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn calculate(&self) -> f64 {
        let cvss_component = self.cvss_score * self.factors.cvss_weight;
        let criticality_component = (self.asset_criticality as i32 as f64 / 4.0) * 10.0 * self.factors.asset_criticality_weight;
        let exploitability_component = self.exploitability * 10.0 * self.factors.exploitability_weight;
        let exposure_component = self.exposure * 10.0 * self.factors.exposure_weight;
        let sensitivity_component = (self.data_sensitivity as i32 as f64 / 3.0) * 10.0 * self.factors.data_sensitivity_weight;
        let compliance_component = if self.compliance.is_empty() { 0.0 } else { 5.0 * self.factors.compliance_weight };
        let confidence_component = self.confidence * 10.0 * self.factors.confidence_weight;

        let total = cvss_component + criticality_component + exploitability_component 
            + exposure_component + sensitivity_component + compliance_component + confidence_component;
        
        total.clamp(0.0, 10.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cvss_severity() {
        let critical = CvssScore::new(9.5);
        assert_eq!(critical.calculate_severity(), crate::Severity::Critical);

        let high = CvssScore::new(7.5);
        assert_eq!(high.calculate_severity(), crate::Severity::High);

        let medium = CvssScore::new(5.5);
        assert_eq!(medium.calculate_severity(), crate::Severity::Medium);

        let low = CvssScore::new(2.5);
        assert_eq!(low.calculate_severity(), crate::Severity::Low);
    }

    #[test]
    fn test_risk_calculation() {
        let calc = RiskCalculation::new(7.5)
            .with_asset_criticality(AssetCriticality::High)
            .with_exploitability(0.8)
            .with_exposure(0.6)
            .with_data_sensitivity(DataSensitivity::Confidential)
            .add_compliance(ComplianceFramework::Owasp);

        let score = calc.calculate();
        assert!(score > 0.0 && score <= 10.0);
    }

    #[test]
    fn test_risk_factors() {
        let factors = RiskFactors::default();
        let sum = factors.cvss_weight + factors.asset_criticality_weight + factors.exploitability_weight
            + factors.exposure_weight + factors.data_sensitivity_weight + factors.compliance_weight
            + factors.confidence_weight;
        
        // Weights should sum to approximately 1.0
        assert!((sum - 1.0).abs() < 0.01);
    }
}
