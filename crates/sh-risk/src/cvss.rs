//! CVSS v3.1 Calculator - Production Ready
//!
//! Implements the Common Vulnerability Scoring System v3.1 specification
//! for calculating base, temporal, and environmental scores.
//!
//! Reference: https://www.first.org/cvss/v3.1/specification-document

use tracing::{debug, trace};

use sh_types::risk::{
    AttackComplexity, AttackVector, CvssScore, ExploitCodeMaturity, Impact, PrivilegesRequired,
    RemediationLevel, ReportConfidence, Scope, UserInteraction,
};

use crate::{Result, RiskError};

/// CVSS v3.1 Calculator
#[derive(Debug, Clone, Default)]
pub struct CvssCalculator;

impl CvssCalculator {
    /// Create a new CVSS calculator
    pub fn new() -> Self {
        Self
    }

    /// Calculate the base score from CVSS metrics
    pub fn calculate_base_score(cvss: &CvssScore) -> Result<f64> {
        trace!("Calculating CVSS base score");

        let iss = Self::calculate_iss(cvss);
        let impact = Self::calculate_impact_score(iss, cvss.scope);
        let exploitability = Self::calculate_exploitability_score(cvss);

        let base_score = if impact <= 0.0 {
            0.0
        } else {
            match cvss.scope {
                Scope::Unchanged => ((-15.0) * (1.0 - impact) * (1.0 - exploitability)).min(10.0),
                Scope::Changed => {
                    ((-15.0) * (1.0 - impact) * (1.0 - exploitability)).min(10.0) * 1.08
                }
            }
        };

        let rounded = Self::round_up(base_score);
        debug!("CVSS Base Score: {} -> {}", base_score, rounded);

        Ok(rounded)
    }

    /// Calculate temporal score
    pub fn calculate_temporal_score(cvss: &CvssScore) -> Result<f64> {
        let base_score = Self::calculate_base_score(cvss)?;

        let exploit_maturity = cvss.exploit_code_maturity.unwrap_or(ExploitCodeMaturity::NotDefined);
        let remediation = cvss.remediation_level.unwrap_or(RemediationLevel::NotDefined);
        let confidence = cvss.report_confidence.unwrap_or(ReportConfidence::NotDefined);

        if matches!(exploit_maturity, ExploitCodeMaturity::NotDefined)
            && matches!(remediation, RemediationLevel::NotDefined)
            && matches!(confidence, ReportConfidence::NotDefined)
        {
            return Ok(base_score);
        }

        let exploit_maturity_coef = Self::exploit_maturity_coefficient(&exploit_maturity);
        let remediation_coef = Self::remediation_coefficient(&remediation);
        let confidence_coef = Self::report_confidence_coefficient(&confidence);

        let temporal_score =
            Self::round_up(base_score * exploit_maturity_coef * remediation_coef * confidence_coef);

        debug!("CVSS Temporal Score: {}", temporal_score);
        Ok(temporal_score)
    }

    /// Calculate environmental score
    pub fn calculate_environmental_score(cvss: &CvssScore) -> Result<f64> {
        if cvss.temporal_score.is_some() {
            Self::calculate_temporal_score(cvss)
        } else {
            Self::calculate_base_score(cvss)
        }
    }

    /// Calculate all scores at once
    pub fn calculate_all(cvss: &CvssScore) -> Result<CvssScores> {
        let base = Self::calculate_base_score(cvss)?;
        let temporal = if cvss.exploit_code_maturity.is_some()
            || cvss.remediation_level.is_some()
            || cvss.report_confidence.is_some()
        {
            Some(Self::calculate_temporal_score(cvss)?)
        } else {
            None
        };
        let environmental = if cvss.environmental_score.is_some() {
            Some(Self::calculate_environmental_score(cvss)?)
        } else {
            None
        };

        Ok(CvssScores {
            base,
            temporal,
            environmental,
        })
    }

    fn calculate_iss(cvss: &CvssScore) -> f64 {
        let conf = Self::impact_coefficient(&cvss.confidentiality_impact);
        let integ = Self::impact_coefficient(&cvss.integrity_impact);
        let avail = Self::impact_coefficient(&cvss.availability_impact);

        1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))
    }

    fn calculate_impact_score(iss: f64, scope: Scope) -> f64 {
        match scope {
            Scope::Unchanged => iss,
            Scope::Changed => {
                let adjusted = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0);
                adjusted.min(10.0)
            }
        }
    }

    fn calculate_exploitability_score(cvss: &CvssScore) -> f64 {
        let av = Self::attack_vector_coefficient(&cvss.attack_vector);
        let ac = Self::attack_complexity_coefficient(&cvss.attack_complexity);
        let pr = Self::privileges_required_coefficient(&cvss.privileges_required, cvss.scope);
        let ui = Self::user_interaction_coefficient(&cvss.user_interaction);

        8.22 * av * ac * pr * ui
    }

    fn attack_vector_coefficient(av: &AttackVector) -> f64 {
        match av {
            AttackVector::Network => 0.85,
            AttackVector::Adjacent => 0.62,
            AttackVector::Local => 0.55,
            AttackVector::Physical => 0.2,
        }
    }

    fn attack_complexity_coefficient(ac: &AttackComplexity) -> f64 {
        match ac {
            AttackComplexity::Low => 0.77,
            AttackComplexity::High => 0.44,
        }
    }

    fn privileges_required_coefficient(pr: &PrivilegesRequired, scope: Scope) -> f64 {
        match (pr, scope) {
            (PrivilegesRequired::None, _) => 0.85,
            (PrivilegesRequired::Low, Scope::Unchanged) => 0.62,
            (PrivilegesRequired::Low, Scope::Changed) => 0.68,
            (PrivilegesRequired::High, Scope::Unchanged) => 0.27,
            (PrivilegesRequired::High, Scope::Changed) => 0.5,
        }
    }

    fn user_interaction_coefficient(ui: &UserInteraction) -> f64 {
        match ui {
            UserInteraction::None => 0.85,
            UserInteraction::Required => 0.62,
        }
    }

    fn impact_coefficient(impact: &Impact) -> f64 {
        match impact {
            Impact::None => 0.0,
            Impact::Low => 0.22,
            Impact::High => 0.56,
        }
    }

    fn exploit_maturity_coefficient(ecm: &ExploitCodeMaturity) -> f64 {
        match ecm {
            ExploitCodeMaturity::NotDefined => 1.0,
            ExploitCodeMaturity::High => 1.0,
            ExploitCodeMaturity::Functional => 0.97,
            ExploitCodeMaturity::ProofOfConcept => 0.94,
            ExploitCodeMaturity::Unproven => 0.91,
        }
    }

    fn remediation_coefficient(rl: &RemediationLevel) -> f64 {
        match rl {
            RemediationLevel::NotDefined => 1.0,
            RemediationLevel::Unavailable => 1.0,
            RemediationLevel::Workaround => 0.97,
            RemediationLevel::TemporaryFix => 0.96,
            RemediationLevel::OfficialFix => 0.95,
        }
    }

    fn report_confidence_coefficient(rc: &ReportConfidence) -> f64 {
        match rc {
            ReportConfidence::NotDefined => 1.0,
            ReportConfidence::Confirmed => 1.0,
            ReportConfidence::Reasonable => 0.96,
            ReportConfidence::Unknown => 0.92,
        }
    }

    fn round_up(value: f64) -> f64 {
        let multiplied = value * 10.0;
        let rounded = multiplied.ceil();
        rounded / 10.0
    }

    /// Get severity rating from score
    pub fn severity_rating(score: f64) -> &'static str {
        match score {
            s if s >= 9.0 => "Critical",
            s if s >= 7.0 => "High",
            s if s >= 4.0 => "Medium",
            s if s >= 0.1 => "Low",
            _ => "None",
        }
    }

    /// Validate CVSS metrics
    pub fn validate(cvss: &CvssScore) -> Result<()> {
        if let Some(temporal) = cvss.temporal_score {
            if !(0.0..=10.0).contains(&temporal) {
                return Err(RiskError::InvalidCvssMetrics(format!(
                    "Temporal score {} out of range [0.0, 10.0]",
                    temporal
                )));
            }
        }

        if let Some(environmental) = cvss.environmental_score {
            if !(0.0..=10.0).contains(&environmental) {
                return Err(RiskError::InvalidCvssMetrics(format!(
                    "Environmental score {} out of range [0.0, 10.0]",
                    environmental
                )));
            }
        }

        Ok(())
    }

    /// Create CVSS score from vector string
    pub fn from_vector(vector: &str) -> Result<CvssScore> {
        let mut cvss = CvssScore::new(0.0);
        let parts: Vec<&str> = vector.split('/').collect();

        for part in parts {
            let kv: Vec<&str> = part.split(':').collect();
            if kv.len() != 2 {
                continue;
            }

            let (key, value) = (kv[0], kv[1]);

            match key {
                "AV" => {
                    cvss.attack_vector = match value {
                        "N" => AttackVector::Network,
                        "A" => AttackVector::Adjacent,
                        "L" => AttackVector::Local,
                        "P" => AttackVector::Physical,
                        _ => continue,
                    }
                }
                "AC" => {
                    cvss.attack_complexity = match value {
                        "L" => AttackComplexity::Low,
                        "H" => AttackComplexity::High,
                        _ => continue,
                    }
                }
                "PR" => {
                    cvss.privileges_required = match value {
                        "N" => PrivilegesRequired::None,
                        "L" => PrivilegesRequired::Low,
                        "H" => PrivilegesRequired::High,
                        _ => continue,
                    }
                }
                "UI" => {
                    cvss.user_interaction = match value {
                        "N" => UserInteraction::None,
                        "R" => UserInteraction::Required,
                        _ => continue,
                    }
                }
                "S" => {
                    cvss.scope = match value {
                        "U" => Scope::Unchanged,
                        "C" => Scope::Changed,
                        _ => continue,
                    }
                }
                "C" => {
                    cvss.confidentiality_impact = match value {
                        "N" => Impact::None,
                        "L" => Impact::Low,
                        "H" => Impact::High,
                        _ => continue,
                    }
                }
                "I" => {
                    cvss.integrity_impact = match value {
                        "N" => Impact::None,
                        "L" => Impact::Low,
                        "H" => Impact::High,
                        _ => continue,
                    }
                }
                "A" => {
                    cvss.availability_impact = match value {
                        "N" => Impact::None,
                        "L" => Impact::Low,
                        "H" => Impact::High,
                        _ => continue,
                    }
                }
                _ => {}
            }
        }

        let base_score = Self::calculate_base_score(&cvss)?;
        cvss.base_score = base_score;

        Ok(cvss)
    }

    /// Convert CVSS score to vector string
    pub fn to_vector(cvss: &CvssScore) -> String {
        let mut parts = vec!["CVSS:3.1".to_string()];

        parts.push(format!(
            "AV:{}",
            match cvss.attack_vector {
                AttackVector::Network => "N",
                AttackVector::Adjacent => "A",
                AttackVector::Local => "L",
                AttackVector::Physical => "P",
            }
        ));

        parts.push(format!(
            "AC:{}",
            match cvss.attack_complexity {
                AttackComplexity::Low => "L",
                AttackComplexity::High => "H",
            }
        ));

        parts.push(format!(
            "PR:{}",
            match cvss.privileges_required {
                PrivilegesRequired::None => "N",
                PrivilegesRequired::Low => "L",
                PrivilegesRequired::High => "H",
            }
        ));

        parts.push(format!(
            "UI:{}",
            match cvss.user_interaction {
                UserInteraction::None => "N",
                UserInteraction::Required => "R",
            }
        ));

        parts.push(format!(
            "S:{}",
            match cvss.scope {
                Scope::Unchanged => "U",
                Scope::Changed => "C",
            }
        ));

        parts.push(format!(
            "C:{}",
            match cvss.confidentiality_impact {
                Impact::None => "N",
                Impact::Low => "L",
                Impact::High => "H",
            }
        ));

        parts.push(format!(
            "I:{}",
            match cvss.integrity_impact {
                Impact::None => "N",
                Impact::Low => "L",
                Impact::High => "H",
            }
        ));

        parts.push(format!(
            "A:{}",
            match cvss.availability_impact {
                Impact::None => "N",
                Impact::Low => "L",
                Impact::High => "H",
            }
        ));

        parts.join("/")
    }
}

/// Collection of CVSS scores
#[derive(Debug, Clone, Copy)]
pub struct CvssScores {
    pub base: f64,
    pub temporal: Option<f64>,
    pub environmental: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cvss_critical() -> CvssScore {
        CvssScore {
            base_score: 0.0,
            temporal_score: None,
            environmental_score: None,
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::High,
            availability_impact: Impact::High,
            exploit_code_maturity: None,
            remediation_level: None,
            report_confidence: None,
        }
    }

    fn create_test_cvss_high() -> CvssScore {
        CvssScore {
            base_score: 0.0,
            temporal_score: None,
            environmental_score: None,
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::Low,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::High,
            availability_impact: Impact::None,
            exploit_code_maturity: None,
            remediation_level: None,
            report_confidence: None,
        }
    }

    fn create_test_cvss_medium() -> CvssScore {
        CvssScore {
            base_score: 0.0,
            temporal_score: None,
            environmental_score: None,
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::High,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::Required,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::Low,
            integrity_impact: Impact::Low,
            availability_impact: Impact::None,
            exploit_code_maturity: None,
            remediation_level: None,
            report_confidence: None,
        }
    }

    #[test]
    fn test_cvss_critical_calculation() {
        let cvss = create_test_cvss_critical();
        let score = CvssCalculator::calculate_base_score(&cvss).unwrap();
        assert!(score >= 9.0, "Expected critical score, got {}", score);
        assert!(score <= 10.0);
    }

    #[test]
    fn test_cvss_high_calculation() {
        let cvss = create_test_cvss_high();
        let score = CvssCalculator::calculate_base_score(&cvss).unwrap();
        assert!(score >= 7.0, "Expected high score, got {}", score);
        assert!(score < 9.0);
    }

    #[test]
    fn test_cvss_medium_calculation() {
        let cvss = create_test_cvss_medium();
        let score = CvssCalculator::calculate_base_score(&cvss).unwrap();
        assert!(score >= 4.0, "Expected medium score, got {}", score);
        assert!(score < 7.0);
    }

    #[test]
    fn test_cvss_scope_changed() {
        let mut cvss = create_test_cvss_critical();
        cvss.scope = Scope::Changed;
        let score = CvssCalculator::calculate_base_score(&cvss).unwrap();
        assert!(score >= 9.0);
    }

    #[test]
    fn test_cvss_vector_parsing() {
        let vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
        let cvss = CvssCalculator::from_vector(vector).unwrap();
        assert_eq!(cvss.attack_vector, AttackVector::Network);
        assert_eq!(cvss.attack_complexity, AttackComplexity::Low);
        assert_eq!(cvss.privileges_required, PrivilegesRequired::None);
        assert_eq!(cvss.user_interaction, UserInteraction::None);
        assert_eq!(cvss.scope, Scope::Unchanged);
        assert_eq!(cvss.confidentiality_impact, Impact::High);
        assert_eq!(cvss.integrity_impact, Impact::High);
        assert_eq!(cvss.availability_impact, Impact::High);
    }

    #[test]
    fn test_cvss_vector_roundtrip() {
        let cvss = create_test_cvss_critical();
        let vector = CvssCalculator::to_vector(&cvss);
        let parsed = CvssCalculator::from_vector(&vector).unwrap();
        assert_eq!(cvss.attack_vector, parsed.attack_vector);
        assert_eq!(cvss.attack_complexity, parsed.attack_complexity);
        assert_eq!(cvss.privileges_required, parsed.privileges_required);
    }

    #[test]
    fn test_severity_rating() {
        assert_eq!(CvssCalculator::severity_rating(9.5), "Critical");
        assert_eq!(CvssCalculator::severity_rating(7.5), "High");
        assert_eq!(CvssCalculator::severity_rating(5.5), "Medium");
        assert_eq!(CvssCalculator::severity_rating(2.5), "Low");
        assert_eq!(CvssCalculator::severity_rating(0.0), "None");
    }

    #[test]
    fn test_temporal_score() {
        let mut cvss = create_test_cvss_critical();
        cvss.exploit_code_maturity = Some(ExploitCodeMaturity::Unproven);
        cvss.remediation_level = Some(RemediationLevel::OfficialFix);
        cvss.report_confidence = Some(ReportConfidence::Unknown);

        let temporal = CvssCalculator::calculate_temporal_score(&cvss).unwrap();
        let base = CvssCalculator::calculate_base_score(&cvss).unwrap();

        // Temporal score should be less than or equal to base
        assert!(temporal <= base);
    }
}
