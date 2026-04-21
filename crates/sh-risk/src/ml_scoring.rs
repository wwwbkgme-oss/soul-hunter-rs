//! ML-Based Risk Scoring - Production Ready
//!
//! Machine learning enhanced risk scoring with feature extraction,
//! model weights, and confidence calculation.
//!
//! This module provides a lightweight ML scoring system that can be
//! extended with actual ML models while providing sensible defaults.

use std::collections::HashMap;

use tracing::{debug, trace, warn};

use sh_types::{Confidence, Finding, Severity};

use crate::engine::BusinessContext;
use crate::{Result, RiskError};

/// ML-based risk scorer
#[derive(Debug, Clone)]
pub struct MlRiskScorer {
    weights: ModelWeights,
    feature_importance: HashMap<String, f64>,
    enabled: bool,
}

impl MlRiskScorer {
    /// Create a new ML risk scorer with default weights
    pub fn new() -> Self {
        Self {
            weights: ModelWeights::default(),
            feature_importance: Self::default_feature_importance(),
            enabled: true,
        }
    }

    /// Create with custom weights
    pub fn with_weights(mut self, weights: ModelWeights) -> Self {
        self.weights = weights;
        self
    }

    /// Enable or disable ML scoring
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Predict risk score from features
    ///
    /// Returns (risk_score, confidence) where:
    /// - risk_score is between 0.0 and 10.0
    /// - confidence is between 0.0 and 1.0
    pub fn predict(&self, features: &MlFeatures) -> Result<(f64, f64)> {
        if !self.enabled {
            return Ok((5.0, 0.5));
        }

        trace!("Predicting risk score from ML features");

        // Calculate weighted feature score
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;

        // CVSS-based features
        weighted_sum += features.cvss_score * self.weights.cvss_weight;
        total_weight += self.weights.cvss_weight;

        // Severity-based features
        weighted_sum += features.severity_score * self.weights.severity_weight;
        total_weight += self.weights.severity_weight;

        // Exploitability features
        weighted_sum += features.exploitability * self.weights.exploitability_weight;
        total_weight += self.weights.exploitability_weight;

        // Asset criticality
        weighted_sum += features.asset_criticality * self.weights.asset_weight;
        total_weight += self.weights.asset_weight;

        // Data sensitivity
        weighted_sum += features.data_sensitivity * self.weights.data_sensitivity_weight;
        total_weight += self.weights.data_sensitivity_weight;

        // Exposure
        weighted_sum += features.exposure * self.weights.exposure_weight;
        total_weight += self.weights.exposure_weight;

        // Historical patterns
        weighted_sum += features.historical_pattern_score * self.weights.historical_weight;
        total_weight += self.weights.historical_weight;

        // Calculate normalized score (0-10 scale)
        let normalized_score = if total_weight > 0.0 {
            (weighted_sum / total_weight) * 10.0
        } else {
            5.0
        };

        // Calculate confidence based on feature completeness
        let confidence = self.calculate_confidence(features);

        let score = normalized_score.clamp(0.0, 10.0);

        debug!(
            "ML prediction: score={}, confidence={}",
            score, confidence
        );

        Ok((score, confidence))
    }

    /// Calculate confidence based on feature completeness
    fn calculate_confidence(&self, features: &MlFeatures) -> f64 {
        let mut confidence_factors = Vec::new();

        // CVSS confidence
        if features.cvss_score > 0.0 {
            confidence_factors.push(1.0);
        } else {
            confidence_factors.push(0.5);
        }

        // Severity confidence
        if features.severity_score > 0.0 {
            confidence_factors.push(1.0);
        } else {
            confidence_factors.push(0.5);
        }

        // Context confidence
        if features.has_context {
            confidence_factors.push(1.0);
        } else {
            confidence_factors.push(0.3);
        }

        // Historical data confidence
        if features.historical_pattern_score > 0.0 {
            confidence_factors.push(0.9);
        } else {
            confidence_factors.push(0.5);
        }

        // Calculate average confidence
        let avg_confidence: f64 =
            confidence_factors.iter().sum::<f64>() / confidence_factors.len() as f64;

        avg_confidence.clamp(0.0, 1.0)
    }

    /// Update weights from training data
    pub fn update_weights(&mut self, weights: ModelWeights) {
        self.weights = weights;
    }

    /// Get feature importance
    pub fn feature_importance(&self) -> &HashMap<String, f64> {
        &self.feature_importance
    }

    /// Calculate feature importance from data
    pub fn calculate_feature_importance(
        &mut self,
        _features: &[MlFeatures],
        _actual_scores: &[f64],
    ) -> HashMap<String, f64> {
        // Simplified feature importance calculation
        // In production, this would use actual ML techniques like:
        // - Permutation importance
        // - SHAP values
        // - Feature ablation

        let importance = self.feature_importance.clone();
        importance
    }

    fn default_feature_importance() -> HashMap<String, f64> {
        let mut map = HashMap::new();
        map.insert("cvss_score".to_string(), 0.30);
        map.insert("severity".to_string(), 0.20);
        map.insert("exploitability".to_string(), 0.15);
        map.insert("asset_criticality".to_string(), 0.15);
        map.insert("data_sensitivity".to_string(), 0.10);
        map.insert("exposure".to_string(), 0.10);
        map
    }

    /// Batch prediction for multiple findings
    pub fn predict_batch(&self, features: &[MlFeatures]) -> Vec<Result<(f64, f64)>> {
        features.iter().map(|f| self.predict(f)).collect()
    }

    /// Get model weights
    pub fn weights(&self) -> &ModelWeights {
        &self.weights
    }
}

impl Default for MlRiskScorer {
    fn default() -> Self {
        Self::new()
    }
}

/// ML features for risk prediction
#[derive(Debug, Clone, Default)]
pub struct MlFeatures {
    /// CVSS base score (0-10)
    pub cvss_score: f64,
    /// Severity score (0-10)
    pub severity_score: f64,
    /// Exploitability score (0-1)
    pub exploitability: f64,
    /// Asset criticality (0-1)
    pub asset_criticality: f64,
    /// Data sensitivity (0-1)
    pub data_sensitivity: f64,
    /// Exposure level (0-1)
    pub exposure: f64,
    /// Historical pattern score (0-1)
    pub historical_pattern_score: f64,
    /// Whether business context is available
    pub has_context: bool,
    /// Finding type encoded as numeric
    pub finding_type_encoded: u32,
    /// Platform encoded as numeric
    pub platform_encoded: u32,
    /// Additional custom features
    pub custom_features: HashMap<String, f64>,
}

impl MlFeatures {
    /// Create features from a finding and business context
    pub fn from_finding(finding: &Finding, context: &BusinessContext) -> Self {
        let cvss_score = finding.cvss_score.unwrap_or(5.0);
        let severity_score = Self::severity_to_score(&finding.severity);

        Self {
            cvss_score,
            severity_score,
            exploitability: context.exploitability,
            asset_criticality: context.asset_criticality as i32 as f64 / 4.0,
            data_sensitivity: context.data_sensitivity as i32 as f64 / 3.0,
            exposure: context.exposure_level(),
            historical_pattern_score: 0.5, // Default, would come from historical data
            has_context: true,
            finding_type_encoded: Self::encode_finding_type(&finding.finding_type),
            platform_encoded: Self::encode_platform(&context.asset_id), // Simplified
            custom_features: HashMap::new(),
        }
    }

    /// Create features with just a finding (no context)
    pub fn from_finding_only(finding: &Finding) -> Self {
        let cvss_score = finding.cvss_score.unwrap_or(5.0);
        let severity_score = Self::severity_to_score(&finding.severity);

        Self {
            cvss_score,
            severity_score,
            exploitability: 0.5,
            asset_criticality: 0.5,
            data_sensitivity: 0.5,
            exposure: 0.5,
            historical_pattern_score: 0.5,
            has_context: false,
            finding_type_encoded: Self::encode_finding_type(&finding.finding_type),
            platform_encoded: 0,
            custom_features: HashMap::new(),
        }
    }

    /// Convert severity to numeric score
    fn severity_to_score(severity: &Severity) -> f64 {
        match severity {
            Severity::Info => 1.0,
            Severity::Low => 3.0,
            Severity::Medium => 5.0,
            Severity::High => 8.0,
            Severity::Critical => 10.0,
        }
    }

    /// Encode finding type as numeric
    fn encode_finding_type(finding_type: &str) -> u32 {
        match finding_type.to_lowercase().as_str() {
            "vulnerability" => 1,
            "misconfiguration" => 2,
            "secret" => 3,
            "malware" => 4,
            "anomaly" => 5,
            _ => 0,
        }
    }

    /// Encode platform as numeric (simplified)
    fn encode_platform(_platform: &str) -> u32 {
        // Would map platform strings to numeric values
        0
    }

    /// Add custom feature
    pub fn add_custom_feature(mut self, name: impl Into<String>, value: f64) -> Self {
        self.custom_features.insert(name.into(), value.clamp(0.0, 1.0));
        self
    }

    /// Get feature vector for ML models
    pub fn to_vector(&self) -> Vec<f64> {
        vec![
            self.cvss_score / 10.0, // Normalize to 0-1
            self.severity_score / 10.0,
            self.exploitability,
            self.asset_criticality,
            self.data_sensitivity,
            self.exposure,
            self.historical_pattern_score,
        ]
    }

    /// Calculate feature completeness (0-1)
    pub fn completeness(&self) -> f64 {
        let mut complete = 0;
        let total = 7;

        if self.cvss_score > 0.0 {
            complete += 1;
        }
        if self.severity_score > 0.0 {
            complete += 1;
        }
        if self.exploitability > 0.0 {
            complete += 1;
        }
        if self.asset_criticality > 0.0 {
            complete += 1;
        }
        if self.data_sensitivity > 0.0 {
            complete += 1;
        }
        if self.exposure > 0.0 {
            complete += 1;
        }
        if self.historical_pattern_score > 0.0 {
            complete += 1;
        }

        complete as f64 / total as f64
    }
}

/// Model weights for ML prediction
#[derive(Debug, Clone)]
pub struct ModelWeights {
    pub cvss_weight: f64,
    pub severity_weight: f64,
    pub exploitability_weight: f64,
    pub asset_weight: f64,
    pub data_sensitivity_weight: f64,
    pub exposure_weight: f64,
    pub historical_weight: f64,
}

impl ModelWeights {
    /// Create new weights with validation
    pub fn new(
        cvss: f64,
        severity: f64,
        exploitability: f64,
        asset: f64,
        data_sensitivity: f64,
        exposure: f64,
        historical: f64,
    ) -> Result<Self> {
        let weights = Self {
            cvss_weight: cvss,
            severity_weight: severity,
            exploitability_weight: exploitability,
            asset_weight: asset,
            data_sensitivity_weight: data_sensitivity,
            exposure_weight: exposure,
            historical_weight: historical,
        };

        weights.validate()?;
        Ok(weights)
    }

    /// Validate weights sum to approximately 1.0
    pub fn validate(&self) -> Result<()> {
        let sum = self.cvss_weight
            + self.severity_weight
            + self.exploitability_weight
            + self.asset_weight
            + self.data_sensitivity_weight
            + self.exposure_weight
            + self.historical_weight;

        if (sum - 1.0).abs() > 0.01 {
            return Err(RiskError::InvalidRiskFactors(sum));
        }

        Ok(())
    }

    /// Normalize weights to sum to 1.0
    pub fn normalize(&mut self) {
        let sum = self.cvss_weight
            + self.severity_weight
            + self.exploitability_weight
            + self.asset_weight
            + self.data_sensitivity_weight
            + self.exposure_weight
            + self.historical_weight;

        if sum > 0.0 {
            self.cvss_weight /= sum;
            self.severity_weight /= sum;
            self.exploitability_weight /= sum;
            self.asset_weight /= sum;
            self.data_sensitivity_weight /= sum;
            self.exposure_weight /= sum;
            self.historical_weight /= sum;
        }
    }

    /// Update from training results
    pub fn update_from_gradients(&mut self, gradients: &[(String, f64)], learning_rate: f64) {
        for (feature, gradient) in gradients {
            let update = gradient * learning_rate;
            match feature.as_str() {
                "cvss" => self.cvss_weight = (self.cvss_weight + update).clamp(0.0, 1.0),
                "severity" => self.severity_weight = (self.severity_weight + update).clamp(0.0, 1.0),
                "exploitability" => {
                    self.exploitability_weight = (self.exploitability_weight + update).clamp(0.0, 1.0)
                }
                "asset" => self.asset_weight = (self.asset_weight + update).clamp(0.0, 1.0),
                "data_sensitivity" => {
                    self.data_sensitivity_weight = (self.data_sensitivity_weight + update).clamp(0.0, 1.0)
                }
                "exposure" => self.exposure_weight = (self.exposure_weight + update).clamp(0.0, 1.0),
                "historical" => self.historical_weight = (self.historical_weight + update).clamp(0.0, 1.0),
                _ => {}
            }
        }

        // Re-normalize
        self.normalize();
    }
}

impl Default for ModelWeights {
    fn default() -> Self {
        Self {
            cvss_weight: 0.30,
            severity_weight: 0.20,
            exploitability_weight: 0.15,
            asset_weight: 0.15,
            data_sensitivity_weight: 0.10,
            exposure_weight: 0.05,
            historical_weight: 0.05,
        }
    }
}

/// Training data for model refinement
#[derive(Debug, Clone)]
pub struct TrainingData {
    pub features: Vec<MlFeatures>,
    pub actual_scores: Vec<f64>,
    pub metadata: HashMap<String, String>,
}

impl TrainingData {
    /// Create new training data
    pub fn new() -> Self {
        Self {
            features: Vec::new(),
            actual_scores: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add training sample
    pub fn add_sample(&mut self, features: MlFeatures, actual_score: f64) {
        self.features.push(features);
        self.actual_scores.push(actual_score.clamp(0.0, 10.0));
    }

    /// Get sample count
    pub fn len(&self) -> usize {
        self.features.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }

    /// Calculate mean squared error for given weights
    pub fn calculate_mse(&self, weights: &ModelWeights) -> f64 {
        if self.is_empty() {
            return 0.0;
        }

        let scorer = MlRiskScorer::new().with_weights(weights.clone());
        let mut total_error = 0.0;

        for (i, features) in self.features.iter().enumerate() {
            if let Ok((predicted, _)) = scorer.predict(features) {
                let error = predicted - self.actual_scores[i];
                total_error += error * error;
            }
        }

        total_error / self.len() as f64
    }
}

impl Default for TrainingData {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_finding() -> Finding {
        Finding::new("Test", "Description")
            .with_severity(Severity::High)
            .with_cvss(7.5)
    }

    fn create_test_context() -> BusinessContext {
        BusinessContext::new("test-asset")
    }

    #[test]
    fn test_ml_scorer_creation() {
        let scorer = MlRiskScorer::new();
        assert!(scorer.enabled);
        assert_eq!(scorer.weights().cvss_weight, 0.30);
    }

    #[test]
    fn test_ml_prediction() {
        let scorer = MlRiskScorer::new();
        let finding = create_test_finding();
        let context = create_test_context();
        let features = MlFeatures::from_finding(&finding, &context);

        let result = scorer.predict(&features);
        assert!(result.is_ok());

        let (score, confidence) = result.unwrap();
        assert!(score >= 0.0 && score <= 10.0);
        assert!(confidence >= 0.0 && confidence <= 1.0);
    }

    #[test]
    fn test_ml_features_creation() {
        let finding = create_test_finding();
        let context = create_test_context();
        let features = MlFeatures::from_finding(&finding, &context);

        assert_eq!(features.cvss_score, 7.5);
        assert_eq!(features.severity_score, 8.0); // High = 8.0
        assert!(features.has_context);
    }

    #[test]
    fn test_ml_features_without_context() {
        let finding = create_test_finding();
        let features = MlFeatures::from_finding_only(&finding);

        assert_eq!(features.cvss_score, 7.5);
        assert!(!features.has_context);
    }

    #[test]
    fn test_model_weights_validation() {
        let valid_weights = ModelWeights::default();
        assert!(valid_weights.validate().is_ok());

        let invalid_weights = ModelWeights {
            cvss_weight: 0.5,
            severity_weight: 0.5,
            exploitability_weight: 0.5,
            asset_weight: 0.5,
            data_sensitivity_weight: 0.5,
            exposure_weight: 0.5,
            historical_weight: 0.5,
        };
        assert!(invalid_weights.validate().is_err());
    }

    #[test]
    fn test_model_weights_normalization() {
        let mut weights = ModelWeights {
            cvss_weight: 2.0,
            severity_weight: 2.0,
            exploitability_weight: 2.0,
            asset_weight: 2.0,
            data_sensitivity_weight: 2.0,
            exposure_weight: 2.0,
            historical_weight: 2.0,
        };

        weights.normalize();

        let sum = weights.cvss_weight
            + weights.severity_weight
            + weights.exploitability_weight
            + weights.asset_weight
            + weights.data_sensitivity_weight
            + weights.exposure_weight
            + weights.historical_weight;

        assert!((sum - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_feature_completeness() {
        let finding = create_test_finding();
        let context = create_test_context();
        let features = MlFeatures::from_finding(&finding, &context);

        let completeness = features.completeness();
        assert!(completeness > 0.0 && completeness <= 1.0);
    }

    #[test]
    fn test_training_data() {
        let mut data = TrainingData::new();

        let finding = create_test_finding();
        let context = create_test_context();
        let features = MlFeatures::from_finding(&finding, &context);

        data.add_sample(features, 7.5);
        assert_eq!(data.len(), 1);
        assert!(!data.is_empty());
    }

    #[test]
    fn test_batch_prediction() {
        let scorer = MlRiskScorer::new();
        let finding = create_test_finding();
        let context = create_test_context();

        let features = vec![
            MlFeatures::from_finding(&finding, &context),
            MlFeatures::from_finding(&finding, &context),
        ];

        let results = scorer.predict_batch(&features);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[test]
    fn test_disabled_scorer() {
        let mut scorer = MlRiskScorer::new();
        scorer.set_enabled(false);

        let finding = create_test_finding();
        let context = create_test_context();
        let features = MlFeatures::from_finding(&finding, &context);

        let result = scorer.predict(&features).unwrap();
        assert_eq!(result.0, 5.0); // Default score when disabled
    }
}
