//! State Tracking - Production Ready
//!
//! Real-time state management for assessments, phases, and skills.
//! Provides thread-safe state tracking with event broadcasting.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use sh_types::{AssessmentId, AssessmentStatus, FindingCollection, Platform};

/// Assessment state with full lifecycle tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessmentState {
    pub id: AssessmentId,
    pub name: String,
    pub status: AssessmentStateStatus,
    pub target_path: String,
    pub platform: Platform,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub progress_percent: u8,
    pub current_phase: String,
    pub phases: Vec<PhaseState>,
    pub findings_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub error: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Assessment state status enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStateStatus {
    Idle,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl Default for AssessmentStateStatus {
    fn default() -> Self {
        AssessmentStateStatus::Idle
    }
}

impl From<AssessmentStatus> for AssessmentStateStatus {
    fn from(status: AssessmentStatus) -> Self {
        match status {
            AssessmentStatus::Created => AssessmentStateStatus::Idle,
            AssessmentStatus::Queued => AssessmentStateStatus::Idle,
            AssessmentStatus::Running => AssessmentStateStatus::Running,
            AssessmentStatus::Paused => AssessmentStateStatus::Paused,
            AssessmentStatus::Completed => AssessmentStateStatus::Completed,
            AssessmentStatus::Failed => AssessmentStateStatus::Failed,
            AssessmentStatus::Cancelled => AssessmentStateStatus::Cancelled,
        }
    }
}

/// Phase state tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseState {
    pub id: String,
    pub name: String,
    pub status: PhaseStateStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub progress_percent: u8,
    pub skills: Vec<SkillState>,
    pub error: Option<String>,
}

/// Phase state status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStateStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

impl Default for PhaseStateStatus {
    fn default() -> Self {
        PhaseStateStatus::Pending
    }
}

/// Skill state tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillState {
    pub id: String,
    pub name: String,
    pub status: SkillStateStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub progress_percent: u8,
    pub findings_count: usize,
    pub error: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Skill state status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillStateStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl Default for SkillStateStatus {
    fn default() -> Self {
        SkillStateStatus::Pending
    }
}

/// State update event for real-time broadcasting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateUpdateEvent {
    pub event_type: StateUpdateType,
    pub assessment_id: AssessmentId,
    pub timestamp: DateTime<Utc>,
    pub data: StateUpdateData,
}

/// State update types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateUpdateType {
    AssessmentCreated,
    AssessmentStarted,
    AssessmentProgress,
    AssessmentCompleted,
    AssessmentFailed,
    AssessmentCancelled,
    PhaseStarted,
    PhaseProgress,
    PhaseCompleted,
    PhaseFailed,
    SkillStarted,
    SkillProgress,
    SkillCompleted,
    SkillFailed,
    FindingDiscovered,
}

/// State update data payload
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum StateUpdateData {
    AssessmentState(AssessmentState),
    PhaseState(PhaseState),
    SkillState(SkillState),
    Progress { phase: String, percent: u8 },
    FindingCount { severity: String, count: usize },
    Error { message: String },
}

/// State manager for tracking all assessments
#[derive(Debug)]
pub struct StateManager {
    /// Assessment states by ID
    assessments: Arc<DashMap<AssessmentId, AssessmentState>>,
    /// Event broadcaster for state updates
    event_tx: broadcast::Sender<StateUpdateEvent>,
    /// Global statistics
    stats: Arc<RwLock<GlobalStats>>,
}

/// Global statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalStats {
    pub total_assessments: usize,
    pub active_assessments: usize,
    pub completed_assessments: usize,
    pub failed_assessments: usize,
    pub total_findings: usize,
    pub total_phases: usize,
    pub total_skills: usize,
    pub last_updated: DateTime<Utc>,
}

impl StateManager {
    /// Create a new state manager
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(1000);
        
        Self {
            assessments: Arc::new(DashMap::new()),
            event_tx,
            stats: Arc::new(RwLock::new(GlobalStats::default())),
        }
    }

    /// Get event sender for external subscription
    pub fn event_sender(&self) -> broadcast::Sender<StateUpdateEvent> {
        self.event_tx.clone()
    }

    /// Create a new assessment state
    pub async fn create_assessment(
        &self,
        id: AssessmentId,
        name: impl Into<String>,
        target_path: impl Into<String>,
        platform: Platform,
    ) -> AssessmentState {
        let state = AssessmentState {
            id,
            name: name.into(),
            status: AssessmentStateStatus::Idle,
            target_path: target_path.into(),
            platform,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            progress_percent: 0,
            current_phase: "initialized".to_string(),
            phases: Vec::new(),
            findings_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            info_count: 0,
            error: None,
            metadata: HashMap::new(),
        };

        self.assessments.insert(id, state.clone());
        self.update_stats().await;

        let event = StateUpdateEvent {
            event_type: StateUpdateType::AssessmentCreated,
            assessment_id: id,
            timestamp: Utc::now(),
            data: StateUpdateData::AssessmentState(state.clone()),
        };
        let _ = self.event_tx.send(event);

        info!("Created assessment state: {}", id);
        state
    }

    /// Start an assessment
    pub async fn start_assessment(&self, id: AssessmentId) -> Option<AssessmentState> {
        if let Some(mut state) = self.assessments.get_mut(&id) {
            state.status = AssessmentStateStatus::Running;
            state.started_at = Some(Utc::now());
            state.current_phase = "starting".to_string();
            
            let event = StateUpdateEvent {
                event_type: StateUpdateType::AssessmentStarted,
                assessment_id: id,
                timestamp: Utc::now(),
                data: StateUpdateData::AssessmentState(state.clone()),
            };
            let _ = self.event_tx.send(event);
            
            self.update_stats().await;
            info!("Started assessment: {}", id);
            return Some(state.clone());
        }
        None
    }

    /// Update assessment progress
    pub async fn update_assessment_progress(
        &self,
        id: AssessmentId,
        phase: impl Into<String>,
        percent: u8,
    ) -> Option<AssessmentState> {
        if let Some(mut state) = self.assessments.get_mut(&id) {
            state.current_phase = phase.into();
            state.progress_percent = percent.min(100);
            
            let event = StateUpdateEvent {
                event_type: StateUpdateType::AssessmentProgress,
                assessment_id: id,
                timestamp: Utc::now(),
                data: StateUpdateData::Progress {
                    phase: state.current_phase.clone(),
                    percent: state.progress_percent,
                },
            };
            let _ = self.event_tx.send(event);
            
            return Some(state.clone());
        }
        None
    }

    /// Complete an assessment
    pub async fn complete_assessment(
        &self,
        id: AssessmentId,
        findings: &FindingCollection,
    ) -> Option<AssessmentState> {
        if let Some(mut state) = self.assessments.get_mut(&id) {
            state.status = AssessmentStateStatus::Completed;
            state.completed_at = Some(Utc::now());
            state.progress_percent = 100;
            state.findings_count = findings.total_count;
            state.critical_count = findings.critical().len();
            state.high_count = findings.high().len();
            state.medium_count = findings.medium().len();
            state.low_count = findings.low().len();
            state.info_count = findings.info().len();
            
            let event = StateUpdateEvent {
                event_type: StateUpdateType::AssessmentCompleted,
                assessment_id: id,
                timestamp: Utc::now(),
                data: StateUpdateData::AssessmentState(state.clone()),
            };
            let _ = self.event_tx.send(event);
            
            self.update_stats().await;
            info!("Completed assessment: {} with {} findings", id, findings.total_count);
            return Some(state.clone());
        }
        None
    }

    /// Fail an assessment
    pub async fn fail_assessment(&self, id: AssessmentId, error: impl Into<String>) -> Option<AssessmentState> {
        if let Some(mut state) = self.assessments.get_mut(&id) {
            state.status = AssessmentStateStatus::Failed;
            state.error = Some(error.into());
            state.completed_at = Some(Utc::now());
            
            let event = StateUpdateEvent {
                event_type: StateUpdateType::AssessmentFailed,
                assessment_id: id,
                timestamp: Utc::now(),
                data: StateUpdateData::Error { message: state.error.clone().unwrap_or_default() },
            };
            let _ = self.event_tx.send(event);
            
            self.update_stats().await;
            warn!("Failed assessment: {}", id);
            return Some(state.clone());
        }
        None
    }

    /// Add a phase to an assessment
    pub async fn add_phase(
        &self,
        assessment_id: AssessmentId,
        phase_id: impl Into<String>,
        name: impl Into<String>,
    ) -> Option<PhaseState> {
        let phase = PhaseState {
            id: phase_id.into(),
            name: name.into(),
            status: PhaseStateStatus::Pending,
            started_at: None,
            completed_at: None,
            progress_percent: 0,
            skills: Vec::new(),
            error: None,
        };

        if let Some(mut state) = self.assessments.get_mut(&assessment_id) {
            state.phases.push(phase.clone());
            return Some(phase);
        }
        None
    }

    /// Start a phase
    pub async fn start_phase(
        &self,
        assessment_id: AssessmentId,
        phase_id: impl AsRef<str>,
    ) -> Option<PhaseState> {
        if let Some(mut state) = self.assessments.get_mut(&assessment_id) {
            if let Some(phase) = state.phases.iter_mut().find(|p| p.id == phase_id.as_ref()) {
                phase.status = PhaseStateStatus::Running;
                phase.started_at = Some(Utc::now());
                state.current_phase = phase.name.clone();
                
                let event = StateUpdateEvent {
                    event_type: StateUpdateType::PhaseStarted,
                    assessment_id,
                    timestamp: Utc::now(),
                    data: StateUpdateData::PhaseState(phase.clone()),
                };
                let _ = self.event_tx.send(event);
                
                return Some(phase.clone());
            }
        }
        None
    }

    /// Update phase progress
    pub async fn update_phase_progress(
        &self,
        assessment_id: AssessmentId,
        phase_id: impl AsRef<str>,
        percent: u8,
    ) -> Option<PhaseState> {
        if let Some(mut state) = self.assessments.get_mut(&assessment_id) {
            if let Some(phase) = state.phases.iter_mut().find(|p| p.id == phase_id.as_ref()) {
                phase.progress_percent = percent.min(100);
                
                // Update overall assessment progress based on phases
                let total_progress: u8 = state.phases.iter().map(|p| p.progress_percent).sum::<u8>()
                    / state.phases.len().max(1) as u8;
                state.progress_percent = total_progress;
                
                let event = StateUpdateEvent {
                    event_type: StateUpdateType::PhaseProgress,
                    assessment_id,
                    timestamp: Utc::now(),
                    data: StateUpdateData::PhaseState(phase.clone()),
                };
                let _ = self.event_tx.send(event);
                
                return Some(phase.clone());
            }
        }
        None
    }

    /// Complete a phase
    pub async fn complete_phase(
        &self,
        assessment_id: AssessmentId,
        phase_id: impl AsRef<str>,
    ) -> Option<PhaseState> {
        if let Some(mut state) = self.assessments.get_mut(&assessment_id) {
            if let Some(phase) = state.phases.iter_mut().find(|p| p.id == phase_id.as_ref()) {
                phase.status = PhaseStateStatus::Completed;
                phase.completed_at = Some(Utc::now());
                phase.progress_percent = 100;
                
                let event = StateUpdateEvent {
                    event_type: StateUpdateType::PhaseCompleted,
                    assessment_id,
                    timestamp: Utc::now(),
                    data: StateUpdateData::PhaseState(phase.clone()),
                };
                let _ = self.event_tx.send(event);
                
                return Some(phase.clone());
            }
        }
        None
    }

    /// Add a skill to a phase
    pub async fn add_skill(
        &self,
        assessment_id: AssessmentId,
        phase_id: impl AsRef<str>,
        skill_id: impl Into<String>,
        name: impl Into<String>,
    ) -> Option<SkillState> {
        let skill = SkillState {
            id: skill_id.into(),
            name: name.into(),
            status: SkillStateStatus::Pending,
            started_at: None,
            completed_at: None,
            progress_percent: 0,
            findings_count: 0,
            error: None,
            metadata: HashMap::new(),
        };

        if let Some(mut state) = self.assessments.get_mut(&assessment_id) {
            if let Some(phase) = state.phases.iter_mut().find(|p| p.id == phase_id.as_ref()) {
                phase.skills.push(skill.clone());
                return Some(skill);
            }
        }
        None
    }

    /// Start a skill
    pub async fn start_skill(
        &self,
        assessment_id: AssessmentId,
        phase_id: impl AsRef<str>,
        skill_id: impl AsRef<str>,
    ) -> Option<SkillState> {
        if let Some(mut state) = self.assessments.get_mut(&assessment_id) {
            if let Some(phase) = state.phases.iter_mut().find(|p| p.id == phase_id.as_ref()) {
                if let Some(skill) = phase.skills.iter_mut().find(|s| s.id == skill_id.as_ref()) {
                    skill.status = SkillStateStatus::Running;
                    skill.started_at = Some(Utc::now());
                    
                    let event = StateUpdateEvent {
                        event_type: StateUpdateType::SkillStarted,
                        assessment_id,
                        timestamp: Utc::now(),
                        data: StateUpdateData::SkillState(skill.clone()),
                    };
                    let _ = self.event_tx.send(event);
                    
                    return Some(skill.clone());
                }
            }
        }
        None
    }

    /// Update skill progress (0-100%)
    pub async fn update_skill_progress(
        &self,
        assessment_id: AssessmentId,
        phase_id: impl AsRef<str>,
        skill_id: impl AsRef<str>,
        percent: u8,
    ) -> Option<SkillState> {
        if let Some(mut state) = self.assessments.get_mut(&assessment_id) {
            if let Some(phase) = state.phases.iter_mut().find(|p| p.id == phase_id.as_ref()) {
                if let Some(skill) = phase.skills.iter_mut().find(|s| s.id == skill_id.as_ref()) {
                    skill.progress_percent = percent.min(100);
                    
                    let event = StateUpdateEvent {
                        event_type: StateUpdateType::SkillProgress,
                        assessment_id,
                        timestamp: Utc::now(),
                        data: StateUpdateData::SkillState(skill.clone()),
                    };
                    let _ = self.event_tx.send(event);
                    
                    return Some(skill.clone());
                }
            }
        }
        None
    }

    /// Complete a skill
    pub async fn complete_skill(
        &self,
        assessment_id: AssessmentId,
        phase_id: impl AsRef<str>,
        skill_id: impl AsRef<str>,
        findings_count: usize,
    ) -> Option<SkillState> {
        if let Some(mut state) = self.assessments.get_mut(&assessment_id) {
            if let Some(phase) = state.phases.iter_mut().find(|p| p.id == phase_id.as_ref()) {
                if let Some(skill) = phase.skills.iter_mut().find(|s| s.id == skill_id.as_ref()) {
                    skill.status = SkillStateStatus::Completed;
                    skill.completed_at = Some(Utc::now());
                    skill.progress_percent = 100;
                    skill.findings_count = findings_count;
                    
                    let event = StateUpdateEvent {
                        event_type: StateUpdateType::SkillCompleted,
                        assessment_id,
                        timestamp: Utc::now(),
                        data: StateUpdateData::SkillState(skill.clone()),
                    };
                    let _ = self.event_tx.send(event);
                    
                    return Some(skill.clone());
                }
            }
        }
        None
    }

    /// Fail a skill
    pub async fn fail_skill(
        &self,
        assessment_id: AssessmentId,
        phase_id: impl AsRef<str>,
        skill_id: impl AsRef<str>,
        error: impl Into<String>,
    ) -> Option<SkillState> {
        if let Some(mut state) = self.assessments.get_mut(&assessment_id) {
            if let Some(phase) = state.phases.iter_mut().find(|p| p.id == phase_id.as_ref()) {
                if let Some(skill) = phase.skills.iter_mut().find(|s| s.id == skill_id.as_ref()) {
                    skill.status = SkillStateStatus::Failed;
                    skill.error = Some(error.into());
                    
                    let event = StateUpdateEvent {
                        event_type: StateUpdateType::SkillFailed,
                        assessment_id,
                        timestamp: Utc::now(),
                        data: StateUpdateData::SkillState(skill.clone()),
                    };
                    let _ = self.event_tx.send(event);
                    
                    return Some(skill.clone());
                }
            }
        }
        None
    }

    /// Get assessment state
    pub fn get_assessment(&self, id: AssessmentId) -> Option<AssessmentState> {
        self.assessments.get(&id).map(|s| s.clone())
    }

    /// Get all assessments
    pub fn get_all_assessments(&self) -> Vec<AssessmentState> {
        self.assessments.iter().map(|s| s.clone()).collect()
    }

    /// Get assessments by status
    pub fn get_assessments_by_status(&self, status: AssessmentStateStatus) -> Vec<AssessmentState> {
        self.assessments
            .iter()
            .filter(|s| s.status == status)
            .map(|s| s.clone())
            .collect()
    }

    /// Get global statistics
    pub async fn get_stats(&self) -> GlobalStats {
        self.stats.read().await.clone()
    }

    /// Update global statistics
    async fn update_stats(&self) {
        let mut stats = self.stats.write().await;
        stats.total_assessments = self.assessments.len();
        stats.active_assessments = self
            .assessments
            .iter()
            .filter(|s| s.status == AssessmentStateStatus::Running)
            .count();
        stats.completed_assessments = self
            .assessments
            .iter()
            .filter(|s| s.status == AssessmentStateStatus::Completed)
            .count();
        stats.failed_assessments = self
            .assessments
            .iter()
            .filter(|s| s.status == AssessmentStateStatus::Failed)
            .count();
        stats.total_findings = self
            .assessments
            .iter()
            .map(|s| s.findings_count)
            .sum();
        stats.total_phases = self
            .assessments
            .iter()
            .map(|s| s.phases.len())
            .sum();
        stats.total_skills = self
            .assessments
            .iter()
            .map(|s| s.phases.iter().map(|p| p.skills.len()).sum::<usize>())
            .sum();
        stats.last_updated = Utc::now();
    }

    /// Remove an assessment
    pub async fn remove_assessment(&self, id: AssessmentId) -> Option<AssessmentState> {
        let removed = self.assessments.remove(&id).map(|(_, v)| v);
        if removed.is_some() {
            self.update_stats().await;
        }
        removed
    }

    /// Clear all assessments
    pub async fn clear_all(&self) {
        self.assessments.clear();
        self.update_stats().await;
        info!("Cleared all assessment states");
    }
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_assessment_lifecycle() {
        let manager = StateManager::new();
        let id = Uuid::new_v4();

        // Create
        let state = manager.create_assessment(id, "Test", "/test", Platform::Android).await;
        assert_eq!(state.status, AssessmentStateStatus::Idle);
        assert_eq!(state.progress_percent, 0);

        // Start
        let state = manager.start_assessment(id).await.unwrap();
        assert_eq!(state.status, AssessmentStateStatus::Running);
        assert!(state.started_at.is_some());

        // Complete
        let findings = FindingCollection::default();
        let state = manager.complete_assessment(id, &findings).await.unwrap();
        assert_eq!(state.status, AssessmentStateStatus::Completed);
        assert_eq!(state.progress_percent, 100);
        assert!(state.completed_at.is_some());
    }

    #[tokio::test]
    async fn test_phase_tracking() {
        let manager = StateManager::new();
        let id = Uuid::new_v4();

        manager.create_assessment(id, "Test", "/test", Platform::Android).await;
        
        // Add phase
        let phase = manager.add_phase(id, "phase1", "Analysis").await.unwrap();
        assert_eq!(phase.status, PhaseStateStatus::Pending);

        // Start phase
        let phase = manager.start_phase(id, "phase1").await.unwrap();
        assert_eq!(phase.status, PhaseStateStatus::Running);

        // Complete phase
        let phase = manager.complete_phase(id, "phase1").await.unwrap();
        assert_eq!(phase.status, PhaseStateStatus::Completed);
        assert_eq!(phase.progress_percent, 100);
    }

    #[tokio::test]
    async fn test_skill_progress() {
        let manager = StateManager::new();
        let id = Uuid::new_v4();

        manager.create_assessment(id, "Test", "/test", Platform::Android).await;
        manager.add_phase(id, "phase1", "Analysis").await;
        manager.add_skill(id, "phase1", "skill1", "Static Analysis").await;

        // Start skill
        let skill = manager.start_skill(id, "phase1", "skill1").await.unwrap();
        assert_eq!(skill.status, SkillStateStatus::Running);

        // Update progress
        let skill = manager.update_skill_progress(id, "phase1", "skill1", 50).await.unwrap();
        assert_eq!(skill.progress_percent, 50);

        // Complete skill
        let skill = manager.complete_skill(id, "phase1", "skill1", 5).await.unwrap();
        assert_eq!(skill.status, SkillStateStatus::Completed);
        assert_eq!(skill.progress_percent, 100);
        assert_eq!(skill.findings_count, 5);
    }

    #[tokio::test]
    async fn test_global_stats() {
        let manager = StateManager::new();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        manager.create_assessment(id1, "Test1", "/test1", Platform::Android).await;
        manager.create_assessment(id2, "Test2", "/test2", Platform::Ios).await;

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_assessments, 2);
    }

    #[tokio::test]
    async fn test_state_events() {
        let manager = StateManager::new();
        let mut rx = manager.event_sender().subscribe();
        let id = Uuid::new_v4();

        manager.create_assessment(id, "Test", "/test", Platform::Android).await;

        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_type, StateUpdateType::AssessmentCreated);
        assert_eq!(event.assessment_id, id);
    }
}
