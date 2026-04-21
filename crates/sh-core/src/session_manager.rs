//! Session Manager - Production Ready
//! 
//! Manages assessment sessions with persistence and lifecycle tracking
//! Based on zero-hero-rs session management

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use sh_types::prelude::*;
use sh_types::{Assessment, AssessmentConfig, AssessmentId, AssessmentStatus, FindingCollection, Platform};

use crate::CoreError;

/// Assessment session with runtime state
#[derive(Debug, Clone)]
pub struct AssessmentSession {
    pub assessment: Assessment,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub job_ids: Vec<Uuid>,
    pub current_phase: String,
    pub progress_percent: u8,
}

impl AssessmentSession {
    pub fn new(assessment: Assessment) -> Self {
        let now = Utc::now();
        Self {
            assessment,
            created_at: now,
            updated_at: now,
            job_ids: Vec::new(),
            current_phase: "created".to_string(),
            progress_percent: 0,
        }
    }

    pub fn update_progress(&mut self, phase: impl Into<String>, percent: u8) {
        self.current_phase = phase.into();
        self.progress_percent = percent.min(100);
        self.updated_at = Utc::now();
    }

    pub fn add_job(&mut self, job_id: Uuid) {
        self.job_ids.push(job_id);
        self.updated_at = Utc::now();
    }

    pub fn is_active(&self) -> bool {
        matches!(self.assessment.status, AssessmentStatus::Created | AssessmentStatus::Running)
    }
}

/// Session manager for tracking assessments
pub struct SessionManager {
    sessions: Arc<DashMap<AssessmentId, AssessmentSession>>,
    assessments: Arc<RwLock<HashMap<AssessmentId, Assessment>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            assessments: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create new session
    pub async fn create_session(&self, id: AssessmentId, assessment: Assessment) -> std::result::Result<(), CoreError> {
        let session = AssessmentSession::new(assessment.clone());
        
        self.sessions.insert(id, session);
        self.assessments.write().await.insert(id, assessment);
        
        debug!("Created session {}", id);
        Ok(())
    }

    /// Get session by ID
    pub fn get_session(&self, id: &AssessmentId) -> Option<AssessmentSession> {
        self.sessions.get(id).map(|s| s.clone())
    }

    /// Get assessment by ID
    pub async fn get_assessment(&self, id: &AssessmentId) -> Option<Assessment> {
        self.assessments.read().await.get(id).cloned()
    }

    /// Update assessment
    pub async fn update_assessment(&self, id: &AssessmentId, assessment: Assessment) -> std::result::Result<(), CoreError> {
        if let Some(mut session) = self.sessions.get_mut(id) {
            session.assessment = assessment.clone();
            session.updated_at = Utc::now();
        }
        
        self.assessments.write().await.insert(*id, assessment);
        Ok(())
    }

    /// Update session progress
    pub fn update_progress(&self, id: &AssessmentId, phase: impl Into<String>, percent: u8) -> std::result::Result<(), CoreError> {
        if let Some(mut session) = self.sessions.get_mut(id) {
            session.update_progress(phase, percent);
            Ok(())
        } else {
            Err(CoreError::SessionNotFound(id.to_string()))
        }
    }

    /// Add job to session
    pub fn add_job(&self, id: &AssessmentId, job_id: Uuid) -> std::result::Result<(), CoreError> {
        if let Some(mut session) = self.sessions.get_mut(id) {
            session.add_job(job_id);
            Ok(())
        } else {
            Err(CoreError::SessionNotFound(id.to_string()))
        }
    }

    /// Cancel session
    pub async fn cancel_session(&self, id: &AssessmentId) -> std::result::Result<(), CoreError> {
        if let Some(mut session) = self.sessions.get_mut(id) {
            session.assessment.status = AssessmentStatus::Cancelled;
            session.updated_at = Utc::now();
            
            self.assessments.write().await.insert(*id, session.assessment.clone());
            info!("Cancelled session {}", id);
            Ok(())
        } else {
            Err(CoreError::SessionNotFound(id.to_string()))
        }
    }

    /// Remove session
    pub fn remove_session(&self, id: &AssessmentId) -> std::result::Result<(), CoreError> {
        self.sessions.remove(id);
        Ok(())
    }

    /// List all sessions
    pub fn list_sessions(&self) -> Vec<AssessmentSession> {
        self.sessions.iter().map(|s| s.clone()).collect()
    }

    /// List all assessments
    pub async fn list_assessments(&self) -> Vec<Assessment> {
        self.assessments.read().await.values().cloned().collect()
    }

    /// Get active sessions
    pub fn get_active_sessions(&self) -> Vec<AssessmentSession> {
        self.sessions
            .iter()
            .filter(|s| s.is_active())
            .map(|s| s.clone())
            .collect()
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get active session count
    pub fn active_session_count(&self) -> usize {
        self.get_active_sessions().len()
    }

    /// Cleanup completed sessions
    pub fn cleanup_completed(&self, max_age_hours: i64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::hours(max_age_hours);
        let mut removed = 0;
        
        self.sessions.retain(|id, session| {
            let should_retain = session.is_active() || session.updated_at > cutoff;
            if !should_retain {
                removed += 1;
                debug!("Cleaned up session {}", id);
            }
            should_retain
        });
        
        removed
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_manager() {
        let manager = SessionManager::new();
        let id = Uuid::new_v4();
        
        let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
        let assessment = Assessment::new("Test", target);
        
        manager.create_session(id, assessment.clone()).await.unwrap();
        assert_eq!(manager.session_count(), 1);
        
        let session = manager.get_session(&id).unwrap();
        assert!(session.is_active());
        
        manager.update_progress(&id, "analysis", 50).unwrap();
        
        let session = manager.get_session(&id).unwrap();
        assert_eq!(session.progress_percent, 50);
        assert_eq!(session.current_phase, "analysis");
    }

    #[tokio::test]
    async fn test_session_cleanup() {
        let manager = SessionManager::new();
        
        // Create a session
        let id = Uuid::new_v4();
        let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
        let assessment = Assessment::new("Test", target);
        
        manager.create_session(id, assessment).await.unwrap();
        
        // Cleanup with 0 hours should remove all
        let removed = manager.cleanup_completed(0);
        assert_eq!(removed, 1);
        assert_eq!(manager.session_count(), 0);
    }
}
