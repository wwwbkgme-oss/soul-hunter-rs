//! Agent Manager - Production Ready
//! 
//! Manages security analysis agents with hierarchical team structure
//! Based on newbie-rs agent orchestration and tracker-brain-rs agent patterns

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use dashmap::DashMap;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use sh_types::prelude::*;
use sh_types::{Agent, AgentCapability, AgentConfig, AgentId, AgentPriority, AgentStatus, AgentTeam, AgentTask, AgentType, AnalysisTarget, FindingCollection, Platform};

use crate::CoreError;

/// Agent manager for orchestrating security agents
pub struct AgentManager {
    agents: Arc<DashMap<AgentId, Agent>>,
    teams: Arc<RwLock<HashMap<Uuid, AgentTeam>>>,
    tasks: Arc<DashMap<Uuid, AgentTask>>,
    max_workers: usize,
}

impl AgentManager {
    pub fn new(max_workers: usize) -> Self {
        Self {
            agents: Arc::new(DashMap::new()),
            teams: Arc::new(RwLock::new(HashMap::new())),
            tasks: Arc::new(DashMap::new()),
            max_workers,
        }
    }

    /// Register a new agent
    pub async fn register_agent(&self, agent: Agent) -> std::result::Result<(), CoreError> {
        let id = agent.id;
        self.agents.insert(id, agent);
        info!("Registered agent {} (type: {:?})", id, self.agents.get(&id).unwrap().agent_type);
        Ok(())
    }

    /// Deregister an agent
    pub async fn deregister_agent(&self, id: &AgentId) -> std::result::Result<(), CoreError> {
        self.agents.remove(id);
        info!("Deregistered agent {}", id);
        Ok(())
    }

    /// Get agent by ID
    pub fn get_agent(&self, id: &AgentId) -> Option<Agent> {
        self.agents.get(id).map(|a| a.clone())
    }

    /// Update agent status
    pub fn update_agent_status(&self, id: &AgentId, status: AgentStatus) -> std::result::Result<(), CoreError> {
        if let Some(mut agent) = self.agents.get_mut(id) {
            agent.status = status;
            agent.update_heartbeat();
            debug!("Updated agent {} status to {:?}", id, status);
            Ok(())
        } else {
            Err(CoreError::AgentNotFound(id.to_string()))
        }
    }

    /// Find available agent for task
    pub fn find_available_agent(&self, capability: AgentCapability) -> Option<Agent> {
        self.agents.iter()
            .filter(|a| a.is_available() && a.can_handle(&capability))
            .max_by_key(|a| a.config.priority)
            .map(|a| a.clone())
    }

    /// List all agents
    pub fn list_agents(&self) -> Vec<Agent> {
        self.agents.iter().map(|a| a.clone()).collect()
    }

    /// List agents by type
    pub fn list_agents_by_type(&self, agent_type: AgentType) -> Vec<Agent> {
        self.agents.iter()
            .filter(|a| a.agent_type == agent_type)
            .map(|a| a.clone())
            .collect()
    }

    /// List available agents
    pub fn list_available_agents(&self) -> Vec<Agent> {
        self.agents.iter()
            .filter(|a| a.is_available())
            .map(|a| a.clone())
            .collect()
    }

    /// Create agent team
    pub async fn create_team(&self, team: AgentTeam) -> std::result::Result<(), CoreError> {
        let id = team.id;
        self.teams.write().await.insert(id, team);
        info!("Created agent team {}", id);
        Ok(())
    }

    /// Get team by ID
    pub async fn get_team(&self, id: &Uuid) -> Option<AgentTeam> {
        self.teams.read().await.get(id).cloned()
    }

    /// List all teams
    pub async fn list_teams(&self) -> Vec<AgentTeam> {
        self.teams.read().await.values().cloned().collect()
    }

    /// Assign task to agent
    pub async fn assign_task(&self, agent_id: AgentId, target: AnalysisTarget, task_type: impl Into<String>) -> std::result::Result<Uuid, CoreError> {
        let task_id = Uuid::new_v4();
        
        // Update agent status
        if let Some(mut agent) = self.agents.get_mut(&agent_id) {
            agent.assign_job(task_id);
        } else {
            return Err(CoreError::AgentNotFound(agent_id.to_string()));
        }

        // Create task
        let task = AgentTask::new(agent_id, task_id, target, task_type);
        self.tasks.insert(task.id, task);
        
        info!("Assigned task {} to agent {}", task_id, agent_id);
        Ok(task_id)
    }

    /// Complete task
    pub async fn complete_task(&self, task_id: &Uuid, result: FindingCollection) -> std::result::Result<(), CoreError> {
        if let Some(mut task) = self.tasks.get_mut(task_id) {
            task.mark_completed(result);
            
            // Update agent
            if let Some(mut agent) = self.agents.get_mut(&task.agent_id) {
                agent.complete_job();
            }
            
            info!("Completed task {}", task_id);
            Ok(())
        } else {
            Err(CoreError::AssessmentFailed(format!("Task not found: {}", task_id)))
        }
    }

    /// Fail task
    pub async fn fail_task(&self, task_id: &Uuid, error: impl Into<String>) -> std::result::Result<(), CoreError> {
        if let Some(mut task) = self.tasks.get_mut(task_id) {
            task.mark_failed(error);
            
            // Update agent
            if let Some(mut agent) = self.agents.get_mut(&task.agent_id) {
                agent.status = AgentStatus::Error;
            }
            
            warn!("Task {} failed", task_id);
            Ok(())
        } else {
            Err(CoreError::AssessmentFailed(format!("Task not found: {}", task_id)))
        }
    }

    /// Get task by ID
    pub fn get_task(&self, id: &Uuid) -> Option<AgentTask> {
        self.tasks.get(id).map(|t| t.clone())
    }

    /// List tasks for agent
    pub fn list_agent_tasks(&self, agent_id: &AgentId) -> Vec<AgentTask> {
        self.tasks.iter()
            .filter(|t| t.agent_id == *agent_id)
            .map(|t| t.clone())
            .collect()
    }

    /// Get agent count
    pub fn agent_count(&self) -> usize {
        self.agents.len()
    }

    /// Get active task count
    pub fn active_task_count(&self) -> usize {
        self.tasks.iter()
            .filter(|t| matches!(t.status, sh_types::TaskStatus::Running | sh_types::TaskStatus::Pending))
            .count()
    }

    /// Cleanup stale agents
    pub async fn cleanup_stale_agents(&self, max_age_secs: i64) -> usize {
        let cutoff = Utc::now() - chrono::Duration::seconds(max_age_secs);
        let mut removed = 0;
        
        self.agents.retain(|id, agent| {
            let should_retain = agent.last_heartbeat
                .map(|hb| hb > cutoff)
                .unwrap_or(true);
            
            if !should_retain {
                removed += 1;
                warn!("Removed stale agent {}", id);
            }
            should_retain
        });
        
        removed
    }
}

impl Default for AgentManager {
    fn default() -> Self {
        Self::new(8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_agent(name: &str, agent_type: AgentType) -> Agent {
        Agent::new(name, agent_type)
            .add_capability(AgentCapability::StaticAnalysis)
    }

    #[tokio::test]
    async fn test_agent_registration() {
        let manager = AgentManager::new(8);
        let agent = create_test_agent("Test Agent", AgentType::Static);
        let id = agent.id;
        
        manager.register_agent(agent).await.unwrap();
        assert_eq!(manager.agent_count(), 1);
        
        let retrieved = manager.get_agent(&id).unwrap();
        assert_eq!(retrieved.name, "Test Agent");
    }

    #[tokio::test]
    async fn test_agent_availability() {
        let manager = AgentManager::new(8);
        let agent = create_test_agent("Available Agent", AgentType::Static);
        let id = agent.id;
        
        manager.register_agent(agent).await.unwrap();
        
        let available = manager.find_available_agent(AgentCapability::StaticAnalysis);
        assert!(available.is_some());
        assert_eq!(available.unwrap().id, id);
    }

    #[tokio::test]
    async fn test_team_management() {
        let manager = AgentManager::new(8);
        let team = AgentTeam::new("Security Team")
            .with_description("Core security analysis team");
        
        manager.create_team(team.clone()).await.unwrap();
        
        let teams = manager.list_teams().await;
        assert_eq!(teams.len(), 1);
        assert_eq!(teams[0].name, "Security Team");
    }

    #[tokio::test]
    async fn test_task_lifecycle() {
        let manager = AgentManager::new(8);
        let agent = create_test_agent("Task Agent", AgentType::Static);
        let agent_id = agent.id;
        
        manager.register_agent(agent).await.unwrap();
        
        let target = AnalysisTarget::new("/test/app.apk", Platform::Android);
        let task_id = manager.assign_task(agent_id, target, "static_analysis").await.unwrap();
        
        let task = manager.get_task(&task_id).unwrap();
        assert_eq!(task.agent_id, agent_id);
        
        let findings = FindingCollection::default();
        manager.complete_task(&task_id, findings).await.unwrap();
    }
}
