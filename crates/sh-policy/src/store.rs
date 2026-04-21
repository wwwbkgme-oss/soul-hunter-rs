//! Policy storage and management

use crate::error::{PolicyError, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sh_types::{Policy, PolicyId, PolicySet, PolicyType};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// In-memory policy store with persistence support
#[derive(Debug, Clone)]
pub struct PolicyStore {
    policies: Arc<DashMap<PolicyId, StoredPolicy>>,
    policy_sets: Arc<DashMap<Uuid, PolicySet>>,
}

/// Stored policy with metadata
#[derive(Debug, Clone)]
struct StoredPolicy {
    policy: Policy,
    compiled: bool,
    compiled_at: Option<DateTime<Utc>>,
    compile_error: Option<String>,
    evaluation_count: u64,
    last_evaluated: Option<DateTime<Utc>>,
}

impl StoredPolicy {
    fn new(policy: Policy) -> Self {
        Self {
            policy,
            compiled: false,
            compiled_at: None,
            compile_error: None,
            evaluation_count: 0,
            last_evaluated: None,
        }
    }
}

impl PolicyStore {
    /// Create a new policy store
    pub fn new() -> Self {
        Self {
            policies: Arc::new(DashMap::new()),
            policy_sets: Arc::new(DashMap::new()),
        }
    }

    /// Store a policy
    pub fn store(&self, policy: Policy) -> Result<()> {
        let id = policy.id;
        let stored = StoredPolicy::new(policy);

        self.policies.insert(id, stored);
        info!(policy_id = %id, "Policy stored successfully");

        Ok(())
    }

    /// Get a policy by ID
    pub fn get(&self, id: PolicyId) -> Result<Option<Policy>> {
        match self.policies.get(&id) {
            Some(entry) => Ok(Some(entry.policy.clone())),
            None => Ok(None),
        }
    }

    /// Get all policies
    pub fn get_all(&self) -> Vec<Policy> {
        self.policies
            .iter()
            .map(|entry| entry.policy.clone())
            .collect()
    }

    /// Get policies by type
    pub fn get_by_type(&self, policy_type: PolicyType) -> Vec<Policy> {
        self.policies
            .iter()
            .filter(|entry| entry.policy.policy_type == policy_type)
            .map(|entry| entry.policy.clone())
            .collect()
    }

    /// Get enabled policies
    pub fn get_enabled(&self) -> Vec<Policy> {
        self.policies
            .iter()
            .filter(|entry| entry.policy.enabled)
            .map(|entry| entry.policy.clone())
            .collect()
    }

    /// Update a policy
    pub fn update(&self, id: PolicyId, policy: Policy) -> Result<()> {
        if !self.policies.contains_key(&id) {
            return Err(PolicyError::PolicyNotFound(id.to_string()));
        }

        let mut stored = StoredPolicy::new(policy);
        stored.compiled = false; // Reset compiled status on update
        stored.compiled_at = None;
        stored.compile_error = None;

        self.policies.insert(id, stored);
        info!(policy_id = %id, "Policy updated successfully");

        Ok(())
    }

    /// Delete a policy
    pub fn delete(&self, id: PolicyId) -> Result<bool> {
        match self.policies.remove(&id) {
            Some(_) => {
                info!(policy_id = %id, "Policy deleted successfully");
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Mark policy as compiled
    pub fn mark_compiled(&self, id: PolicyId, success: bool, error: Option<String>) -> Result<()> {
        match self.policies.get_mut(&id) {
            Some(mut entry) => {
                entry.compiled = success;
                entry.compiled_at = Some(Utc::now());
                entry.compile_error = error;
                debug!(policy_id = %id, compiled = success, "Policy compilation status updated");
                Ok(())
            }
            None => Err(PolicyError::PolicyNotFound(id.to_string())),
        }
    }

    /// Check if policy is compiled
    pub fn is_compiled(&self, id: PolicyId) -> Result<bool> {
        match self.policies.get(&id) {
            Some(entry) => Ok(entry.compiled),
            None => Err(PolicyError::PolicyNotFound(id.to_string())),
        }
    }

    /// Record policy evaluation
    pub fn record_evaluation(&self, id: PolicyId) -> Result<()> {
        match self.policies.get_mut(&id) {
            Some(mut entry) => {
                entry.evaluation_count += 1;
                entry.last_evaluated = Some(Utc::now());
                Ok(())
            }
            None => Err(PolicyError::PolicyNotFound(id.to_string())),
        }
    }

    /// Get policy statistics
    pub fn get_stats(&self, id: PolicyId) -> Result<Option<PolicyStats>> {
        match self.policies.get(&id) {
            Some(entry) => Ok(Some(PolicyStats {
                evaluation_count: entry.evaluation_count,
                compiled: entry.compiled,
                compiled_at: entry.compiled_at,
                last_evaluated: entry.last_evaluated,
                compile_error: entry.compile_error.clone(),
            })),
            None => Ok(None),
        }
    }

    /// Store a policy set
    pub fn store_policy_set(&self, policy_set: PolicySet) -> Result<()> {
        let id = policy_set.id;
        self.policy_sets.insert(id, policy_set);
        info!(policy_set_id = %id, "Policy set stored successfully");
        Ok(())
    }

    /// Get a policy set by ID
    pub fn get_policy_set(&self, id: Uuid) -> Result<Option<PolicySet>> {
        match self.policy_sets.get(&id) {
            Some(entry) => Ok(Some(entry.clone())),
            None => Ok(None),
        }
    }

    /// Get all policy sets
    pub fn get_all_policy_sets(&self) -> Vec<PolicySet> {
        self.policy_sets
            .iter()
            .map(|entry| entry.clone())
            .collect()
    }

    /// Delete a policy set
    pub fn delete_policy_set(&self, id: Uuid) -> Result<bool> {
        match self.policy_sets.remove(&id) {
            Some(_) => {
                info!(policy_set_id = %id, "Policy set deleted successfully");
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Get policies in a set
    pub fn get_policy_set_policies(&self, set_id: Uuid) -> Result<Vec<Policy>> {
        let policy_set = self
            .get_policy_set(set_id)?
            .ok_or_else(|| PolicyError::PolicyNotFound(format!("Policy set: {}", set_id)))?;

        let mut policies = Vec::new();
        for policy_id in &policy_set.policies {
            if let Some(policy) = self.get(*policy_id)? {
                policies.push(policy);
            } else {
                warn!(policy_id = %policy_id, "Policy in set not found");
            }
        }

        Ok(policies)
    }

    /// Count total policies
    pub fn count(&self) -> usize {
        self.policies.len()
    }

    /// Count policies by type
    pub fn count_by_type(&self, policy_type: PolicyType) -> usize {
        self.policies
            .iter()
            .filter(|entry| entry.policy.policy_type == policy_type)
            .count()
    }
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Policy statistics
#[derive(Debug, Clone)]
pub struct PolicyStats {
    pub evaluation_count: u64,
    pub compiled: bool,
    pub compiled_at: Option<DateTime<Utc>>,
    pub last_evaluated: Option<DateTime<Utc>>,
    pub compile_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{EnforcementMode, PolicyType};

    #[test]
    fn test_store_and_retrieve() {
        let store = PolicyStore::new();
        let policy = Policy::new("test-policy", PolicyType::Rego, "package test");
        let id = policy.id;

        store.store(policy.clone()).unwrap();
        let retrieved = store.get(id).unwrap().unwrap();

        assert_eq!(retrieved.name, "test-policy");
        assert_eq!(retrieved.policy_type, PolicyType::Rego);
    }

    #[test]
    fn test_get_by_type() {
        let store = PolicyStore::new();
        let policy1 = Policy::new("wasm-policy", PolicyType::Wasm, "wasm-content");
        let policy2 = Policy::new("rego-policy", PolicyType::Rego, "package test");

        store.store(policy1).unwrap();
        store.store(policy2).unwrap();

        let wasm_policies = store.get_by_type(PolicyType::Wasm);
        assert_eq!(wasm_policies.len(), 1);
        assert_eq!(wasm_policies[0].name, "wasm-policy");
    }

    #[test]
    fn test_mark_compiled() {
        let store = PolicyStore::new();
        let policy = Policy::new("test-policy", PolicyType::Rego, "package test");
        let id = policy.id;

        store.store(policy).unwrap();
        store.mark_compiled(id, true, None).unwrap();

        assert!(store.is_compiled(id).unwrap());
    }

    #[test]
    fn test_policy_set() {
        let store = PolicyStore::new();
        let policy = Policy::new("test-policy", PolicyType::Rego, "package test");
        let policy_id = policy.id;

        store.store(policy).unwrap();

        let policy_set = PolicySet::new("test-set").add_policy(policy_id);
        let set_id = policy_set.id;

        store.store_policy_set(policy_set).unwrap();

        let policies = store.get_policy_set_policies(set_id).unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].id, policy_id);
    }
}
