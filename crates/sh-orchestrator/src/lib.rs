//! # Sh Orchestrator
//!
//! Advanced orchestration engine for Soul Hunter RS, implementing production-grade
//! patterns from opencode-orchestrator:
//!
//! - **MVCC State Synchronization**: Concurrent task updates without data loss using
//!   multi-version concurrency control with atomic operations
//! - **Work-Stealing Queues**: Chase-Lev work-stealing deque for optimal load balancing
//!   across parallel workers
//! - **Hook System**: Lifecycle hooks with phase ordering (early/normal/late) and
//!   topological sort for dependency-aware execution
//! - **Session Pool**: Isolated session contexts with auto-compaction and cleanup
//! - **Memory Pooling**: Object, string, and buffer pooling to reduce allocation overhead
//! - **Circuit Breaker**: Fault tolerance with automatic recovery from API failures
//! - **Autonomous Recovery**: Self-healing loops with diagnostic intervention and
//!   exponential backoff retry
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                   Enhanced Orchestrator                     │
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
//! │  │  MVCC State │  │ Work-Steal  │  │   Hook Registry     │  │
//! │  │  Sync       │  │ Queue       │  │  (Phased)           │  │
//! │  └─────────────┘  └─────────────┘  └─────────────────────┘  │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
//! │  │ Session     │  │ Memory      │  │   Circuit           │  │
//! │  │ Pool        │  │ Pool        │  │   Breaker           │  │
//! │  └─────────────┘  └─────────────┘  └─────────────────────┘  │
//! ├─────────────────────────────────────────────────────────────┤
//! │              Autonomous Recovery Engine                      │
//! │  ┌───────────────────────────────────────────────────────┐  │
//! │  │  Stagnation Detection → Diagnostic Mode → Recovery    │  │
//! │  └───────────────────────────────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Integration with Existing Soul Hunter Components
//!
//! The sh-orchestrator enhances the existing `sh-core` Orchestrator:
//!
//! - **sh-core::Orchestrator**: Uses MVCC for assessment state, work-stealing for
//!   agent distribution, hooks for lifecycle management
//! - **sh-scheduler::Scheduler**: Can be upgraded to use work-stealing queues instead
//!   of binary heap priority queues
//! - **sh-agent-manager**: Integrates with work-stealing for agent task assignment
//! - **sh-executor**: Executes jobs in isolated session contexts from the pool
//! - **sh-event-bus**: Publishes hook events and recovery diagnostics
//!
//! ## Usage Example
//!
//! ```rust
//! use sh_orchestrator::prelude::*;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create enhanced orchestrator with full feature set
//!     let orchestrator = EnhancedOrchestrator::new(EnhancedConfig::default());
//!
//!     // Run assessment with all enhancements
//!     let result = orchestrator.assess_with_recovery("/path/to/app.apk").await?;
//!
//!     // Monitor orchestration metrics
//!     let metrics = orchestrator.get_metrics();
//!     println!("Work-stealing efficiency: {}", metrics.work_steal_success_rate);
//!     println!("MVCC conflict resolution: {}", metrics.mvcc_conflicts_resolved);
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

/// Multi-Version Concurrency Control for atomic state updates
pub mod mvcc;
/// Work-stealing deque implementation (Chase-Lev algorithm)
pub mod worksteal;
/// Hook system with phase ordering and topological execution
pub mod hooks;
/// Session pool with isolation and auto-compaction
pub mod session_pool;
/// Memory pooling (object, string, buffer)
pub mod memory_pool;
/// Circuit breaker for fault tolerance
pub mod circuit_breaker;
/// Autonomous recovery with diagnostics
pub mod recovery;
/// Enhanced orchestrator that integrates all components
pub mod orchestrator;
/// Metrics and monitoring
pub mod metrics;
/// Utility types and traits
pub mod util;

// Re-export core types for convenience
pub use mvcc::{MvccStore, MvccVersion, MvccError};
pub use worksteal::{WorkStealingQueue, WorkStealingConfig, StealError};
pub use hooks::{Hook, HookRegistry, HookPhase, HookError, HookContext};
pub use session_pool::{SessionPool, SessionPoolConfig, SessionError};
pub use memory_pool::{MemoryPool, ObjectPool, PooledObject};
pub use circuit_breaker::{CircuitBreaker, CircuitState, BreakerError};
pub use recovery::{RecoveryEngine, DiagnosticMode, RecoveryStrategy};
pub use orchestrator::{EnhancedOrchestrator, EnhancedConfig, OrchestrationStrategy};
pub use metrics::OrchestrationMetrics;

/// Prelude module for convenient imports
pub mod prelude {
    pub use super::mvcc::*;
    pub use super::worksteal::*;
    pub use super::hooks::*;
    pub use super::session_pool::*;
    pub use super::memory_pool::*;
    pub use super::circuit_breaker::*;
    pub use super::recovery::*;
    pub use super::orchestrator::*;
    pub use super::metrics::*;
    pub use super::util::*;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orchestrator_module_compiles() {
        // Basic smoke test
        let config = EnhancedConfig::default();
        assert!(config.enable_mvcc);
        assert!(config.enable_work_stealing);
    }
}
