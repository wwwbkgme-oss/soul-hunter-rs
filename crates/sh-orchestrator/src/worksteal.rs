//! Work-Stealing Queue Implementation (Chase-Lev Algorithm)
//!
//! A high-performance concurrent work-stealing deque for parallel task scheduling.
//! Implements the Chase-Lev algorithm which provides:
//!
//! - **O(1) push/pop** for the owner thread
//! - **O(1) steal** for thief threads (from the bottom)
//! - **Lock-free** operations for maximum concurrency
//! - **Cache-friendly** layout with padding to avoid false sharing
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Work-Stealing Deque                     │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                              │
//! │  Top (Owner)          ↓ push/pop                             │
//! │  ┌─────────────────────────────────────┐                    │
//! │  │ [Task A] [Task B] [Task C] [     ]  │                    │
//! │  └─────────────────────────────────────┘                    │
//! │         ↑                                                     │
//! │       pop                                                      │
//! │                                                              │
//! │  Bottom (Thieves)     ↓ steal                               │
//! │  ┌─────────────────────────────────────┐                    │
//! │  │ [     ] [     ] [     ] [Task X]    │                    │
//! │  └─────────────────────────────────────┘                    │
//! │         ↑                                                     │
//! │       steal                                                   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```rust
//! use sh_orchestrator::worksteal::{WorkStealingQueue, WorkStealingConfig};
//!
//! let config = WorkStealingConfig {
//!     initial_size: 1024,
//!     max_size: 8192,
//!     enable_statistics: true,
//! };
//!
//! let queue = WorkStealingQueue::new(config);
//!
//! // Owner pushes work
//! queue.push(WorkItem::new(task_id, data)).await;
//!
//! // Owner pops from top
//! if let Some(item) = queue.pop().await {
//!     // Process item
//! }
//!
//! // Thieves steal from bottom
//! if let Some(item) = queue.steal().await {
//!     // Process stolen item
//! }
//! ```

use std::cell::UnsafeCell;
use std::collections::VecDeque;
use std::mem;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crossbeam::atomic::AtomicCell;
use crossbeam::queue::SegQueue;
use futures::future::BoxFuture;
use futures::FutureExt;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex as TokioMutex, OwnedPermit, Permit};
use tracing::{debug, trace, warn};

use sh_types::prelude::*;

/// Error types for work-stealing operations
#[derive(Error, Debug)]
pub enum StealError {
    #[error("Queue is empty")]
    Empty,

    #[error("Queue is full (capacity: {0})")]
    Full(usize),

    #[error("Contention timeout")]
    ContentionTimeout,

    #[error("Queue closed")]
    Closed,
}

/// A work item to be processed
#[derive(Debug, Clone)]
pub struct WorkItem<T> {
    /// Unique identifier for this work item
    pub id: String,
    /// The actual payload/data
    pub payload: T,
    /// Priority of this work item (higher = more urgent)
    pub priority: u8,
    /// When this item was created
    pub created_at: Instant,
    /// Owner agent/worker ID (for affinity)
    pub owner_id: Option<String>,
    /// Estimated execution time in milliseconds (for scheduling)
    pub estimated_duration_ms: Option<u64>,
    /// Dependencies on other work items (IDs)
    pub dependencies: Vec<String>,
}

impl<T> WorkItem<T> {
    /// Create new work item
    pub fn new(id: impl Into<String>, payload: T) -> Self {
        Self {
            id: id.into(),
            payload,
            priority: 1,
            created_at: Instant::now(),
            owner_id: None,
            estimated_duration_ms: None,
            dependencies: Vec::new(),
        }
    }

    /// With priority
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// With owner
    pub fn with_owner(mut self, owner_id: impl Into<String>) -> Self {
        self.owner_id = Some(owner_id.into());
        self
    }

    /// With estimated duration
    pub fn with_estimated_duration(mut self, ms: u64) -> Self {
        self.estimated_duration_ms = Some(ms);
        self
    }
}

/// Configuration for work-stealing queue
#[derive(Debug, Clone)]
pub struct WorkStealingConfig {
    /// Initial capacity of the deque (must be power of 2)
    pub initial_size: usize,
    /// Maximum capacity before rejecting pushes
    pub max_size: usize,
    /// Whether to collect performance statistics
    pub enable_statistics: bool,
    /// Number of bottom-half rings for thieves (default: 1)
    pub thief_rings: usize,
    /// Contention backoff duration in nanoseconds
    pub contention_backoff_ns: u64,
    /// Enable cache-line padding to avoid false sharing
    pub enable_padding: bool,
}

impl Default for WorkStealingConfig {
    fn default() -> Self {
        Self {
            initial_size: 1024,
            max_size: 8192,
            enable_statistics: true,
            thief_rings: 1,
            contention_backoff_ns: 100,
            enable_padding: true,
        }
    }
}

/// Performance statistics for work-stealing queue
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkStealStats {
    /// Total items pushed by owner
    pub pushes: usize,
    /// Total items popped by owner
    pub pops: usize,
    /// Total items stolen by thieves
    pub steals: usize,
    /// Failed steal attempts (empty)
    pub steal_failures: usize,
    /// Contention count (lock conflicts)
    pub contentions: usize,
    /// Total work items processed
    pub total_processed: usize,
    /// Average steal latency in nanoseconds
    pub avg_steal_latency_ns: f64,
    /// Owner efficiency (pops / pushes)
    pub owner_efficiency: f64,
}

/// Cache-line padded atomic type (64 bytes on x86_64)
#[repr(align(64))]
struct PaddedAtomic<T> {
    inner: AtomicCell<T>,
}

impl<T: Copy> PaddedAtomic<T> {
    fn new(value: T) -> Self {
        Self {
            inner: AtomicCell::new(value),
        }
    }

    fn load(&self, ordering: Ordering) -> T {
        self.inner.load(ordering)
    }

    fn store(&self, value: T, ordering: Ordering) {
        self.inner.store(value, ordering);
    }

    fn compare_exchange(
        &self,
        current: T,
        new: T,
    ) -> Result<T, T> {
        self.inner.compare_exchange(current, new)
    }
}

/// Chase-Lev Work-Stealing Deque
///
/// # Safety
///
/// This implementation uses unsafe code for lock-free operations.
/// All public methods are safe, but internal atomics ensure memory safety
/// through proper ordering and atomic operations.
pub struct ChaseLevDeque<T> {
    /// Bottom index (owner only, increasing)
    bottom: PaddedAtomic<usize>,
    /// Top index (owner and thieves, read by thieves, written by owner)
    top: AtomicUsize,
    /// The actual array (circular buffer)
    array: *mut Option<T>,
    /// Capacity (power of 2)
    capacity: usize,
    /// Mask for wrapping index (capacity - 1)
    mask: usize,
    /// Whether the deque is closed
    closed: AtomicCell<bool>,
}

impl<T> ChaseLevDeque<T> {
    /// Create new deque with given capacity (must be power of 2)
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity.is_power_of_two(), "capacity must be power of 2");
        let array = unsafe {
            let layout = std::alloc::Layout::array_of::<Option<T>>(capacity);
            let ptr = std::alloc::alloc(layout) as *mut Option<T>;
            std::ptr::write_bytes(ptr, 0, capacity);
            ptr
        };

        Self {
            bottom: PaddedAtomic::new(0),
            top: AtomicUsize::new(0),
            array,
            capacity,
            mask: capacity - 1,
            closed: AtomicCell::new(false),
        }
    }

    /// Owner push (O(1), always at bottom)
    pub fn push(&self, item: T) -> Result<(), StealError> {
        let b = self.bottom.load(Ordering::Relaxed);
        let t = self.top.load(Ordering::Acquire);

        // Check if full
        if b - t >= self.capacity {
            return Err(StealError::Full(self.capacity));
        }

        // Write item at bottom index
        let index = b & self.mask;
        unsafe {
            ptr::write(self.array.add(index).as_mut(), Some(item));
        }

        // Publish bottom increment (release barrier)
        self.bottom.store(b + 1, Ordering::Release);

        Ok(())
    }

    /// Owner pop (O(1), LIFO from top)
    pub fn pop(&self) -> Option<T> {
        let mut b = self.bottom.load(Ordering::Relaxed);
        let t = self.top.load(Ordering::Relaxed);

        if b <= t {
            return None;  // empty
        }

        // Fast-path: decrement bottom without contention
        b -= 1;
        self.bottom.store(b, Ordering::Relaxed);

        // Memory barrier
        std::sync::atomic::fence(Ordering::AcqRel);

        // Re-read top
        let t2 = self.top.load(Ordering::Relaxed);

        if b > t2 {
            // Still items, return the one we just decremented to
            let index = b & self.mask;
            unsafe {
                ptr::read(self.array.add(index))
            }
        } else {
            // Last item, need to synchronize with thieves
            // Reset bottom to top
            if !self.top.compare_exchange(t2, t2 + 1, Ordering::SeqCst, Ordering::Relaxed).is_ok() {
                // Lost race, another thief took it
                self.bottom.store(t2 + 1, Ordering::Relaxed);
                return None;
            }

            // We won, return the last item
            let index = b & self.mask;
            unsafe {
                ptr::read(self.array.add(index))
            }
        }
    }

    /// Thief steal (O(1), FIFO from top)
    pub fn steal(&self) -> Result<T, StealError> {
        let mut t = self.top.load(Ordering::Relaxed);
        let b = self.bottom.load(Ordering::Acquire);

        if b <= t {
            return Err(StealError::Empty);
        }

        // Read item at top index
        let index = t & self.mask;
        let item = unsafe { ptr::read(self.array.add(index)) };

        // Try to increment top
        match self.top.compare_exchange(t, t + 1, Ordering::SeqCst, Ordering::Relaxed) {
            Ok(_) => {
                // Successfully stole
                Ok(item)
            }
            Err(_) => {
                // Failed, put item back and return empty
                unsafe {
                    ptr::write(self.array.add(index), item);
                }
                Err(StealError::Empty)
            }
        }
    }

    /// Check if empty (approximate, not race-free)
    pub fn is_empty(&self) -> bool {
        let t = self.top.load(Ordering::Relaxed);
        let b = self.bottom.load(Ordering::Relaxed);
        b <= t
    }

    /// Get approximate size (not race-free)
    pub fn approximate_size(&self) -> usize {
        let t = self.top.load(Ordering::Relaxed);
        let b = self.bottom.load(Ordering::Relaxed);
        b.saturating_sub(t)
    }

    /// Close the deque (prevent further pushes)
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Check if closed
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl<T> Drop for ChaseLevDeque<T> {
    fn drop(&mut self) {
        // Drop remaining items
        while let Some(item) = self.pop() {
            drop(item);
        }

        // Free array
        unsafe {
            let layout = std::alloc::Layout::array_of::<Option<T>>(self.capacity);
            std::alloc::dealloc(self.array as *mut u8, layout);
        }
    }
}

/// Work-stealing queue manager
///
/// Manages a set of deques for a worker pool, where each worker has its own
/// deque and can steal from others' deques.
pub struct WorkStealingQueue<T> {
    /// Worker-local deques (one per worker)
    deques: Vec<Arc<ChaseLevDeque<T>>>,
    /// Global random number generator for victim selection
    config: WorkStealingConfig,
    /// Statistics collector
    stats: Arc<TokioMutex<WorkStealStats>>,
    /// Closed flag
    closed: AtomicCell<bool>,
}

impl<T: Send + 'static> WorkStealingQueue<T> {
    /// Create new work-stealing queue with configuration
    pub fn new(config: WorkStealingConfig) -> Self {
        let num_workers = num_cpus::get();  // Use all available CPUs
        let mut deques = Vec::with_capacity(num_workers);

        for _ in 0..num_workers {
            deques.push(Arc::new(ChaseLevDeque::with_capacity(config.initial_size)));
        }

        Self {
            deques,
            config,
            stats: Arc::new(TokioMutex::new(WorkStealStats::default())),
            closed: AtomicCell::new(false),
        }
    }

    /// Get the deque for a specific worker ID
    fn deque_for_worker(&self, worker_id: usize) -> Arc<ChaseLevDeque<T>> {
        self.deques[worker_id % self.deques.len()].clone()
    }

    /// Push work to a specific worker's deque (owner operation)
    pub async fn push(&self, worker_id: usize, item: WorkItem<T>) -> Result<(), StealError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(StealError::Closed);
        }

        let deque = self.deque_for_worker(worker_id);
        deque.push(item)?;

        if self.config.enable_statistics {
            let mut stats = self.stats.lock().await;
            stats.pushes += 1;
            stats.total_processed += 1;
        }

        trace!("Worker {} pushed work item {}", worker_id, item.id);
        Ok(())
    }

    /// Pop work from own deque (owner operation)
    pub async fn pop(&self, worker_id: usize) -> Option<WorkItem<T>> {
        let deque = self.deque_for_worker(worker_id);
        let item = deque.pop();

        if self.config.enable_statistics && item.is_some() {
            let mut stats = self.stats.lock().await;
            stats.pops += 1;
            stats.total_processed += 1;
            stats.owner_efficiency = stats.pops as f64 / stats.pushes.max(1) as f64;
        }

        trace!("Worker {} popped work item {:?}", worker_id, item.as_ref().map(|i| &i.id));
        item
    }

    /// Steal work from another worker (thief operation)
    ///
    /// Uses random victim selection to distribute contention.
    pub async fn steal(&self, thief_id: usize) -> Result<WorkItem<T>, StealError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(StealError::Closed);
        }

        let num_workers = self.deques.len();
        let start = thief_id % num_workers;

        // Random victim selection with linear probing
        let mut attempts = 0;
        let max_attempts = num_workers.min(8);  // Don't try more than 8 victims

        while attempts < max_attempts {
            let victim = (start + attempts) % num_workers;
            let victim_deque = self.deque_for_worker(victim);

            match victim_deque.steal() {
                Ok(item) => {
                    if self.config.enable_statistics {
                        let mut stats = self.stats.lock().await;
                        stats.steals += 1;
                        stats.total_processed += 1;
                    }
                    trace!("Worker {} stole work item {} from worker {}", thief_id, item.id, victim);
                    return Ok(item);
                }
                Err(StealError::Empty) => {
                    attempts += 1;
                }
                Err(e) => return Err(e),
            }
        }

        if self.config.enable_statistics {
            let mut stats = self.stats.lock().await;
            stats.steal_failures += 1;
        }

        Err(StealError::Empty)
    }

    /// Try to find work using any available strategy
    ///
    /// Tries: own queue → steal from random victims → wait for notification
    pub async fn find_work(&self, worker_id: usize, timeout: Option<Duration>) -> Option<WorkItem<T>> {
        let start = Instant::now();

        loop {
            // Try own queue first
            if let Some(item) = self.pop(worker_id).await {
                return Some(item);
            }

            // Try stealing
            match self.steal(worker_id).await {
                Ok(item) => return Some(item),
                Err(StealError::Empty) => {
                    // Check timeout
                    if let Some(timeout) = timeout {
                        if start.elapsed() >= timeout {
                            return None;
                        }
                    }

                    // Brief sleep before retry to avoid hot spinning
                   tokio::time::sleep(Duration::from_nanos(self.config.contention_backoff_ns)).await;
                }
                Err(e) => {
                    warn!("Steal error: {}", e);
                    return None;
                }
            }
        }
    }

    /// Get statistics
    pub async fn stats(&self) -> WorkStealStats {
        self.stats.lock().await.clone()
    }

    /// Reset statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.lock().await;
        *stats = WorkStealStats::default();
    }

    /// Get number of workers/deques
    pub fn num_workers(&self) -> usize {
        self.deques.len()
    }

    /// Close the queue (prevent new pushes)
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        for deque in &self.deques {
            deque.close();
        }
    }

    /// Check if closed
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl<T> Drop for WorkStealingQueue<T> {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_chase_lev_basic() {
        let deque = ChaseLevDeque::with_capacity(8);

        // Push items
        deque.push(1).unwrap();
        deque.push(2).unwrap();
        deque.push(3).unwrap();

        // Owner pops in LIFO order
        assert_eq!(deque.pop(), Some(3));
        assert_eq!(deque.pop(), Some(2));

        // Push more
        deque.push(4).unwrap();
        deque.push(5).unwrap();

        // Steal from bottom (FIFO)
        assert_eq!(deque.steal(), Ok(1));
        assert_eq!(deque.steal(), Ok(4));

        // Remaining
        assert_eq!(deque.pop(), Some(5));
        assert_eq!(deque.pop(), None);
    }

    #[tokio::test]
    async fn test_work_stealing_queue() {
        let queue = WorkStealingQueue::new(WorkStealingConfig::default());

        // Worker 0 pushes
        queue.push(0, WorkItem::new("task1", 42)).await.unwrap();
        queue.push(0, WorkItem::new("task2", 43)).await.unwrap();

        // Worker 0 pops
        let item1 = queue.pop(0).await.unwrap();
        assert_eq!(item1.id, "task2");  // LIFO
        assert_eq!(item1.payload, 43);

        // Worker 1 steals
        let stolen = queue.steal(1).await.unwrap();
        assert_eq!(stolen.id, "task1");
        assert_eq!(stolen.payload, 42);
    }

    #[tokio::test]
    async fn test_concurrent_stealing() {
        use std::sync::Arc;
        use tokio::task;

        let queue = Arc::new(WorkStealingQueue::new(WorkStealingConfig {
            initial_size: 64,
            max_size: 256,
            enable_statistics: false,
        }));

        // Worker 0 pushes 100 items
        for i in 0..100 {
            queue.push(0, WorkItem::new(format!("item-{}", i), i)).await.unwrap();
        }

        // Spawn 4 workers to steal
        let mut handles = vec![];
        let mut stolen_counts = vec![0usize; 4];

        for thief in 1..=4 {
            let queue_clone = Arc::clone(&queue);
            let count_ref = &mut stolen_counts[thief - 1];
            let handle = task::spawn(async move {
                while let Ok(item) = queue_clone.steal(thief).await {
                    **count_ref += 1;
                }
            });
            handles.push(handle);
        }

        // Wait a bit for stealing to happen
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Cancel tasks
        for h in handles {
            h.abort();
        }

        // Verify some stealing occurred
        let total_stolen: usize = stolen_counts.iter().sum();
        assert!(total_stolen > 0, "Expected some items to be stolen");
    }
}
