//! Priority Queue Implementation for Jobs
//!
//! Uses a binary heap to efficiently manage jobs by priority.
//! Higher priority jobs are processed first, with FIFO ordering
//! for jobs of the same priority.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;
use tracing::{debug, trace};

use sh_types::{Job, JobId, JobPriority};

/// Wrapper for jobs in the priority queue
///
/// Implements ordering so that:
/// 1. Higher priority jobs come first
/// 2. For same priority, earlier scheduled jobs come first (FIFO)
#[derive(Debug, Clone)]
pub struct PrioritizedJob {
    pub job: Job,
    pub scheduled_at: Instant,
    pub sequence: u64,
}

impl PrioritizedJob {
    /// Create a new prioritized job wrapper
    pub fn new(job: Job, sequence: u64) -> Self {
        Self {
            job,
            scheduled_at: Instant::now(),
            sequence,
        }
    }
}

impl PartialEq for PrioritizedJob {
    fn eq(&self, other: &Self) -> bool {
        self.job.priority == other.job.priority
            && self.scheduled_at == other.scheduled_at
            && self.sequence == other.sequence
    }
}

impl Eq for PrioritizedJob {}

impl PartialOrd for PrioritizedJob {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PrioritizedJob {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare by priority first (higher priority value = higher priority)
        // JobPriority enum values: Critical=100, High=75, Normal=50, Low=25, Lowest=0
        match self.job.priority.cmp(&other.job.priority) {
            Ordering::Greater => Ordering::Less,    // Higher priority comes first
            Ordering::Less => Ordering::Greater,    // Lower priority comes later
            Ordering::Equal => {
                // Same priority: earlier scheduled job comes first
                // Use sequence number for stable ordering
                other.sequence.cmp(&self.sequence)
            }
        }
    }
}

/// Thread-safe priority queue for jobs
///
/// Uses a binary heap internally for O(log n) push and pop operations.
/// Wrapped in an Arc<Mutex<>> for thread-safe access across async boundaries.
#[derive(Debug)]
pub struct JobPriorityQueue {
    inner: Arc<Mutex<BinaryHeap<PrioritizedJob>>>,
    sequence_counter: Arc<Mutex<u64>>,
    max_size: usize,
}

impl JobPriorityQueue {
    /// Create a new priority queue with the specified maximum size
    pub fn new(max_size: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BinaryHeap::new())),
            sequence_counter: Arc::new(Mutex::new(0)),
            max_size,
        }
    }

    /// Push a job onto the queue
    ///
    /// Returns an error if the queue is at capacity.
    pub async fn push(&self, job: Job) -> Result<(), PriorityQueueError> {
        let mut queue = self.inner.lock().await;

        if queue.len() >= self.max_size {
            return Err(PriorityQueueError::QueueFull(self.max_size));
        }

        let mut counter = self.sequence_counter.lock().await;
        let sequence = *counter;
        *counter += 1;
        drop(counter);

        let prioritized = PrioritizedJob::new(job, sequence);
        trace!(
            "Pushing job {} with priority {:?} (sequence: {})",
            prioritized.job.id,
            prioritized.job.priority,
            sequence
        );

        queue.push(prioritized);
        debug!("Job pushed to queue. Current size: {}", queue.len());

        Ok(())
    }

    /// Pop the highest priority job from the queue
    ///
    /// Returns None if the queue is empty.
    pub async fn pop(&self) -> Option<Job> {
        let mut queue = self.inner.lock().await;
        let result = queue.pop();

        if let Some(ref pj) = result {
            debug!(
                "Popped job {} with priority {:?}. Remaining: {}",
                pj.job.id,
                pj.job.priority,
                queue.len()
            );
        }

        result.map(|pj| pj.job)
    }

    /// Peek at the highest priority job without removing it
    pub async fn peek(&self) -> Option<Job> {
        let queue = self.inner.lock().await;
        queue.peek().map(|pj| pj.job.clone())
    }

    /// Get the current size of the queue
    pub async fn len(&self) -> usize {
        let queue = self.inner.lock().await;
        queue.len()
    }

    /// Check if the queue is empty
    pub async fn is_empty(&self) -> bool {
        let queue = self.inner.lock().await;
        queue.is_empty()
    }

    /// Get the maximum capacity of the queue
    pub fn capacity(&self) -> usize {
        self.max_size
    }

    /// Clear all jobs from the queue
    pub async fn clear(&self) {
        let mut queue = self.inner.lock().await;
        let count = queue.len();
        queue.clear();
        debug!("Cleared {} jobs from queue", count);
    }

    /// Get all jobs currently in the queue (for inspection/debugging)
    pub async fn get_jobs(&self) -> Vec<Job> {
        let queue = self.inner.lock().await;
        queue.iter().map(|pj| pj.job.clone()).collect()
    }

    /// Remove a specific job by ID
    pub async fn remove(&self, job_id: JobId) -> Option<Job> {
        let mut queue = self.inner.lock().await;
        let mut temp = BinaryHeap::new();
        let mut found = None;

        while let Some(pj) = queue.pop() {
            if pj.job.id == job_id {
                found = Some(pj.job);
                break;
            }
            temp.push(pj);
        }

        // Restore remaining items
        while let Some(pj) = temp.pop() {
            queue.push(pj);
        }

        found
    }

    /// Reprioritize a job (remove and re-insert with new priority)
    pub async fn reprioritize(&self, job_id: JobId, new_priority: JobPriority) -> Result<(), PriorityQueueError> {
        let mut queue = self.inner.lock().await;
        let mut temp = BinaryHeap::new();
        let mut found = None;

        // Find and remove the job
        while let Some(pj) = queue.pop() {
            if pj.job.id == job_id {
                found = Some(pj);
                break;
            }
            temp.push(pj);
        }

        // Restore temp items
        while let Some(pj) = temp.pop() {
            queue.push(pj);
        }

        // Re-insert with new priority if found
        if let Some(mut pj) = found {
            pj.job.priority = new_priority;
            queue.push(pj);
            debug!("Reprioritized job {} to {:?}", job_id, new_priority);
            Ok(())
        } else {
            Err(PriorityQueueError::JobNotFound(job_id))
        }
    }
}

impl Clone for JobPriorityQueue {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            sequence_counter: Arc::clone(&self.sequence_counter),
            max_size: self.max_size,
        }
    }
}

/// Errors that can occur in the priority queue
#[derive(Debug, thiserror::Error)]
pub enum PriorityQueueError {
    #[error("Queue is full (max capacity: {0})")]
    QueueFull(usize),

    #[error("Job not found: {0}")]
    JobNotFound(JobId),
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_types::{AnalysisTarget, Platform};

    fn create_test_job(job_type: &str, priority: JobPriority) -> Job {
        let target = AnalysisTarget::new("/test", Platform::Android);
        Job::new(job_type, target).with_priority(priority)
    }

    #[tokio::test]
    async fn test_priority_ordering() {
        let queue = JobPriorityQueue::new(100);

        let job_low = create_test_job("test", JobPriority::Low);
        let job_high = create_test_job("test", JobPriority::High);
        let job_critical = create_test_job("test", JobPriority::Critical);
        let job_normal = create_test_job("test", JobPriority::Normal);

        queue.push(job_low.clone()).await.unwrap();
        queue.push(job_high.clone()).await.unwrap();
        queue.push(job_critical.clone()).await.unwrap();
        queue.push(job_normal.clone()).await.unwrap();

        // Should pop in priority order: Critical, High, Normal, Low
        assert_eq!(queue.pop().await.unwrap().priority, JobPriority::Critical);
        assert_eq!(queue.pop().await.unwrap().priority, JobPriority::High);
        assert_eq!(queue.pop().await.unwrap().priority, JobPriority::Normal);
        assert_eq!(queue.pop().await.unwrap().priority, JobPriority::Low);
    }

    #[tokio::test]
    async fn test_fifo_same_priority() {
        let queue = JobPriorityQueue::new(100);

        let job1 = create_test_job("test1", JobPriority::Normal);
        let job2 = create_test_job("test2", JobPriority::Normal);
        let job3 = create_test_job("test3", JobPriority::Normal);

        let id1 = job1.id;
        let id2 = job2.id;
        let id3 = job3.id;

        queue.push(job1).await.unwrap();
        queue.push(job2).await.unwrap();
        queue.push(job3).await.unwrap();

        // Should maintain FIFO order for same priority
        assert_eq!(queue.pop().await.unwrap().id, id1);
        assert_eq!(queue.pop().await.unwrap().id, id2);
        assert_eq!(queue.pop().await.unwrap().id, id3);
    }

    #[tokio::test]
    async fn test_queue_full() {
        let queue = JobPriorityQueue::new(2);

        let job1 = create_test_job("test1", JobPriority::Normal);
        let job2 = create_test_job("test2", JobPriority::Normal);
        let job3 = create_test_job("test3", JobPriority::Normal);

        queue.push(job1).await.unwrap();
        queue.push(job2).await.unwrap();

        let result = queue.push(job3).await;
        assert!(matches!(result, Err(PriorityQueueError::QueueFull(2))));
    }

    #[tokio::test]
    async fn test_remove_job() {
        let queue = JobPriorityQueue::new(100);

        let job1 = create_test_job("test1", JobPriority::Normal);
        let job2 = create_test_job("test2", JobPriority::High);
        let id1 = job1.id;

        queue.push(job1).await.unwrap();
        queue.push(job2).await.unwrap();

        let removed = queue.remove(id1).await;
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().id, id1);

        // Should only have job2 left
        assert_eq!(queue.len().await, 1);
        assert_eq!(queue.pop().await.unwrap().priority, JobPriority::High);
    }

    #[tokio::test]
    async fn test_reprioritize() {
        let queue = JobPriorityQueue::new(100);

        let job = create_test_job("test", JobPriority::Low);
        let id = job.id;

        queue.push(job).await.unwrap();
        queue.reprioritize(id, JobPriority::Critical).await.unwrap();

        assert_eq!(queue.pop().await.unwrap().priority, JobPriority::Critical);
    }

    #[tokio::test]
    async fn test_clear() {
        let queue = JobPriorityQueue::new(100);

        for i in 0..5 {
            let job = create_test_job(&format!("test{}", i), JobPriority::Normal);
            queue.push(job).await.unwrap();
        }

        assert_eq!(queue.len().await, 5);
        queue.clear().await;
        assert_eq!(queue.len().await, 0);
        assert!(queue.is_empty().await);
    }
}
