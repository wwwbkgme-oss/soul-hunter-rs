//! Memory Pooling for Performance Optimization
//!
//! Reduces allocation overhead by reusing objects, strings, and buffers.
//! Implements object pooling patterns for high-throughput scenarios.

use std::mem;
use std::ptr::{self, NonNull};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam::queue::SegQueue;
use parking_lot::{Mutex, MutexGuard};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, trace};

use sh_types::prelude::*;

/// Object pool for reusable allocations
pub struct ObjectPool<T> {
    /// Pool of reusable objects
    pool: SegQueue<T>,
    /// Factory function for creating new objects
    factory: Box<dyn Fn() -> T + Send + Sync>,
    /// Maximum size before dropping excess objects
    max_size: usize,
    /// Statistics
    metrics: bool,
}

impl<T> ObjectPool<T> {
    /// Create new object pool
    pub fn new<F>(max_size: usize, factory: F) -> Self
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        Self {
            pool: SegQueue::new(),
            factory: Box::new(factory),
            max_size,
            metrics: false,
        }
    }

    /// Enable metrics collection
    pub fn with_metrics(mut self) -> Self {
        self.metrics = true;
        self
    }

    /// Get an object from pool or create new one
    pub fn get(&self) -> T {
        match self.pool.try_pop() {
            Some(obj) => {
                trace!("ObjectPool: reused object");
                obj
            }
            None => {
                trace!("ObjectPool: created new object");
                (self.factory)()
            }
        }
    }

    /// Return object to pool
    pub fn put(&self, obj: T) {
        if self.pool.len() < self.max_size {
            self.pool.push(obj);
            trace!("ObjectPool: returned object (size now {})", self.pool.len());
        } else {
            trace!("ObjectPool: dropped object (pool full)");
        }
    }

    /// Get current pool size
    pub fn len(&self) -> usize {
        self.pool.len()
    }

    /// Check if pool is empty
    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }

    /// Clear the pool (drops all objects)
    pub fn clear(&self) {
        let mut count = 0;
        while self.pool.try_pop().is_some() {
            count += 1;
        }
        debug!("ObjectPool: cleared {} objects", count);
    }
}

/// String interning pool to reduce duplicate string allocations
pub struct StringPool {
    shared_strings: DashMap<String, Arc<str>>,
    max_shared: usize,
}

impl StringPool {
    pub fn new(max_shared: usize) -> Self {
        Self {
            shared_strings: DashMap::new(),
            max_shared,
        }
    }

    /// Intern a string, returning an Arc<str>
    pub fn intern(&self, s: &str) -> Arc<str> {
        if let Some(entry) = self.shared_strings.get(s) {
            return Arc::clone(entry.value());
        }

        // Evict oldest if at capacity
        if self.shared_strings.len() >= self.max_shared {
            if let Some(oldest) = self.shared_strings.iter().next() {
                self.shared_strings.remove(oldest.key());
            }
        }

        let interned: Arc<str> = Arc::from(s.to_string());
        self.shared_strings.insert(s.to_string(), Arc::clone(&interned));
        interned
    }

    /// Get stats
    pub fn stats(&self) -> StringPoolStats {
        StringPoolStats {
            total_strings: self.shared_strings.len(),
            estimated_savings: self.shared_strings.len() * std::mem::size_of::<String>(),
        }
    }
}

/// Statistics for string pool
#[derive(Debug, Clone)]
pub struct StringPoolStats {
    pub total_strings: usize,
    pub estimated_savings: usize,
}

/// Buffer pool for reusing byte buffers
pub struct BufferPool {
    buffers: SegQueue<Vec<u8>>,
    buffer_sizes: Vec<usize>,  // Available sizes (ascending)
    max_buffers_per_size: usize,
}

impl BufferPool {
    pub fn new(buffer_sizes: Vec<usize>, max_buffers_per_size: usize) -> Self {
        Self {
            buffers: SegQueue::new(),
            buffer_sizes: buffer_sizes.into_iter().sorted().collect(),
            max_buffers_per_size,
        }
    }

    /// Rent a buffer of at least `min_size` bytes
    pub fn rent(&self, min_size: usize) -> Vec<u8> {
        // Find appropriate size
            let size = *self.buffer_sizes
                .iter()
                .find(|&&s| s >= min_size)
                .unwrap_or(&min_size);

        // Try to get from pool
        if let Some(mut buf) = self.buffers.try_pop() {
            if buf.capacity() >= size {
                buf.clear();
                buf.resize(size, 0);
                trace!("BufferPool: reused buffer of size {}", size);
                return buf;
            }
        }

        // Create new buffer
        trace!("BufferPool: created new buffer of size {}", size);
        vec![0u8; size]
    }

    /// Return buffer to pool
    pub fn return_buffer(&self, mut buf: Vec<u8>) {
        if self.buffers.len() < self.max_buffers_per_size {
            buf.clear();
            buf.shrink_to_fit();
            self.buffers.push(buf);
            trace!("BufferPool: returned buffer");
        } else {
            trace!("BufferPool: dropped buffer (pool full)");
        }
    }

    /// Get statistics
    pub fn stats(&self) -> BufferPoolStats {
        BufferPoolStats {
            available_buffers: self.buffers.len(),
        }
    }
}

/// Buffer pool statistics
#[derive(Debug, Clone)]
pub struct BufferPoolStats {
    pub available_buffers: usize,
}

/// Generic pooled object wrapper
pub struct Pooled<T> {
    inner: T,
    pool: Arc<ObjectPool<T>>,
}

impl<T> Pooled<T> {
    pub fn new(inner: T, pool: Arc<ObjectPool<T>>) -> Self {
        Self { inner, pool }
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> Drop for Pooled<T> {
    fn drop(&mut self) {
        // Return to pool when dropped
        unsafe {
            let inner = ptr::read(&self.inner);
            self.pool.put(inner);
        }
    }
}

/// Dedicated allocator for arena-based memory pooling
pub struct ArenaAllocator {
    arena: Vec<u8>,
    offset: usize,
    capacity: usize,
}

impl ArenaAllocator {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            arena: Vec::with_capacity(cacity),
            offset: 0,
            capacity,
        }
    }

    /// Allocate `size` bytes from arena (no free, bump allocation)
    pub fn allocate(&mut self, size: usize) -> Result<&mut [u8], AllocError> {
        if self.offset + size > self.capacity {
            return Err(AllocError::OutOfMemory);
        }

        let start = self.offset;
        self.offset += size;

        // SAFETY: We own the buffer and ensure bounds
        unsafe {
            self.arena.set_len(self.offset);
            Ok(&mut self.arena.as_mut_ptr().add(start)[..size])
        }
    }

    /// Reset arena (destroys all allocations)
    pub fn reset(&mut self) {
        self.arena.clear();
        self.offset = 0;
    }

    /// Get used memory
    pub fn used(&self) -> usize {
        self.offset
    }

    /// Get total capacity
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Allocation error
#[derive(Error, Debug)]
pub enum AllocError {
    #[error("Out of memory in arena (capacity: {0}, requested: {1})")]
    OutOfMemory,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_pool() {
        let pool = Arc::new(ObjectPool::new(10, || String::new()));

        // Get and return
        let obj1 = pool.get();
        pool.put(obj1);

        assert!(pool.len() == 1);

        let obj2 = pool.get();
        assert!(obj2.is_empty());  // Reused
        drop(obj2);

        assert!(pool.len() == 1);
    }

    #[test]
    fn test_string_pool() {
        let pool = StringPool::new(100);

        let s1 = pool.intern("hello");
        let s2 = pool.intern("hello");
        let s3 = pool.intern("world");

        assert!(Arc::ptr_eq(&s1, &s2));  // Same pointer
        assert!(!Arc::ptr_eq(&s1, &s3));  // Different
    }

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(vec![64, 128, 256, 512], 10);

        let buf1 = pool.rent(100);
        assert_eq!(buf1.len(), 128);
        assert!(buf1.is_ascii());  // Zero-initialized

        pool.return_buffer(buf1);  // Would return
        // Note: can't easily test return_buffer due to internal pool state
    }

    #[test]
    fn test_arena_allocator() {
        let mut arena = ArenaAllocator::with_capacity(1024);

        let alloc1 = arena.allocate(100).unwrap();
        let alloc2 = arena.allocate(50).unwrap();

        assert_eq!(arena.used(), 150);

        arena.reset();
        assert_eq!(arena.used(), 0);
    }
}
