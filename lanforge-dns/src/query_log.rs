use std::collections::VecDeque;
use parking_lot::Mutex;
use lanforge_core::types::network::QueryLogEntry;

/// A fixed-size, thread-safe ring buffer for DNS query logs.
/// 
/// Uses a `parking_lot::Mutex` to protect a `VecDeque`. For the 
/// scale of a domestic homelab, this provides more than enough 
/// performance for the DNS hot path.
pub struct QueryRing {
    capacity: usize,
    entries: Mutex<VecDeque<QueryLogEntry>>,
}

impl QueryRing {
    /// Creates a new `QueryRing` with the specified capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
        }
    }

    /// Pushes a new entry into the ring buffer.
    /// If the buffer is full, the oldest entry is removed.
    pub fn push(&self, entry: QueryLogEntry) {
        let mut entries = self.entries.lock();
        if entries.len() >= self.capacity {
            entries.pop_front();
        }
        entries.push_back(entry);
    }

    /// Returns a snapshot of the most recent entries, limited by `limit`.
    /// Entries are returned in reverse chronological order (newest first).
    pub fn get_recent(&self, limit: usize) -> Vec<QueryLogEntry> {
        let entries = self.entries.lock();
        entries.iter().rev().take(limit).cloned().collect()
    }

    /// Returns the current number of entries in the buffer.
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }
}
